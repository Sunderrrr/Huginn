//! Administration CRUD API — port of the hub's admin routes
//! (`hub/app/api/routes/{settings,mcp,tags,schedules,custom_actions,enrollment}.py`).
//!
//! | route                                    | Python handler            |
//! |------------------------------------------|---------------------------|
//! | `GET/PUT /api/settings`                  | `settings.py`             |
//! | `GET/POST /api/mcp/tokens`               | `mcp.py`                  |
//! | `PATCH/DELETE /api/mcp/tokens/{id}`      | `mcp.py`                  |
//! | `GET /api/mcp/whoami`                    | `mcp.py:whoami`           |
//! | `GET/POST /api/tags`, `PUT/DELETE …/{id}`| `tags.py`                 |
//! | `GET/POST /api/schedules`, `PUT/DELETE …/{id}` | `schedules.py`    |
//! | `GET/POST /api/actions`, `PATCH/DELETE …/{id}` | `custom_actions.py` |
//! | `GET/POST /api/enrollment-tokens`, `DELETE …/{id}` | `enrollment.py` |
//!
//! The handlers mirror the FastAPI surface exactly: the same status codes and
//! `{"detail": ...}` error shapes, the same request validation (pydantic field
//! bounds, cross-field checks), the same response models (secrets are never
//! listed — a plaintext token is returned exactly once, at creation), and the
//! same audit events through the tamper-evident audit chain.
//!
//! Two behaviors are worth calling out because they are easy to lose in a port:
//!
//! * **Authentication comes before body validation** — FastAPI solves
//!   dependencies (`get_principal` / `require_admin` / …) before it validates
//!   the request body, so an unauthenticated caller sees 401 even when the body
//!   is malformed. Only the global body-size cap (`app/main.py` middleware) runs
//!   earlier.
//! * **`GET /api/settings` is truncated for non-admins**: only the fleet fields
//!   (`target_worker_version`, `target_release_repo`, `allowed_release_domains`,
//!   `auto_update_enabled`, `updated_at`) are visible; SSO/LDAP/notification
//!   config (and every secret) stays admin-only.
//!
//! Data access goes through [`AdminStore`]; [`PgStore`] is the sqlx-backed
//! implementation used in production and `testing::MockStore` the in-memory one
//! used by the tests.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::{rejection::JsonRejection, ConnectInfo, DefaultBodyLimit, Extension};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::custom_action::{CustomAction, CustomActionNew, CustomActionPatch};
use crate::models::enrollment::{EnrollmentToken, EnrollmentTokenNew};
use crate::models::mcp_token::{McpToken, McpTokenNew};
use crate::models::scheduled_command::{ScheduledCommand, ScheduledCommandNew};
use crate::models::setting::{Setting, SettingValues};
use crate::models::tag::{Tag, TagPatch};
use crate::models::user::User;
use crate::models::{ActorType, UserRole};
use crate::security::SecurityConfig;

use self::schedules::SchedulePatch;

pub mod custom_actions;
pub mod enrollment;
pub mod mcp_tokens;
pub mod schedules;
pub mod settings;
pub mod tags;

// ---------------------------------------------------------------------------
// Errors: `ApiError` plus the few response headers FastAPI adds
// ---------------------------------------------------------------------------

/// Route error: [`ApiError`] plus optional response headers (e.g. the
/// `WWW-Authenticate: Bearer` FastAPI sends on a missing/invalid bearer
/// scheme — `ApiError` itself only renders the `{"detail": ...}` body).
#[derive(Debug, Clone)]
pub struct RouteError {
    api: ApiError,
    www_authenticate: bool,
}

impl RouteError {
    /// 401 with `WWW-Authenticate: Bearer` (`HTTPBearer`/`get_principal`).
    pub fn unauthorized_bearer(detail: impl Into<String>) -> Self {
        Self {
            api: ApiError::unauthorized(detail),
            www_authenticate: true,
        }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        ApiError::bad_request(detail).into()
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        ApiError::unauthorized(detail).into()
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        ApiError::forbidden(detail).into()
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        ApiError::not_found(detail).into()
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        ApiError::conflict(detail).into()
    }

    pub fn unprocessable_entity(detail: impl Into<String>) -> Self {
        ApiError::unprocessable_entity(detail).into()
    }

    pub fn payload_too_large(detail: impl Into<String>) -> Self {
        ApiError::payload_too_large(detail).into()
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        ApiError::internal(detail).into()
    }

    /// The FastAPI status code, for assertions.
    pub fn status(&self) -> StatusCode {
        self.api.status()
    }
}

impl From<ApiError> for RouteError {
    fn from(api: ApiError) -> Self {
        Self {
            api,
            www_authenticate: false,
        }
    }
}

impl From<DbError> for RouteError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::Conflict(detail) => Self::conflict(detail),
            DbError::Invalid(detail) => Self::bad_request(detail),
            DbError::NotFound => Self::not_found("not found"),
            other => Self::internal(other.to_string()),
        }
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let mut response = self.api.into_response();
        if self.www_authenticate {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                "Bearer".parse().unwrap(),
            );
        }
        response
    }
}

// ---------------------------------------------------------------------------
// The authenticated caller (app/core/principal.py + app/api/deps.py)
// ---------------------------------------------------------------------------

/// Who is performing an action: a user session, or the MCP façade acting for
/// itself / on behalf of a user (`app/core/principal.py`).
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub role: UserRole,
    pub user: Option<User>,
}

impl Principal {
    /// A real user is behind this principal — a direct human session or an MCP
    /// agent acting on behalf of a user (a per-user MCP token).
    fn has_identity(&self) -> bool {
        self.actor_type == ActorType::User || self.user.is_some()
    }

    /// True for an admin user, including via an on-behalf-of MCP token. The
    /// anonymous service-token agent is never admin.
    pub fn is_admin(&self) -> bool {
        self.has_identity() && self.role == UserRole::Admin
    }

    /// True for admin/operator users (including via an on-behalf-of MCP token).
    pub fn is_operator(&self) -> bool {
        self.has_identity() && matches!(self.role, UserRole::Admin | UserRole::Operator)
    }

    /// Operator capability: run actions/commands, read the catalog. Granted to
    /// operators/admins (human or MCP on-behalf-of) and to the anonymous
    /// service-token agent — never to read-only users, even through MCP.
    pub fn can_execute(&self) -> bool {
        if self.actor_type == ActorType::Agent && self.user.is_none() {
            return true;
        }
        self.is_operator()
    }

    /// A direct user session.
    pub fn from_user(user: &User) -> Self {
        Self {
            actor_type: ActorType::User,
            actor_id: user.id.to_string(),
            role: user.role,
            user: Some(user.clone()),
        }
    }

    /// The MCP façade. With a user (per-user MCP token) it acts AS that user;
    /// `actor_type` stays `agent` so the audit shows "mcp". Without a user it is
    /// the anonymous service-token agent ("hermes", read-only role).
    pub fn agent(user: Option<&User>) -> Self {
        match user {
            Some(user) => Self {
                actor_type: ActorType::Agent,
                actor_id: user.id.to_string(),
                role: user.role,
                user: Some(user.clone()),
            },
            None => Self {
                actor_type: ActorType::Agent,
                actor_id: "hermes".to_owned(),
                role: UserRole::Readonly,
                user: None,
            },
        }
    }
}

/// The authenticated caller plus the best-effort client IP used for auditing.
#[derive(Debug, Clone)]
pub struct Caller {
    pub principal: Principal,
    pub source_ip: Option<String>,
}

impl Caller {
    /// `require_admin` — human admin (or an admin's MCP token), 403 otherwise.
    pub fn require_admin(&self) -> Result<(), RouteError> {
        if self.principal.is_admin() {
            Ok(())
        } else {
            Err(RouteError::forbidden("admin role required"))
        }
    }

    /// `require_operator` — admin/operator/agent, 403 for read-only users.
    pub fn require_operator(&self) -> Result<(), RouteError> {
        if self.principal.can_execute() {
            Ok(())
        } else {
            Err(RouteError::forbidden("operator privileges required"))
        }
    }

    /// `mcp.py:_require_user` — the user behind the request.
    pub fn require_user(&self) -> Result<&User, RouteError> {
        self.principal
            .user
            .as_ref()
            .ok_or_else(|| RouteError::forbidden("a user session is required"))
    }
}

// ---------------------------------------------------------------------------
// State + data-access trait
// ---------------------------------------------------------------------------

/// Boxed future returned by [`AdminStore`] methods (dyn-compatible async trait).
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything the admin routes need. Cheap to clone.
#[derive(Clone)]
pub struct AdminState {
    pub config: Config,
    pub security: SecurityConfig,
    pub store: Arc<dyn AdminStore>,
}

impl AdminState {
    /// Production state backed by the sqlx data layer.
    pub fn new(pool: sqlx::PgPool, config: Config) -> Self {
        let security = SecurityConfig::new(
            &config.mfa_encryption_key,
            &config.jwt_secret,
            &config.secret_hash_key,
        );
        Self {
            config,
            security,
            store: Arc::new(PgStore { pool }),
        }
    }

    /// The hard global request-body cap (`app/main.py` middleware): the largest
    /// legitimate body is a worker result carrying stdout+stderr each up to
    /// `max_output_bytes`.
    pub fn global_body_cap(&self) -> usize {
        self.config.max_output_bytes * 2 + 65_536
    }
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState").finish_non_exhaustive()
    }
}

/// The data the admin routes touch. Mirrors `app/services/*` query semantics
/// one level down (the `crate::models` layer), so the routes stay pure
/// request/response + validation and tests can swap in an in-memory store.
pub trait AdminStore: Send + Sync {
    // users (principal resolution)
    fn get_user(&self, id: Uuid) -> StoreFuture<'_, Result<Option<User>, DbError>>;

    // settings (single row)
    fn get_settings(&self) -> StoreFuture<'_, Result<Option<Setting>, DbError>>;
    fn save_settings(&self, values: SettingValues) -> StoreFuture<'_, Result<Setting, DbError>>;

    // mcp tokens
    fn list_mcp_tokens(&self, user_id: Uuid) -> StoreFuture<'_, Result<Vec<McpToken>, DbError>>;
    fn create_mcp_token(&self, new: McpTokenNew) -> StoreFuture<'_, Result<McpToken, DbError>>;
    fn set_mcp_allowed_ip(
        &self,
        token_id: Uuid,
        user_id: Uuid,
        allowed_ip: Option<String>,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>>;
    fn revoke_mcp_token(
        &self,
        token_id: Uuid,
        user_id: Uuid,
    ) -> StoreFuture<'_, Result<bool, DbError>>;
    fn active_mcp_token_by_hash(
        &self,
        token_hash: &str,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>>;
    fn touch_mcp_token(
        &self,
        token_id: Uuid,
        at: DateTime<Utc>,
    ) -> StoreFuture<'_, Result<(), DbError>>;

    // tags
    fn list_tags(&self) -> StoreFuture<'_, Result<Vec<Tag>, DbError>>;
    fn get_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<Option<Tag>, DbError>>;
    fn create_tag(&self, name: &str, color: &str) -> StoreFuture<'_, Result<Tag, DbError>>;
    fn update_tag(
        &self,
        tag_id: Uuid,
        patch: TagPatch,
    ) -> StoreFuture<'_, Result<Option<Tag>, DbError>>;
    fn delete_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>>;

    // scheduled commands
    fn list_schedules(&self) -> StoreFuture<'_, Result<Vec<ScheduledCommand>, DbError>>;
    fn get_schedule(
        &self,
        schedule_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>>;
    fn create_schedule(
        &self,
        new: ScheduledCommandNew,
    ) -> StoreFuture<'_, Result<ScheduledCommand, DbError>>;
    fn update_schedule(
        &self,
        schedule_id: Uuid,
        patch: SchedulePatch,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>>;
    fn delete_schedule(&self, schedule_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>>;

    // custom actions
    fn list_actions(&self) -> StoreFuture<'_, Result<Vec<CustomAction>, DbError>>;
    fn get_action(&self, action_id: Uuid)
        -> StoreFuture<'_, Result<Option<CustomAction>, DbError>>;
    fn create_action(&self, new: CustomActionNew)
        -> StoreFuture<'_, Result<CustomAction, DbError>>;
    fn update_action(
        &self,
        action_id: Uuid,
        patch: CustomActionPatch,
    ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>>;
    fn remove_action(&self, action_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>>;
    fn action_tag_ids(&self, action_id: Uuid) -> StoreFuture<'_, Result<Vec<Uuid>, DbError>>;

    // enrollment tokens
    fn create_enrollment_token(
        &self,
        new: EnrollmentTokenNew,
    ) -> StoreFuture<'_, Result<EnrollmentToken, DbError>>;
    fn list_enrollment_tokens(&self) -> StoreFuture<'_, Result<Vec<EnrollmentToken>, DbError>>;
    fn revoke_enrollment_token(
        &self,
        token_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<EnrollmentToken>, DbError>>;

    // audit chain
    fn record_audit(&self, entry: AuditNew) -> StoreFuture<'_, Result<(), DbError>>;
}

/// [`AdminStore`] over the sqlx data layer (production).
pub struct PgStore {
    pub pool: sqlx::PgPool,
}

impl AdminStore for PgStore {
    fn get_user(&self, id: Uuid) -> StoreFuture<'_, Result<Option<User>, DbError>> {
        Box::pin(async move { crate::models::user::get_by_id(&self.pool, id).await })
    }

    fn get_settings(&self) -> StoreFuture<'_, Result<Option<Setting>, DbError>> {
        Box::pin(async move { crate::models::setting::get_settings_row(&self.pool).await })
    }

    fn save_settings(&self, values: SettingValues) -> StoreFuture<'_, Result<Setting, DbError>> {
        Box::pin(async move { crate::models::setting::upsert(&self.pool, values).await })
    }

    fn list_mcp_tokens(&self, user_id: Uuid) -> StoreFuture<'_, Result<Vec<McpToken>, DbError>> {
        Box::pin(
            async move { crate::models::mcp_token::list_for_user(&self.pool, user_id, true).await },
        )
    }

    fn create_mcp_token(&self, new: McpTokenNew) -> StoreFuture<'_, Result<McpToken, DbError>> {
        Box::pin(async move { crate::models::mcp_token::create(&self.pool, new).await })
    }

    fn set_mcp_allowed_ip(
        &self,
        token_id: Uuid,
        user_id: Uuid,
        allowed_ip: Option<String>,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>> {
        Box::pin(async move {
            crate::models::mcp_token::set_allowed_ip(
                &self.pool,
                token_id,
                user_id,
                allowed_ip.as_deref(),
            )
            .await
        })
    }

    fn revoke_mcp_token(
        &self,
        token_id: Uuid,
        user_id: Uuid,
    ) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(
            async move { crate::models::mcp_token::revoke(&self.pool, token_id, user_id).await },
        )
    }

    fn active_mcp_token_by_hash(
        &self,
        token_hash: &str,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>> {
        // Owned copy so the future only borrows `self` (the trait's `'_`).
        let token_hash = token_hash.to_owned();
        Box::pin(async move {
            crate::models::mcp_token::get_active_by_token_hash(&self.pool, &token_hash).await
        })
    }

    fn touch_mcp_token(
        &self,
        token_id: Uuid,
        at: DateTime<Utc>,
    ) -> StoreFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            crate::models::mcp_token::touch_last_used(&self.pool, token_id, at)
                .await
                .map(|_| ())
        })
    }

    fn list_tags(&self) -> StoreFuture<'_, Result<Vec<Tag>, DbError>> {
        Box::pin(async move { crate::models::tag::list_tags(&self.pool).await })
    }

    fn get_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<Option<Tag>, DbError>> {
        Box::pin(async move { crate::models::tag::get_tag(&self.pool, tag_id).await })
    }

    fn create_tag(&self, name: &str, color: &str) -> StoreFuture<'_, Result<Tag, DbError>> {
        let (name, color) = (name.to_owned(), color.to_owned());
        Box::pin(async move { crate::models::tag::create_tag(&self.pool, &name, &color).await })
    }

    fn update_tag(
        &self,
        tag_id: Uuid,
        patch: TagPatch,
    ) -> StoreFuture<'_, Result<Option<Tag>, DbError>> {
        Box::pin(async move { crate::models::tag::update_tag(&self.pool, tag_id, patch).await })
    }

    fn delete_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(async move { crate::models::tag::delete_tag(&self.pool, tag_id).await })
    }

    fn list_schedules(&self) -> StoreFuture<'_, Result<Vec<ScheduledCommand>, DbError>> {
        Box::pin(async move { crate::models::scheduled_command::list_schedules(&self.pool).await })
    }

    fn get_schedule(
        &self,
        schedule_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>> {
        Box::pin(
            async move { crate::models::scheduled_command::get(&self.pool, schedule_id).await },
        )
    }

    fn create_schedule(
        &self,
        new: ScheduledCommandNew,
    ) -> StoreFuture<'_, Result<ScheduledCommand, DbError>> {
        Box::pin(async move { crate::models::scheduled_command::create(&self.pool, new).await })
    }

    fn update_schedule(
        &self,
        schedule_id: Uuid,
        patch: SchedulePatch,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>> {
        Box::pin(async move {
            // `COALESCE` covers "leave untouched"; the boolean flags cover
            // "explicitly sent as null" (`exclude_unset` + `setattr(None)` in
            // the Python service) — clearing a column is the one case the
            // models layer's COALESCE-only patch cannot express.
            let clear_vm = patch.target_vm_id.is_some_and(|v| v.is_none());
            let clear_tag = patch.target_tag_id.is_some_and(|v| v.is_none());
            let clear_action = patch.action_name.as_ref().is_some_and(|v| v.is_none());
            let clear_command = patch.command.as_ref().is_some_and(|v| v.is_none());
            let row = sqlx::query_as::<_, ScheduledCommand>(
                "UPDATE scheduled_commands SET \
                 name = COALESCE($2, name), \
                 enabled = COALESCE($3, enabled), \
                 target_kind = COALESCE($4, target_kind), \
                 target_vm_id = CASE WHEN $5 THEN NULL ELSE COALESCE($6, target_vm_id) END, \
                 target_tag_id = CASE WHEN $7 THEN NULL ELSE COALESCE($8, target_tag_id) END, \
                 task_kind = COALESCE($9, task_kind), \
                 action_name = CASE WHEN $10 THEN NULL ELSE COALESCE($11, action_name) END, \
                 params = COALESCE($12::json, params), \
                 command = CASE WHEN $13 THEN NULL ELSE COALESCE($14, command) END, \
                 cron_expression = COALESCE($15, cron_expression), \
                 updated_at = $16 \
                 WHERE id = $1 RETURNING *",
            )
            .bind(schedule_id)
            .bind(&patch.name)
            .bind(patch.enabled)
            .bind(&patch.target_kind)
            .bind(clear_vm)
            .bind(patch.target_vm_id.flatten())
            .bind(clear_tag)
            .bind(patch.target_tag_id.flatten())
            .bind(&patch.task_kind)
            .bind(clear_action)
            .bind(patch.action_name.as_ref().and_then(|v| v.as_deref()))
            .bind(patch.params.clone())
            .bind(clear_command)
            .bind(patch.command.as_ref().and_then(|v| v.as_deref()))
            .bind(&patch.cron_expression)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await?;
            Ok(row)
        })
    }

    fn delete_schedule(&self, schedule_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(
            async move { crate::models::scheduled_command::delete(&self.pool, schedule_id).await },
        )
    }

    fn list_actions(&self) -> StoreFuture<'_, Result<Vec<CustomAction>, DbError>> {
        Box::pin(async move { crate::models::custom_action::list_all(&self.pool).await })
    }

    fn get_action(
        &self,
        action_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>> {
        Box::pin(async move { crate::models::custom_action::get(&self.pool, action_id).await })
    }

    fn create_action(
        &self,
        new: CustomActionNew,
    ) -> StoreFuture<'_, Result<CustomAction, DbError>> {
        Box::pin(async move { crate::models::custom_action::create(&self.pool, new).await })
    }

    fn update_action(
        &self,
        action_id: Uuid,
        patch: CustomActionPatch,
    ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>> {
        Box::pin(
            async move { crate::models::custom_action::update(&self.pool, action_id, patch).await },
        )
    }

    fn remove_action(&self, action_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(async move { crate::models::custom_action::remove(&self.pool, action_id).await })
    }

    fn action_tag_ids(&self, action_id: Uuid) -> StoreFuture<'_, Result<Vec<Uuid>, DbError>> {
        Box::pin(
            async move { crate::models::custom_action::tag_ids_for(&self.pool, action_id).await },
        )
    }

    fn create_enrollment_token(
        &self,
        new: EnrollmentTokenNew,
    ) -> StoreFuture<'_, Result<EnrollmentToken, DbError>> {
        Box::pin(async move { crate::models::enrollment::create_token(&self.pool, new).await })
    }

    fn list_enrollment_tokens(&self) -> StoreFuture<'_, Result<Vec<EnrollmentToken>, DbError>> {
        Box::pin(async move { crate::models::enrollment::list_tokens(&self.pool).await })
    }

    fn revoke_enrollment_token(
        &self,
        token_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<EnrollmentToken>, DbError>> {
        Box::pin(async move { crate::models::enrollment::revoke_token(&self.pool, token_id).await })
    }

    fn record_audit(&self, entry: AuditNew) -> StoreFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            // Hash-chain append: `row_hash = sha256(prev_hash + canonical(fields))`
            // while holding the advisory lock (models::audit).
            crate::models::audit::append_chained(&self.pool, entry, |entry, prev| {
                (
                    prev.to_owned(),
                    crate::security::compute_row_hash(prev, &entry.hash_fields()),
                )
            })
            .await
            .map(|_| ())
        })
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// The `/api/settings` + `/api/mcp` + `/api/tags` + `/api/schedules` +
/// `/api/actions` + `/api/enrollment-tokens` router (prefixes included, so it
/// can be merged as-is).
pub fn router(state: AdminState) -> Router {
    // Same hard global request-body cap as `app/main.py`'s middleware.
    let global_cap = state.global_body_cap();
    Router::new()
        .merge(settings::routes())
        .merge(mcp_tokens::routes())
        .merge(tags::routes())
        .merge(schedules::routes())
        .merge(custom_actions::routes())
        .merge(enrollment::routes())
        .layer(DefaultBodyLimit::max(global_cap))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Request pipeline helpers (app/api/deps.py + app/main.py)
// ---------------------------------------------------------------------------

/// Header lookup, case-insensitive (HeaderMap already is).
pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Peer address from axum's `ConnectInfo` extension (absent in unit tests).
pub fn peer_addr(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<SocketAddr> {
    peer.map(|Extension(ConnectInfo(addr))| addr)
}

/// Python `repr()` of a string — the `!r` formatting used in the hub's error
/// messages (e.g. `f"unknown action: {name!r}"`).
pub fn py_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Best-effort real client IP (`deps.client_ip`): the first hop of
/// `X-Forwarded-For` when `trust_forwarded_for` is explicitly set, otherwise
/// the peer address.
pub fn client_ip(headers: &HeaderMap, config: &Config, peer: Option<SocketAddr>) -> Option<String> {
    if config.trust_forwarded_for {
        if let Some(forwarded) = header_str(headers, "x-forwarded-for") {
            if let Some(first) = forwarded.split(',').map(str::trim).find(|s| !s.is_empty()) {
                return Some(first.to_owned());
            }
        }
    }
    peer.map(|p| p.ip().to_string())
}

/// `app/main.py`'s global body cap, checked before authentication exactly like
/// the middleware (Content-Length first, then the actual body size).
pub fn enforce_body_size(headers: &HeaderMap, cap: usize) -> Result<(), RouteError> {
    if let Some(cl) = header_str(headers, "content-length") {
        if let Ok(len) = cl.trim().parse::<usize>() {
            if len > cap {
                return Err(RouteError::payload_too_large("request body too large"));
            }
        }
    }
    Ok(())
}

/// Axum JSON rejections mapped onto FastAPI semantics: oversized bodies are 413
/// ("request body too large"), every parse/shape failure is 422 (pydantic's
/// status).
pub fn json_body<T: serde::de::DeserializeOwned>(
    body: Result<Json<T>, JsonRejection>,
) -> Result<T, RouteError> {
    match body {
        Ok(Json(value)) => Ok(value),
        Err(err) if err.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(RouteError::payload_too_large("request body too large"))
        }
        Err(err) => Err(RouteError::unprocessable_entity(err.body_text())),
    }
}

/// Authenticate the caller as a user (JWT bearer) or the MCP agent (service
/// token) — `deps.get_principal`.
pub async fn authenticate(
    state: &AdminState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Result<Caller, RouteError> {
    let source_ip = client_ip(headers, &state.config, peer);
    let principal = principal_of(state, headers, source_ip.as_deref()).await?;
    Ok(Caller {
        principal,
        source_ip,
    })
}

async fn principal_of(
    state: &AdminState,
    headers: &HeaderMap,
    client_ip: Option<&str>,
) -> Result<Principal, RouteError> {
    // MCP façade: timing-safe service-token check, then optional on-behalf-of.
    if let Some(service_token) = header_str(headers, "x-mcp-service-token") {
        if !crate::security::constant_time_equals(service_token, &state.config.mcp_service_token) {
            return Err(RouteError::unauthorized("invalid service token"));
        }
        if let Some(presented) = header_str(headers, "x-mcp-on-behalf-of").filter(|s| !s.is_empty())
        {
            let user = mcp_tokens::resolve(state, presented, client_ip).await?;
            let Some(user) = user else {
                return Err(RouteError::unauthorized("invalid MCP token"));
            };
            return Ok(Principal::agent(Some(&user)));
        }
        return Ok(Principal::agent(None));
    }

    let Some(authorization) = header_str(headers, "authorization") else {
        return Err(RouteError::unauthorized_bearer("authentication required"));
    };
    let mut parts = authorization.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let Some(token) = parts.next().map(str::trim).filter(|t| !t.is_empty()) else {
        return Err(RouteError::unauthorized_bearer("authentication required"));
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(RouteError::unauthorized_bearer("authentication required"));
    }

    let payload = crate::security::decode_access_token(&state.security.jwt_secret, token)
        .map_err(|_| RouteError::unauthorized("invalid token"))?;
    let Some(sub) = payload.get("sub").and_then(|v| v.as_str()) else {
        return Err(RouteError::unauthorized("invalid token"));
    };
    let Ok(user_id) = Uuid::parse_str(sub) else {
        return Err(RouteError::unauthorized("invalid token"));
    };
    // Intermediate MFA challenge/setup tokens are not valid for the business
    // API: they may only be presented to `/api/auth/mfa`.
    if let Some(scope) = payload.get("scope").and_then(|v| v.as_str()) {
        if crate::security::MFA_SCOPES.contains(&scope) {
            return Err(RouteError::unauthorized("token not valid for API access"));
        }
    }
    let user = state
        .store
        .get_user(user_id)
        .await
        .map_err(RouteError::from)?;
    let Some(user) = user.filter(|u| u.is_active) else {
        return Err(RouteError::unauthorized("user not found or inactive"));
    };
    Ok(Principal::from_user(&user))
}

/// `audit.record(...)` — append one tamper-evident audit entry.
pub async fn audit_record(
    state: &AdminState,
    caller: &Caller,
    event_type: &str,
    detail: serde_json::Value,
) -> Result<(), RouteError> {
    let mut entry = AuditNew::new(
        caller.principal.actor_type,
        caller.principal.actor_id.clone(),
        event_type,
    );
    entry.detail = detail;
    entry.source_ip = caller.source_ip.clone();
    state.store.record_audit(entry).await.map_err(Into::into)
}

/// Parse a path id the way FastAPI parses `uuid.UUID` path params.
pub fn path_uuid(raw: &str, what: &str) -> Result<Uuid, RouteError> {
    raw.parse::<Uuid>()
        .map_err(|_| RouteError::unprocessable_entity(format!("{what} must be a valid UUID")))
}

// ---------------------------------------------------------------------------
// Test store + shared test helpers (no live database required)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::models::custom_action::CustomActionNew;
    use crate::models::enrollment::EnrollmentTokenNew;
    use crate::models::mcp_token::McpTokenNew;
    use crate::models::scheduled_command::ScheduledCommandNew;

    /// In-memory [`AdminStore`] for route tests.
    #[derive(Default)]
    pub struct MockStore {
        pub db: Mutex<MockDb>,
    }

    /// The rows a mock store keeps. Tests read/write these directly.
    #[derive(Default)]
    pub struct MockDb {
        pub users: HashMap<Uuid, User>,
        pub settings: Option<Setting>,
        pub mcp_tokens: HashMap<Uuid, McpToken>,
        pub tags: HashMap<Uuid, Tag>,
        pub schedules: HashMap<Uuid, ScheduledCommand>,
        pub actions: HashMap<Uuid, CustomAction>,
        pub action_tags: HashMap<Uuid, Vec<Uuid>>,
        pub enrollment_tokens: HashMap<Uuid, EnrollmentToken>,
        pub audit: Vec<AuditNew>,
    }

    impl MockDb {
        /// Tags sorted by name (parity with `services.tags.list_tags`).
        pub fn tags_by_name(&self) -> Vec<Tag> {
            let mut tags: Vec<Tag> = self.tags.values().cloned().collect();
            tags.sort_by(|a, b| a.name.cmp(&b.name));
            tags
        }

        /// MCP tokens of one user, oldest first (parity with `list_for_user`).
        pub fn mcp_tokens_of(&self, user_id: Uuid) -> Vec<McpToken> {
            let mut tokens: Vec<McpToken> = self
                .mcp_tokens
                .values()
                .filter(|t| t.user_id == user_id && t.revoked_at.is_none())
                .cloned()
                .collect();
            tokens.sort_by_key(|t| t.created_at);
            tokens
        }

        /// Schedules, newest first (parity with `list_schedules`).
        pub fn schedules_newest_first(&self) -> Vec<ScheduledCommand> {
            let mut rows: Vec<ScheduledCommand> = self.schedules.values().cloned().collect();
            rows.sort_by_key(|a| std::cmp::Reverse(a.created_at));
            rows
        }

        /// Custom actions sorted by name (parity with `list_all`).
        pub fn actions_by_name(&self) -> Vec<CustomAction> {
            let mut rows: Vec<CustomAction> = self.actions.values().cloned().collect();
            rows.sort_by(|a, b| a.name.cmp(&b.name));
            rows
        }

        /// Enrollment tokens, newest first (parity with `list_tokens`).
        pub fn enrollment_newest_first(&self) -> Vec<EnrollmentToken> {
            let mut rows: Vec<EnrollmentToken> = self.enrollment_tokens.values().cloned().collect();
            rows.sort_by_key(|a| std::cmp::Reverse(a.created_at));
            rows
        }
    }

    impl AdminStore for MockStore {
        fn get_user(&self, id: Uuid) -> StoreFuture<'_, Result<Option<User>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().users.get(&id).cloned()) })
        }

        fn get_settings(&self) -> StoreFuture<'_, Result<Option<Setting>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().settings.clone()) })
        }

        fn save_settings(
            &self,
            values: SettingValues,
        ) -> StoreFuture<'_, Result<Setting, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let row = settings::setting_row(values, Utc::now());
                db.settings = Some(row.clone());
                Ok(row)
            })
        }

        fn list_mcp_tokens(
            &self,
            user_id: Uuid,
        ) -> StoreFuture<'_, Result<Vec<McpToken>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().mcp_tokens_of(user_id)) })
        }

        fn create_mcp_token(&self, new: McpTokenNew) -> StoreFuture<'_, Result<McpToken, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let now = Utc::now();
                let token = McpToken {
                    id: Uuid::new_v4(),
                    user_id: new.user_id,
                    token_hash: new.token_hash,
                    name: new.name,
                    allowed_ip: new.allowed_ip,
                    last_used_at: None,
                    revoked_at: None,
                    created_at: now,
                    updated_at: now,
                };
                db.mcp_tokens.insert(token.id, token.clone());
                Ok(token)
            })
        }

        fn set_mcp_allowed_ip(
            &self,
            token_id: Uuid,
            user_id: Uuid,
            allowed_ip: Option<String>,
        ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let now = Utc::now();
                let Some(token) = db.mcp_tokens.get_mut(&token_id) else {
                    return Ok(None);
                };
                if token.user_id != user_id || token.revoked_at.is_some() {
                    return Ok(None);
                }
                token.allowed_ip = allowed_ip;
                token.updated_at = now;
                Ok(Some(token.clone()))
            })
        }

        fn revoke_mcp_token(
            &self,
            token_id: Uuid,
            user_id: Uuid,
        ) -> StoreFuture<'_, Result<bool, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let now = Utc::now();
                let Some(token) = db.mcp_tokens.get_mut(&token_id) else {
                    return Ok(false);
                };
                if token.user_id != user_id || token.revoked_at.is_some() {
                    return Ok(false);
                }
                token.revoked_at = Some(now);
                token.updated_at = now;
                Ok(true)
            })
        }

        fn active_mcp_token_by_hash(
            &self,
            token_hash: &str,
        ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>> {
            // Owned copy so the future only borrows `self` (the trait's `'_`).
            let token_hash = token_hash.to_owned();
            Box::pin(async move {
                Ok(self
                    .db
                    .lock()
                    .unwrap()
                    .mcp_tokens
                    .values()
                    .find(|t| t.token_hash == token_hash && t.revoked_at.is_none())
                    .cloned())
            })
        }

        fn touch_mcp_token(
            &self,
            token_id: Uuid,
            at: DateTime<Utc>,
        ) -> StoreFuture<'_, Result<(), DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                if let Some(token) = db.mcp_tokens.get_mut(&token_id) {
                    token.last_used_at = Some(at);
                    token.updated_at = at;
                }
                Ok(())
            })
        }

        fn list_tags(&self) -> StoreFuture<'_, Result<Vec<Tag>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().tags_by_name()) })
        }

        fn get_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<Option<Tag>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().tags.get(&tag_id).cloned()) })
        }

        fn create_tag(&self, name: &str, color: &str) -> StoreFuture<'_, Result<Tag, DbError>> {
            let (name, color) = (name.to_owned(), color.to_owned());
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                if db.tags.values().any(|t| t.name == name) {
                    return Err(DbError::Conflict(
                        "a tag with that name already exists".into(),
                    ));
                }
                let now = Utc::now();
                let tag = Tag {
                    id: Uuid::new_v4(),
                    name,
                    color,
                    created_at: now,
                    updated_at: now,
                };
                db.tags.insert(tag.id, tag.clone());
                Ok(tag)
            })
        }

        fn update_tag(
            &self,
            tag_id: Uuid,
            patch: TagPatch,
        ) -> StoreFuture<'_, Result<Option<Tag>, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                if !db.tags.contains_key(&tag_id) {
                    return Ok(None);
                }
                if let Some(name) = &patch.name {
                    if db.tags.values().any(|t| t.name == *name && t.id != tag_id) {
                        return Err(DbError::Conflict(
                            "a tag with that name already exists".into(),
                        ));
                    }
                }
                let now = Utc::now();
                let tag = db.tags.get_mut(&tag_id).unwrap();
                if let Some(name) = patch.name {
                    tag.name = name;
                }
                if let Some(color) = patch.color {
                    tag.color = color;
                }
                tag.updated_at = now;
                Ok(Some(tag.clone()))
            })
        }

        fn delete_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().tags.remove(&tag_id).is_some()) })
        }

        fn list_schedules(&self) -> StoreFuture<'_, Result<Vec<ScheduledCommand>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().schedules_newest_first()) })
        }

        fn get_schedule(
            &self,
            schedule_id: Uuid,
        ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>> {
            Box::pin(
                async move { Ok(self.db.lock().unwrap().schedules.get(&schedule_id).cloned()) },
            )
        }

        fn create_schedule(
            &self,
            new: ScheduledCommandNew,
        ) -> StoreFuture<'_, Result<ScheduledCommand, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let now = Utc::now();
                let row = ScheduledCommand {
                    id: Uuid::new_v4(),
                    name: new.name,
                    enabled: new.enabled,
                    target_kind: new.target_kind,
                    target_vm_id: new.target_vm_id,
                    target_tag_id: new.target_tag_id,
                    task_kind: new.task_kind,
                    action_name: new.action_name,
                    params: new.params,
                    command: new.command,
                    cron_expression: new.cron_expression,
                    last_run_at: None,
                    created_by: new.created_by,
                    created_at: now,
                    updated_at: now,
                };
                db.schedules.insert(row.id, row.clone());
                Ok(row)
            })
        }

        fn update_schedule(
            &self,
            schedule_id: Uuid,
            patch: SchedulePatch,
        ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let Some(row) = db.schedules.get_mut(&schedule_id) else {
                    return Ok(None);
                };
                if let Some(v) = patch.name {
                    row.name = v;
                }
                if let Some(v) = patch.enabled {
                    row.enabled = v;
                }
                if let Some(v) = patch.target_kind {
                    row.target_kind = v;
                }
                if let Some(v) = patch.target_vm_id {
                    row.target_vm_id = v;
                }
                if let Some(v) = patch.target_tag_id {
                    row.target_tag_id = v;
                }
                if let Some(v) = patch.task_kind {
                    row.task_kind = v;
                }
                if let Some(v) = patch.action_name {
                    row.action_name = v;
                }
                if let Some(v) = patch.params {
                    row.params = v;
                }
                if let Some(v) = patch.command {
                    row.command = v;
                }
                if let Some(v) = patch.cron_expression {
                    row.cron_expression = v;
                }
                row.updated_at = Utc::now();
                Ok(Some(row.clone()))
            })
        }

        fn delete_schedule(&self, schedule_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
            Box::pin(async move {
                Ok(self
                    .db
                    .lock()
                    .unwrap()
                    .schedules
                    .remove(&schedule_id)
                    .is_some())
            })
        }

        fn list_actions(&self) -> StoreFuture<'_, Result<Vec<CustomAction>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().actions_by_name()) })
        }

        fn get_action(
            &self,
            action_id: Uuid,
        ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().actions.get(&action_id).cloned()) })
        }

        fn create_action(
            &self,
            new: CustomActionNew,
        ) -> StoreFuture<'_, Result<CustomAction, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let now = Utc::now();
                let commands = serde_json::Value::Array(
                    new.commands
                        .iter()
                        .map(|argv| serde_json::json!(argv))
                        .collect(),
                );
                let row = CustomAction {
                    id: Uuid::new_v4(),
                    name: new.name,
                    description: new.description,
                    commands,
                    enabled: true,
                    created_by: new.created_by,
                    created_at: now,
                    updated_at: now,
                };
                db.actions.insert(row.id, row.clone());
                db.action_tags.insert(row.id, new.tag_ids);
                Ok(row)
            })
        }

        fn update_action(
            &self,
            action_id: Uuid,
            patch: CustomActionPatch,
        ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                if !db.actions.contains_key(&action_id) {
                    return Ok(None);
                }
                if let Some(tag_ids) = patch.tag_ids {
                    db.action_tags.insert(action_id, tag_ids);
                }
                let now = Utc::now();
                let row = db.actions.get_mut(&action_id).unwrap();
                if let Some(v) = patch.description {
                    row.description = v;
                }
                if let Some(v) = patch.commands {
                    row.commands = serde_json::Value::Array(
                        v.iter().map(|argv| serde_json::json!(argv)).collect(),
                    );
                }
                if let Some(v) = patch.enabled {
                    row.enabled = v;
                }
                row.updated_at = now;
                Ok(Some(row.clone()))
            })
        }

        fn remove_action(&self, action_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                db.action_tags.remove(&action_id);
                Ok(db.actions.remove(&action_id).is_some())
            })
        }

        fn action_tag_ids(&self, action_id: Uuid) -> StoreFuture<'_, Result<Vec<Uuid>, DbError>> {
            Box::pin(async move {
                Ok(self
                    .db
                    .lock()
                    .unwrap()
                    .action_tags
                    .get(&action_id)
                    .cloned()
                    .unwrap_or_default())
            })
        }

        fn create_enrollment_token(
            &self,
            new: EnrollmentTokenNew,
        ) -> StoreFuture<'_, Result<EnrollmentToken, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let now = Utc::now();
                let expires_at = if new.ttl_seconds == 0 {
                    // ttl_seconds == 0 → never expires (parity: year 9999).
                    chrono::TimeZone::with_ymd_and_hms(&Utc, 9999, 12, 31, 23, 59, 59)
                        .single()
                        .unwrap()
                } else {
                    now + chrono::Duration::seconds(new.ttl_seconds)
                };
                let row = EnrollmentToken {
                    id: Uuid::new_v4(),
                    token_hash: new.token_hash,
                    label: new.label,
                    created_by: new.created_by,
                    max_uses: new.max_uses,
                    uses_count: 0,
                    expires_at,
                    revoked_at: None,
                    created_at: now,
                    updated_at: now,
                    auto_approve: new.auto_approve,
                };
                db.enrollment_tokens.insert(row.id, row.clone());
                Ok(row)
            })
        }

        fn list_enrollment_tokens(&self) -> StoreFuture<'_, Result<Vec<EnrollmentToken>, DbError>> {
            Box::pin(async move { Ok(self.db.lock().unwrap().enrollment_newest_first()) })
        }

        fn revoke_enrollment_token(
            &self,
            token_id: Uuid,
        ) -> StoreFuture<'_, Result<Option<EnrollmentToken>, DbError>> {
            Box::pin(async move {
                let mut db = self.db.lock().unwrap();
                let now = Utc::now();
                let Some(row) = db.enrollment_tokens.get_mut(&token_id) else {
                    return Ok(None);
                };
                if row.revoked_at.is_none() {
                    row.revoked_at = Some(now);
                    row.updated_at = now;
                }
                Ok(Some(row.clone()))
            })
        }

        fn record_audit(&self, entry: AuditNew) -> StoreFuture<'_, Result<(), DbError>> {
            Box::pin(async move {
                self.db.lock().unwrap().audit.push(entry);
                Ok(())
            })
        }
    }

    // -- shared test fixtures ----------------------------------------------

    /// Config with fixed keys and a known MCP service token.
    pub fn test_config() -> Config {
        Config {
            mcp_service_token: "mcp-service-token".to_owned(),
            ..Config::default()
        }
    }

    /// State with a mock store; `store` lets a test seed rows.
    pub fn test_state(store: Arc<MockStore>) -> AdminState {
        let config = test_config();
        let security = SecurityConfig::new(
            &config.mfa_encryption_key,
            &config.jwt_secret,
            &config.secret_hash_key,
        );
        AdminState {
            config,
            security,
            store,
        }
    }

    /// A user row for the mock store.
    pub fn make_user(username: &str, role: UserRole) -> User {
        let now = Utc::now();
        User {
            id: Uuid::new_v4(),
            username: username.to_owned(),
            email: Some(format!("{username}@example.com")),
            password_hash: Some("hash".to_owned()),
            oidc_subject: None,
            ldap_dn: None,
            role,
            is_active: true,
            last_login_at: None,
            created_at: now,
            updated_at: now,
            totp_secret_enc: None,
            totp_enabled: false,
            totp_confirmed_at: None,
            totp_last_step: None,
        }
    }

    /// Register `user` in the store and return it (with its id).
    pub fn seed_user(store: &MockStore, user: User) -> User {
        store.db.lock().unwrap().users.insert(user.id, user.clone());
        user
    }

    /// A settings row seeded from the SQLAlchemy column defaults.
    pub fn seed_settings(store: &MockStore) -> Setting {
        let row = settings::setting_row(SettingValues::default(), Utc::now());
        store.db.lock().unwrap().settings = Some(row.clone());
        row
    }

    /// A stored (hashed) MCP token for `user`; returns the plaintext secret.
    pub async fn seed_mcp_token(
        state: &AdminState,
        store: &MockStore,
        user_id: Uuid,
        name: &str,
        allowed_ip: Option<&str>,
    ) -> (McpToken, String) {
        let plaintext = crate::security::generate_secret();
        let token = store
            .create_mcp_token(McpTokenNew {
                user_id,
                token_hash: state.security.hash_secret(&plaintext),
                name: name.to_owned(),
                allowed_ip: allowed_ip.map(str::to_owned),
            })
            .await
            .unwrap();
        (token, plaintext)
    }

    /// A bearer-JWT request for `user` against the test config's secret.
    pub fn bearer(state: &AdminState, user: &User) -> String {
        state
            .security
            .jwt()
            .create_access_token(&user.id.to_string(), user.role.as_str(), 15)
            .unwrap()
    }

    /// JSON request helper.
    pub fn json_request(
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> axum::http::Request<axum::body::Body> {
        let (payload, content_length) = if method == "GET" || method == "DELETE" {
            (String::new(), 0)
        } else {
            (body.to_string(), body.to_string().len())
        };
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("content-length", content_length.to_string())
            .body(axum::body::Body::from(payload))
            .unwrap()
    }

    /// Request with a JSON body and headers.
    pub fn json_request_with(
        method: &str,
        uri: &str,
        body: serde_json::Value,
        headers: &[(&'static str, String)],
    ) -> axum::http::Request<axum::body::Body> {
        let mut request = json_request(method, uri, body);
        for (name, value) in headers {
            request.headers_mut().insert(*name, value.parse().unwrap());
        }
        request
    }

    /// Collect a response body as JSON.
    pub async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn principal_capability_matches_python() {
        // Admin user: admin + operator + execute.
        let admin = make_user("admin", UserRole::Admin);
        let p = Principal::from_user(&admin);
        assert!(p.is_admin() && p.is_operator() && p.can_execute());
        assert_eq!(p.actor_type, ActorType::User);
        assert_eq!(p.actor_id, admin.id.to_string());

        // Read-only user: no admin, no operator, no execute.
        let ro = make_user("ro", UserRole::Readonly);
        let p = Principal::from_user(&ro);
        assert!(!p.is_admin() && !p.is_operator() && !p.can_execute());

        // MCP on-behalf-of an admin user keeps the user's role, but the audit
        // actor is the agent.
        let p = Principal::agent(Some(&admin));
        assert!(p.is_admin());
        assert_eq!(p.actor_type, ActorType::Agent);
        assert_eq!(p.actor_id, admin.id.to_string());

        // MCP on-behalf-of a read-only user never gains capabilities.
        let p = Principal::agent(Some(&ro));
        assert!(!p.is_admin() && !p.is_operator() && !p.can_execute());

        // Anonymous service-token agent: may execute, never admin.
        let p = Principal::agent(None);
        assert!(!p.is_admin() && !p.is_operator());
        assert!(p.can_execute());
        assert_eq!(p.actor_id, "hermes");
    }

    #[test]
    fn route_error_renders_the_fastapi_shape() {
        let response = RouteError::not_found("tag not found").into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = RouteError::unauthorized_bearer("authentication required").into_response();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer"
        );
    }

    #[tokio::test]
    async fn unauthenticated_requests_get_401_before_anything_else() {
        let store = Arc::new(MockStore::default());
        let app = router(test_state(store));
        let response = tower::ServiceExt::oneshot(
            app,
            json_request("GET", "/api/settings", serde_json::Value::Null),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"detail": "authentication required"})
        );
    }

    #[tokio::test]
    async fn invalid_service_token_is_rejected() {
        let store = Arc::new(MockStore::default());
        let app = router(test_state(store));
        let request = json_request_with(
            "GET",
            "/api/mcp/whoami",
            serde_json::Value::Null,
            &[("x-mcp-service-token", "wrong".to_owned())],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"detail": "invalid service token"})
        );
    }
}

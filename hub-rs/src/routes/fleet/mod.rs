//! Fleet / execution / task / audit / event routes (port of
//! `hub/app/api/routes/{vms,execution,tasks,audit,events}.py`).
//!
//! | route                                   | Python handler                       |
//! |-----------------------------------------|--------------------------------------|
//! | `GET    /api/vms`                       | `vms.list_vms`                       |
//! | `GET    /api/vms/{vm_id}`               | `vms.get_vm`                         |
//! | `PUT    /api/vms/{vm_id}/tags`          | `vms.set_vm_tags`                    |
//! | `POST   /api/vms/{vm_id}/approve`       | `vms.approve_vm`                     |
//! | `PUT    /api/vms/{vm_id}/exec-mode`     | `vms.set_exec_mode`                  |
//! | `POST   /api/vms/{vm_id}/revoke`        | `vms.revoke_vm`                      |
//! | `DELETE /api/vms/{vm_id}`               | `vms.delete_vm`                      |
//! | `POST   /api/vms/bulk/actions`          | `execution.run_bulk_action`          |
//! | `POST   /api/vms/{vm_id}/actions`       | `execution.run_action`               |
//! | `POST   /api/vms/{vm_id}/commands`      | `execution.run_command`              |
//! | `POST   /api/vms/{vm_id}/update`        | `execution.trigger_update`           |
//! | `GET    /api/tasks/{task_id}`           | `tasks.get_task`                     |
//! | `GET    /api/tasks/{task_id}/wait`      | `tasks.wait_task`                    |
//! | `GET    /api/audit`                     | `audit.list_audit`                   |
//! | `GET    /api/audit/verify`              | `audit.verify_audit`                 |
//! | `GET    /api/events`                    | `events.events_stream` (SSE)         |
//!
//! This module owns the request plumbing the Python hub puts in
//! `app/api/deps.py` (principal/RBAC, VM access, the execution rate limit, the
//! body-size cap, `client_ip`) plus the wire shapes of `app/schemas/{vm,task,
//! audit,tag}.py`. The business rules of `app/services/tasks.py` (task
//! creation, action catalog, exec-mode gating, SSRF-safe release URLs) live in
//! [`tasks`].
//!
//! Everything routes through [`RouteError`], which renders exactly like
//! FastAPI's `HTTPException` ([`ApiError`]) and may carry response headers
//! (the `WWW-Authenticate: Bearer` challenge, which FastAPI sends on 401).

pub mod audit;
pub mod events;
pub mod execution;
pub mod tasks;
pub mod vms;

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::error::ApiError;
use crate::models::enums::{ActorType, UserRole};
use crate::models::mcp_token;
use crate::models::user::{self, User};
use crate::models::vm::VM;
use crate::security::jwt::{decode_access_token, MFA_SCOPES};
use crate::security::{constant_time_equals, SecurityConfig};
use crate::services::task_events::TaskEvents;

use events::EventBus;

// ---------------------------------------------------------------------------
// Datetime wire format
// ---------------------------------------------------------------------------

/// Datetimes render exactly like pydantic's JSON serializer: ISO 8601 with a
/// `Z` suffix and, when present, exactly six fractional digits
/// (`2024-05-01T12:34:56Z`, `2024-05-01T12:34:56.123456Z`).
pub mod ts {
    use chrono::{DateTime, Utc};
    use serde::Serializer;

    /// Format one timestamp the way `pydantic` serializes a UTC `datetime`.
    pub fn format_ts(dt: &DateTime<Utc>) -> String {
        let micros = dt.timestamp_subsec_micros();
        if micros == 0 {
            dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        } else {
            format!("{}.{:06}Z", dt.format("%Y-%m-%dT%H:%M:%S"), micros)
        }
    }

    /// `#[serde(with = "ts")]` for a required timestamp.
    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_ts(dt))
    }
}

/// `#[serde(with = "ts_opt")]` for `Option<DateTime<Utc>>` fields.
pub mod ts_opt {
    use super::ts::format_ts;
    use chrono::{DateTime, Utc};
    use serde::Serializer;

    pub fn serialize<S: Serializer>(dt: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
        match dt {
            Some(dt) => s.serialize_str(&format_ts(dt)),
            None => s.serialize_none(),
        }
    }
}

// ---------------------------------------------------------------------------
// Python-compatible literals (error messages are compared byte-for-byte)
// ---------------------------------------------------------------------------

/// `repr()` of a Python string — single quotes, backslash and quote escaped.
/// Action names are ASCII identifiers, so this matches Python exactly.
pub fn py_repr(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// `repr()` of a Python `list[str]` (e.g. `sorted(extra)` in an error message).
pub fn py_repr_list(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|v| py_repr(v)).collect();
    format!("[{}]", items.join(", "))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Route error: an [`ApiError`] body plus optional response headers.
///
/// FastAPI's `HTTPException(status, detail, headers=...)` carries the
/// `WWW-Authenticate: Bearer` challenge on 401; [`ApiError`] alone cannot.
#[derive(Debug)]
pub struct RouteError {
    inner: ApiError,
    headers: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
}

impl RouteError {
    pub fn new(inner: ApiError) -> Self {
        Self {
            inner,
            headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        if let (Ok(name), Ok(value)) = (name.parse(), value.parse()) {
            self.headers.push((name, value));
        }
        self
    }

    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    pub fn detail(&self) -> &str {
        self.inner.detail()
    }
}

impl From<ApiError> for RouteError {
    fn from(inner: ApiError) -> Self {
        Self::new(inner)
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let mut response = self.inner.into_response();
        for (name, value) in self.headers {
            response.headers_mut().insert(name, value);
        }
        response
    }
}

/// 401 with the bearer challenge FastAPI attaches to `HTTPException`.
fn unauthorized_bearer(detail: &str) -> RouteError {
    RouteError::new(ApiError::unauthorized(detail)).with_header("www-authenticate", "Bearer")
}

/// Axum JSON rejections mapped onto FastAPI semantics: oversized bodies are
/// 413 ("request body too large"), every parse/shape failure is 422 (pydantic's
/// status). Same convention as `routes/worker.rs`.
pub fn map_json_rejection(err: axum::extract::rejection::JsonRejection) -> RouteError {
    if err.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large("request body too large").into()
    } else {
        ApiError::unprocessable_entity(err.body_text()).into()
    }
}

/// Query/path rejections (bad UUID, bad enum, bad integer) are 422, like
/// pydantic's path/query validation failures.
pub fn map_path_rejection(err: impl std::fmt::Display) -> RouteError {
    ApiError::unprocessable_entity(err.to_string()).into()
}

/// Data-layer failures surface as 500 (the Python handler lets them bubble).
pub fn db_err(err: DbError) -> RouteError {
    ApiError::internal(err.to_string()).into()
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Everything the fleet routes need. Cheap to clone.
#[derive(Debug, Clone)]
pub struct FleetState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub security: SecurityConfig,
    /// Task-completion / queue-availability wakes (`app/core/task_events.py`).
    /// Must be shared with `routes/worker.rs` so a task creation here wakes the
    /// worker long-poll there.
    pub events: Arc<TaskEvents>,
    /// Dashboard SSE bus (`app/core/events.py`).
    pub bus: Arc<EventBus>,
    /// Shared limiter for the execution endpoints (`rate_limit_exec`).
    exec_limiter: crate::routes::worker::RateLimiter,
}

impl FleetState {
    /// Build a state with its own event buses (single-router deployments).
    pub fn new(pool: sqlx::PgPool, config: Config) -> Self {
        Self::with_events(
            pool,
            config,
            TaskEvents::new(),
            Arc::new(EventBus::new_default()),
        )
    }

    /// Build a state around shared buses (the app assembly wires one
    /// [`TaskEvents`] into both the worker and the fleet routes).
    pub fn with_events(
        pool: sqlx::PgPool,
        config: Config,
        events: Arc<TaskEvents>,
        bus: Arc<EventBus>,
    ) -> Self {
        let security = SecurityConfig::new(
            &config.mfa_encryption_key,
            &config.jwt_secret,
            &config.secret_hash_key,
        );
        let exec_limiter =
            crate::routes::worker::RateLimiter::new(config.rate_limit_exec_per_minute);
        Self {
            pool,
            config,
            security,
            events,
            bus,
            exec_limiter,
        }
    }
}

/// The merged `/api/vms` + `/api/tasks` + `/api/audit` + `/api/events` router
/// (prefixes included, so it can be merged as-is).
pub fn router(state: FleetState) -> Router {
    vms::router(state.clone())
        .merge(execution::router(state.clone()))
        .merge(tasks::router(state.clone()))
        .merge(audit::router(state.clone()))
        .merge(events::router(state))
}

// ---------------------------------------------------------------------------
// Principal + RBAC (app/api/deps.py, app/core/principal.py)
// ---------------------------------------------------------------------------

/// The authenticated principal acting on a request (a user or an agent).
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub role: UserRole,
    pub user: Option<User>,
}

impl Principal {
    pub fn from_user(user: User) -> Self {
        Self {
            actor_type: ActorType::User,
            actor_id: user.id.to_string(),
            role: user.role,
            user: Some(user),
        }
    }

    /// The MCP façade. With a user (per-user MCP token) it acts AS that user:
    /// `actor_type` stays `agent` so the audit shows "mcp", `actor_id` is the
    /// user's id, and authorization uses the user's real role. Without a user
    /// (service-token-only calls) it is an operator capability, not an admin.
    pub fn agent(user: Option<User>) -> Self {
        match user {
            Some(user) => Self {
                actor_type: ActorType::Agent,
                actor_id: user.id.to_string(),
                role: user.role,
                user: Some(user),
            },
            None => Self {
                actor_type: ActorType::Agent,
                actor_id: "hermes".to_owned(),
                role: UserRole::Readonly,
                user: None,
            },
        }
    }

    /// A real user is behind this principal — a direct human session or an MCP
    /// agent acting on behalf of a user.
    pub fn has_identity(&self) -> bool {
        self.actor_type == ActorType::User || self.user.is_some()
    }

    /// Admin user, including via an on-behalf-of MCP token. The anonymous
    /// service-token agent is NOT admin (control-plane operations require a
    /// real admin identity).
    pub fn is_admin(&self) -> bool {
        self.has_identity() && self.role == UserRole::Admin
    }

    /// Admin/operator users (including via an on-behalf-of MCP token).
    pub fn is_operator(&self) -> bool {
        self.has_identity() && matches!(self.role, UserRole::Admin | UserRole::Operator)
    }

    /// Operator capability: run actions/commands, trigger updates, read audit.
    /// Granted to operators/admins (human or on-behalf-of MCP) and to the
    /// anonymous service-token agent — never to read-only users, even via MCP.
    pub fn can_execute(&self) -> bool {
        if self.actor_type == ActorType::Agent && self.user.is_none() {
            return true;
        }
        self.is_operator()
    }
}

/// Best-effort real client IP (`deps.client_ip`): behind the bundled reverse
/// proxy the peer address is the proxy's, so the first hop of a trusted
/// `X-Forwarded-For` is used. The header is only honoured when explicitly
/// trusted, since clients could otherwise spoof it.
pub fn client_ip(
    headers: &HeaderMap,
    config: &Config,
    peer: Option<std::net::SocketAddr>,
) -> Option<String> {
    if config.trust_forwarded_for {
        if let Some(forwarded) = header_str(headers, "x-forwarded-for") {
            if let Some(first) = forwarded.split(',').next() {
                let first = first.trim();
                if !first.is_empty() {
                    return Some(first.to_owned());
                }
            }
        }
    }
    peer.map(|addr| addr.ip().to_string())
}

/// The peer address as axum's `ConnectInfo` layer provides it (absent when no
/// such layer is applied).
pub type Peer = Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>;

/// Unwrap the [`Peer`] extractor argument.
pub fn peer_addr(peer: Peer) -> Option<std::net::SocketAddr> {
    peer.map(|axum::extract::Extension(axum::extract::ConnectInfo(addr))| addr)
}

/// `deps.enforce_body_size` — reject oversized request bodies early.
pub fn enforce_body_size(headers: &HeaderMap, max_body_bytes: usize) -> Result<(), RouteError> {
    if let Some(len) = header_str(headers, "content-length") {
        if let Ok(len) = len.trim().parse::<usize>() {
            if len > max_body_bytes {
                return Err(ApiError::payload_too_large("request body too large").into());
            }
        }
    }
    Ok(())
}

pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// `Bearer <token>` from the Authorization header (scheme is case-insensitive).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = header_str(headers, "authorization")?;
    let (scheme, param) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") && !param.trim().is_empty() {
        Some(param.trim())
    } else {
        None
    }
}

/// `deps.get_principal` — authenticate as a user (JWT) or the MCP agent
/// (service token, optionally on behalf of a user).
pub async fn authenticate(
    state: &FleetState,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> Result<Principal, RouteError> {
    // MCP façade: timing-safe service-token check, then optional on-behalf-of.
    if let Some(presented) = header_str(headers, "x-mcp-service-token") {
        if !constant_time_equals(presented, &state.config.mcp_service_token) {
            return Err(ApiError::unauthorized("invalid service token").into());
        }
        if let Some(obo) = header_str(headers, "x-mcp-on-behalf-of") {
            let user = resolve_mcp_token(state, obo, ip).await?;
            return match user {
                Some(user) => Ok(Principal::agent(Some(user))),
                None => Err(ApiError::unauthorized("invalid MCP token").into()),
            };
        }
        return Ok(Principal::agent(None));
    }

    let Some(token) = bearer_token(headers) else {
        return Err(unauthorized_bearer("authentication required"));
    };
    let payload = decode_access_token(&state.config.jwt_secret, token)
        .map_err(|_| ApiError::unauthorized("invalid token"))?;
    let user_id = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<Uuid>().ok())
        .ok_or_else(|| ApiError::unauthorized("invalid token"))?;

    // Intermediate MFA challenge/setup tokens are NOT valid for the business
    // API: they may only be presented to the dedicated /api/auth/mfa endpoints.
    if let Some(scope) = payload.get("scope").and_then(|v| v.as_str()) {
        if MFA_SCOPES.contains(&scope) {
            return Err(ApiError::unauthorized("token not valid for API access").into());
        }
    }

    let user = user::get_by_id(&state.pool, user_id)
        .await
        .map_err(db_err)?;
    match user {
        Some(user) if user.is_active => Ok(Principal::from_user(user)),
        _ => Err(ApiError::unauthorized("user not found or inactive").into()),
    }
}

/// `deps.require_admin` — human admin only (excludes the automation agent).
pub async fn require_admin(
    state: &FleetState,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> Result<Principal, RouteError> {
    let principal = authenticate(state, headers, ip).await?;
    if !principal.is_admin() {
        return Err(ApiError::forbidden("admin role required").into());
    }
    Ok(principal)
}

/// `deps.require_operator` — admin, operator, or agent; read-only users are
/// rejected.
pub async fn require_operator(
    state: &FleetState,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> Result<Principal, RouteError> {
    let principal = authenticate(state, headers, ip).await?;
    if !principal.can_execute() {
        return Err(ApiError::forbidden("operator privileges required").into());
    }
    Ok(principal)
}

/// `deps.rate_limit_exec` — authorize as operator, then throttle the execution
/// endpoints per principal.
pub async fn rate_limit_exec(
    state: &FleetState,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> Result<Principal, RouteError> {
    let principal = require_operator(state, headers, ip).await?;
    throttle_exec(state, &principal)?;
    Ok(principal)
}

/// `rate_limit_exec`'s throttle: one fixed window per `{actor_type}:{actor_id}`.
pub fn throttle_exec(state: &FleetState, principal: &Principal) -> Result<(), RouteError> {
    let key = format!("{}:{}", principal.actor_type.as_str(), principal.actor_id);
    if state.exec_limiter.allow(&key) {
        Ok(())
    } else {
        Err(ApiError::too_many_requests("rate limit exceeded; slow down").into())
    }
}

/// `deps.principal_can_access_vm` — admins and the anonymous service-token
/// agent always can; everyone else needs an entry in `user_vm_access`.
pub async fn principal_can_access_vm(
    pool: &sqlx::PgPool,
    principal: &Principal,
    vm_id: Uuid,
) -> Result<bool, DbError> {
    if principal.is_admin()
        || (principal.actor_type == ActorType::Agent && principal.user.is_none())
    {
        return Ok(true);
    }
    let Some(user) = &principal.user else {
        return Ok(false);
    };
    let ids = user::user_ids_for_vm(pool, vm_id).await?;
    Ok(ids.contains(&user.id))
}

/// `deps.accessible_vm_ids` — VM ids the principal may see, or `None` when
/// unrestricted (admin / anonymous agent).
pub async fn accessible_vm_ids(
    pool: &sqlx::PgPool,
    principal: &Principal,
) -> Result<Option<Vec<Uuid>>, DbError> {
    if principal.is_admin()
        || (principal.actor_type == ActorType::Agent && principal.user.is_none())
    {
        return Ok(None);
    }
    let Some(user) = &principal.user else {
        return Ok(Some(Vec::new()));
    };
    Ok(Some(user::vm_ids_for_user(pool, user.id).await?))
}

/// `services/mcp_tokens.resolve` — map a presented MCP token to its active
/// owner: deterministic keyed HMAC lookup, optional IP allow-list, `last_used_at`
/// bump.
async fn resolve_mcp_token(
    state: &FleetState,
    presented: &str,
    client_ip: Option<&str>,
) -> Result<Option<User>, RouteError> {
    if presented.is_empty() {
        return Ok(None);
    }
    let token_hash = state.security.hash_secret(presented);
    let token = mcp_token::get_active_by_token_hash(&state.pool, &token_hash)
        .await
        .map_err(db_err)?;
    let Some(token) = token else {
        return Ok(None);
    };
    if !ip_allowed(client_ip, token.allowed_ip.as_deref()) {
        tracing::warn!(
            "MCP token {} rejected: client ip {:?} not in allow-list {:?}",
            token.id,
            client_ip,
            token.allowed_ip
        );
        return Ok(None);
    }
    let user = user::get_by_id(&state.pool, token.user_id)
        .await
        .map_err(db_err)?;
    let Some(user) = user else {
        return Ok(None);
    };
    if !user.is_active {
        return Ok(None);
    }
    mcp_token::touch_last_used(&state.pool, token.id, Utc::now())
        .await
        .map_err(db_err)?;
    Ok(Some(user))
}

/// `mcp_tokens.ip_allowed` — no rule → always allowed; a rule with no/invalid
/// client IP → denied.
pub fn ip_allowed(client_ip: Option<&str>, allowed: Option<&str>) -> bool {
    let Some(allowed) = allowed else {
        return true;
    };
    let Some(client_ip) = client_ip else {
        return false;
    };
    ip_in_network(client_ip, allowed)
}

/// True when `ip` falls inside `network` (an address or CIDR range).
fn ip_in_network(ip: &str, network: &str) -> bool {
    let Ok(ip) = ip.trim().parse::<std::net::IpAddr>() else {
        return false;
    };
    let network = network.trim();
    let (base, prefix) = match network.split_once('/') {
        Some((base, prefix)) => {
            let Ok(prefix) = prefix.parse::<u32>() else {
                return false;
            };
            (base, prefix)
        }
        None => (network, u32::MAX),
    };
    let Ok(base) = base.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (ip, base) {
        (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(base)) => {
            let prefix = prefix.min(32);
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(base) & mask
        }
        (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(base)) => {
            let prefix = prefix.min(128);
            let (ip, base) = (u128::from(ip), u128::from(base));
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            ip & mask == base & mask
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Shared wire shapes
// ---------------------------------------------------------------------------

/// Load a VM or answer FastAPI's 404 shape (`"VM not found"`).
pub async fn load_vm(state: &FleetState, vm_id: Uuid) -> Result<VM, RouteError> {
    crate::models::vm::get_by_id(&state.pool, vm_id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("VM not found").into())
}

/// Datetime equality helper for tests: serialize through the wire format.
#[derive(Debug, Serialize)]
pub struct TimestampProbe {
    #[serde(with = "ts")]
    pub value: DateTime<Utc>,
    #[serde(with = "ts_opt")]
    pub optional: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::json;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn test_state() -> FleetState {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        FleetState::new(pool, Config::default())
    }

    fn sample_user(role: UserRole) -> User {
        User {
            id: Uuid::nil(),
            username: "alice".into(),
            email: None,
            password_hash: None,
            oidc_subject: None,
            ldap_dn: None,
            role,
            is_active: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            totp_secret_enc: None,
            totp_enabled: false,
            totp_confirmed_at: None,
            totp_last_step: None,
        }
    }

    #[test]
    fn timestamps_match_pydantic_serialization() {
        use chrono::TimeZone;
        let naive = Utc.with_ymd_and_hms(2024, 5, 1, 12, 34, 56).unwrap();
        assert_eq!(ts::format_ts(&naive), "2024-05-01T12:34:56Z");
        let with_micros = naive + chrono::Duration::microseconds(123456);
        assert_eq!(ts::format_ts(&with_micros), "2024-05-01T12:34:56.123456Z");
        let rounded = naive + chrono::Duration::microseconds(100000);
        assert_eq!(ts::format_ts(&rounded), "2024-05-01T12:34:56.100000Z");

        let probe = TimestampProbe {
            value: naive,
            optional: None,
        };
        assert_eq!(
            serde_json::to_value(&probe).unwrap(),
            json!({"value": "2024-05-01T12:34:56Z", "optional": null})
        );
    }

    #[test]
    fn python_repr_matches_for_identifiers() {
        assert_eq!(py_repr("restart_service"), "'restart_service'");
        assert_eq!(py_repr("o'brien"), "'o\\'brien'");
        assert_eq!(py_repr_list(&["a".into(), "b".into()]), "['a', 'b']");
        assert_eq!(py_repr_list(&[]), "[]");
    }

    #[test]
    fn ip_allow_list_matches_python_ipaddress() {
        assert!(ip_allowed(Some("10.0.0.5"), None), "no rule → allowed");
        assert!(
            !ip_allowed(None, Some("10.0.0.0/8")),
            "rule, no ip → denied"
        );
        assert!(ip_allowed(Some("10.0.0.5"), Some("10.0.0.0/8")));
        assert!(!ip_allowed(Some("11.0.0.5"), Some("10.0.0.0/8")));
        assert!(ip_allowed(Some("192.168.1.9"), Some("192.168.1.9")), "/32");
        assert!(!ip_allowed(Some("192.168.1.10"), Some("192.168.1.9")));
        assert!(
            ip_allowed(Some("2001:db8::1"), Some("2001:db8::/32")),
            "IPv6"
        );
        assert!(!ip_allowed(Some("2001:db9::1"), Some("2001:db8::/32")));
        assert!(!ip_allowed(Some("nope"), Some("10.0.0.0/8")), "invalid ip");
        assert!(
            !ip_allowed(Some("10.0.0.1"), Some("garbage")),
            "invalid rule"
        );
    }

    #[test]
    fn principal_capability_matches_python() {
        let mut user = sample_user(UserRole::Operator);

        let operator = Principal::from_user(user.clone());
        assert!(operator.is_operator());
        assert!(!operator.is_admin());
        assert!(operator.can_execute());

        user.role = UserRole::Readonly;
        let readonly = Principal::from_user(user.clone());
        assert!(!readonly.can_execute(), "read-only users never execute");

        user.role = UserRole::Admin;
        let admin = Principal::from_user(user);
        assert!(admin.is_admin());

        let agent = Principal::agent(None);
        assert!(!agent.is_admin(), "anonymous agent is never admin");
        assert!(!agent.is_operator());
        assert!(agent.can_execute(), "but it may execute");
        assert_eq!(agent.actor_id, "hermes");

        let agent_obo = Principal::agent(Some(sample_user(UserRole::Readonly)));
        assert!(
            !agent_obo.can_execute(),
            "MCP never exceeds the owner's role"
        );
        assert_eq!(agent_obo.actor_type, ActorType::Agent);
    }

    #[tokio::test]
    async fn execution_rate_limit_is_per_principal() {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let state = FleetState::new(
            pool,
            Config {
                rate_limit_exec_per_minute: 2,
                ..Config::default()
            },
        );
        let principal = Principal::from_user(sample_user(UserRole::Operator));
        assert!(throttle_exec(&state, &principal).is_ok());
        assert!(throttle_exec(&state, &principal).is_ok());
        let error = throttle_exec(&state, &principal).unwrap_err();
        assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.detail(), "rate limit exceeded; slow down");

        // Each principal gets its own window.
        assert!(throttle_exec(&state, &Principal::agent(None)).is_ok());
    }

    #[tokio::test]
    async fn fleet_routes_challenge_unauthenticated_callers() {
        use tower::ServiceExt;
        let app = router(test_state());
        for uri in [
            "/api/vms",
            "/api/vms/00000000-0000-0000-0000-000000000001",
            "/api/tasks/00000000-0000-0000-0000-000000000001",
            "/api/tasks/00000000-0000-0000-0000-000000000001/wait",
            "/api/audit",
            "/api/audit/verify",
            "/api/events",
        ] {
            let request = axum::http::Request::builder()
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} must require authentication"
            );
        }

        // The execution endpoints are reached through POST.
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/vms/00000000-0000-0000-0000-000000000001/actions")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unauthenticated_requests_get_the_bearer_challenge() {
        let state = test_state();
        let headers = HeaderMap::new();
        let error = authenticate(&state, &headers, None).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(error.detail(), "authentication required");
        let response = error.into_response();
        assert_eq!(
            response.headers().get("www-authenticate").unwrap(),
            "Bearer"
        );
    }

    #[tokio::test]
    async fn mfa_scoped_tokens_are_not_api_tokens() {
        let state = test_state();
        let token = crate::security::jwt::create_mfa_challenge_token(
            &state.config.jwt_secret,
            &Uuid::new_v4().to_string(),
            crate::security::jwt::MFA_SCOPE,
            60,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let error = authenticate(&state, &headers, None).await.unwrap_err();
        assert_eq!(error.detail(), "token not valid for API access");
    }

    #[tokio::test]
    async fn oversized_bodies_are_413_before_anything_else() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", "70000".parse().unwrap());
        let error = enforce_body_size(&headers, 65_536).unwrap_err();
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.detail(), "request body too large");
        assert!(enforce_body_size(&headers, 200_000).is_ok());
    }

    #[test]
    fn route_error_renders_the_fastapi_detail_shape() {
        let response = RouteError::from(ApiError::not_found("VM not found")).into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn route_error_body_is_the_fastapi_detail_shape() {
        let response = RouteError::from(ApiError::forbidden("admin role required")).into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "admin role required"})
        );
    }
}

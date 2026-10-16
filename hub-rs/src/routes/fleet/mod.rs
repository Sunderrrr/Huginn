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
//! | `POST   /api/vms/{vm_id}/browser`       | `browser.run_browser` (hub-rs ext)   |
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
pub mod browser;
pub mod events;
pub mod execution;
pub mod tasks;
pub mod vms;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::error::ApiError;
use crate::models::vm::VM;
use crate::security::SecurityConfig;
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

/// Data-layer failures surface as a bare 500 (L-2): the sqlx detail can
/// quote user data, SQL text and constraint names, so it goes to the server
/// log only — the client just gets "internal error". Callers that owe the
/// client a specific status (vms.rs's Invalid/NotFound handling, tasks'
/// Conflict) map their DbError variant *before* this.
pub fn db_err(err: DbError) -> RouteError {
    tracing::warn!(error = %err, "database error");
    ApiError::internal("internal error").into()
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
        .merge(browser::router(state.clone()))
        .merge(tasks::router(state.clone()))
        .merge(audit::router(state.clone()))
        .merge(events::router(state))
}

// ---------------------------------------------------------------------------
// Submodules — the authenticated caller + request enforcement
// ---------------------------------------------------------------------------

mod principal;

pub use principal::{
    accessible_vm_ids, authenticate, client_ip, enforce_body_size, peer_addr,
    principal_can_access_vm, rate_limit_exec, require_admin, require_operator, Peer,
};

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use axum::body::Body;
    use axum::response::Response;
    use http_body_util::BodyExt;

    use crate::models::enums::UserRole;
    use crate::models::user::User;

    pub(crate) async fn body_json(response: Response) -> serde_json::Value {
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    pub(crate) fn test_state() -> FleetState {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        FleetState::new(pool, Config::default())
    }

    pub(crate) fn sample_user(role: UserRole) -> User {
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
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use axum::body::Body;
    use axum::http::HeaderMap;
    use serde_json::json;

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

    #[test]
    fn db_err_never_leaks_the_sqlx_detail() {
        // L-2: the client gets a bare 500 "internal error"; the sqlx detail
        // goes to the server log only.
        let err = db_err(DbError::Conflict("secret constraint detail".into()));
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.detail(), "internal error");
        assert!(!err.detail().contains("secret"));
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

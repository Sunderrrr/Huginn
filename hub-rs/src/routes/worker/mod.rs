//! Worker-facing API (`/api/worker`) — port of `hub/app/api/routes/worker.py`.
//!
//! | route                              | Python handler            |
//! |------------------------------------|---------------------------|
//! | `POST /api/worker/enroll`          | `enroll`                  |
//! | `POST /api/worker/heartbeat`       | `heartbeat`               |
//! | `GET  /api/worker/tasks/next`      | `next_task` (long-poll)   |
//! | `POST /api/worker/tasks/{id}/result` | `submit_result`         |
//!
//! Also ported here: worker authentication (`app/api/deps.py:current_worker`,
//! headers `X-Worker-Id`/`X-Worker-Secret` with a timing-safe secret check),
//! the TLS refusal (`worker.py:_enforce_tls`), the worker-facing request
//! schemas (`app/schemas/{enrollment,task}.py`), the request-body caps
//! (`app/main.py` global cap + `deps.enforce_body_size`'s 64 KB) and a minimal
//! fixed-window rate limiter (`app/core/ratelimit.py`) for the unauthenticated
//! enrollment endpoint.
//!
//! Task-creation services in the Python hub register queue wakes through
//! `task_events.notify_queue_on_commit`; since the Rust data layer commits
//! inside each call, the wake is fired here right after the creating call
//! returns — the exact "wake once the task is visible" ordering (see
//! `services::task_events`).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{rejection::JsonRejection, DefaultBodyLimit};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::{get, post};
use axum::Router;
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::error::ApiError;
use crate::models::vm::VM;
use crate::models::VMState;
use crate::security::SecurityConfig;
use crate::services::task_events::TaskEvents;

use self::enroll::enroll;
use self::heartbeat::heartbeat;
use self::longpoll::next_task;
use self::results::submit_task_result;

// ---------------------------------------------------------------------------
// Submodules — worker protocol split by function
// ---------------------------------------------------------------------------

mod enroll;
mod heartbeat;
mod longpoll;
mod results;

/// Long-poll cap (`worker.py:_MAX_WAIT_SECONDS`): a worker asking for more
/// still parks at most this long per request.
pub const MAX_WAIT_SECONDS: f64 = 25.0;

// ---------------------------------------------------------------------------
// State + router
// ---------------------------------------------------------------------------

/// Everything the worker routes need. Cheap to clone.
#[derive(Debug, Clone)]
pub struct WorkerState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub security: SecurityConfig,
    pub events: Arc<TaskEvents>,
    /// Dashboard SSE bus (`app/core/events.py`), shared with `routes/fleet` so
    /// task results published here reach connected dashboards.
    pub bus: Arc<crate::routes::fleet::events::EventBus>,
    enroll_limiter: RateLimiter,
}

impl WorkerState {
    pub fn new(pool: sqlx::PgPool, config: Config) -> Self {
        Self::with_events(
            pool,
            config,
            TaskEvents::new(),
            Arc::new(crate::routes::fleet::events::EventBus::new_default()),
        )
    }

    /// Build a state around shared buses (the app assembly wires one
    /// [`TaskEvents`] and one [`EventBus`] into worker + fleet routes).
    pub fn with_events(
        pool: sqlx::PgPool,
        config: Config,
        events: Arc<TaskEvents>,
        bus: Arc<crate::routes::fleet::events::EventBus>,
    ) -> Self {
        let security = SecurityConfig::new(
            &config.mfa_encryption_key,
            &config.jwt_secret,
            &config.secret_hash_key,
        );
        let enroll_limiter = RateLimiter::new(config.rate_limit_exec_per_minute);
        Self {
            pool,
            config,
            security,
            events,
            bus,
            enroll_limiter,
        }
    }
}

/// The `/api/worker` router (prefix included, so it can be merged as-is).
pub fn router(state: WorkerState) -> Router {
    // Global request-body cap, sized like `app/main.py`: the largest legitimate
    // body is a worker result carrying stdout+stderr each up to
    // `max_output_bytes`.
    let global_cap = state.config.max_output_bytes * 2 + 65_536;
    Router::new()
        .route("/api/worker/enroll", post(enroll))
        .route("/api/worker/heartbeat", post(heartbeat))
        .route("/api/worker/tasks/next", get(next_task))
        .route("/api/worker/tasks/{id}/result", post(submit_task_result))
        .layer(DefaultBodyLimit::max(global_cap))
        .with_state(state)
}

fn validate_ip_literal(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::unprocessable_entity(
            "ip_address must be a valid IP literal",
        ));
    }
    Ok(())
}

/// `_validate_os_info`: at most 20 keys, keys ≤ 64 chars, string values ≤ 256.
fn validate_os_info(value: &serde_json::Value) -> Result<(), ApiError> {
    let Some(obj) = value.as_object() else {
        return Err(ApiError::unprocessable_entity(
            "os_info must be an object (dict)",
        ));
    };
    if obj.len() > 20 {
        return Err(ApiError::unprocessable_entity(
            "os_info has too many keys (max 20)",
        ));
    }
    for (k, v) in obj {
        if k.chars().count() > 64 {
            return Err(ApiError::unprocessable_entity(
                "os_info keys must be strings <= 64 chars",
            ));
        }
        if let Some(s) = v.as_str() {
            if s.chars().count() > 256 {
                return Err(ApiError::unprocessable_entity(
                    "os_info string values must be <= 256 chars",
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Worker auth + request enforcement (app/api/deps.py + worker.py)
// ---------------------------------------------------------------------------

/// Authenticate a worker by its VM id + per-worker secret (timing-safe).
///
/// Mirrors `deps.current_worker`: 401 for missing/invalid credentials (the
/// secret is verified even when the VM is missing, so timing does not leak
/// existence), 403 for workers that are not approved yet.
async fn current_worker(state: &WorkerState, headers: &HeaderMap) -> Result<VM, ApiError> {
    let worker_id = header_str(headers, "x-worker-id").filter(|s| !s.is_empty());
    let worker_secret = header_str(headers, "x-worker-secret").filter(|s| !s.is_empty());
    let (Some(worker_id), Some(worker_secret)) = (worker_id, worker_secret) else {
        return Err(ApiError::unauthorized("worker credentials required"));
    };
    let Ok(vm_id) = worker_id.parse::<Uuid>() else {
        return Err(ApiError::unauthorized("invalid worker id"));
    };

    let vm = crate::models::vm::get_by_id(&state.pool, vm_id)
        .await
        .map_err(db_err)?;
    // Verify the secret even when the VM is missing to avoid leaking existence
    // via timing; verify_secret on a None hash is constant-ish and returns false.
    let secret_ok = state.security.verify_secret(
        worker_secret,
        vm.as_ref().and_then(|v| v.worker_secret_hash.as_deref()),
    );
    let Some(vm) = vm.filter(|_| secret_ok) else {
        return Err(ApiError::unauthorized("worker authentication failed"));
    };
    if !matches!(vm.state, VMState::Active | VMState::Offline) {
        // PENDING/REVOKED workers may not interact beyond enrollment.
        return Err(ApiError::forbidden("worker not approved"));
    }
    Ok(vm)
}

/// In prod, refuse plaintext hub<->worker traffic (`worker.py:_enforce_tls`).
fn enforce_tls(headers: &HeaderMap, uri: &Uri, config: &Config) -> Result<(), ApiError> {
    if !config.require_tls {
        return Ok(());
    }
    let forwarded = header_str(headers, "x-forwarded-proto")
        .map(|v| {
            v.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let scheme = if forwarded.is_empty() {
        uri.scheme()
            .map(|s| s.as_str())
            .unwrap_or("http")
            .to_ascii_lowercase()
    } else {
        forwarded
    };
    if scheme != "https" {
        return Err(ApiError::bad_request(
            "TLS is required for worker communication",
        ));
    }
    Ok(())
}

/// Reject oversized request bodies early (`deps.enforce_body_size`).
fn enforce_body_size(headers: &HeaderMap, max_body_bytes: usize) -> Result<(), ApiError> {
    if let Some(cl) = header_str(headers, "content-length") {
        if let Ok(len) = cl.trim().parse::<usize>() {
            if len > max_body_bytes {
                return Err(ApiError::payload_too_large("request body too large"));
            }
        }
    }
    Ok(())
}

/// Best-effort real client IP (`deps.client_ip`): when `trust_forwarded_for`
/// is set the LAST hop of `X-Forwarded-For` (the one the trusted proxy
/// appended — see the bundled Caddyfile's `header_up`), otherwise the peer
/// address. The header is only honoured when explicitly trusted, since
/// clients could otherwise spoof it. Delegates to the single shared
/// implementation in [`crate::routes::authapi::client_ip`] (H-1).
fn client_ip(headers: &HeaderMap, config: &Config, peer: Option<SocketAddr>) -> Option<String> {
    crate::routes::authapi::client_ip(headers, config, peer)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Axum JSON rejections mapped onto FastAPI semantics: oversized bodies are
/// 413 ("request body too large", like the global body cap middleware), every
/// parse/shape failure is 422 (pydantic's status).
fn map_json_rejection(err: JsonRejection) -> ApiError {
    if err.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large("request body too large")
    } else {
        ApiError::unprocessable_entity(err.body_text())
    }
}

/// Data-layer failures surface as a bare 500 (L-2): the sqlx detail can
/// quote user data, SQL text and constraint names, so it goes to the server
/// log only — the client just gets "internal error". Callers that owe the
/// client a specific status map their DbError variant *before* this.
fn db_err(err: DbError) -> ApiError {
    tracing::warn!(error = %err, "database error");
    ApiError::internal("internal error")
}

// ---------------------------------------------------------------------------
// Minimal rate limiter (app/core/ratelimit.py)
// ---------------------------------------------------------------------------

/// In-process fixed-window rate limiter — the single shared implementation
/// (`app/core/ratelimit.py`): fixed windows with expiry reset and eviction of
/// expired windows past the cap (H-1), so every router throttles identically.
/// Re-exported from `routes::authapi` (which owns it in `middleware`); for a
/// horizontally-scaled deployment back this with Redis.
pub use crate::routes::authapi::RateLimiter;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Shared fixtures for the route tests (no database needed).
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::json;

    pub(crate) fn test_state(require_tls: bool) -> WorkerState {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let config = Config {
            require_tls,
            ..Config::default()
        };
        WorkerState::new(pool, config)
    }

    pub(crate) fn json_request(
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-forwarded-proto", "https")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    pub(crate) async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(json!(null))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::json;
    use tower::ServiceExt;

    // ---- enforcement helpers ----------------------------------------------

    #[test]
    fn enforce_tls_matches_the_python_helper() {
        let config = Config {
            require_tls: true,
            ..Config::default()
        };
        let uri = Uri::from_static("http://hub/api/worker/heartbeat");

        let mut headers = HeaderMap::new();
        assert!(
            enforce_tls(&headers, &uri, &config).is_err(),
            "no proto → http → refused"
        );

        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(enforce_tls(&headers, &uri, &config).is_ok());

        headers.insert("x-forwarded-proto", "https, http".parse().unwrap());
        assert!(
            enforce_tls(&headers, &uri, &config).is_ok(),
            "first hop wins"
        );

        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(enforce_tls(&headers, &uri, &config).is_err());

        headers.insert("x-forwarded-proto", "HTTPS".parse().unwrap());
        assert!(
            enforce_tls(&headers, &uri, &config).is_ok(),
            "case-insensitive"
        );

        let dev = Config {
            require_tls: false,
            ..Config::default()
        };
        assert!(enforce_tls(&HeaderMap::new(), &uri, &dev).is_ok());
    }

    #[test]
    fn client_ip_honours_trust_forwarded_for() {
        let mut config = Config::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.7, 172.16.0.2".parse().unwrap(),
        );
        let peer: SocketAddr = "10.0.0.1:4321".parse().unwrap();

        config.trust_forwarded_for = true;
        // H-1: the LAST hop (the proxy-appended one) wins, never the
        // client-controlled first entry.
        assert_eq!(
            client_ip(&headers, &config, Some(peer)).as_deref(),
            Some("172.16.0.2")
        );
        config.trust_forwarded_for = false;
        assert_eq!(
            client_ip(&headers, &config, Some(peer)).as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(client_ip(&headers, &config, None), None);
    }

    #[test]
    fn body_cap_rejects_oversized_content_length() {
        let mut headers = HeaderMap::new();
        assert!(enforce_body_size(&headers, 65_536).is_ok());
        headers.insert("content-length", "65536".parse().unwrap());
        assert!(
            enforce_body_size(&headers, 65_536).is_ok(),
            "at the cap is fine"
        );
        headers.insert("content-length", "65537".parse().unwrap());
        let err = enforce_body_size(&headers, 65_536).unwrap_err();
        assert_eq!(err.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn rate_limiter_is_a_fixed_window() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.allow("ip"));
        assert!(limiter.allow("ip"));
        assert!(limiter.allow("ip"));
        assert!(!limiter.allow("ip"), "budget spent");
        assert!(limiter.allow("other"), "budgets are per key");
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
    async fn worker_endpoints_require_credentials() {
        let app = router(test_state(false));
        let response = app
            .oneshot(json_request("POST", "/api/worker/heartbeat", json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "worker credentials required"})
        );
    }

    #[tokio::test]
    async fn malformed_worker_id_is_401() {
        let app = router(test_state(false));
        let mut request = json_request("POST", "/api/worker/heartbeat", json!({}));
        request
            .headers_mut()
            .insert("x-worker-id", "not-a-uuid".parse().unwrap());
        request
            .headers_mut()
            .insert("x-worker-secret", "s3cret".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "invalid worker id"})
        );
    }
}

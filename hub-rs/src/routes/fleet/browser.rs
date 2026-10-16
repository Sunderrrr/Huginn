//! Browser automation route: `POST /api/vms/{vm_id}/browser` queues a
//! `browser` task — an ordered list of steps (navigate, click, type, eval,
//! screenshot, get_text, get_html, wait_for) executed by a Linux worker that
//! drives a local Obscura headless-browser process over CDP. hub-rs extension
//! (migration 0004); no Python-hub counterpart.
//!
//! Same guard chain as `run_command`: `rate_limit_exec` (operator+admin RBAC
//! and the shared per-principal execution throttle), the body-size cap, the
//! M-1 VM-access guard, then the service-layer validation. The audit entry
//! records the step COUNT — never the step content (a `type` step can carry
//! credentials into a login form).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

use super::audit::{entry, record};
use super::execution::{maybe_wait, require_vm_access};
use super::tasks::{self, ExecError, TaskOut};
use super::{
    client_ip, db_err, enforce_body_size, load_vm, map_json_rejection, map_path_rejection,
    peer_addr, rate_limit_exec, FleetState, Peer, RouteError,
};

/// Upper bound for the whole-task timeout — the worker enforces the same cap
/// (it refuses to keep an Obscura process alive longer).
pub const BROWSER_MAX_TIMEOUT_SECONDS: i64 = 300;

/// Default whole-task timeout (seconds) when the request omits one.
fn default_browser_timeout() -> i64 {
    120
}

/// `BrowserRequest` — the steps array plus the whole-task timeout.
///
/// ```json
/// {
///   "steps": [
///     { "action": "navigate", "url": "https://example.com" },
///     { "action": "click", "selector": "#button" },
///     { "action": "type", "selector": "#input", "text": "hello" },
///     { "action": "eval", "js": "document.title" },
///     { "action": "screenshot", "format": "jpeg", "quality": 80 },
///     { "action": "get_text" },
///     { "action": "get_html" },
///     { "action": "wait_for", "selector": "#result", "timeout_ms": 5000 }
///   ],
///   "timeout": 120
/// }
/// ```
///
/// The steps are kept as raw JSON here: their shape is validated by the
/// service layer (`models::task::validate_browser_steps` + the payload cap),
/// never interpreted by the hub.
#[derive(Debug, Clone, Deserialize)]
pub struct BrowserRequest {
    pub steps: serde_json::Value,
    #[serde(default = "default_browser_timeout")]
    pub timeout: i64,
    #[serde(default)]
    pub wait: bool,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

impl BrowserRequest {
    /// Field bounds the route itself enforces (the steps are validated by the
    /// service layer).
    fn validate(&self) -> Result<(), RouteError> {
        if !(1..=BROWSER_MAX_TIMEOUT_SECONDS).contains(&self.timeout) {
            return Err(ApiError::unprocessable_entity(format!(
                "timeout must be between 1 and {BROWSER_MAX_TIMEOUT_SECONDS}"
            ))
            .into());
        }
        if let Some(key) = &self.idempotency_key {
            if key.chars().count() > 128 {
                return Err(ApiError::unprocessable_entity(
                    "idempotency_key must be at most 128 characters",
                )
                .into());
            }
        }
        Ok(())
    }
}

/// `POST /api/vms/{vm_id}/browser` + `POST /api/vms/bulk/actions` is not
/// offered for browser tasks (each VM runs its own Obscura; bulk browser
/// runs would multiply memory use unpredictably).
pub fn router(state: FleetState) -> Router {
    Router::new()
        .route("/api/vms/{vm_id}/browser", post(run_browser))
        .with_state(state)
}

async fn run_browser(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    body: Result<Json<BrowserRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = rate_limit_exec(&state, &headers, ip.as_deref()).await?;
    enforce_body_size(&headers, state.config.max_body_bytes)?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    let vm = load_vm(&state, vm_id).await?;
    require_vm_access(&state, &principal, vm_id).await?;

    let (task, step_count) = tasks::create_browser_task(
        &state,
        &vm,
        &body.steps,
        body.timeout,
        &principal.actor_id,
        body.idempotency_key.as_deref(),
    )
    .await
    .map_err(browser_err)?;

    // Audited with the step count only — a `type` step can carry a password
    // into a login form, so the step content never reaches the audit chain.
    let mut new = entry(principal.actor_type, &principal.actor_id, "browser_task");
    new.vm_id = Some(vm.id);
    new.detail = serde_json::json!({
        "step_count": step_count,
        "timeout": body.timeout,
        "task_id": task.id.to_string(),
    });
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;

    let task = maybe_wait(&state, task, body.wait).await;
    Ok((StatusCode::ACCEPTED, Json(TaskOut::from(task))))
}

/// `ExecError` → the status codes `run_browser` answers (mirrors
/// `run_command`: input errors 400, state refusals 403).
fn browser_err(err: ExecError) -> RouteError {
    match err {
        ExecError::Input(detail) => ApiError::bad_request(detail),
        ExecError::Forbidden(detail) => ApiError::forbidden(detail),
        ExecError::Db(db) => return db_err(db),
        // The browser path never raises these, but map them the way the
        // sibling execution routes do rather than silently dropping them.
        ExecError::Action(detail) => ApiError::bad_request(detail),
        ExecError::Ssrf(detail) => ApiError::bad_request(format!("unsafe release URL: {detail}")),
        ExecError::Settings => ApiError::internal("settings not initialized"),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn browser_request_bounds() {
        let ok = BrowserRequest {
            steps: json!([{ "action": "get_text" }]),
            timeout: 120,
            wait: false,
            idempotency_key: None,
        };
        assert!(ok.validate().is_ok());
        // The default timeout kicks in at deserialization.
        let req: BrowserRequest = serde_json::from_value(json!({ "steps": [] })).expect("parse");
        assert_eq!(req.timeout, default_browser_timeout());
        assert!(!req.wait);

        for timeout in [0, -1, 301, 3600] {
            let err = BrowserRequest {
                timeout,
                ..ok.clone()
            }
            .validate()
            .unwrap_err();
            assert_eq!(
                err.detail(),
                "timeout must be between 1 and 300",
                "timeout {timeout}"
            );
        }
        // Boundary values pass.
        for timeout in [1, 300] {
            assert!(BrowserRequest {
                timeout,
                ..ok.clone()
            }
            .validate()
            .is_ok());
        }

        let err = BrowserRequest {
            idempotency_key: Some("k".repeat(129)),
            ..ok.clone()
        }
        .validate()
        .unwrap_err();
        assert_eq!(
            err.detail(),
            "idempotency_key must be at most 128 characters"
        );
    }

    #[test]
    fn browser_error_mapping_matches_run_command() {
        assert_eq!(
            browser_err(ExecError::Input("steps must be a JSON array".into())).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            browser_err(ExecError::Forbidden("VM is not approved/active".into())).status(),
            StatusCode::FORBIDDEN
        );
        // DB failures stay a bare 500 (L-2: no sqlx detail reaches the client).
        let err = browser_err(ExecError::Db(crate::db::DbError::Conflict("detail".into())));
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.detail(), "internal error");
    }

    /// The audit detail commits the step COUNT and the task id — a `type`
    /// step's text (a password) must never be serialized into it.
    #[test]
    fn audit_detail_never_contains_step_content() {
        let detail = serde_json::json!({
            "step_count": 3,
            "timeout": 120,
            "task_id": Uuid::new_v4().to_string(),
        });
        let serialized = serde_json::to_string(&detail).unwrap();
        assert_eq!(detail["step_count"], 3);
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("steps"));
    }

    /// The documented wire shape round-trips through the request type.
    #[test]
    fn documented_payload_parses() {
        let body: BrowserRequest = serde_json::from_value(json!({
            "steps": [
                { "action": "navigate", "url": "https://example.com" },
                { "action": "click", "selector": "#button" },
                { "action": "type", "selector": "#input", "text": "hello" },
                { "action": "eval", "js": "document.title" },
                { "action": "screenshot", "format": "jpeg", "quality": 80 },
                { "action": "get_text" },
                { "action": "get_html" },
                { "action": "wait_for", "selector": "#result", "timeout_ms": 5000 }
            ],
            "timeout": 120
        }))
        .expect("parse");
        assert_eq!(body.timeout, 120);
        assert!(crate::models::task::validate_browser_steps(&body.steps).is_ok());
    }

    /// End-to-end exercise against a live PostgreSQL (skipped unless
    /// `HUGINN_TEST_DATABASE_URL` is set, like the execution live test):
    /// the IDOR guard, the RBAC gate, step validation, the queued payload
    /// shape, and the audit entry (step count, never step content).
    #[tokio::test]
    async fn browser_endpoint_guards_queues_and_audits() {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return;
        };
        let guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = crate::db::connect(&url, 4).await.expect("connect");
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(&pool)
            .await
            .expect("drop schema");
        sqlx::query("CREATE SCHEMA public")
            .execute(&pool)
            .await
            .expect("create schema");
        crate::db::run_migrations(&pool).await.expect("migrations");

        let state = FleetState::new(pool.clone(), crate::config::Config::default());
        let app = crate::routes::fleet::router(state.clone());
        let body_json = super::super::testing::body_json;

        let vm = crate::models::vm::create(
            &pool,
            crate::models::vm::VmNew::new("vm-1", crate::models::WorkerArch::Amd64),
        )
        .await
        .unwrap();
        crate::models::vm::approve(&pool, vm.id, None)
            .await
            .unwrap()
            .unwrap();
        let make_user =
            |username: &str, role: crate::models::UserRole| crate::models::user::UserNew {
                username: username.into(),
                password_hash: Some("h".into()),
                role,
                is_active: true,
                ..Default::default()
            };
        let ungranted = crate::models::user::create(
            &pool,
            make_user("no-grant", crate::models::UserRole::Operator),
        )
        .await
        .unwrap();
        let granted = crate::models::user::create(
            &pool,
            make_user("has-grant", crate::models::UserRole::Operator),
        )
        .await
        .unwrap();
        crate::models::user::replace_vm_access(&pool, granted.id, &[vm.id])
            .await
            .unwrap();

        let token = |user: &crate::models::user::User| {
            state
                .security
                .jwt()
                .create_access_token(&user.id.to_string(), user.role.as_str(), 60)
                .unwrap()
        };
        let post = |uri: String, body: serde_json::Value, token: &str| {
            axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        };
        let steps = json!([
            { "action": "navigate", "url": "https://example.com" },
            { "action": "type", "selector": "#pw", "text": "hunter2" },
        ]);
        let uri = format!("/api/vms/{}/browser", vm.id);

        // 1. The M-1 VM-access guard: an operator without a grant gets 403 and
        //    nothing is queued.
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            post(uri.clone(), json!({ "steps": steps }), &token(&ungranted)),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "access to this VM denied"})
        );

        // 2. Bad steps are a 400 with the validator's reason.
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            post(
                uri.clone(),
                json!({ "steps": [{ "action": "navigate", "url": "file:///etc/passwd" }] }),
                &token(&granted),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(response).await["detail"]
            .as_str()
            .unwrap()
            .contains("http(s)://"));

        // 3. A granted operator queues a `browser` task with the documented
        //    payload shape and gets a 202 + TaskOut.
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            post(
                uri.clone(),
                json!({ "steps": steps, "timeout": 60 }),
                &token(&granted),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let out = body_json(response).await;
        assert_eq!(out["type"], "browser");
        assert_eq!(out["status"], "pending");
        let task_id: Uuid = out["id"].as_str().unwrap().parse().unwrap();
        let (task_type, payload): (String, serde_json::Value) =
            sqlx::query_as("SELECT type::text, payload FROM tasks WHERE id = $1")
                .bind(task_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(task_type, "browser");
        assert_eq!(payload["timeout"], 60);
        assert_eq!(payload["steps"].as_array().unwrap().len(), 2);

        // 4. The audit entry commits the step count — never the typed text.
        let (event_type, detail): (String, serde_json::Value) = sqlx::query_as(
            "SELECT event_type, detail FROM audit_log \
             WHERE event_type = 'browser_task' ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(event_type, "browser_task");
        assert_eq!(detail["step_count"], 2);
        assert_eq!(detail["task_id"], task_id.to_string());
        assert!(
            !detail.to_string().contains("hunter2"),
            "typed text must never reach the audit chain"
        );

        drop(guard);
    }
}

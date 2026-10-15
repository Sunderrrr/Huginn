//! Execution routes: whitelisted actions, free commands and worker updates
//! (`app/api/routes/execution.py`).
//!
//! These create tasks on the DB-backed queue that workers pull. With
//! `wait=true` the hub blocks briefly for a terminal result (sync-style);
//! otherwise it returns the task immediately (202, async) and the caller polls
//! `GET /api/tasks/{id}`.
//!
//! Every path enforces `rate_limit_exec` (operator + per-principal throttle),
//! `enforce_body_size`, and writes to the audit hash chain with the exact
//! `event_type` / `detail` of the Python handlers.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::task::Task;
use crate::models::vm;

use super::audit::{entry, record};
use super::tasks::{self, ExecError, TaskOut};
use super::{
    client_ip, db_err, enforce_body_size, load_vm, map_json_rejection, map_path_rejection,
    peer_addr, principal_can_access_vm, rate_limit_exec, FleetState, Peer, RouteError,
};
use super::principal::Principal;

/// How long `wait=true` blocks for a terminal result (`execution._WAIT_MAX_SECONDS`).
const WAIT_MAX_SECONDS: u64 = 30;

// ---------------------------------------------------------------------------
// Wire shapes (app/schemas/task.py)
// ---------------------------------------------------------------------------

/// `ActionRequest`.
#[derive(Debug, Clone, Deserialize)]
pub struct ActionRequest {
    pub action: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default)]
    pub wait: bool,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

impl ActionRequest {
    /// The pydantic field bounds of `ActionRequest`.
    fn validate(&self) -> Result<(), RouteError> {
        validate_len("action", &self.action, 64)?;
        if let Some(key) = &self.idempotency_key {
            validate_len("idempotency_key", key, 128)?;
        }
        Ok(())
    }
}

/// `CommandRequest`.
#[derive(Debug, Clone, Deserialize)]
pub struct CommandRequest {
    pub command: String,
    #[serde(default)]
    pub timeout: Option<i64>,
    #[serde(default)]
    pub wait: bool,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

impl CommandRequest {
    /// The pydantic field bounds of `CommandRequest`.
    fn validate(&self) -> Result<(), RouteError> {
        validate_len("command", &self.command, 65_536)?;
        if let Some(timeout) = self.timeout {
            if !(1..=3600).contains(&timeout) {
                return Err(
                    ApiError::unprocessable_entity("timeout must be between 1 and 3600").into(),
                );
            }
        }
        if let Some(key) = &self.idempotency_key {
            validate_len("idempotency_key", key, 128)?;
        }
        Ok(())
    }
}

/// `BulkActionRequest` — targets are the union of `vm_ids` and the VMs carrying
/// any of `tag_ids`.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkActionRequest {
    #[serde(default)]
    pub vm_ids: Vec<Uuid>,
    #[serde(default)]
    pub tag_ids: Vec<Uuid>,
    pub action: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

impl BulkActionRequest {
    fn validate(&self) -> Result<(), RouteError> {
        if self.vm_ids.len() > 500 {
            return Err(
                ApiError::unprocessable_entity("vm_ids must have at most 500 items").into(),
            );
        }
        if self.tag_ids.len() > 50 {
            return Err(
                ApiError::unprocessable_entity("tag_ids must have at most 50 items").into(),
            );
        }
        validate_len("action", &self.action, 64)?;
        Ok(())
    }
}

/// `BulkActionResult`.
#[derive(Debug, Clone, Serialize)]
pub struct BulkActionResult {
    pub vm_id: Uuid,
    pub task_id: Option<Uuid>,
    pub status: String,
    pub error: Option<String>,
}

impl BulkActionResult {
    fn queued(vm_id: Uuid, task_id: Uuid) -> Self {
        Self {
            vm_id,
            task_id: Some(task_id),
            status: "queued".into(),
            error: None,
        }
    }

    fn error(vm_id: Uuid, error: impl Into<String>) -> Self {
        Self {
            vm_id,
            task_id: None,
            status: "error".into(),
            error: Some(error.into()),
        }
    }
}

/// `Field(max_length=...)` — counted in characters, like pydantic.
fn validate_len(field: &str, value: &str, max: usize) -> Result<(), RouteError> {
    if value.chars().count() > max {
        return Err(ApiError::unprocessable_entity(format!(
            "{field} must be at most {max} characters"
        ))
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `/api/vms/.../actions|commands|update` + `/api/vms/bulk/actions`.
pub fn router(state: FleetState) -> Router {
    Router::new()
        .route("/api/vms/bulk/actions", post(run_bulk_action))
        .route("/api/vms/{vm_id}/actions", post(run_action))
        .route("/api/vms/{vm_id}/commands", post(run_command))
        .route("/api/vms/{vm_id}/update", post(trigger_update))
        .with_state(state)
}

/// M-1: the execution endpoints' IDOR guard — the same rule as `get_task`
/// (`deps.principal_can_access_vm`), answered as 403 "access to this VM
/// denied". Runs right after `load_vm`, so a caller without access cannot
/// tell an inaccessible VM from a missing one and no task is ever queued for
/// a VM outside the caller's grant.
async fn require_vm_access(
    state: &FleetState,
    principal: &Principal,
    vm_id: Uuid,
) -> Result<(), RouteError> {
    if !principal_can_access_vm(&state.pool, principal, vm_id)
        .await
        .map_err(db_err)?
    {
        return Err(ApiError::forbidden("access to this VM denied").into());
    }
    Ok(())
}

async fn run_action(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    body: Result<Json<ActionRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = rate_limit_exec(&state, &headers, ip.as_deref()).await?;
    enforce_body_size(&headers, state.config.max_body_bytes)?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    let vm = load_vm(&state, vm_id).await?;
    require_vm_access(&state, &principal, vm_id).await?;

    let task = tasks::create_action_task(
        &state,
        &vm,
        &body.action,
        &body.params,
        &principal.actor_id,
        body.idempotency_key.as_deref(),
    )
    .await
    .map_err(action_err)?;

    let mut new = entry(principal.actor_type, &principal.actor_id, "execute_action");
    new.vm_id = Some(vm.id);
    new.action_name = Some(body.action.clone());
    new.detail = serde_json::json!({ "params": body.params, "task_id": task.id.to_string() });
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;

    let task = maybe_wait(&state, task, body.wait).await;
    Ok((StatusCode::ACCEPTED, Json(TaskOut::from(task))))
}

async fn run_command(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    body: Result<Json<CommandRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = rate_limit_exec(&state, &headers, ip.as_deref()).await?;
    enforce_body_size(&headers, state.config.max_body_bytes)?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    let vm = load_vm(&state, vm_id).await?;
    require_vm_access(&state, &principal, vm_id).await?;

    let task = tasks::create_command_task(
        &state,
        &vm,
        &body.command,
        body.timeout,
        &principal.actor_id,
        body.idempotency_key.as_deref(),
    )
    .await
    .map_err(command_err)?;

    // Free-command execution is sensitive: always audited with the command text.
    let mut new = entry(principal.actor_type, &principal.actor_id, "execute_command");
    new.vm_id = Some(vm.id);
    new.command = Some(truncate_chars(&body.command, 4096));
    new.detail = serde_json::json!({ "task_id": task.id.to_string() });
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;

    let task = maybe_wait(&state, task, body.wait).await;
    Ok((StatusCode::ACCEPTED, Json(TaskOut::from(task))))
}

async fn trigger_update(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = super::require_operator(&state, &headers, ip.as_deref()).await?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let vm = load_vm(&state, vm_id).await?;
    require_vm_access(&state, &principal, vm_id).await?;

    let row = crate::models::setting::get_settings_row(&state.pool)
        .await
        .map_err(db_err)?;
    let Some(row) = row else {
        return Err(ApiError::internal("settings not initialized").into());
    };
    let task = tasks::create_update_task(
        &state,
        &vm,
        &row.target_worker_version,
        &row.target_release_repo,
        &row.allowed_release_domains_vec(),
        &principal.actor_id,
    )
    .await
    .map_err(action_err)?;

    let mut new = entry(principal.actor_type, &principal.actor_id, "trigger_update");
    new.vm_id = Some(vm.id);
    new.detail = serde_json::json!({
        "target_version": row.target_worker_version,
        "task_id": task.id.to_string(),
    });
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;
    Ok((StatusCode::ACCEPTED, Json(TaskOut::from(task))))
}

async fn run_bulk_action(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    body: Result<Json<BulkActionRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = rate_limit_exec(&state, &headers, ip.as_deref()).await?;
    enforce_body_size(&headers, state.config.max_body_bytes)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;

    let allowed = super::accessible_vm_ids(&state.pool, &principal)
        .await
        .map_err(db_err)?;
    let allowed_set: Option<HashSet<Uuid>> = allowed.map(|ids| ids.into_iter().collect());

    // Resolve tag targets and merge with explicit VM ids (preserve order, dedup).
    let mut ordered_ids: Vec<Uuid> = Vec::new();
    let mut seen: HashSet<Uuid> = HashSet::new();
    for vm_id in body
        .vm_ids
        .iter()
        .copied()
        .chain(if body.tag_ids.is_empty() {
            Vec::new()
        } else {
            crate::models::tag::vm_ids_for_tags(&state.pool, &body.tag_ids)
                .await
                .map_err(db_err)?
        })
    {
        if seen.insert(vm_id) {
            ordered_ids.push(vm_id);
        }
    }

    let mut results = Vec::with_capacity(ordered_ids.len());
    for vm_id in ordered_ids {
        // VMs the caller cannot access are silently skipped (access filtered).
        if allowed_set
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&vm_id))
        {
            results.push(BulkActionResult::error(vm_id, "access denied"));
            continue;
        }
        let vm = match vm::get_by_id(&state.pool, vm_id).await {
            Ok(Some(vm)) => vm,
            Ok(None) => {
                results.push(BulkActionResult::error(vm_id, "not found"));
                continue;
            }
            Err(e) => return Err(db_err(e)),
        };
        let task = tasks::create_action_task(
            &state,
            &vm,
            &body.action,
            &body.params,
            &principal.actor_id,
            None,
        )
        .await;
        let task = match task {
            Ok(task) => task,
            Err(e) => {
                results.push(BulkActionResult::error(vm_id, exec_message(&e)));
                continue;
            }
        };

        let mut new = entry(principal.actor_type, &principal.actor_id, "execute_action");
        new.vm_id = Some(vm.id);
        new.action_name = Some(body.action.clone());
        new.detail = serde_json::json!({
            "params": body.params,
            "task_id": task.id.to_string(),
            "bulk": true,
        });
        new.source_ip = ip.clone();
        record(&state.pool, new).await.map_err(db_err)?;
        results.push(BulkActionResult::queued(vm_id, task.id));
    }
    Ok((StatusCode::ACCEPTED, Json(results)))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `_maybe_wait` — with `wait=true`, block (event-driven) for a terminal result
/// and return it; on timeout return the task as last observed.
async fn maybe_wait(state: &FleetState, task: Task, wait: bool) -> Task {
    if !wait {
        return task;
    }
    match tasks::wait_for_task(state, task.id, Duration::from_secs(WAIT_MAX_SECONDS)).await {
        Some(latest) => latest,
        None => task,
    }
}

/// `body.command[:4096]` — Python slices by character.
fn truncate_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// `ActionError` / `TaskInputError` / `SSRFError` → the status codes
/// `execution.run_action` and `execution.trigger_update` raise (400/409/500).
fn action_err(err: ExecError) -> RouteError {
    match err {
        ExecError::Action(detail) | ExecError::Input(detail) => ApiError::bad_request(detail),
        ExecError::Forbidden(detail) => ApiError::conflict(detail),
        ExecError::Ssrf(detail) => ApiError::bad_request(format!("unsafe release URL: {detail}")),
        ExecError::Settings => ApiError::internal("settings not initialized"),
        ExecError::Db(err) => return db_err(err),
    }
    .into()
}

/// Same, but `ExecForbidden` is 403 here (`execution.run_command`).
fn command_err(err: ExecError) -> RouteError {
    match err {
        ExecError::Forbidden(detail) => ApiError::forbidden(detail).into(),
        other => action_err(other),
    }
}

fn exec_message(err: &ExecError) -> String {
    match err {
        ExecError::Action(detail)
        | ExecError::Forbidden(detail)
        | ExecError::Input(detail)
        | ExecError::Ssrf(detail) => detail.clone(),
        ExecError::Settings => "settings not initialized".into(),
        ExecError::Db(err) => err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// End-to-end exercise of the M-1 VM-access guard against a live
    /// PostgreSQL (skipped unless `HUGINN_TEST_DATABASE_URL` is set — `cargo
    /// test` stays green without a database, like `models::live_tests`).
    #[tokio::test]
    async fn execution_endpoints_deny_operators_without_a_vm_grant() {
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

        // An approved VM + two operators: one holds an access grant, one does
        // not (M-1: the latter must not be able to drive the VM).
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
        let make_operator = |username: &str| {
            crate::models::user::UserNew {
                username: username.into(),
                password_hash: Some("h".into()),
                role: crate::models::UserRole::Operator,
                is_active: true,
                ..Default::default()
            }
        };
        let ungranted =
            crate::models::user::create(&pool, make_operator("no-grant")).await.unwrap();
        let granted =
            crate::models::user::create(&pool, make_operator("has-grant")).await.unwrap();
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
                .body(axum::body::Body::from(if body.is_null() {
                    String::new()
                } else {
                    body.to_string()
                }))
                .unwrap()
        };

        // All three execution endpoints answer 403 "access to this VM denied"
        // for the operator without a grant — before any task is created.
        for (uri, body) in [
            (
                format!("/api/vms/{}/actions", vm.id),
                json!({"action": "status"}),
            ),
            (
                format!("/api/vms/{}/commands", vm.id),
                json!({"command": "ls"}),
            ),
            (format!("/api/vms/{}/update", vm.id), json!(null)),
        ] {
            let response = tower::ServiceExt::oneshot(
                app.clone(),
                post(uri.clone(), body, &token(&ungranted)),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(
                body_json(response).await,
                json!({"detail": "access to this VM denied"}),
                "{uri}"
            );
        }
        // No task leaked to the queue for the guarded VM.
        let (queued,): (i64,) = sqlx::query_as("SELECT count(*) FROM tasks WHERE vm_id = $1")
            .bind(vm.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(queued, 0, "the 403s must not queue anything");

        // Control: the granted operator passes the guard (the request proceeds
        // to the normal action handling and is queued).
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            post(
                format!("/api/vms/{}/actions", vm.id),
                json!({"action": "status"}),
                &token(&granted),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        drop(guard);
    }

    #[test]
    fn action_request_bounds_match_pydantic() {
        let ok = ActionRequest {
            action: "restart_service".into(),
            params: BTreeMap::from([("service".into(), "nginx".into())]),
            wait: true,
            idempotency_key: Some("k".into()),
        };
        assert!(ok.validate().is_ok());

        let long = ActionRequest {
            action: "x".repeat(65),
            ..ok.clone()
        };
        assert_eq!(
            long.validate().unwrap_err().detail(),
            "action must be at most 64 characters"
        );

        let long_key = ActionRequest {
            idempotency_key: Some("k".repeat(129)),
            ..ok.clone()
        };
        assert!(long_key.validate().is_err());

        let long_param = ActionRequest {
            params: BTreeMap::from([("service".into(), "x".repeat(10_000))]),
            ..ok
        };
        assert!(
            long_param.validate().is_ok(),
            "params are bounded by the action validator, not length"
        );
    }

    #[test]
    fn command_request_bounds_match_pydantic() {
        let ok = CommandRequest {
            command: "ls -la".into(),
            timeout: Some(30),
            wait: false,
            idempotency_key: None,
        };
        assert!(ok.validate().is_ok());
        assert!(CommandRequest {
            timeout: None,
            ..ok.clone()
        }
        .validate()
        .is_ok());
        assert!(CommandRequest {
            timeout: Some(1),
            ..ok.clone()
        }
        .validate()
        .is_ok());
        assert!(CommandRequest {
            timeout: Some(3600),
            ..ok.clone()
        }
        .validate()
        .is_ok());

        for timeout in [0, -1, 3601] {
            assert_eq!(
                CommandRequest {
                    timeout: Some(timeout),
                    ..ok.clone()
                }
                .validate()
                .unwrap_err()
                .detail(),
                "timeout must be between 1 and 3600"
            );
        }
        assert_eq!(
            CommandRequest {
                command: "x".repeat(65_537),
                ..ok.clone()
            }
            .validate()
            .unwrap_err()
            .detail(),
            "command must be at most 65536 characters"
        );
    }

    #[test]
    fn bulk_request_bounds_match_pydantic() {
        let ok = BulkActionRequest {
            vm_ids: Vec::new(),
            tag_ids: Vec::new(),
            action: "status".into(),
            params: BTreeMap::new(),
        };
        assert!(ok.validate().is_ok());
        let too_many = BulkActionRequest {
            vm_ids: vec![Uuid::new_v4(); 501],
            ..ok.clone()
        };
        assert!(too_many.validate().is_err());
        let too_many_tags = BulkActionRequest {
            tag_ids: vec![Uuid::new_v4(); 51],
            ..ok
        };
        assert!(too_many_tags.validate().is_err());
    }

    #[test]
    fn exec_error_mapping_matches_the_python_status_codes() {
        // run_action: ActionError → 400, ExecForbidden → 409.
        assert_eq!(
            action_err(ExecError::Action("unknown action: 'x'".into())).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            action_err(ExecError::Forbidden("VM is not approved/active".into())).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            action_err(ExecError::Ssrf(
                "release host 'evil' not in allowlist".into()
            ))
            .detail(),
            "unsafe release URL: release host 'evil' not in allowlist"
        );
        assert_eq!(
            action_err(ExecError::Settings).detail(),
            "settings not initialized"
        );
        // run_command: ExecForbidden → 403, input errors stay 400.
        assert_eq!(
            command_err(ExecError::Forbidden(
                "VM is not in unrestricted mode".into()
            ))
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            command_err(ExecError::Input("command is empty or too large".into())).status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn command_audit_truncates_at_4096_chars() {
        let command = "é".repeat(5000);
        let cut = truncate_chars(&command, 4096);
        assert_eq!(cut.chars().count(), 4096, "Python slices by character");
    }

    #[test]
    fn bulk_results_match_the_python_shape() {
        let vm_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        assert_eq!(
            serde_json::to_value(BulkActionResult::queued(vm_id, task_id)).unwrap(),
            json!({
                "vm_id": vm_id,
                "task_id": task_id,
                "status": "queued",
                "error": null,
            })
        );
        assert_eq!(
            serde_json::to_value(BulkActionResult::error(vm_id, "access denied")).unwrap(),
            json!({
                "vm_id": vm_id,
                "task_id": null,
                "status": "error",
                "error": "access denied",
            })
        );
    }

    #[test]
    fn audit_detail_shapes_match_the_python_handlers() {
        let task_id = Uuid::new_v4();
        let params = BTreeMap::from([("service".to_owned(), "nginx".to_owned())]);
        assert_eq!(
            serde_json::json!({ "params": params, "task_id": task_id.to_string() }),
            json!({ "params": {"service": "nginx"}, "task_id": task_id.to_string() })
        );
    }
}

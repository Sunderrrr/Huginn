//! VM inventory + lifecycle routes (`app/api/routes/vms.py`).
//!
//! | route                    | handler        | notes                                       |
//! |--------------------------|----------------|---------------------------------------------|
//! | `GET /api/vms`           | `list_vms`     | `state` + `tag_id` filters, access-scoped    |
//! | `GET /api/vms/{vm_id}`   | `get_vm`       | IDOR-guarded, 404 shape of FastAPI           |
//! | `PUT /api/vms/{vm_id}/tags`      | `set_vm_tags` | admin, audited `vm_tags_set`            |
//! | `POST /api/vms/{vm_id}/approve`  | `approve_vm`  | pending → active, audited, telemetry refresh |
//! | `PUT /api/vms/{vm_id}/exec-mode` | `set_exec_mode` | audited `toggle_unrestricted`         |
//! | `POST /api/vms/{vm_id}/revoke`   | `revoke_vm`   | optional uninstall task first, audited       |
//! | `DELETE /api/vms/{vm_id}`        | `delete_vm`   | revoked VMs only, 204, audited `vm_deleted`  |
//!
//! The response shapes are `app/schemas/vm.py` and `app/schemas/tag.py`. As in
//! Python, the list/get/tags responses carry the VM's tags while approve /
//! exec-mode / revoke validate straight from the row (no tag join) and render
//! `"tags": []`.

use std::future::Future;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbError;
use crate::error::ApiError;
use crate::models::enums::{ExecMode, TaskStatus, VMState, WorkerArch};
use crate::models::tag::{self, Tag};
use crate::models::task;
use crate::models::vm::{self, VmListFilter, VM};

use super::audit::{entry, record};
use super::tasks::{self, ExecError};
use super::{
    client_ip, db_err, load_vm, map_path_rejection, peer_addr, require_admin, ts, ts_opt,
    FleetState, Peer, RouteError,
};

// ---------------------------------------------------------------------------
// Wire shapes (app/schemas/vm.py, app/schemas/tag.py)
// ---------------------------------------------------------------------------

/// `TagOut`.
#[derive(Debug, Clone, Serialize)]
pub struct TagOut {
    pub id: Uuid,
    pub name: String,
    pub color: String,
    #[serde(with = "ts")]
    pub created_at: DateTime<Utc>,
}

impl From<Tag> for TagOut {
    fn from(tag: Tag) -> Self {
        Self {
            id: tag.id,
            name: tag.name,
            color: tag.color,
            created_at: tag.created_at,
        }
    }
}

/// `VMOut`.
#[derive(Debug, Clone, Serialize)]
pub struct VMOut {
    pub id: Uuid,
    pub name: String,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub arch: WorkerArch,
    pub state: VMState,
    pub exec_mode: ExecMode,
    pub worker_version: Option<String>,
    #[serde(with = "ts_opt")]
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    #[serde(with = "ts_opt")]
    pub enrolled_at: Option<DateTime<Utc>>,
    #[serde(with = "ts_opt")]
    pub approved_at: Option<DateTime<Utc>>,
    #[serde(with = "ts")]
    pub created_at: DateTime<Utc>,
    pub tags: Vec<TagOut>,
    /// Browser automation gate (migrations/0005) — off until an admin
    /// enables it on the VM.
    pub browser_enabled: bool,
    /// The Obscura engine version the worker reported (migrations/0009);
    /// `None` = no engine installed on that node.
    pub browser_engine_version: Option<String>,
    /// When the worker last reported its engine state.
    #[serde(with = "ts_opt")]
    pub browser_engine_reported_at: Option<DateTime<Utc>>,
}

impl VMOut {
    /// `_vm_out` — the row plus its tags.
    fn with_tags(vm: &VM, tags: Vec<Tag>) -> Self {
        Self {
            tags: tags.into_iter().map(TagOut::from).collect(),
            ..Self::from_row(vm)
        }
    }

    /// `VMOut.model_validate(vm)` — the row alone renders `"tags": []`.
    fn from_row(vm: &VM) -> Self {
        Self {
            id: vm.id,
            name: vm.name.clone(),
            hostname: vm.hostname.clone(),
            ip_address: vm.ip_address.clone(),
            arch: vm.arch,
            state: vm.state,
            exec_mode: vm.exec_mode,
            worker_version: vm.worker_version.clone(),
            last_heartbeat_at: vm.last_heartbeat_at,
            enrolled_at: vm.enrolled_at,
            approved_at: vm.approved_at,
            created_at: vm.created_at,
            tags: Vec::new(),
            browser_enabled: vm.browser_enabled,
            browser_engine_version: vm.browser_engine_version.clone(),
            browser_engine_reported_at: vm.browser_engine_reported_at,
        }
    }
}

/// `VMTagsUpdate`.
#[derive(Debug, Clone, Deserialize)]
pub struct VMTagsUpdate {
    pub tag_ids: Vec<Uuid>,
}

/// `ExecModeUpdate`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecModeUpdate {
    pub exec_mode: ExecMode,
}

/// `BrowserEnabledUpdate` — the per-VM browser automation toggle
/// (migrations/0005).
#[derive(Debug, Clone, Deserialize)]
pub struct BrowserEnabledUpdate {
    pub enabled: bool,
}

/// `RevokeRequest` — the body is optional in the Python handler.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RevokeRequest {
    #[serde(default)]
    pub uninstall: bool,
}

/// Query for `GET /api/vms`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListVmsQuery {
    #[serde(default)]
    pub state: Option<VMState>,
    #[serde(default)]
    pub tag_id: Vec<Uuid>,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `/api/vms` inventory + lifecycle router.
pub fn router(state: FleetState) -> Router {
    Router::new()
        .route("/api/vms", get(list_vms))
        .route("/api/vms/{vm_id}", get(get_vm).delete(delete_vm))
        .route("/api/vms/{vm_id}/tags", put(set_vm_tags))
        .route("/api/vms/{vm_id}/approve", post(approve_vm))
        .route("/api/vms/{vm_id}/exec-mode", put(set_exec_mode))
        .route("/api/vms/{vm_id}/browser-enabled", put(set_browser_enabled))
        .route("/api/vms/{vm_id}/revoke", post(revoke_vm))
        .with_state(state)
}

async fn list_vms(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    query: Result<Query<ListVmsQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = super::authenticate(&state, &headers, ip.as_deref()).await?;
    let Query(query) = query.map_err(map_path_rejection)?;

    let allowed = super::accessible_vm_ids(&state.pool, &principal)
        .await
        .map_err(db_err)?;
    let vms = vm::list_vms(
        &state.pool,
        VmListFilter {
            state: query.state,
            allowed_vm_ids: allowed,
            tag_ids: (!query.tag_id.is_empty()).then(|| query.tag_id.clone()),
        },
    )
    .await
    .map_err(db_err)?;

    let ids: Vec<Uuid> = vms.iter().map(|v| v.id).collect();
    let tag_map = tag::load_tags_for_vms(&state.pool, &ids)
        .await
        .map_err(db_err)?;
    let out: Vec<VMOut> = vms
        .iter()
        .map(|v| VMOut::with_tags(v, tag_map.get(&v.id).cloned().unwrap_or_default()))
        .collect();
    Ok(Json(out))
}

async fn get_vm(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = super::authenticate(&state, &headers, ip.as_deref()).await?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;

    // Access is checked before existence (parity with `vms.get_vm`).
    if !super::principal_can_access_vm(&state.pool, &principal, vm_id)
        .await
        .map_err(db_err)?
    {
        return Err(ApiError::forbidden("access to this VM denied").into());
    }
    let vm = load_vm(&state, vm_id).await?;
    let tags = tag::load_tags_for_vms(&state.pool, &[vm.id])
        .await
        .map_err(db_err)?
        .remove(&vm.id)
        .unwrap_or_default();
    Ok(Json(VMOut::with_tags(&vm, tags)))
}

async fn set_vm_tags(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    body: Result<Json<VMTagsUpdate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = require_admin(&state, &headers, ip.as_deref()).await?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let body = body.map_err(super::map_json_rejection)?.0;
    let vm = load_vm(&state, vm_id).await?;

    tag::set_vm_tags(&state.pool, vm.id, &body.tag_ids)
        .await
        .map_err(db_err)?;
    let mut new = entry(principal.actor_type, &principal.actor_id, "vm_tags_set");
    new.vm_id = Some(vm.id);
    new.detail = serde_json::json!({ "tag_count": body.tag_ids.len() });
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;

    let tags = tag::load_tags_for_vms(&state.pool, &[vm.id])
        .await
        .map_err(db_err)?
        .remove(&vm.id)
        .unwrap_or_default();
    Ok(Json(VMOut::with_tags(&vm, tags)))
}

async fn approve_vm(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = require_admin(&state, &headers, ip.as_deref()).await?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let vm = load_vm(&state, vm_id).await?;
    let was_pending = vm.state == VMState::Pending;

    let approved_by = principal.user.as_ref().map(|user| user.id);
    let vm = vm::approve(&state.pool, vm.id, approved_by)
        .await
        .map_err(vm_state_err)?
        .ok_or_else(|| ApiError::not_found("VM not found"))?;

    let mut new = entry(principal.actor_type, &principal.actor_id, "approve");
    new.vm_id = Some(vm.id);
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;

    // On the pending→active transition, queue a status + metrics refresh so the
    // dashboard shows live telemetry as soon as the worker next polls — no
    // manual "run status" needed. Best-effort: never fail the approval.
    if was_pending {
        for action in ["status", "metrics"] {
            if let Err(e) = tasks::create_action_task(
                &state,
                &vm,
                action,
                &std::collections::BTreeMap::new(),
                "system:post-approve",
                None,
            )
            .await
            {
                tracing::warn!(
                    "could not queue {} refresh for vm {}: {:?}",
                    action,
                    vm.id,
                    e
                );
            }
        }
    }
    Ok(Json(VMOut::from_row(&vm)))
}

async fn set_exec_mode(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    body: Result<Json<ExecModeUpdate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = require_admin(&state, &headers, ip.as_deref()).await?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let body = body.map_err(super::map_json_rejection)?.0;
    let vm = load_vm(&state, vm_id).await?;

    let vm = vm::set_exec_mode(&state.pool, vm.id, body.exec_mode)
        .await
        .map_err(vm_state_err)?
        .ok_or_else(|| ApiError::not_found("VM not found"))?;

    // Enabling unrestricted mode is a sensitive, explicitly audited action.
    let mut new = entry(
        principal.actor_type,
        &principal.actor_id,
        "toggle_unrestricted",
    );
    new.vm_id = Some(vm.id);
    new.detail = serde_json::json!({
        "exec_mode": body.exec_mode.as_str(),
        "unrestricted": body.exec_mode == ExecMode::Unrestricted,
    });
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;
    Ok(Json(VMOut::from_row(&vm)))
}

/// `PUT /api/vms/{vm_id}/browser-enabled` — the browser automation gate
/// (migrations/0005). Off by default; only an admin may flip it, and the
/// flip is audited (mirrors `set_exec_mode`). Operators can then run
/// browser tasks; readonly never can (the browser route rides the exec
/// RBAC chain).
async fn set_browser_enabled(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    body: Result<Json<BrowserEnabledUpdate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = require_admin(&state, &headers, ip.as_deref()).await?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let body = body.map_err(super::map_json_rejection)?.0;
    let vm = load_vm(&state, vm_id).await?;

    let vm = vm::set_browser_enabled(&state.pool, vm.id, body.enabled)
        .await
        .map_err(vm_state_err)?
        .ok_or_else(|| ApiError::not_found("VM not found"))?;

    // Enabling a remote-controlled browser is a sensitive, explicitly
    // audited action.
    let mut new = entry(principal.actor_type, &principal.actor_id, "toggle_browser");
    new.vm_id = Some(vm.id);
    new.detail = serde_json::json!({ "enabled": body.enabled });
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;
    Ok(Json(VMOut::from_row(&vm)))
}

async fn revoke_vm(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = require_admin(&state, &headers, ip.as_deref()).await?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    // The body is optional (`RevokeRequest | None = None` in Python): an empty
    // body or `null` means "no uninstall".
    let body: Option<RevokeRequest> = if body.is_empty() {
        None
    } else {
        serde_json::from_slice(&body).map_err(|e| ApiError::unprocessable_entity(e.to_string()))?
    };
    let vm = load_vm(&state, vm_id).await?;
    let mut uninstall_result: Option<String> = None;

    if body.is_some_and(|b| b.uninstall) && matches!(vm.state, VMState::Active | VMState::Offline) {
        // Send the uninstall task to the worker first, then wait for its result
        // (best-effort) — the revocation happens either way.
        let created_by = principal
            .user
            .as_ref()
            .map(|user| user.id.to_string())
            .unwrap_or_else(|| "system".to_owned());
        uninstall_result = Some(
            match tasks::create_uninstall_task(&state, &vm, &created_by).await {
                Ok(uninstall) => {
                    wait_uninstall_result(
                        || async {
                            task::get_by_id(&state.pool, uninstall.id)
                                .await
                                .ok()
                                .flatten()
                                .map(|task| task.status)
                        },
                        UNINSTALL_POLL_ATTEMPTS,
                        UNINSTALL_POLL_INTERVAL,
                    )
                    .await
                }
                Err(ExecError::Forbidden(_)) => "vm_not_active".to_owned(),
                Err(_) => "error".to_owned(),
            },
        );
    }

    // Proceed with revocation regardless of the uninstall outcome.
    let vm = vm::revoke(&state.pool, vm.id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("VM not found"))?;

    let mut new = entry(principal.actor_type, &principal.actor_id, "revoke");
    new.vm_id = Some(vm.id);
    new.detail = match &uninstall_result {
        Some(result) => serde_json::json!({ "uninstall_result": result }),
        None => serde_json::json!({}),
    };
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;
    Ok(Json(VMOut::from_row(&vm)))
}

async fn delete_vm(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    let principal = require_admin(&state, &headers, ip.as_deref()).await?;
    let Path(vm_id) = path.map_err(map_path_rejection)?;
    let vm = load_vm(&state, vm_id).await?;
    let name = vm.name.clone();

    vm::delete(&state.pool, vm.id).await.map_err(vm_state_err)?;
    // Record after the VM row is gone — the audit log keeps its own copy of the
    // id and the name, so the VM's history survives the deletion.
    let mut new = entry(principal.actor_type, &principal.actor_id, "vm_deleted");
    new.vm_id = Some(vm_id);
    new.detail = serde_json::json!({ "name": name });
    new.source_ip = ip;
    record(&state.pool, new).await.map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Revocation helpers
// ---------------------------------------------------------------------------

/// How long `revoke?uninstall=true` waits for the worker to run the uninstall
/// (30 × 1s in `vms.revoke_vm`).
const UNINSTALL_POLL_ATTEMPTS: usize = 30;
const UNINSTALL_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Poll the uninstall task until it is terminal, answering its status value
/// (e.g. `"succeeded"`) or `"timeout"` — exactly `vms.revoke_vm`'s loop.
async fn wait_uninstall_result<F, Fut>(mut load: F, attempts: usize, interval: Duration) -> String
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<TaskStatus>>,
{
    for _ in 0..attempts {
        tokio::time::sleep(interval).await;
        if let Some(status) = load().await {
            if status.is_terminal() {
                return status.as_str().to_owned();
            }
        }
    }
    "timeout".to_owned()
}

/// VM state errors are 409 (`VMError` in `vms_service`), missing rows 404.
fn vm_state_err(err: DbError) -> RouteError {
    match err {
        DbError::Invalid(detail) => ApiError::conflict(detail).into(),
        DbError::NotFound => ApiError::not_found("VM not found").into(),
        err => db_err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_vm() -> VM {
        VM {
            id: Uuid::new_v4(),
            name: "worker-1".into(),
            hostname: Some("host-1".into()),
            ip_address: Some("10.0.0.9".into()),
            arch: WorkerArch::Amd64,
            os_info: json!({"os": "linux"}),
            state: VMState::Active,
            exec_mode: ExecMode::Whitelist,
            worker_version: Some("v1.4.0".into()),
            worker_secret_hash: Some("hmac".into()),
            enrollment_token_id: None,
            approved_by: None,
            last_heartbeat_at: None,
            enrolled_at: None,
            approved_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            browser_enabled: false,
            browser_engine_version: None,
            browser_engine_reported_at: None,
        }
    }

    #[test]
    fn vm_out_matches_the_python_schema() {
        let vm = sample_vm();
        let tag = Tag {
            id: Uuid::new_v4(),
            name: "prod".into(),
            color: "#46d39a".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let out = serde_json::to_value(VMOut::with_tags(&vm, vec![tag])).unwrap();

        // Exact keys of `schemas.vm.VMOut` — the secret hash and os_info stay
        // internal.
        let expected = json!({
            "id": vm.id,
            "name": "worker-1",
            "hostname": "host-1",
            "ip_address": "10.0.0.9",
            "arch": "amd64",
            "state": "active",
            "exec_mode": "whitelist",
            "worker_version": "v1.4.0",
            "browser_enabled": false,
            "browser_engine_version": null,
            "browser_engine_reported_at": null,
            "last_heartbeat_at": null,
            "enrolled_at": null,
            "approved_at": null,
            "created_at": out["created_at"],
            "tags": [{
                "id": out["tags"][0]["id"],
                "name": "prod",
                "color": "#46d39a",
                "created_at": out["tags"][0]["created_at"],
            }],
        });
        assert_eq!(out, expected);
    }

    #[test]
    fn row_only_responses_render_empty_tags() {
        // approve / exec-mode / revoke validate straight from the row in
        // Python (`VMOut.model_validate(vm)`), which never joins tags.
        let out = serde_json::to_value(VMOut::from_row(&sample_vm())).unwrap();
        assert_eq!(out["tags"], json!([]));
    }

    #[test]
    fn revoke_request_body_is_optional() {
        let none: Option<RevokeRequest> = serde_json::from_slice(b"").ok().flatten();
        assert!(none.is_none(), "an empty body parses outside serde");
        let nulled: Option<RevokeRequest> = serde_json::from_slice(b"null").unwrap();
        assert!(nulled.is_none());
        let default: Option<RevokeRequest> = serde_json::from_slice(b"{}").unwrap();
        assert!(!default.unwrap().uninstall);
        let flagged: Option<RevokeRequest> =
            serde_json::from_slice(br#"{"uninstall": true}"#).unwrap();
        assert!(flagged.unwrap().uninstall);
    }

    #[tokio::test]
    async fn uninstall_poll_reports_the_terminal_status() {
        let statuses = [Some(TaskStatus::Running), Some(TaskStatus::Succeeded)];
        let seen = std::cell::Cell::new(0);
        let result = wait_uninstall_result(
            || {
                let status = statuses[seen.get().min(statuses.len() - 1)];
                seen.set(seen.get() + 1);
                async move { status }
            },
            5,
            Duration::ZERO,
        )
        .await;
        assert_eq!(result, "succeeded");
    }

    #[tokio::test]
    async fn uninstall_poll_gives_up_after_the_attempts() {
        let result =
            wait_uninstall_result(|| async { Some(TaskStatus::Pending) }, 3, Duration::ZERO).await;
        assert_eq!(result, "timeout");
        let none = wait_uninstall_result(|| async { None }, 3, Duration::ZERO).await;
        assert_eq!(none, "timeout", "a vanished task is also a timeout");
    }
}

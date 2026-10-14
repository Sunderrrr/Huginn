//! Task queue service + `/api/tasks` routes.
//!
//! Ports `app/services/tasks.py` (the DB-backed queue's creation rules) and the
//! `/api/tasks` routes of `app/api/routes/tasks.py`:
//!
//! - the whitelisted action catalog and parameter validation
//!   (`app/core/actions.py`);
//! - exec-mode gating for admin-defined custom commands and free commands;
//! - idempotent inserts, `update_worker`'s SSRF-validated release URLs
//!   (`app/services/versioning.py`);
//! - `GET /api/tasks/{id}` and the event-driven `GET /api/tasks/{id}/wait`.
//!
//! The queue itself (claim, results, sweeps) lives in `models::task`; the
//! completion wakes live in `services::task_events`. As in Python, a task
//! creation only *flushes* — the queue wake fires after the caller's commit
//! (`TaskEvents::notify_queue_on_commit`), so a parked worker never re-claims a
//! task that is not yet visible.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbError;
use crate::error::ApiError;
use crate::models::enums::{ExecMode, TaskStatus, VMState};
use crate::models::task::{self, ActionTaskNew, CommandTaskNew, Task, TaskNew, UpdateTaskNew};
use crate::models::vm::VM;
use crate::services::task_events::TaskEvents;

use super::{
    authenticate, client_ip, db_err, map_path_rejection, principal_can_access_vm, py_repr, ts,
    ts_opt, FleetState, RouteError,
};

// ---------------------------------------------------------------------------
// Action catalog (app/core/actions.py)
// ---------------------------------------------------------------------------

/// A conservative identifier for things like systemd unit names: letters,
/// digits and a few separators. Prevents smuggling shell metacharacters
/// through params (`actions._SAFE_NAME`).
pub fn safe_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric()) {
        return false;
    }
    value.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
}

/// One declared action parameter (`actions.ActionParam`).
#[derive(Debug, Clone, Copy)]
pub struct ActionParam {
    pub name: &'static str,
    pub required: bool,
}

/// One whitelisted action (`actions.ActionSpec`).
#[derive(Debug, Clone, Copy)]
pub struct ActionSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub params: &'static [ActionParam],
}

const RESTART_SERVICE_PARAMS: &[ActionParam] = &[ActionParam {
    name: "service",
    required: true,
}];

/// Server-side catalog of whitelisted actions. The worker holds the
/// authoritative name → argv mapping; the hub never ships a shell string.
pub const ACTION_CATALOG: &[ActionSpec] = &[
    ActionSpec {
        name: "status",
        description: "Report worker and host status.",
        params: &[],
    },
    ActionSpec {
        name: "metrics",
        description: "Report basic host metrics (cpu/mem/disk).",
        params: &[],
    },
    ActionSpec {
        name: "restart_service",
        description: "Restart a systemd service by name.",
        params: RESTART_SERVICE_PARAMS,
    },
    ActionSpec {
        name: "list_upgradable_packages",
        description: "List packages with available upgrades.",
        params: &[],
    },
    ActionSpec {
        name: "apt_upgrade",
        description: "Apply available apt package upgrades.",
        params: &[],
    },
    ActionSpec {
        name: "update_worker",
        description: "Update the worker to the target version.",
        params: &[],
    },
];

/// Look an action up in the built-in catalog.
pub fn action_spec(name: &str) -> Option<&'static ActionSpec> {
    ACTION_CATALOG.iter().find(|spec| spec.name == name)
}

/// `actions.validate_action` — validate an action request and return the
/// normalized params. `Err` carries the exact `ActionError` message.
pub fn validate_action(
    name: &str,
    params: &BTreeMap<String, String>,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let Some(spec) = action_spec(name) else {
        return Err(format!("unknown action: {}", py_repr(name)));
    };

    let mut extra: Vec<String> = params
        .keys()
        .filter(|key| !spec.params.iter().any(|p| p.name == **key))
        .cloned()
        .collect();
    if !extra.is_empty() {
        extra.sort();
        return Err(format!(
            "unknown parameter(s) for {}: {}",
            py_repr(name),
            super::py_repr_list(&extra)
        ));
    }

    let mut normalized = serde_json::Map::new();
    for param in spec.params {
        let Some(value) = params.get(param.name) else {
            if param.required {
                return Err(format!(
                    "missing required parameter {} for {}",
                    py_repr(param.name),
                    py_repr(name)
                ));
            }
            continue;
        };
        if !safe_name(value) {
            return Err(format!(
                "invalid value for parameter {}",
                py_repr(param.name)
            ));
        }
        normalized.insert(
            param.name.to_owned(),
            serde_json::Value::String(value.clone()),
        );
    }
    Ok(normalized)
}

// ---------------------------------------------------------------------------
// Release URLs (app/services/versioning.py)
// ---------------------------------------------------------------------------

/// `versioning.SSRFError` — a release URL host is not in the allowlist.
pub fn build_release_urls(
    repo: &str,
    version: &str,
    arch: crate::models::enums::WorkerArch,
    allowed_domains: &[String],
) -> Result<serde_json::Value, String> {
    let asset = format!("huginn-worker-linux-{}", arch.as_str());
    if !valid_version(version) {
        return Err(format!("invalid version: {}", py_repr(version)));
    }
    let urls = if let Some(base) = repo
        .strip_prefix("https://")
        .or(repo.strip_prefix("http://"))
    {
        // Self-hosted mode: repo is a base URL.
        let base = format!(
            "{}://{}",
            &repo[..repo.len() - base.len() - 3],
            base.trim_end_matches('/')
        );
        serde_json::json!({
            "binary_url": format!("{base}/{asset}"),
            "checksums_url": format!("{base}/checksums.txt"),
            "asset_name": asset,
            "version": version,
        })
    } else {
        // GitHub releases mode: repo is owner/repo.
        if !valid_repo(repo) {
            return Err(format!("invalid repo: {}", py_repr(repo)));
        }
        let base = format!("https://github.com/{repo}/releases/download/{version}");
        serde_json::json!({
            "binary_url": format!("{base}/{asset}"),
            "checksums_url": format!("{base}/checksums.txt"),
            "asset_name": asset,
            "version": version,
        })
    };
    for key in ["binary_url", "checksums_url"] {
        validate_url_host(urls[key].as_str().unwrap(), allowed_domains)?;
    }
    Ok(urls)
}

/// `"owner/repo"` — no path traversal, no userinfo, no metacharacters
/// (`versioning._REPO_RE`).
fn valid_repo(repo: &str) -> bool {
    let parts: Vec<&str> = repo.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        })
}

/// A tag like `v1.2.3` (`versioning._VERSION_RE`).
fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-'))
}

/// `versioning.validate_url_host` — every release URL host must be on the
/// allowlist (defense in depth; the worker enforces the same list).
pub fn validate_url_host(url: &str, allowed_domains: &[String]) -> Result<(), String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(format!(
            "release URL must be http or https: {}",
            py_repr(url)
        ));
    };
    if scheme != "https" && scheme != "http" {
        return Err(format!(
            "release URL must be http or https: {}",
            py_repr(url)
        ));
    }
    let host = rest.split('/').next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or("");
    let host = if let Some(inner) = host.strip_prefix('[') {
        inner.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    let host = host.to_ascii_lowercase();
    if !allowed_domains
        .iter()
        .any(|d| d.trim().to_ascii_lowercase() == host)
    {
        return Err(format!("release host {} not in allowlist", py_repr(&host)));
    }
    Ok(())
}

/// `versioning.validate_release_domain` — reject allowlist entries that are
/// unsafe (loopback, link-local, `.local`/`.internal`, ...). Used by the
/// settings routes when the allow-list is edited.
pub fn validate_release_domain(domain: &str) -> Result<(), String> {
    let host = domain.trim().to_ascii_lowercase();
    if host.is_empty() || host.contains('/') || host.contains(':') {
        return Err(format!("invalid release domain: {}", py_repr(domain)));
    }
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return Err(format!("release domain not allowed: {}", py_repr(domain)));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let (loopback, link_local, unspecified, multicast) = match ip {
            std::net::IpAddr::V4(ip) => (
                ip.is_loopback(),
                ip.is_link_local(),
                ip.is_unspecified(),
                ip.is_multicast(),
            ),
            std::net::IpAddr::V6(ip) => (
                ip.is_loopback(),
                ip.is_unicast_link_local(),
                ip.is_unspecified(),
                ip.is_multicast(),
            ),
        };
        if loopback || link_local || unspecified || multicast {
            return Err(format!(
                "release domain not allowed (loopback/link-local): {}",
                py_repr(domain)
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Task creation (app/services/tasks.py)
// ---------------------------------------------------------------------------

/// `tasks_service.ExecForbidden` / `TaskInputError` / `ActionError` /
/// `versioning.SSRFError`, as one error type. Each route maps it onto the
/// status code its Python handler raises.
#[derive(Debug)]
pub enum ExecError {
    /// `ActionError` — unknown action or invalid parameters.
    Action(String),
    /// `ExecForbidden` — execution is not permitted for this VM's state/mode.
    Forbidden(String),
    /// `TaskInputError` — oversized/empty command, uninitialized settings.
    Input(String),
    /// `SSRFError` — release URL host not in the allowlist.
    Ssrf(String),
    /// The fleet settings row is missing (`update` targets).
    Settings,
    /// Data-layer failure.
    Db(DbError),
}

impl From<DbError> for ExecError {
    fn from(err: DbError) -> Self {
        ExecError::Db(err)
    }
}

/// `tasks_service._require_active` — only approved VMs may run tasks.
fn require_active(vm: &VM) -> Result<(), ExecError> {
    if matches!(vm.state, VMState::Active | VMState::Offline) {
        Ok(())
    } else {
        Err(ExecError::Forbidden("VM is not approved/active".into()))
    }
}

/// Queue a named action (`tasks_service.create_action_task`).
///
/// A name outside the built-in catalog may be an admin-defined custom command,
/// gated on the VM's exec mode AND tags. `update_worker` is fulfilled as an
/// update task (SSRF-validated release URLs) rather than a shell command.
pub async fn create_action_task(
    state: &FleetState,
    vm: &VM,
    action_name: &str,
    params: &BTreeMap<String, String>,
    created_by: &str,
    idempotency_key: Option<&str>,
) -> Result<Task, ExecError> {
    require_active(vm)?;
    if let Some(task) = find_idempotent(state, vm.id, idempotency_key).await? {
        return Ok(task);
    }
    if action_spec(action_name).is_none() {
        return create_custom_action_task(state, vm, action_name, created_by, idempotency_key)
            .await;
    }
    let normalized = validate_action(action_name, params).map_err(ExecError::Action)?;
    if action_name == "update_worker" {
        let row = crate::models::setting::get_settings_row(&state.pool).await?;
        let Some(row) = row else {
            return Err(ExecError::Settings);
        };
        return create_update_task(
            state,
            vm,
            &row.target_worker_version,
            &row.target_release_repo,
            &row.allowed_release_domains_vec(),
            created_by,
        )
        .await;
    }
    let task = task::create_action_task(
        &state.pool,
        ActionTaskNew {
            vm_id: vm.id,
            action_name: action_name.to_owned(),
            params: serde_json::Value::Object(normalized),
            timeout_seconds: state.config.default_task_timeout_seconds as i64,
            created_by: created_by.to_owned(),
            idempotency_key: idempotency_key.map(str::to_owned),
        },
    )
    .await?;
    wake_queue(state, vm.id);
    Ok(task)
}

/// Fire the queue wake for `vm_id` once the creating transaction is committed
/// and the task is claimable (`tasks_service` registers it with
/// `notify_queue_on_commit`; the data layer commits inside each call).
fn wake_queue(state: &FleetState, vm_id: Uuid) {
    state.events.notify_queue_on_commit(&vm_id.to_string());
}

/// `_create_custom_action_task` — an admin-defined custom command, gated on the
/// VM's mode AND tags. The fixed-argv commands ship in the task payload; the
/// worker runs them in order without a shell.
async fn create_custom_action_task(
    state: &FleetState,
    vm: &VM,
    action_name: &str,
    created_by: &str,
    idempotency_key: Option<&str>,
) -> Result<Task, ExecError> {
    let action = crate::models::custom_action::get_by_name(&state.pool, action_name).await?;
    let Some(action) = action.filter(|a| a.enabled) else {
        return Err(ExecError::Action(format!(
            "unknown action: {}",
            py_repr(action_name)
        )));
    };
    if !matches!(vm.exec_mode, ExecMode::Custom | ExecMode::Unrestricted) {
        return Err(ExecError::Forbidden(format!(
            "VM must be in 'custom' mode to run {}",
            py_repr(action_name)
        )));
    }
    if !crate::models::custom_action::vm_allowed(&state.pool, action.id, vm.id).await? {
        return Err(ExecError::Forbidden(format!(
            "VM's tags are not permitted to run {}",
            py_repr(action_name)
        )));
    }
    let payload = serde_json::json!({
        "action": action_name,
        "commands": action.commands,
        "timeout": state.config.default_task_timeout_seconds,
    });
    let task = task::insert_idempotent(
        &state.pool,
        TaskNew {
            vm_id: vm.id,
            task_type: crate::models::enums::TaskType::Action,
            action_name: Some(action_name.to_owned()),
            payload,
            created_by: created_by.to_owned(),
            idempotency_key: idempotency_key.map(str::to_owned),
        },
    )
    .await?;
    wake_queue(state, vm.id);
    Ok(task)
}

/// `create_command_task` — a free-form command. Only allowed in `unrestricted`
/// mode; the command text is size-capped.
pub async fn create_command_task(
    state: &FleetState,
    vm: &VM,
    command: &str,
    timeout: Option<i64>,
    created_by: &str,
    idempotency_key: Option<&str>,
) -> Result<Task, ExecError> {
    require_active(vm)?;
    if vm.exec_mode != ExecMode::Unrestricted {
        return Err(ExecError::Forbidden(
            "VM is not in unrestricted mode".into(),
        ));
    }
    if command.is_empty() || command.len() > state.config.max_body_bytes {
        return Err(ExecError::Input("command is empty or too large".into()));
    }
    if let Some(task) = find_idempotent(state, vm.id, idempotency_key).await? {
        return Ok(task);
    }
    let task = task::create_command_task(
        &state.pool,
        CommandTaskNew {
            vm_id: vm.id,
            command: command.to_owned(),
            timeout_seconds: timeout.unwrap_or(state.config.default_task_timeout_seconds as i64),
            created_by: created_by.to_owned(),
            idempotency_key: idempotency_key.map(str::to_owned),
        },
    )
    .await?;
    wake_queue(state, vm.id);
    Ok(task)
}

/// `create_update_task` — a self-update carrying SSRF-validated release URLs.
pub async fn create_update_task(
    state: &FleetState,
    vm: &VM,
    target_version: &str,
    repo: &str,
    allowed_domains: &[String],
    created_by: &str,
) -> Result<Task, ExecError> {
    require_active(vm)?;
    let urls = build_release_urls(repo, target_version, vm.arch, allowed_domains)
        .map_err(ExecError::Ssrf)?;
    let task = task::create_update_task(
        &state.pool,
        UpdateTaskNew {
            vm_id: vm.id,
            target_version: target_version.to_owned(),
            urls,
            created_by: created_by.to_owned(),
        },
    )
    .await?;
    wake_queue(state, vm.id);
    Ok(task)
}

/// `create_uninstall_task` — tell the worker to remove itself (revocation).
pub async fn create_uninstall_task(
    state: &FleetState,
    vm: &VM,
    created_by: &str,
) -> Result<Task, ExecError> {
    require_active(vm)?;
    let created = task::create_uninstall_task(&state.pool, vm.id, created_by).await?;
    wake_queue(state, vm.id);
    Ok(created)
}

async fn find_idempotent(
    state: &FleetState,
    vm_id: Uuid,
    idempotency_key: Option<&str>,
) -> Result<Option<Task>, ExecError> {
    match idempotency_key {
        Some(key) => Ok(task::find_idempotent(&state.pool, vm_id, key).await?),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Waiting (services/tasks.wait_for_terminal, event-driven)
// ---------------------------------------------------------------------------

/// Block until `load`'s row is terminal or `timeout` elapses — the Python
/// `wait_for_terminal` loop with the DB re-read abstracted behind `load`, so it
/// is testable without a database. Returns the row as last observed, or `None`
/// when it never existed.
pub async fn wait_for_task_row<T, F, Fut>(
    events: &Arc<TaskEvents>,
    task_id: Uuid,
    timeout: Duration,
    load: F,
    is_terminal: impl Fn(&T) -> bool,
) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    events
        .wait_for_terminal_checked(&task_id.to_string(), timeout, load, is_terminal)
        .await
}

/// Wait for a task to reach a terminal state (or `timeout`), re-reading its row
/// on every completion wake.
pub async fn wait_for_task(state: &FleetState, task_id: Uuid, timeout: Duration) -> Option<Task> {
    wait_for_task_row(
        &state.events,
        task_id,
        timeout,
        || async { task::get_by_id(&state.pool, task_id).await.ok().flatten() },
        |task: &Task| task.status.is_terminal(),
    )
    .await
}

// ---------------------------------------------------------------------------
// Wire shapes (app/schemas/task.py)
// ---------------------------------------------------------------------------

/// `TaskOut` — the dashboard/MCP view of a task.
#[derive(Debug, Clone, Serialize)]
pub struct TaskOut {
    pub id: Uuid,
    pub vm_id: Uuid,
    #[serde(rename = "type")]
    pub task_type: crate::models::enums::TaskType,
    pub action_name: Option<String>,
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub error: Option<String>,
    #[serde(with = "ts")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "ts_opt")]
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<Task> for TaskOut {
    fn from(task: Task) -> Self {
        Self {
            id: task.id,
            vm_id: task.vm_id,
            task_type: task.task_type,
            action_name: task.action_name,
            status: task.status,
            exit_code: task.exit_code,
            stdout: task.stdout,
            stderr: task.stderr,
            error: task.error,
            created_at: task.created_at,
            finished_at: task.finished_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `/api/tasks` router (`app/api/routes/tasks.py`).
pub fn router(state: FleetState) -> Router {
    Router::new()
        .route("/api/tasks/{task_id}", get(get_task))
        .route("/api/tasks/{task_id}/wait", get(wait_task))
        .with_state(state)
}

/// Query for `GET /api/tasks/{id}/wait` (`timeout` defaults to 30s, capped at
/// 300s like `tasks.py:_WAIT_MAX_SECONDS`).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct WaitQuery {
    #[serde(default = "default_wait_timeout")]
    pub timeout: i64,
}

fn default_wait_timeout() -> i64 {
    30
}

/// Cap for a single `/wait` call (`tasks.py:_WAIT_MAX_SECONDS`).
pub const WAIT_MAX_SECONDS: i64 = 300;

async fn get_task(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: super::Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, super::peer_addr(peer));
    let principal = authenticate(&state, &headers, ip.as_deref()).await?;
    let Path(task_id) = path.map_err(map_path_rejection)?;

    let Some(task) = task::get_by_id(&state.pool, task_id)
        .await
        .map_err(db_err)?
    else {
        return Err(ApiError::not_found("task not found").into());
    };
    // IDOR guard: the caller must have access to the task's VM.
    if !principal_can_access_vm(&state.pool, &principal, task.vm_id)
        .await
        .map_err(db_err)?
    {
        return Err(ApiError::forbidden("access to this task denied").into());
    }
    Ok(Json(TaskOut::from(task)))
}

async fn wait_task(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: super::Peer,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    query: Result<Query<WaitQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, super::peer_addr(peer));
    let principal = authenticate(&state, &headers, ip.as_deref()).await?;
    let Path(task_id) = path.map_err(map_path_rejection)?;
    let Query(query) = query.map_err(map_path_rejection)?;
    if !(0..=WAIT_MAX_SECONDS).contains(&query.timeout) {
        return Err(ApiError::unprocessable_entity(format!(
            "timeout must be between 0 and {WAIT_MAX_SECONDS}"
        ))
        .into());
    }

    let Some(task) = task::get_by_id(&state.pool, task_id)
        .await
        .map_err(db_err)?
    else {
        return Err(ApiError::not_found("task not found").into());
    };
    if !principal_can_access_vm(&state.pool, &principal, task.vm_id)
        .await
        .map_err(db_err)?
    {
        return Err(ApiError::forbidden("access to this task denied").into());
    }

    // Long-poll: block until terminal or the timeout passes; the caller re-calls
    // to keep waiting. Returns the task's current state on timeout.
    let task = wait_for_task(&state, task_id, Duration::from_secs(query.timeout as u64))
        .await
        .ok_or_else(|| ApiError::not_found("task not found"))?;
    Ok(Json(TaskOut::from(task)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::enums::{TaskType, WorkerArch};
    use serde_json::json;

    fn params(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn validate_action_normalizes_known_actions() {
        assert!(validate_action("status", &params(&[])).unwrap().is_empty());
        assert_eq!(
            serde_json::Value::Object(
                validate_action("restart_service", &params(&[("service", "nginx")])).unwrap()
            ),
            json!({"service": "nginx"})
        );
    }

    #[test]
    fn validate_action_error_messages_match_python() {
        assert_eq!(
            validate_action("nope", &params(&[])).unwrap_err(),
            "unknown action: 'nope'"
        );
        assert_eq!(
            validate_action("status", &params(&[("extra", "x"), ("other", "y")])).unwrap_err(),
            "unknown parameter(s) for 'status': ['extra', 'other']"
        );
        assert_eq!(
            validate_action("restart_service", &params(&[])).unwrap_err(),
            "missing required parameter 'service' for 'restart_service'"
        );
        assert_eq!(
            validate_action(
                "restart_service",
                &params(&[("service", "nginx; rm -rf /")])
            )
            .unwrap_err(),
            "invalid value for parameter 'service'"
        );
        assert_eq!(
            validate_action("restart_service", &params(&[("service", "")])).unwrap_err(),
            "invalid value for parameter 'service'"
        );
    }

    #[test]
    fn safe_name_rejects_shell_metacharacters() {
        assert!(safe_name("nginx"));
        assert!(safe_name("systemd-resolved.service"));
        assert!(safe_name("user@100.service"));
        assert!(!safe_name("-leading"));
        assert!(!safe_name("has space"));
        assert!(!safe_name("has;semicolon"));
        assert!(!safe_name(""));
        assert!(!safe_name(&"x".repeat(129)));
    }

    #[test]
    fn release_urls_match_python_shapes() {
        let domains = vec![
            "github.com".to_string(),
            "objects.githubusercontent.com".to_string(),
        ];
        let urls =
            build_release_urls("Sunderrrr/Huginn", "v1.2.3", WorkerArch::Amd64, &domains).unwrap();
        assert_eq!(
            urls,
            json!({
                "binary_url": "https://github.com/Sunderrrr/Huginn/releases/download/v1.2.3/huginn-worker-linux-amd64",
                "checksums_url": "https://github.com/Sunderrrr/Huginn/releases/download/v1.2.3/checksums.txt",
                "asset_name": "huginn-worker-linux-amd64",
                "version": "v1.2.3",
            })
        );

        let self_hosted = build_release_urls(
            "https://hub.example.com/dist",
            "v1.2.3",
            WorkerArch::Arm64,
            &["hub.example.com".into()],
        )
        .unwrap();
        assert_eq!(
            self_hosted["binary_url"],
            "https://hub.example.com/dist/huginn-worker-linux-arm64"
        );
        assert_eq!(self_hosted["version"], "v1.2.3");
    }

    #[test]
    fn release_urls_are_ssrf_gated() {
        let domains = vec!["github.com".to_string()];
        assert_eq!(
            build_release_urls("Sunderrrr/Huginn", "v1;rm -rf", WorkerArch::Amd64, &domains)
                .unwrap_err(),
            "invalid version: 'v1;rm -rf'"
        );
        assert_eq!(
            build_release_urls("../etc/passwd", "v1", WorkerArch::Amd64, &domains).unwrap_err(),
            "invalid repo: '../etc/passwd'"
        );
        assert_eq!(
            build_release_urls(
                "https://evil.example.com/dist",
                "v1",
                WorkerArch::Amd64,
                &domains
            )
            .unwrap_err(),
            "release host 'evil.example.com' not in allowlist"
        );
        assert!(
            build_release_urls("Sunderrrr/Huginn", "v1", WorkerArch::Amd64, &[]).is_err(),
            "an empty allowlist rejects everything"
        );
    }

    #[test]
    fn release_domain_validation_rejects_metadata_endpoints() {
        assert!(validate_release_domain("github.com").is_ok());
        assert!(
            validate_release_domain("172.16.0.2").is_ok(),
            "LAN is allowed"
        );
        assert!(validate_release_domain("localhost").is_err());
        assert!(validate_release_domain("metadata.google.internal").is_err());
        assert!(validate_release_domain("127.0.0.1").is_err());
        assert!(validate_release_domain("169.254.169.254").is_err());
        assert!(validate_release_domain("0.0.0.0").is_err());
        assert!(validate_release_domain("hub/foo").is_err());
    }

    // ---- event-driven wait (no database) ----------------------------------

    fn sample_task(status: TaskStatus) -> Task {
        Task {
            id: Uuid::new_v4(),
            vm_id: Uuid::new_v4(),
            task_type: TaskType::Action,
            action_name: Some("status".into()),
            payload: json!({"action": "status", "params": {}, "timeout": 60}),
            status,
            stdout: None,
            stderr: None,
            exit_code: None,
            error: None,
            retries: 0,
            created_by: "admin".into(),
            idempotency_key: None,
            dispatched_at: None,
            started_at: None,
            finished_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn wait_for_task_times_out_and_returns_the_last_state() {
        let events = TaskEvents::new();
        let row = Arc::new(std::sync::Mutex::new(Some(sample_task(
            TaskStatus::Pending,
        ))));
        let started = std::time::Instant::now();
        let task = wait_for_task_row(
            &events,
            Uuid::nil(),
            Duration::from_millis(50),
            {
                let row = Arc::clone(&row);
                move || {
                    let row = Arc::clone(&row);
                    async move { row.lock().unwrap().clone() }
                }
            },
            |task: &Task| task.status.is_terminal(),
        )
        .await
        .unwrap();
        assert_eq!(task.status, TaskStatus::Pending, "still pending at timeout");
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "parks the full wait"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn wait_for_task_returns_immediately_for_a_terminal_task() {
        let events = TaskEvents::new();
        let row = Arc::new(std::sync::Mutex::new(Some(sample_task(
            TaskStatus::Succeeded,
        ))));
        let task = wait_for_task_row(
            &events,
            Uuid::nil(),
            Duration::from_secs(5),
            {
                let row = Arc::clone(&row);
                move || {
                    let row = Arc::clone(&row);
                    async move { row.lock().unwrap().clone() }
                }
            },
            |task: &Task| task.status.is_terminal(),
        )
        .await
        .unwrap();
        assert_eq!(task.status, TaskStatus::Succeeded);
    }

    #[tokio::test]
    async fn wait_for_task_wakes_on_the_completion_notify() {
        let events = TaskEvents::new();
        let row = Arc::new(std::sync::Mutex::new(Some(sample_task(
            TaskStatus::Running,
        ))));
        let driver = {
            let events = Arc::clone(&events);
            let row = Arc::clone(&row);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                row.lock().unwrap().as_mut().unwrap().status = TaskStatus::Succeeded;
                events.notify(&Uuid::nil().to_string());
            })
        };
        let started = std::time::Instant::now();
        let task = wait_for_task_row(
            &events,
            Uuid::nil(),
            Duration::from_secs(5),
            {
                let row = Arc::clone(&row);
                move || {
                    let row = Arc::clone(&row);
                    async move { row.lock().unwrap().clone() }
                }
            },
            |task: &Task| task.status.is_terminal(),
        )
        .await
        .unwrap();
        driver.await.unwrap();
        assert_eq!(task.status, TaskStatus::Succeeded);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "woken by the notify, not by the timeout"
        );
    }

    #[tokio::test]
    async fn wait_for_task_returns_none_for_a_missing_task() {
        let events = TaskEvents::new();
        let missing = wait_for_task_row(
            &events,
            Uuid::nil(),
            Duration::from_millis(50),
            || async { None::<Task> },
            |task: &Task| task.status.is_terminal(),
        )
        .await;
        assert!(missing.is_none());
    }

    // ---- exec-mode gating (no database: refusals happen before the queue) ---

    fn test_state() -> FleetState {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        FleetState::new(pool, crate::config::Config::default())
    }

    fn vm_with(state: VMState, mode: ExecMode) -> VM {
        VM {
            id: Uuid::new_v4(),
            name: "worker-1".into(),
            hostname: None,
            ip_address: None,
            arch: WorkerArch::Amd64,
            os_info: json!({}),
            state,
            exec_mode: mode,
            worker_version: None,
            worker_secret_hash: None,
            enrollment_token_id: None,
            approved_by: None,
            last_heartbeat_at: None,
            enrolled_at: None,
            approved_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn free_commands_are_refused_outside_unrestricted_mode() {
        let state = test_state();
        for mode in [ExecMode::Whitelist, ExecMode::Custom] {
            let vm = vm_with(VMState::Active, mode);
            let err = create_command_task(&state, &vm, "ls -la", None, "admin", None)
                .await
                .unwrap_err();
            match err {
                ExecError::Forbidden(detail) => {
                    assert_eq!(detail, "VM is not in unrestricted mode")
                }
                other => panic!("expected the mode refusal, got {other:?}"),
            }
        }

        // The gate opens in unrestricted mode: the request reaches the queue
        // (which the lazy pool cannot service — that is the DB's job).
        let vm = vm_with(VMState::Active, ExecMode::Unrestricted);
        let err = create_command_task(&state, &vm, "ls -la", None, "admin", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ExecError::Db(_)),
            "past the gate the queue is reached: {err:?}"
        );
    }

    #[tokio::test]
    async fn unapproved_vms_may_not_run_anything() {
        let state = test_state();
        for state_kind in [VMState::Pending, VMState::Revoked] {
            let vm = vm_with(state_kind, ExecMode::Unrestricted);
            let err = create_command_task(&state, &vm, "ls", None, "admin", None)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, ExecError::Forbidden(m) if m == "VM is not approved/active"),
                "{err:?}"
            );
            let err = create_action_task(&state, &vm, "status", &params(&[]), "admin", None)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, ExecError::Forbidden(m) if m == "VM is not approved/active"),
                "{err:?}"
            );
        }
    }

    #[tokio::test]
    async fn command_input_is_capped() {
        let state = test_state();
        let vm = vm_with(VMState::Active, ExecMode::Unrestricted);

        let err = create_command_task(&state, &vm, "", None, "admin", None)
            .await
            .unwrap_err();
        assert!(matches!(&err, ExecError::Input(m) if m == "command is empty or too large"));

        let oversized = "x".repeat(state.config.max_body_bytes + 1);
        let err = create_command_task(&state, &vm, &oversized, None, "admin", None)
            .await
            .unwrap_err();
        assert!(matches!(&err, ExecError::Input(m) if m == "command is empty or too large"));
    }

    // ---- wire shapes ------------------------------------------------------

    #[test]
    fn task_out_matches_the_python_schema() {
        let mut task = sample_task(TaskStatus::Failed);
        task.exit_code = Some(3);
        task.stdout = Some("out".into());
        task.stderr = Some("err".into());
        task.error = Some("boom".into());
        task.finished_at = Some(task.created_at);
        let out = serde_json::to_value(TaskOut::from(task)).unwrap();
        assert_eq!(out["type"], "action");
        assert_eq!(out["status"], "failed");
        assert_eq!(out["exit_code"], 3);
        assert_eq!(out["action_name"], "status");
        assert!(out.get("payload").is_none(), "the payload is never exposed");
        assert!(out.get("created_by").is_none());
        assert_eq!(out["created_at"], out["finished_at"]);
    }
}

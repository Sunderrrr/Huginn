//! Task creation (`app/services/tasks.py`): exec-mode gating, idempotency and
//! the per-type task constructors.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::db::DbError;
use crate::models::enums::{ExecMode, VMState};
use crate::models::task::{
    self, ActionTaskNew, BrowserTaskNew, CommandTaskNew, Task, TaskNew, UpdateTaskNew,
    MAX_BROWSER_PAYLOAD_BYTES,
};
use crate::models::vm::VM;

use super::super::{py_repr, FleetState};
use super::actions::{action_spec, validate_action};
use super::release_urls::build_release_urls;

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

/// `create_browser_task` — queue an Obscura/CDP automation run. Steps are
/// validated by the model layer (non-empty array, ≤ 50 steps, non-empty
/// `action` per step, http(s)-only `navigate` URLs) and the serialized
/// payload is capped; the worker re-validates every field before executing.
/// Linux workers execute the steps; any other OS answers "browser not
/// supported on this OS".
pub async fn create_browser_task(
    state: &FleetState,
    vm: &VM,
    steps: &serde_json::Value,
    timeout_seconds: i64,
    created_by: &str,
    idempotency_key: Option<&str>,
) -> Result<(Task, usize), ExecError> {
    require_active(vm)?;
    // The per-VM capability gate (migrations/0005): browser automation is
    // off until an admin enables it on the VM — the browser equivalent of
    // the exec-mode gate (an admin flips it, audited; operators then use
    // it; readonly never passes the route's RBAC).
    if !vm.browser_enabled {
        return Err(ExecError::Forbidden(
            "browser automation is disabled on this VM; an admin must enable it \
             (PUT /api/vms/{vm_id}/browser-enabled)"
                .into(),
        ));
    }
    let step_count = task::validate_browser_steps(steps).map_err(ExecError::Input)?;
    if serde_json::json!({ "steps": steps, "timeout": timeout_seconds })
        .to_string()
        .len()
        > MAX_BROWSER_PAYLOAD_BYTES
    {
        return Err(ExecError::Input(format!(
            "browser task payload exceeds {MAX_BROWSER_PAYLOAD_BYTES} bytes"
        )));
    }
    if let Some(task) = find_idempotent(state, vm.id, idempotency_key).await? {
        return Ok((task, step_count));
    }
    let task = task::create_browser_task(
        &state.pool,
        BrowserTaskNew {
            vm_id: vm.id,
            steps: steps.clone(),
            timeout_seconds,
            created_by: created_by.to_owned(),
            idempotency_key: idempotency_key.map(str::to_owned),
        },
    )
    .await?;
    wake_queue(state, vm.id);
    Ok((task, step_count))
}

/// `create_browser_install_task` — queue the engine install. The pinned
/// release coordinates (version + per-arch SHA-256) come from the fleet
/// settings row; the worker re-validates them and verifies the download
/// against the SHA-256 before installing. Returns the task plus the pinned
/// version (for the audit entry). Linux workers install the engine; any
/// other OS answers "browser not supported on this OS".
pub async fn create_browser_install_task(
    state: &FleetState,
    vm: &VM,
    created_by: &str,
) -> Result<(Task, String), ExecError> {
    require_active(vm)?;
    // Ensure the engine pin exists: when no version is pinned (auto mode)
    // or auto-update is on, fetch the latest release from GitHub first so
    // the worker always installs a verified (version + SHA-256) build.
    let settings = crate::models::setting::get_settings_row(&state.pool)
        .await?
        .ok_or(ExecError::Settings)?;
    if settings.browser_engine_version.is_empty() {
        crate::services::browser_engine::check_for_update(&state.pool)
            .await
            .map_err(|e| {
                ExecError::Input(format!("could not resolve the browser engine version: {e}"))
            })?;
    }
    let settings = crate::models::setting::get_settings_row(&state.pool)
        .await?
        .ok_or(ExecError::Settings)?;
    let task = task::create_browser_install_task(
        &state.pool,
        task::BrowserInstallTaskNew {
            vm_id: vm.id,
            version: settings.browser_engine_version.clone(),
            sha256: serde_json::json!({
                "amd64": settings.browser_engine_sha256_amd64,
                "arm64": settings.browser_engine_sha256_arm64,
            }),
            created_by: created_by.to_owned(),
        },
    )
    .await?;
    wake_queue(state, vm.id);
    Ok((task, settings.browser_engine_version))
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
    let urls = build_release_urls(
        repo,
        target_version,
        vm.arch,
        crate::services::versioning::WorkerOs::from_vm(vm),
        allowed_domains,
    )
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

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::*;
    use serde_json::json;

    use crate::models::enums::WorkerArch;

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
            browser_enabled: false,
            browser_engine_version: None,
            browser_engine_reported_at: None,
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
}

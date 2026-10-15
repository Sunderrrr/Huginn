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

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::enums::TaskStatus;
use crate::models::task::{self, Task};
use crate::services::task_events::TaskEvents;

use super::{
    authenticate, client_ip, db_err, map_path_rejection, principal_can_access_vm, ts, ts_opt,
    FleetState, RouteError,
};

// ---------------------------------------------------------------------------
// Submodules — task protocol split by function
// ---------------------------------------------------------------------------

/// Shared test fixtures.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::BTreeMap;

    pub(crate) fn params(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
}

mod actions;
mod create;
mod release_urls;

pub use create::{
    create_action_task, create_command_task, create_uninstall_task, create_update_task, ExecError,
};

/// Whether `name` is one of the built-in whitelisted actions (`actions.py`'s
/// catalog). Used by the scheduler to tell a built-in action from an
/// admin-defined custom command (which carries its own exec-mode gate).
pub(crate) use actions::action_spec;

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
    use crate::services::task_events::TaskEvents;
    use serde_json::json;

    use crate::models::enums::TaskType;

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

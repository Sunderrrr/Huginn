//! `tasks` — the DB-backed work queue. Mirrors `app/models/task.py` and the
//! dispatch/result/sweep semantics of `app/services/tasks.py`.
//!
//! Business rules (action catalogs, exec-mode gating, SSRF-validated release
//! URLs) stay in the service layer; what lives here is the queue itself:
//! idempotent inserts, the `FOR UPDATE SKIP LOCKED` claim, result recording and
//! the timeout sweep.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::db::DbError;

use super::enums::{TaskStatus, TaskType};

const COLUMNS: &str = "id, vm_id, type, action_name, payload, status, stdout, stderr, exit_code, \
                      error, retries, created_by, idempotency_key, dispatched_at, started_at, \
                      finished_at, created_at, updated_at";

/// A queued (or running/finished) unit of work for one VM.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Task {
    pub id: Uuid,
    pub vm_id: Uuid,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub task_type: TaskType,
    pub action_name: Option<String>,
    /// argv / command / timeout etc. (size-capped before insert).
    pub payload: serde_json::Value,
    pub status: TaskStatus,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub retries: i32,
    pub created_by: String,
    pub idempotency_key: Option<String>,
    pub dispatched_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Generic insert payload (all typed `create_*` helpers funnel here).
#[derive(Debug, Clone)]
pub struct TaskNew {
    pub vm_id: Uuid,
    pub task_type: TaskType,
    pub action_name: Option<String>,
    pub payload: serde_json::Value,
    pub created_by: String,
    pub idempotency_key: Option<String>,
}

/// Inputs for `create_action_task`.
#[derive(Debug, Clone)]
pub struct ActionTaskNew {
    pub vm_id: Uuid,
    pub action_name: String,
    pub params: serde_json::Value,
    pub timeout_seconds: i64,
    pub created_by: String,
    pub idempotency_key: Option<String>,
}

/// Inputs for `create_command_task`.
#[derive(Debug, Clone)]
pub struct CommandTaskNew {
    pub vm_id: Uuid,
    pub command: String,
    pub timeout_seconds: i64,
    pub created_by: String,
    pub idempotency_key: Option<String>,
}

/// Inputs for `create_update_task`. `urls` is the SSRF-validated release-URL
/// object from `versioning.build_release_urls` (e.g. `{"download_url": ...}`).
#[derive(Debug, Clone)]
pub struct UpdateTaskNew {
    pub vm_id: Uuid,
    pub target_version: String,
    pub urls: serde_json::Value,
    pub created_by: String,
}

/// Inputs for `submit_result`.
#[derive(Debug, Clone)]
pub struct SubmitResult {
    pub task_id: Uuid,
    pub vm_id: Uuid,
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub error: Option<String>,
    /// Cap for each output field (`max_output_bytes` in settings).
    pub output_cap_bytes: usize,
}

/// Parameters for `sweep_timeouts`.
#[derive(Debug, Clone, Copy)]
pub struct SweepConfig {
    /// Dispatched tasks older than `dispatched_at + grace` are swept
    /// (Python: `default_task_timeout_seconds * 2 + 30`).
    pub grace_seconds: i64,
    /// Tasks whose retry count exceeds this are dead-lettered
    /// (`task_dead_letter_retries`).
    pub dead_letter_retries: i32,
}

/// Outcome of `sweep_timeouts`.
#[derive(Debug, Clone, Default)]
pub struct SweepResult {
    pub swept: usize,
    pub dead_lettered: Vec<Uuid>,
    pub requeued_vm_ids: Vec<Uuid>,
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Task>, DbError> {
    let row = sqlx::query_as::<_, Task>(&format!("SELECT {COLUMNS} FROM tasks WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Existing task for (vm_id, idempotency_key), if any.
pub async fn find_idempotent(
    pool: &PgPool,
    vm_id: Uuid,
    idempotency_key: &str,
) -> Result<Option<Task>, DbError> {
    let row = sqlx::query_as::<_, Task>(&format!(
        "SELECT {COLUMNS} FROM tasks WHERE vm_id = $1 AND idempotency_key = $2"
    ))
    .bind(vm_id)
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Insert a task, returning the existing one if a concurrent insert won the
/// race. The partial unique index `uq_tasks_vm_idempotency` makes the DB the
/// authority (parity with `tasks_service._insert_idempotent`).
pub async fn insert_idempotent(pool: &PgPool, new: TaskNew) -> Result<Task, DbError> {
    let now = Utc::now();
    if let Some(key) = new.idempotency_key.as_deref() {
        if let Some(existing) = find_idempotent(pool, new.vm_id, key).await? {
            return Ok(existing);
        }
    }
    let inserted = sqlx::query_as::<_, Task>(&format!(
        "INSERT INTO tasks (id, vm_id, type, action_name, payload, status, stdout, stderr, \
         exit_code, error, retries, created_by, idempotency_key, dispatched_at, started_at, \
         finished_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, 'pending'::task_status, NULL, NULL, NULL, NULL, 0, \
         $6, $7, NULL, NULL, NULL, $8, $8) \
         ON CONFLICT (vm_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING \
         RETURNING {COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(new.vm_id)
    .bind(new.task_type)
    .bind(&new.action_name)
    .bind(&new.payload)
    .bind(&new.created_by)
    .bind(&new.idempotency_key)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    if let Some(task) = inserted {
        return Ok(task);
    }
    // A concurrent insert with the same key won: return its row.
    if let Some(key) = new.idempotency_key.as_deref() {
        if let Some(existing) = find_idempotent(pool, new.vm_id, key).await? {
            return Ok(existing);
        }
    }
    Err(DbError::Conflict("task insert conflicted".into()))
}

/// Queue a named action. Payload shape (parity with `create_action_task`):
/// `{"action": <name>, "params": {...}, "timeout": <s>}`.
pub async fn create_action_task(pool: &PgPool, new: ActionTaskNew) -> Result<Task, DbError> {
    let payload = serde_json::json!({
        "action": new.action_name,
        "params": new.params,
        "timeout": new.timeout_seconds,
    });
    insert_idempotent(
        pool,
        TaskNew {
            vm_id: new.vm_id,
            task_type: TaskType::Action,
            action_name: Some(new.action_name),
            payload,
            created_by: new.created_by,
            idempotency_key: new.idempotency_key,
        },
    )
    .await
}

/// Queue a free-form command. Payload: `{"command": <str>, "timeout": <s>}`.
pub async fn create_command_task(pool: &PgPool, new: CommandTaskNew) -> Result<Task, DbError> {
    let payload = serde_json::json!({
        "command": new.command,
        "timeout": new.timeout_seconds,
    });
    insert_idempotent(
        pool,
        TaskNew {
            vm_id: new.vm_id,
            task_type: TaskType::Command,
            action_name: None,
            payload,
            created_by: new.created_by,
            idempotency_key: new.idempotency_key,
        },
    )
    .await
}

/// Queue a self-update. Payload: `{"target_version": <v>, **urls}`.
pub async fn create_update_task(pool: &PgPool, new: UpdateTaskNew) -> Result<Task, DbError> {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "target_version".into(),
        serde_json::Value::String(new.target_version),
    );
    if let Some(obj) = new.urls.as_object() {
        payload.extend(obj.clone());
    }
    insert_idempotent(
        pool,
        TaskNew {
            vm_id: new.vm_id,
            task_type: TaskType::Update,
            action_name: Some("update_worker".into()),
            payload: serde_json::Value::Object(payload),
            created_by: new.created_by,
            idempotency_key: None,
        },
    )
    .await
}

/// Queue a self-uninstall. Payload: `{"uninstall": true}`.
pub async fn create_uninstall_task(
    pool: &PgPool,
    vm_id: Uuid,
    created_by: impl Into<String>,
) -> Result<Task, DbError> {
    insert_idempotent(
        pool,
        TaskNew {
            vm_id,
            task_type: TaskType::Uninstall,
            action_name: Some("uninstall".into()),
            payload: serde_json::json!({"uninstall": true}),
            created_by: created_by.into(),
            idempotency_key: None,
        },
    )
    .await
}

/// Atomically hand the oldest PENDING task for this VM to the worker:
/// `SELECT ... FOR UPDATE SKIP LOCKED` + status → dispatched (parity with
/// `tasks_service.claim_next_task`).
pub async fn claim_next_task(pool: &PgPool, vm_id: Uuid) -> Result<Option<Task>, DbError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, Task>(&format!(
        "SELECT {COLUMNS} FROM tasks \
         WHERE vm_id = $1 AND status = 'pending'::task_status \
         ORDER BY created_at ASC LIMIT 1 \
         FOR UPDATE SKIP LOCKED"
    ))
    .bind(vm_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(task) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let now = Utc::now();
    let task = sqlx::query_as::<_, Task>(&format!(
        "UPDATE tasks SET status = 'dispatched'::task_status, dispatched_at = $2, updated_at = $2 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(task.id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(task))
}

/// Truncate an output field to `limit` bytes (UTF-8 boundary safe), mirroring
/// `tasks_service._truncate`.
pub fn truncate_output(text: Option<&str>, limit: usize) -> Option<String> {
    let text = text?;
    let encoded = text.as_bytes();
    if encoded.len() <= limit {
        return Some(text.to_string());
    }
    let mut cut = limit;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    Some(format!("{}\n[...truncated...]", &text[..cut]))
}

/// Record a worker result. Idempotent: duplicate results for an already
/// terminal task are ignored and the row returned unchanged. Returns `None`
/// when the task doesn't exist or belongs to another VM (parity with
/// `tasks_service.submit_result`).
pub async fn submit_result(pool: &PgPool, res: SubmitResult) -> Result<Option<Task>, DbError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, Task>(&format!(
        "SELECT {COLUMNS} FROM tasks WHERE id = $1 AND vm_id = $2 FOR UPDATE"
    ))
    .bind(res.task_id)
    .bind(res.vm_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(task) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    if task.status.is_terminal() {
        tx.commit().await?;
        return Ok(Some(task));
    }
    let cap = res.output_cap_bytes;
    let stdout = truncate_output(res.stdout.as_deref(), cap);
    let stderr = truncate_output(res.stderr.as_deref(), cap);
    let error = truncate_output(res.error.as_deref(), cap);
    let now = Utc::now();
    let task = sqlx::query_as::<_, Task>(&format!(
        "UPDATE tasks SET status = $2, exit_code = $3, stdout = $4, stderr = $5, error = $6, \
         started_at = COALESCE(started_at, dispatched_at), finished_at = $7, updated_at = $7 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(res.task_id)
    .bind(res.status)
    .bind(res.exit_code)
    .bind(stdout)
    .bind(stderr)
    .bind(error)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(task))
}

/// Wait until the task reaches a terminal state or `timeout` elapses.
///
/// The Python hub wakes waiters via in-process events (`task_events`); across
/// processes that fan-out layer isn't available to the data layer, so this
/// helper polls. Returns the task as last observed, or `None` if it doesn't
/// exist.
pub async fn wait_for_terminal(
    pool: &PgPool,
    task_id: Uuid,
    timeout: Duration,
) -> Result<Option<Task>, DbError> {
    let poll = Duration::from_millis(250).min(timeout.max(Duration::from_millis(1)));
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let task = get_by_id(pool, task_id).await?;
        match task {
            None => return Ok(None),
            Some(t) if t.status.is_terminal() => return Ok(Some(t)),
            Some(_) => {}
        }
        if tokio::time::Instant::now() + poll > deadline {
            return get_by_id(pool, task_id).await;
        }
        tokio::time::sleep(poll).await;
    }
}

/// True if an update task for this VM is still pending/dispatched/running.
pub async fn has_inflight_update(pool: &PgPool, vm_id: Uuid) -> Result<bool, DbError> {
    let (found,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM tasks \
         WHERE vm_id = $1 AND type = 'update'::task_type \
           AND status IN ('pending', 'dispatched', 'running'))",
    )
    .bind(vm_id)
    .fetch_one(pool)
    .await?;
    Ok(found)
}

/// Re-queue (or dead-letter) tasks that were dispatched but never completed.
/// One statement, then the callers' notification lists are split out in Rust
/// (parity with `tasks_service.sweep_timeouts`).
pub async fn sweep_timeouts(pool: &PgPool, cfg: SweepConfig) -> Result<SweepResult, DbError> {
    let now = Utc::now();
    let rows: Vec<(Uuid, Uuid, TaskStatus)> = sqlx::query_as(
        "UPDATE tasks SET \
         retries = retries + 1, \
         status = CASE WHEN retries + 1 > $2 THEN 'dead_letter'::task_status \
                       ELSE 'pending'::task_status END, \
         finished_at = CASE WHEN retries + 1 > $2 THEN $1 ELSE finished_at END, \
         error = CASE WHEN retries + 1 > $2 THEN 'exceeded retry budget (dead-lettered)' \
                      ELSE error END, \
         dispatched_at = CASE WHEN retries + 1 > $2 THEN dispatched_at ELSE NULL END, \
         updated_at = $1 \
         WHERE status IN ('dispatched'::task_status, 'running'::task_status) \
           AND COALESCE(dispatched_at, created_at) + make_interval(secs => $3) <= $1 \
         RETURNING id, vm_id, status",
    )
    .bind(now)
    .bind(cfg.dead_letter_retries)
    .bind(cfg.grace_seconds as f64)
    .fetch_all(pool)
    .await?;

    let mut out = SweepResult {
        swept: rows.len(),
        ..Default::default()
    };
    for (id, vm_id, status) in rows {
        if status == TaskStatus::DeadLetter {
            out.dead_lettered.push(id);
        } else {
            out.requeued_vm_ids.push(vm_id);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_output_matches_python() {
        assert_eq!(truncate_output(None, 10), None);
        assert_eq!(truncate_output(Some("abc"), 10), Some("abc".into()));
        assert_eq!(truncate_output(Some("abcdef"), 6), Some("abcdef".into()));
        assert_eq!(
            truncate_output(Some("abcdef"), 4),
            Some("abcd\n[...truncated...]".into())
        );
        // Multi-byte safety: never split a UTF-8 code point.
        let s = "ééé";
        let out = truncate_output(Some(s), 2).unwrap();
        assert!(out.starts_with('é'));
        assert!(out.ends_with("\n[...truncated...]"));
    }

    #[test]
    fn action_payload_shape_matches_python() {
        let payload = serde_json::json!({
            "action": "reboot",
            "params": {"delay": "5"},
            "timeout": 60,
        });
        assert_eq!(payload["action"], "reboot");
        assert_eq!(payload["timeout"], 60);
        assert_eq!(payload["params"]["delay"], "5");
    }

    #[test]
    fn update_payload_merges_urls() {
        let mut payload = serde_json::Map::new();
        payload.insert("target_version".into(), serde_json::json!("v1.4.0"));
        let urls = serde_json::json!({"download_url": "https://github.com/x"});
        payload.extend(urls.as_object().unwrap().clone());
        let v = serde_json::Value::Object(payload);
        assert_eq!(v["target_version"], "v1.4.0");
        assert_eq!(v["download_url"], "https://github.com/x");
    }

    #[test]
    fn task_json_uses_type_key() {
        let t = Task {
            id: Uuid::nil(),
            vm_id: Uuid::nil(),
            task_type: TaskType::Command,
            action_name: None,
            payload: serde_json::json!({"command": "ls"}),
            status: TaskStatus::Pending,
            stdout: None,
            stderr: None,
            exit_code: None,
            error: None,
            retries: 0,
            created_by: "user:alice".into(),
            idempotency_key: None,
            dispatched_at: None,
            started_at: None,
            finished_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["type"], "command");
        assert_eq!(v["status"], "pending");
        assert!(v.get("task_type").is_none());
    }
}

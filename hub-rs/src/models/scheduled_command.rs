//! `scheduled_commands` — recurring actions/commands the hub auto-queues
//! (`app/models/scheduled_command.py`, `app/services/scheduled_commands.py`).
//!
//! Cron evaluation (croniter) and task creation live in the service layer;
//! this module stores the schedules and records run markers.
//!
//! `target_kind`: "vm" | "tag" | "all_active"
//! `task_kind`:   "action" | "command"
//! Stored as plain strings (validated in the schema) — no extra DB enum types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

const COLUMNS: &str = "id, name, enabled, target_kind, target_vm_id, target_tag_id, task_kind, \
                      action_name, params, command, cron_expression, last_run_at, created_by, \
                      created_at, updated_at";

/// A recurring action/command definition.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScheduledCommand {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub target_kind: String,
    pub target_vm_id: Option<Uuid>,
    pub target_tag_id: Option<Uuid>,
    pub task_kind: String,
    pub action_name: Option<String>,
    pub params: serde_json::Value,
    pub command: Option<String>,
    pub cron_expression: String,
    pub last_run_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert payload; `id`/timestamps assigned by `create`.
#[derive(Debug, Clone)]
pub struct ScheduledCommandNew {
    pub name: String,
    pub enabled: bool,
    pub target_kind: String,
    pub target_vm_id: Option<Uuid>,
    pub target_tag_id: Option<Uuid>,
    pub task_kind: String,
    pub action_name: Option<String>,
    pub params: serde_json::Value,
    pub command: Option<String>,
    pub cron_expression: String,
    pub created_by: Option<Uuid>,
}

/// Partial update: `None` leaves the field untouched. Passing `enabled` /
/// `command` / ... as `Some` overwrites; use `clear_last_run` to reset the run
/// marker.
#[derive(Debug, Clone, Default)]
pub struct ScheduledCommandPatch {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub target_kind: Option<String>,
    pub target_vm_id: Option<Uuid>,
    pub target_tag_id: Option<Uuid>,
    pub task_kind: Option<String>,
    pub action_name: Option<String>,
    pub params: Option<serde_json::Value>,
    pub command: Option<String>,
    pub cron_expression: Option<String>,
}

/// All schedules, newest first (parity with `list_schedules`).
pub async fn list_schedules(pool: &PgPool) -> Result<Vec<ScheduledCommand>, DbError> {
    let rows = sqlx::query_as::<_, ScheduledCommand>(&format!(
        "SELECT {COLUMNS} FROM scheduled_commands ORDER BY created_at DESC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Enabled schedules (the sweeper's working set).
pub async fn list_enabled(pool: &PgPool) -> Result<Vec<ScheduledCommand>, DbError> {
    let rows = sqlx::query_as::<_, ScheduledCommand>(&format!(
        "SELECT {COLUMNS} FROM scheduled_commands WHERE enabled = true"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get(pool: &PgPool, schedule_id: Uuid) -> Result<Option<ScheduledCommand>, DbError> {
    let row = sqlx::query_as::<_, ScheduledCommand>(&format!(
        "SELECT {COLUMNS} FROM scheduled_commands WHERE id = $1"
    ))
    .bind(schedule_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn create(pool: &PgPool, new: ScheduledCommandNew) -> Result<ScheduledCommand, DbError> {
    let now = Utc::now();
    let row = sqlx::query_as::<_, ScheduledCommand>(&format!(
        "INSERT INTO scheduled_commands (id, name, enabled, target_kind, target_vm_id, \
         target_tag_id, task_kind, action_name, params, command, cron_expression, last_run_at, \
         created_by, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, $12, $13, $13) \
         RETURNING {COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(&new.name)
    .bind(new.enabled)
    .bind(&new.target_kind)
    .bind(new.target_vm_id)
    .bind(new.target_tag_id)
    .bind(&new.task_kind)
    .bind(&new.action_name)
    .bind(&new.params)
    .bind(&new.command)
    .bind(&new.cron_expression)
    .bind(new.created_by)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Partial update.
pub async fn update(
    pool: &PgPool,
    schedule_id: Uuid,
    patch: ScheduledCommandPatch,
) -> Result<Option<ScheduledCommand>, DbError> {
    let row = sqlx::query_as::<_, ScheduledCommand>(&format!(
        "UPDATE scheduled_commands SET \
         name = COALESCE($2, name), \
         enabled = COALESCE($3, enabled), \
         target_kind = COALESCE($4, target_kind), \
         target_vm_id = COALESCE($5, target_vm_id), \
         target_tag_id = COALESCE($6, target_tag_id), \
         task_kind = COALESCE($7, task_kind), \
         action_name = COALESCE($8, action_name), \
         params = COALESCE($9, params), \
         command = COALESCE($10, command), \
         cron_expression = COALESCE($11, cron_expression), \
         updated_at = $12 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(schedule_id)
    .bind(patch.name)
    .bind(patch.enabled)
    .bind(patch.target_kind)
    .bind(patch.target_vm_id)
    .bind(patch.target_tag_id)
    .bind(patch.task_kind)
    .bind(patch.action_name)
    .bind(patch.params)
    .bind(patch.command)
    .bind(patch.cron_expression)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record that the schedule just ran (drives `next_run_at`).
pub async fn set_last_run_at(
    pool: &PgPool,
    schedule_id: Uuid,
    at: DateTime<Utc>,
) -> Result<Option<ScheduledCommand>, DbError> {
    let row = sqlx::query_as::<_, ScheduledCommand>(&format!(
        "UPDATE scheduled_commands SET last_run_at = $2, updated_at = $2 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(schedule_id)
    .bind(at)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn delete(pool: &PgPool, schedule_id: Uuid) -> Result<bool, DbError> {
    let res = sqlx::query("DELETE FROM scheduled_commands WHERE id = $1")
        .bind(schedule_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() == 1)
}

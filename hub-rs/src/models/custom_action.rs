//! `custom_actions` + `custom_action_tags` — admin-defined commands run as
//! fixed argv vectors (never through a shell)
//! (`app/models/custom_action.py`, `app/services/custom_actions.py`).
//!
//! Line parsing/validating (`parse_command_lines`, shlex) stays in the service
//! layer; commands are persisted exactly as stored argv vectors.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

const COLUMNS: &str = "id, name, description, commands, enabled, created_by, created_at, \
                      updated_at";

/// An ordered list of fixed argv vectors (one per command line).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CustomAction {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// `list[list[str]]`: each inner list is one command's argv.
    pub commands: serde_json::Value,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CustomAction {
    /// Typed view of the stored argv vectors.
    pub fn command_argv(&self) -> Vec<Vec<String>> {
        self.commands
            .as_array()
            .map(|cmds| {
                cmds.iter()
                    .filter_map(|c| {
                        c.as_array().map(|argv| {
                            argv.iter()
                                .filter_map(|a| a.as_str().map(str::to_string))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Insert payload; `commands` are argv vectors, `tag_ids` the allowed VM tags.
#[derive(Debug, Clone)]
pub struct CustomActionNew {
    pub name: String,
    pub description: String,
    pub commands: Vec<Vec<String>>,
    pub created_by: Option<String>,
    pub tag_ids: Vec<Uuid>,
}

/// Partial update: `None` leaves the field untouched.
#[derive(Debug, Clone, Default)]
pub struct CustomActionPatch {
    pub description: Option<String>,
    pub commands: Option<Vec<Vec<String>>>,
    pub enabled: Option<bool>,
    pub tag_ids: Option<Vec<Uuid>>,
}

fn commands_json(commands: &[Vec<String>]) -> serde_json::Value {
    serde_json::Value::Array(
        commands
            .iter()
            .map(|argv| serde_json::to_value(argv).unwrap_or_default())
            .collect(),
    )
}

pub async fn list_all(pool: &PgPool) -> Result<Vec<CustomAction>, DbError> {
    let rows = sqlx::query_as::<_, CustomAction>(&format!(
        "SELECT {COLUMNS} FROM custom_actions ORDER BY name ASC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get(pool: &PgPool, action_id: Uuid) -> Result<Option<CustomAction>, DbError> {
    let row = sqlx::query_as::<_, CustomAction>(&format!(
        "SELECT {COLUMNS} FROM custom_actions WHERE id = $1"
    ))
    .bind(action_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn get_by_name(pool: &PgPool, name: &str) -> Result<Option<CustomAction>, DbError> {
    let row = sqlx::query_as::<_, CustomAction>(&format!(
        "SELECT {COLUMNS} FROM custom_actions WHERE name = $1"
    ))
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Allowed VM tag ids for an action (ordered).
pub async fn tag_ids_for(pool: &PgPool, action_id: Uuid) -> Result<Vec<Uuid>, DbError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT tag_id FROM custom_action_tags WHERE action_id = $1 ORDER BY tag_id",
    )
    .bind(action_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Replace the action's allowed tags (deduped, order preserved).
pub async fn set_tags(pool: &PgPool, action_id: Uuid, tag_ids: &[Uuid]) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;
    replace_tags(&mut tx, action_id, tag_ids).await?;
    tx.commit().await?;
    Ok(())
}

/// Create the action and its allowed tags atomically.
pub async fn create(pool: &PgPool, new: CustomActionNew) -> Result<CustomAction, DbError> {
    let now = Utc::now();
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, CustomAction>(&format!(
        "INSERT INTO custom_actions (id, name, description, commands, enabled, created_by, \
         created_at, updated_at) \
         VALUES ($1, $2, $3, $4::json, true, $5, $6, $6) RETURNING {COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(&new.name)
    .bind(&new.description)
    .bind(commands_json(&new.commands))
    .bind(&new.created_by)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    replace_tags(&mut tx, row.id, &new.tag_ids).await?;
    tx.commit().await?;
    Ok(row)
}

/// Wipe and re-insert the action's tag links (deduped, order preserved).
async fn replace_tags(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    action_id: Uuid,
    tag_ids: &[Uuid],
) -> Result<(), DbError> {
    sqlx::query("DELETE FROM custom_action_tags WHERE action_id = $1")
        .bind(action_id)
        .execute(&mut **tx)
        .await?;
    let mut seen = std::collections::HashSet::new();
    for tag_id in tag_ids {
        if seen.insert(*tag_id) {
            sqlx::query(
                "INSERT INTO custom_action_tags (action_id, tag_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(action_id)
            .bind(tag_id)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

/// Partial update (description / commands / enabled / allowed tags).
pub async fn update(
    pool: &PgPool,
    action_id: Uuid,
    patch: CustomActionPatch,
) -> Result<Option<CustomAction>, DbError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, CustomAction>(&format!(
        "UPDATE custom_actions SET \
         description = COALESCE($2, description), \
         commands = COALESCE($3::json, commands), \
         enabled = COALESCE($4, enabled), \
         updated_at = $5 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(action_id)
    .bind(patch.description)
    .bind(patch.commands.as_deref().map(commands_json))
    .bind(patch.enabled)
    .bind(Utc::now())
    .fetch_optional(&mut *tx)
    .await?;
    if row.is_none() {
        tx.commit().await?;
        return Ok(None);
    }
    if let Some(tag_ids) = patch.tag_ids.as_deref() {
        replace_tags(&mut tx, action_id, tag_ids).await?;
    }
    tx.commit().await?;
    Ok(row)
}

/// Delete an action (tag links cascade).
pub async fn remove(pool: &PgPool, action_id: Uuid) -> Result<bool, DbError> {
    let res = sqlx::query("DELETE FROM custom_actions WHERE id = $1")
        .bind(action_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() == 1)
}

/// True if the VM carries at least one of the action's allowed tags. An action
/// with no allowed tags runs nowhere (explicit-scope by design), mirroring
/// `custom_actions.vm_allowed`.
pub async fn vm_allowed(pool: &PgPool, action_id: Uuid, vm_id: Uuid) -> Result<bool, DbError> {
    let (allowed,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM custom_action_tags cat \
         JOIN vm_tags vt ON vt.tag_id = cat.tag_id \
         WHERE cat.action_id = $1 AND vt.vm_id = $2)",
    )
    .bind(action_id)
    .bind(vm_id)
    .fetch_one(pool)
    .await?;
    Ok(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_round_trip_as_argv_vectors() {
        let commands = vec![
            vec![
                "systemctl".to_string(),
                "restart".to_string(),
                "nginx".to_string(),
            ],
            vec!["echo".to_string(), "done".to_string()],
        ];
        let action = CustomAction {
            id: Uuid::nil(),
            name: "restart-nginx".into(),
            description: String::new(),
            commands: commands_json(&commands),
            enabled: true,
            created_by: Some("admin".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(action.command_argv(), commands);
        // JSON shape matches the FastAPI schema: list[list[str]]
        assert_eq!(
            action.commands,
            serde_json::json!([["systemctl", "restart", "nginx"], ["echo", "done"]])
        );
    }
}

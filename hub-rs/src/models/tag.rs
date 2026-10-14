//! `tags` + `vm_tags` — grouping labels for VMs
//! (`app/models/tag.py`, `app/services/tags.py`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::db::DbError;

const COLUMNS: &str = "id, name, color, created_at, updated_at";

/// A named, colored label admins assign to VMs.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tag {
    pub id: Uuid,
    pub name: String,
    /// Hex color like "#46d39a".
    pub color: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Partial update: `None` leaves the column untouched.
#[derive(Debug, Clone, Default)]
pub struct TagPatch {
    pub name: Option<String>,
    pub color: Option<String>,
}

pub async fn list_tags(pool: &PgPool) -> Result<Vec<Tag>, DbError> {
    let rows = sqlx::query_as::<_, Tag>(&format!("SELECT {COLUMNS} FROM tags ORDER BY name ASC"))
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn get_tag(pool: &PgPool, tag_id: Uuid) -> Result<Option<Tag>, DbError> {
    let row = sqlx::query_as::<_, Tag>(&format!("SELECT {COLUMNS} FROM tags WHERE id = $1"))
        .bind(tag_id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn get_by_name(pool: &PgPool, name: &str) -> Result<Option<Tag>, DbError> {
    let row = sqlx::query_as::<_, Tag>(&format!("SELECT {COLUMNS} FROM tags WHERE name = $1"))
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Create a tag; a duplicate name maps to `DbError::Conflict` (parity with
/// `TagError("a tag with that name already exists")`).
pub async fn create_tag(pool: &PgPool, name: &str, color: &str) -> Result<Tag, DbError> {
    if get_by_name(pool, name).await?.is_some() {
        return Err(DbError::Conflict(
            "a tag with that name already exists".into(),
        ));
    }
    let now = Utc::now();
    let row = sqlx::query_as::<_, Tag>(&format!(
        "INSERT INTO tags (id, name, color, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $4) RETURNING {COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(name)
    .bind(color)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        let err: DbError = e.into();
        if err.is_unique_violation() {
            DbError::Conflict("a tag with that name already exists".into())
        } else {
            err
        }
    })?;
    Ok(row)
}

/// Partial update; renaming onto an existing name maps to `DbError::Conflict`.
pub async fn update_tag(
    pool: &PgPool,
    tag_id: Uuid,
    patch: TagPatch,
) -> Result<Option<Tag>, DbError> {
    if let Some(name) = patch.name.as_deref() {
        if let Some(existing) = get_by_name(pool, name).await? {
            if existing.id != tag_id {
                return Err(DbError::Conflict(
                    "a tag with that name already exists".into(),
                ));
            }
        }
    }
    let row = sqlx::query_as::<_, Tag>(&format!(
        "UPDATE tags SET name = COALESCE($2, name), color = COALESCE($3, color), updated_at = $4 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(tag_id)
    .bind(patch.name)
    .bind(patch.color)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Delete a tag (vm_tags / custom_action_tags rows cascade).
pub async fn delete_tag(pool: &PgPool, tag_id: Uuid) -> Result<bool, DbError> {
    let res = sqlx::query("DELETE FROM tags WHERE id = $1")
        .bind(tag_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() == 1)
}

/// Replace the set of tags on a VM (parity with `tags.set_vm_tags`).
pub async fn set_vm_tags(pool: &PgPool, vm_id: Uuid, tag_ids: &[Uuid]) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM vm_tags WHERE vm_id = $1")
        .bind(vm_id)
        .execute(&mut *tx)
        .await?;
    for tag_id in tag_ids {
        sqlx::query("INSERT INTO vm_tags (vm_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(vm_id)
            .bind(tag_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Tag ids on one VM.
pub async fn tag_ids_for_vm(pool: &PgPool, vm_id: Uuid) -> Result<Vec<Uuid>, DbError> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT tag_id FROM vm_tags WHERE vm_id = $1 ORDER BY tag_id")
            .bind(vm_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// VM ids carrying at least one of the given tags (parity with
/// `tags.vm_ids_for_tags`).
pub async fn vm_ids_for_tags(pool: &PgPool, tag_ids: &[Uuid]) -> Result<Vec<Uuid>, DbError> {
    if tag_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT DISTINCT vm_id FROM vm_tags WHERE tag_id = ANY($1) ORDER BY vm_id")
            .bind(tag_ids)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Joined `vm_tags` × `tags` row: (vm_id, tag fields…).
type VmTagJoin = (Uuid, Uuid, String, String, DateTime<Utc>, DateTime<Utc>);

/// Map each VM id to its tags in one query (avoids N+1; parity with
/// `tags.load_tags_for_vms`).
pub async fn load_tags_for_vms(
    pool: &PgPool,
    vm_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<Tag>>, DbError> {
    if vm_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<VmTagJoin> = sqlx::query_as(
        "SELECT vt.vm_id, t.id, t.name, t.color, t.created_at, t.updated_at \
         FROM vm_tags vt JOIN tags t ON t.id = vt.tag_id \
         WHERE vt.vm_id = ANY($1) ORDER BY t.name ASC",
    )
    .bind(vm_ids)
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<Uuid, Vec<Tag>> = HashMap::new();
    for (vm_id, id, name, color, created_at, updated_at) in rows {
        out.entry(vm_id).or_default().push(Tag {
            id,
            name,
            color,
            created_at,
            updated_at,
        });
    }
    Ok(out)
}

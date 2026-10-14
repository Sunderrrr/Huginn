//! `mcp_tokens` — per-user, named, revocable bearer tokens for the MCP server
//! (`app/models/mcp_token.py`, `app/services/mcp_tokens.py`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

const COLUMNS: &str = "id, user_id, token_hash, name, last_used_at, revoked_at, created_at, \
                      updated_at, allowed_ip";

/// A named bearer token owned by one user.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct McpToken {
    pub id: Uuid,
    pub user_id: Uuid,
    /// HMAC of the secret token; the plaintext is shown once at creation.
    pub token_hash: String,
    pub name: String,
    /// Optional IP allow-list: a single IP or CIDR; NULL = usable from anywhere.
    pub allowed_ip: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl McpToken {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Insert payload; `token_hash` is the HMAC computed by the security module.
#[derive(Debug, Clone)]
pub struct McpTokenNew {
    pub user_id: Uuid,
    pub token_hash: String,
    pub name: String,
    /// Normalized IP/CIDR allow-list (the `normalize_allowed_ip` policy lives
    /// in the service layer).
    pub allowed_ip: Option<String>,
}

/// Create a token row (plaintext shown once by the caller).
pub async fn create(pool: &PgPool, new: McpTokenNew) -> Result<McpToken, DbError> {
    let now = Utc::now();
    let row = sqlx::query_as::<_, McpToken>(&format!(
        "INSERT INTO mcp_tokens (id, user_id, token_hash, name, last_used_at, revoked_at, \
         created_at, updated_at, allowed_ip) \
         VALUES ($1, $2, $3, $4, NULL, NULL, $5, $5, $6) \
         RETURNING {COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(new.user_id)
    .bind(&new.token_hash)
    .bind(&new.name)
    .bind(now)
    .bind(&new.allowed_ip)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Any token with this hash, revoked or not.
pub async fn get_by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<McpToken>, DbError> {
    let row = sqlx::query_as::<_, McpToken>(&format!(
        "SELECT {COLUMNS} FROM mcp_tokens WHERE token_hash = $1"
    ))
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// The presented token if it exists and is not revoked
/// (parity with `mcp_tokens.resolve`'s first lookup).
pub async fn get_active_by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<McpToken>, DbError> {
    let row = sqlx::query_as::<_, McpToken>(&format!(
        "SELECT {COLUMNS} FROM mcp_tokens WHERE token_hash = $1 AND revoked_at IS NULL"
    ))
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// A user's tokens, oldest first. `active_only` skips revoked ones (the
/// service's `list_for_user` behavior).
pub async fn list_for_user(
    pool: &PgPool,
    user_id: Uuid,
    active_only: bool,
) -> Result<Vec<McpToken>, DbError> {
    let rows = sqlx::query_as::<_, McpToken>(&format!(
        "SELECT {COLUMNS} FROM mcp_tokens \
         WHERE user_id = $1 AND ($2 = false OR revoked_at IS NULL) \
         ORDER BY created_at ASC"
    ))
    .bind(user_id)
    .bind(active_only)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Revoke a token the caller owns. False when not found / not owned / already
/// revoked (parity with `mcp_tokens.revoke`).
pub async fn revoke(pool: &PgPool, token_id: Uuid, user_id: Uuid) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE mcp_tokens SET revoked_at = $3, updated_at = $3 \
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(token_id)
    .bind(user_id)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Update a token's IP allow-list (caller must own it). `None` clears it.
pub async fn set_allowed_ip(
    pool: &PgPool,
    token_id: Uuid,
    user_id: Uuid,
    allowed_ip: Option<&str>,
) -> Result<Option<McpToken>, DbError> {
    let row = sqlx::query_as::<_, McpToken>(&format!(
        "UPDATE mcp_tokens SET allowed_ip = $3, updated_at = $4 \
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL \
         RETURNING {COLUMNS}"
    ))
    .bind(token_id)
    .bind(user_id)
    .bind(allowed_ip)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Bump `last_used_at` on successful resolution.
pub async fn touch_last_used(
    pool: &PgPool,
    token_id: Uuid,
    at: DateTime<Utc>,
) -> Result<Option<McpToken>, DbError> {
    let row = sqlx::query_as::<_, McpToken>(&format!(
        "UPDATE mcp_tokens SET last_used_at = $2, updated_at = $2 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(token_id)
    .bind(at)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

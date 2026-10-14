//! WebAuthn challenges/credentials and TOTP backup codes —
//! `webauthn_challenges`, `webauthn_credentials`, `mfa_backup_codes`
//! (`app/models/webauthn_*.py`, `app/models/mfa_backup_code.py`).
//!
//! Ceremony verification (py_webauthn) and code formatting/hashing live in the
//! service/security layers; this module persists rows and performs the atomic
//! single-use claims (challenge consumption, backup-code spending).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

const CHALLENGE_COLUMNS: &str =
    "id, challenge, user_id, purpose, expires_at, consumed_at, created_at, updated_at";
const CREDENTIAL_COLUMNS: &str = "id, user_id, name, credential_id, public_key, sign_count, \
                                  transports, aaguid, last_used_at, created_at, updated_at";

/// A pending registration/authentication challenge (single-use, expiring).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WebAuthnChallenge {
    pub id: Uuid,
    pub challenge: String,
    /// Set for registration / 2-step; null for usernameless (discoverable) login.
    pub user_id: Option<Uuid>,
    /// "register" | "login".
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A FIDO2/WebAuthn authenticator bound to a user account.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WebAuthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    /// User-supplied label, e.g. "MacBook Touch ID".
    pub name: String,
    /// base64url of the raw credential id (unique across all users).
    pub credential_id: String,
    /// COSE public key bytes returned by py_webauthn.
    pub public_key: Vec<u8>,
    /// Signature counter — persisted and checked for clone detection.
    pub sign_count: i64,
    pub transports: Option<serde_json::Value>,
    pub aaguid: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A single-use TOTP recovery code (only its HMAC hash is persisted).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MfaBackupCode {
    pub id: Uuid,
    pub user_id: Uuid,
    /// HMAC-SHA256 (keyed) of the plaintext code; unique to detect collisions.
    pub code_hash: String,
    /// Set on consumption — codes are single-use; row kept for audit.
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert payload for a credential.
#[derive(Debug, Clone)]
pub struct CredentialNew {
    pub user_id: Uuid,
    pub name: String,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Option<serde_json::Value>,
    pub aaguid: Option<String>,
}

// --- challenges -----------------------------------------------------------

/// Store a freshly generated challenge (5-minute TTL in the Python service).
pub async fn create_challenge(
    pool: &PgPool,
    challenge: &str,
    user_id: Option<Uuid>,
    purpose: &str,
    expires_at: DateTime<Utc>,
) -> Result<WebAuthnChallenge, DbError> {
    let now = Utc::now();
    let row = sqlx::query_as::<_, WebAuthnChallenge>(&format!(
        "INSERT INTO webauthn_challenges (id, challenge, user_id, purpose, expires_at, \
         consumed_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $6) RETURNING {CHALLENGE_COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(challenge)
    .bind(user_id)
    .bind(purpose)
    .bind(expires_at)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Atomically consume a challenge: a single conditional UPDATE, so two
/// concurrent finishes can't both spend the same challenge (replay). Returns
/// `None` when unknown, already used, wrong purpose, or expired (parity with
/// `webauthn._consume_challenge`).
pub async fn consume_challenge(
    pool: &PgPool,
    challenge: &str,
    purpose: &str,
) -> Result<Option<WebAuthnChallenge>, DbError> {
    let now = Utc::now();
    let mut tx = pool.begin().await?;
    let res = sqlx::query(
        "UPDATE webauthn_challenges SET consumed_at = $3, updated_at = $3 \
         WHERE challenge = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > $3",
    )
    .bind(challenge)
    .bind(purpose)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() != 1 {
        tx.commit().await?;
        return Ok(None);
    }
    let row = sqlx::query_as::<_, WebAuthnChallenge>(&format!(
        "SELECT {CHALLENGE_COLUMNS} FROM webauthn_challenges WHERE challenge = $1"
    ))
    .bind(challenge)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(row))
}

// --- credentials ----------------------------------------------------------

/// A user's registered authenticators (oldest first, like the API listing).
pub async fn list_credentials(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<WebAuthnCredential>, DbError> {
    let rows = sqlx::query_as::<_, WebAuthnCredential>(&format!(
        "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials \
         WHERE user_id = $1 ORDER BY created_at ASC"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_credential_by_credential_id(
    pool: &PgPool,
    credential_id: &str,
) -> Result<Option<WebAuthnCredential>, DbError> {
    let row = sqlx::query_as::<_, WebAuthnCredential>(&format!(
        "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials WHERE credential_id = $1"
    ))
    .bind(credential_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn get_credential_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<WebAuthnCredential>, DbError> {
    let row = sqlx::query_as::<_, WebAuthnCredential>(&format!(
        "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn create_credential(
    pool: &PgPool,
    new: CredentialNew,
) -> Result<WebAuthnCredential, DbError> {
    let now = Utc::now();
    let row = sqlx::query_as::<_, WebAuthnCredential>(&format!(
        "INSERT INTO webauthn_credentials (id, user_id, name, credential_id, public_key, \
         sign_count, transports, aaguid, last_used_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $9) RETURNING {CREDENTIAL_COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(new.user_id)
    .bind(new.name)
    .bind(new.credential_id)
    .bind(new.public_key)
    .bind(new.sign_count)
    .bind(&new.transports)
    .bind(&new.aaguid)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Persist the signature counter and usage time after a successful assertion
/// (clone detection reads the counter back on the next ceremony).
pub async fn update_credential_usage(
    pool: &PgPool,
    id: Uuid,
    sign_count: i64,
    last_used_at: DateTime<Utc>,
) -> Result<Option<WebAuthnCredential>, DbError> {
    let row = sqlx::query_as::<_, WebAuthnCredential>(&format!(
        "UPDATE webauthn_credentials SET sign_count = $2, last_used_at = $3, updated_at = $3 \
         WHERE id = $1 RETURNING {CREDENTIAL_COLUMNS}"
    ))
    .bind(id)
    .bind(sign_count)
    .bind(last_used_at)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Rename a credential.
pub async fn rename_credential(
    pool: &PgPool,
    id: Uuid,
    name: &str,
) -> Result<Option<WebAuthnCredential>, DbError> {
    let row = sqlx::query_as::<_, WebAuthnCredential>(&format!(
        "UPDATE webauthn_credentials SET name = $2, updated_at = $3 \
         WHERE id = $1 RETURNING {CREDENTIAL_COLUMNS}"
    ))
    .bind(id)
    .bind(name)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Remove one of a user's credentials (ownership enforced in the WHERE).
pub async fn delete_credential(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, DbError> {
    let res = sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() == 1)
}

/// Number of registered passkeys for a user (parity with `mfa.passkey_count`).
pub async fn count_credentials(pool: &PgPool, user_id: Uuid) -> Result<i64, DbError> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(n)
}

/// Remove all of a user's passkeys (admin MFA reset).
pub async fn delete_credentials_for_user(pool: &PgPool, user_id: Uuid) -> Result<u64, DbError> {
    let res = sqlx::query("DELETE FROM webauthn_credentials WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

// --- backup codes ---------------------------------------------------------

/// Replace a user's backup codes with freshly hashed ones (parity with
/// `mfa.store_backup_codes`).
pub async fn replace_backup_codes(
    pool: &PgPool,
    user_id: Uuid,
    code_hashes: &[String],
) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM mfa_backup_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for code_hash in code_hashes {
        sqlx::query(
            "INSERT INTO mfa_backup_codes (id, user_id, code_hash, used_at, created_at, updated_at) \
             VALUES ($1, $2, $3, NULL, $4, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(code_hash)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Spend a backup code: returns true and marks it used iff an unused code
/// matches. The row is locked (FOR UPDATE) so two concurrent verifies can't
/// both spend the same code (parity with `mfa.consume_backup_code`).
pub async fn consume_backup_code(
    pool: &PgPool,
    user_id: Uuid,
    code_hash: &str,
) -> Result<bool, DbError> {
    let now = Utc::now();
    let mut tx = pool.begin().await?;
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM mfa_backup_codes \
         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL \
         FOR UPDATE",
    )
    .bind(user_id)
    .bind(code_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id,)) = row else {
        tx.commit().await?;
        return Ok(false);
    };
    sqlx::query("UPDATE mfa_backup_codes SET used_at = $2, updated_at = $2 WHERE id = $1")
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Delete every backup code for a user (TOTP disable/reset).
pub async fn delete_backup_codes(pool: &PgPool, user_id: Uuid) -> Result<u64, DbError> {
    let res = sqlx::query("DELETE FROM mfa_backup_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

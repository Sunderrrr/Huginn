//! `enrollment_tokens` + worker enrollment — mirrors
//! `app/models/enrollment.py` and `app/services/enrollment.py`.
//!
//! Token plaintexts and worker secrets are generated and hashed by the
//! security module; this module only stores/consumes the rows. Consumption is
//! a single conditional UPDATE, so concurrent enrollments can never exceed
//! `max_uses`.

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use crate::db::DbError;

use super::enums::{VMState, WorkerArch};
use super::vm::{VmNew, VM};

const TOKEN_COLUMNS: &str = "id, token_hash, label, created_by, max_uses, uses_count, \
                             expires_at, revoked_at, created_at, updated_at, auto_approve";

/// A limited-use, revocable credential to join the fleet.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EnrollmentToken {
    pub id: Uuid,
    /// HMAC of the secret token; the plaintext is shown once at creation.
    pub token_hash: String,
    pub label: String,
    pub created_by: Uuid,
    /// `max_uses == 0` means unlimited (reusable "join key"); any positive
    /// value caps how many VMs may enroll with it.
    pub max_uses: i32,
    pub uses_count: i32,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When true, enrolled VMs come up ACTIVE instead of PENDING (no manual
    /// approval).
    pub auto_approve: bool,
}

impl EnrollmentToken {
    /// Usable = not revoked, under the use cap (or unlimited), not expired
    /// (parity with `EnrollmentToken.is_usable`).
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none()
            && (self.max_uses == 0 || self.uses_count < self.max_uses)
            && self.expires_at > now
    }
}

/// Insert payload; `token_hash` is the HMAC computed by the security module.
#[derive(Debug, Clone)]
pub struct EnrollmentTokenNew {
    pub token_hash: String,
    pub label: String,
    pub created_by: Uuid,
    /// `0` = never expires (stored as year 9999, like the Python service).
    pub ttl_seconds: i64,
    pub max_uses: i32,
    pub auto_approve: bool,
}

/// Worker registration facts for `create_vm_on_enroll`.
#[derive(Debug, Clone)]
pub struct EnrollVmParams {
    pub name: String,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub arch: WorkerArch,
    pub os_info: serde_json::Value,
    pub worker_version: Option<String>,
    /// HMAC of the freshly issued per-worker secret.
    pub worker_secret_hash: String,
}

/// Result of `create_vm_on_enroll`: the consumed token and the new VM.
#[derive(Debug, Clone)]
pub struct EnrollOutcome {
    pub token: EnrollmentToken,
    pub vm: VM,
}

/// Create a token row; returns it (the plaintext was shown once by the caller).
pub async fn create_token(
    pool: &PgPool,
    new: EnrollmentTokenNew,
) -> Result<EnrollmentToken, DbError> {
    let now = Utc::now();
    // ttl_seconds == 0 → never expires (parity: datetime(9999, 12, 31, ...)).
    let expires_at = if new.ttl_seconds == 0 {
        Utc.with_ymd_and_hms(9999, 12, 31, 23, 59, 59)
            .single()
            .expect("valid far-future date")
    } else {
        now + chrono::Duration::seconds(new.ttl_seconds)
    };
    let row = sqlx::query_as::<_, EnrollmentToken>(&format!(
        "INSERT INTO enrollment_tokens (id, token_hash, label, created_by, max_uses, uses_count, \
         expires_at, revoked_at, created_at, updated_at, auto_approve) \
         VALUES ($1, $2, $3, $4, $5, 0, $6, NULL, $7, $7, $8) \
         RETURNING {TOKEN_COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(&new.token_hash)
    .bind(&new.label)
    .bind(new.created_by)
    .bind(new.max_uses)
    .bind(expires_at)
    .bind(now)
    .bind(new.auto_approve)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// All tokens, newest first (parity with `enrollment.list_tokens`).
pub async fn list_tokens(pool: &PgPool) -> Result<Vec<EnrollmentToken>, DbError> {
    let rows = sqlx::query_as::<_, EnrollmentToken>(&format!(
        "SELECT {TOKEN_COLUMNS} FROM enrollment_tokens ORDER BY created_at DESC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<EnrollmentToken>, DbError> {
    let row = sqlx::query_as::<_, EnrollmentToken>(&format!(
        "SELECT {TOKEN_COLUMNS} FROM enrollment_tokens WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn get_by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<EnrollmentToken>, DbError> {
    let row = sqlx::query_as::<_, EnrollmentToken>(&format!(
        "SELECT {TOKEN_COLUMNS} FROM enrollment_tokens WHERE token_hash = $1"
    ))
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Revoke a token (idempotent — keeps the first `revoked_at`).
pub async fn revoke_token(
    pool: &PgPool,
    token_id: Uuid,
) -> Result<Option<EnrollmentToken>, DbError> {
    let row = sqlx::query_as::<_, EnrollmentToken>(&format!(
        "UPDATE enrollment_tokens SET revoked_at = COALESCE(revoked_at, $2), updated_at = $2 \
         WHERE id = $1 RETURNING {TOKEN_COLUMNS}"
    ))
    .bind(token_id)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Atomically consume one use of the token identified by its hash.
///
/// Returns `None` when the token is unknown, revoked, expired, or exhausted —
/// one-time tokens (`max_uses == 1`) are spent by the first successful claim.
pub async fn consume_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<EnrollmentToken>, DbError> {
    consume_token_exec(pool, token_hash).await
}

async fn consume_token_exec<'e, E>(
    exec: E,
    token_hash: &str,
) -> Result<Option<EnrollmentToken>, DbError>
where
    E: PgExecutor<'e>,
{
    let now = Utc::now();
    let row = sqlx::query_as::<_, EnrollmentToken>(&format!(
        "UPDATE enrollment_tokens SET uses_count = uses_count + 1, updated_at = $2 \
         WHERE token_hash = $1 \
           AND revoked_at IS NULL \
           AND expires_at > $2 \
           AND (max_uses = 0 OR uses_count < max_uses) \
         RETURNING {TOKEN_COLUMNS}"
    ))
    .bind(token_hash)
    .bind(now)
    .fetch_optional(exec)
    .await?;
    Ok(row)
}

/// Consume one token use and register a new VM in a single transaction
/// (parity with `enrollment.enroll_worker`): the VM is PENDING and inert until
/// approved, or ACTIVE immediately when the token is `auto_approve`.
pub async fn create_vm_on_enroll(
    pool: &PgPool,
    token_hash: &str,
    params: EnrollVmParams,
) -> Result<EnrollOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let Some(token) = consume_token_exec(&mut *tx, token_hash).await? else {
        tx.rollback().await?;
        return Err(DbError::Invalid(
            "invalid or expired enrollment token".into(),
        ));
    };

    let now = Utc::now();
    let approved = token.auto_approve;
    let mut new = VmNew::new(params.name, params.arch);
    new.hostname = params.hostname;
    new.ip_address = params.ip_address;
    new.os_info = params.os_info;
    new.worker_version = params.worker_version;
    new.worker_secret_hash = Some(params.worker_secret_hash);
    new.enrollment_token_id = Some(token.id);
    new.state = if approved {
        VMState::Active
    } else {
        VMState::Pending
    };
    // auto-approved VMs are activated by the token itself (no human actor)
    new.approved_at = if approved { Some(now) } else { None };
    new.enrolled_at = Some(now);
    new.last_heartbeat_at = Some(now);

    let vm = super::vm::create_in(&mut *tx, new).await?;
    tx.commit().await?;
    Ok(EnrollOutcome { token, vm })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(
        max_uses: i32,
        uses_count: i32,
        revoked: bool,
        expires_at: DateTime<Utc>,
    ) -> EnrollmentToken {
        EnrollmentToken {
            id: Uuid::nil(),
            token_hash: "h".into(),
            label: "lab".into(),
            created_by: Uuid::nil(),
            max_uses,
            uses_count,
            expires_at,
            revoked_at: if revoked { Some(Utc::now()) } else { None },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            auto_approve: false,
        }
    }

    #[test]
    fn is_usable_matches_python() {
        let now = Utc::now();
        let future = now + chrono::Duration::seconds(60);
        let past = now - chrono::Duration::seconds(60);

        // one-time token, unused → usable; once used → spent
        assert!(token(1, 0, false, future).is_usable(now));
        assert!(!token(1, 1, false, future).is_usable(now));
        // unlimited (max_uses == 0)
        assert!(token(0, 99, false, future).is_usable(now));
        // revoked / expired
        assert!(!token(0, 0, true, future).is_usable(now));
        assert!(!token(0, 0, false, past).is_usable(now));
    }
}

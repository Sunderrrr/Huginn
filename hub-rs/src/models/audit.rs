//! `audit_log` — append-only, tamper-evident audit trail.
//!
//! Each row stores `row_hash = H(prev_hash || canonical(fields))`, forming a
//! hash chain; rows are only ever inserted. The hash itself is computed by the
//! security module (`src/security/`) — this module owns the row shape
//! (`AuditNew`), the exact field map the hash must commit to (`hash_fields`,
//! byte-for-byte the dict hashed by `app/core/audit.py`), and the serialized
//! append (transaction-level advisory lock, like the Python writer).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

use super::enums::ActorType;

const COLUMNS: &str = "id, ts, actor_type, actor_id, event_type, vm_id, action_name, command, \
                      result_status, exit_code, detail, source_ip, prev_hash, row_hash";

/// Chain root: 64 zeros (parity with `app.core.audit.GENESIS_HASH`).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// PostgreSQL transaction-level advisory-lock key that serializes audit
/// appends ("HUGINA", parity with `app.core.audit._AUDIT_LOCK_KEY`).
pub const AUDIT_LOCK_KEY: i64 = 0x4855_4749_4E41;

/// One immutable audit row.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub actor_type: ActorType,
    pub actor_id: String,
    pub event_type: String,
    pub vm_id: Option<Uuid>,
    pub action_name: Option<String>,
    pub command: Option<String>,
    pub result_status: Option<String>,
    pub exit_code: Option<i32>,
    pub detail: serde_json::Value,
    pub source_ip: Option<String>,
    pub prev_hash: String,
    pub row_hash: String,
}

/// A new audit entry *before* hashing: exactly the fields `record()` commits
/// to. The security module turns this into `(prev_hash, row_hash)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditNew {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub event_type: String,
    pub vm_id: Option<Uuid>,
    pub action_name: Option<String>,
    pub command: Option<String>,
    pub result_status: Option<String>,
    pub exit_code: Option<i32>,
    pub detail: serde_json::Value,
    pub source_ip: Option<String>,
}

impl AuditNew {
    pub fn new(
        actor_type: ActorType,
        actor_id: impl Into<String>,
        event_type: impl Into<String>,
    ) -> Self {
        Self {
            actor_type,
            actor_id: actor_id.into(),
            event_type: event_type.into(),
            vm_id: None,
            action_name: None,
            command: None,
            result_status: None,
            exit_code: None,
            detail: serde_json::Value::Object(serde_json::Map::new()),
            source_ip: None,
        }
    }

    /// The exact dict the Python writer hashes (canonical JSON, sorted keys).
    /// Provided so the security module's hashing has a single source of truth
    /// for field inclusion and `vm_id` stringification.
    pub fn hash_fields(&self) -> serde_json::Value {
        serde_json::json!({
            "actor_type": self.actor_type.as_str(),
            "actor_id": self.actor_id,
            "event_type": self.event_type,
            "vm_id": self.vm_id.map(|id| id.to_string()),
            "action_name": self.action_name,
            "command": self.command,
            "result_status": self.result_status,
            "exit_code": self.exit_code,
            "detail": self.detail,
            "source_ip": self.source_ip,
        })
    }
}

/// Hash chain head (`row_hash` of the newest row, or GENESIS when empty).
pub async fn chain_head(pool: &PgPool) -> Result<String, DbError> {
    let head: Option<(String,)> =
        sqlx::query_as("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    Ok(head
        .map(|(h,)| h)
        .unwrap_or_else(|| GENESIS_HASH.to_string()))
}

/// Append one entry with caller-computed hashes.
///
/// When appending back-to-back, prefer [`append_chained`]: it holds the
/// advisory lock while the hash is computed, so concurrent writers cannot fork
/// the chain. L-5: crate-visible only — production writers must go through
/// the chained appends, never assemble a raw (non-locked) audit row.
pub(crate) async fn append(
    pool: &PgPool,
    new: AuditNew,
    prev_hash: String,
    row_hash: String,
) -> Result<AuditLog, DbError> {
    let row = sqlx::query_as::<_, AuditLog>(&format!(
        "INSERT INTO audit_log (id, ts, actor_type, actor_id, event_type, vm_id, action_name, \
         command, result_status, exit_code, detail, source_ip, prev_hash, row_hash) \
         VALUES (DEFAULT, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         RETURNING {COLUMNS}"
    ))
    .bind(Utc::now())
    .bind(new.actor_type)
    .bind(&new.actor_id)
    .bind(&new.event_type)
    .bind(new.vm_id)
    .bind(&new.action_name)
    .bind(&new.command)
    .bind(&new.result_status)
    .bind(new.exit_code)
    .bind(&new.detail)
    .bind(&new.source_ip)
    .bind(prev_hash)
    .bind(row_hash)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Append one entry, computing the hash chain link while holding the
/// transaction-level advisory lock (so concurrent appends serialize exactly
/// like `app.core.audit.record`).
///
/// `compute` receives the entry and the current chain head and returns
/// `(prev_hash, row_hash)` — hashing stays in the security module.
pub async fn append_chained<F>(
    pool: &PgPool,
    new: AuditNew,
    compute: F,
) -> Result<AuditLog, DbError>
where
    F: FnOnce(&AuditNew, &str) -> (String, String),
{
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    let head: Option<(String,)> =
        sqlx::query_as("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let head = head
        .map(|(h,)| h)
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    let (prev_hash, row_hash) = compute(&new, &head);

    let row = sqlx::query_as::<_, AuditLog>(&format!(
        "INSERT INTO audit_log (id, ts, actor_type, actor_id, event_type, vm_id, action_name, \
         command, result_status, exit_code, detail, source_ip, prev_hash, row_hash) \
         VALUES (DEFAULT, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         RETURNING {COLUMNS}"
    ))
    .bind(Utc::now())
    .bind(new.actor_type)
    .bind(&new.actor_id)
    .bind(&new.event_type)
    .bind(new.vm_id)
    .bind(&new.action_name)
    .bind(&new.command)
    .bind(&new.result_status)
    .bind(new.exit_code)
    .bind(&new.detail)
    .bind(&new.source_ip)
    .bind(prev_hash)
    .bind(row_hash)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Filtered listing, newest first (parity with `api/routes/audit.py`).
pub async fn list_filtered(
    pool: &PgPool,
    vm_id: Option<Uuid>,
    event_type: Option<&str>,
    limit: i64,
) -> Result<Vec<AuditLog>, DbError> {
    let rows = sqlx::query_as::<_, AuditLog>(&format!(
        "SELECT {COLUMNS} FROM audit_log \
         WHERE ($1::uuid IS NULL OR vm_id = $1) \
           AND ($2::text IS NULL OR event_type = $2) \
         ORDER BY id DESC LIMIT $3"
    ))
    .bind(vm_id)
    .bind(event_type)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The whole chain in insertion order (for `verify_chain`).
pub async fn get_all_ordered(pool: &PgPool) -> Result<Vec<AuditLog>, DbError> {
    let rows =
        sqlx::query_as::<_, AuditLog>(&format!("SELECT {COLUMNS} FROM audit_log ORDER BY id ASC"))
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_fields_match_python_dict() {
        let mut e = AuditNew::new(ActorType::User, "alice", "vm.approve");
        e.vm_id = Some(Uuid::nil());
        e.action_name = Some("reboot".into());
        e.exit_code = Some(0);
        e.detail = serde_json::json!({"ok": true});

        let f = e.hash_fields();
        assert_eq!(f["actor_type"], "user");
        assert_eq!(f["actor_id"], "alice");
        assert_eq!(f["event_type"], "vm.approve");
        // Python: str(vm_id) → hyphenated uuid string; None → null.
        assert_eq!(f["vm_id"], Uuid::nil().to_string());
        assert_eq!(f["action_name"], "reboot");
        assert_eq!(f["exit_code"], 0);
        assert_eq!(f["detail"]["ok"], true);
        assert!(f["command"].is_null());
        assert!(f["source_ip"].is_null());

        let e2 = AuditNew::new(ActorType::System, "sched", "scheduled_action");
        assert!(e2.hash_fields()["vm_id"].is_null());
    }

    #[test]
    fn genesis_is_64_zeros() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn audit_json_is_snake_case_with_int_id() {
        let row = AuditLog {
            id: 42,
            ts: Utc::now(),
            actor_type: ActorType::Agent,
            actor_id: "worker-1".into(),
            event_type: "task.result".into(),
            vm_id: None,
            action_name: None,
            command: None,
            result_status: Some("succeeded".into()),
            exit_code: Some(0),
            detail: serde_json::json!({}),
            source_ip: None,
            prev_hash: GENESIS_HASH.into(),
            row_hash: "abc".into(),
        };
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["id"], 42);
        assert_eq!(v["actor_type"], "agent");
        assert_eq!(v["result_status"], "succeeded");
    }
}

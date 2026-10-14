//! `vms` — fleet inventory. Mirrors `app/models/vm.py` and the query semantics
//! of `app/services/vms.py` (listing filters, approval, mode toggles,
//! revocation) plus `sweep_offline_vms` from `app/services/tasks.py`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

use super::enums::{ExecMode, VMState, WorkerArch};

const COLUMNS: &str = "id, name, hostname, ip_address, arch, os_info, state, exec_mode, \
                      worker_version, worker_secret_hash, enrollment_token_id, approved_by, \
                      last_heartbeat_at, enrolled_at, approved_at, created_at, updated_at";

/// A fleet VM and its worker.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VM {
    pub id: Uuid,
    pub name: String,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub arch: WorkerArch,
    /// Free-form OS facts reported at enrollment.
    pub os_info: serde_json::Value,
    pub state: VMState,
    pub exec_mode: ExecMode,
    pub worker_version: Option<String>,
    /// HMAC of the per-worker secret issued at approval (NULL = no credential).
    pub worker_secret_hash: Option<String>,
    pub enrollment_token_id: Option<Uuid>,
    pub approved_by: Option<Uuid>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub enrolled_at: Option<DateTime<Utc>>,
    pub approved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VM {
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

/// Insert payload; `id` and timestamps are assigned by `create`.
#[derive(Debug, Clone)]
pub struct VmNew {
    pub name: String,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub arch: WorkerArch,
    pub os_info: serde_json::Value,
    pub state: VMState,
    pub exec_mode: ExecMode,
    pub worker_version: Option<String>,
    pub worker_secret_hash: Option<String>,
    pub enrollment_token_id: Option<Uuid>,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    pub enrolled_at: Option<DateTime<Utc>>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
}

impl VmNew {
    /// A VM starts PENDING in whitelist mode — inert until approved.
    pub fn new(name: impl Into<String>, arch: WorkerArch) -> Self {
        Self {
            name: name.into(),
            hostname: None,
            ip_address: None,
            arch,
            os_info: serde_json::Value::Object(serde_json::Map::new()),
            state: VMState::Pending,
            exec_mode: ExecMode::Whitelist,
            worker_version: None,
            worker_secret_hash: None,
            enrollment_token_id: None,
            approved_by: None,
            approved_at: None,
            enrolled_at: None,
            last_heartbeat_at: None,
        }
    }
}

/// Partial update: `None` leaves the column untouched.
#[derive(Debug, Clone, Default)]
pub struct VmPatch {
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub os_info: Option<serde_json::Value>,
    pub worker_version: Option<String>,
    pub worker_secret_hash: Option<String>,
}

/// Listing filters, mirroring `vms_service.list_vms`:
/// `allowed_vm_ids: None` = unrestricted (admin/agent); `Some([])` = see
/// nothing; `tag_ids` further restricts to VMs carrying at least one of them.
#[derive(Debug, Clone, Default)]
pub struct VmListFilter {
    pub state: Option<VMState>,
    pub allowed_vm_ids: Option<Vec<Uuid>>,
    pub tag_ids: Option<Vec<Uuid>>,
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<VM>, DbError> {
    let row = sqlx::query_as::<_, VM>(&format!("SELECT {COLUMNS} FROM vms WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Exact name match.
pub async fn get_by_name(pool: &PgPool, name: &str) -> Result<Option<VM>, DbError> {
    let row = sqlx::query_as::<_, VM>(&format!("SELECT {COLUMNS} FROM vms WHERE name = $1"))
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Case-insensitive name match.
pub async fn get_by_name_ci(pool: &PgPool, name: &str) -> Result<Option<VM>, DbError> {
    let row = sqlx::query_as::<_, VM>(&format!(
        "SELECT {COLUMNS} FROM vms WHERE lower(name) = lower($1)"
    ))
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List VMs newest-first with the optional state / access / tag filters.
pub async fn list_vms(pool: &PgPool, filter: VmListFilter) -> Result<Vec<VM>, DbError> {
    // Explicitly empty access list → nothing visible (parity with Python).
    if matches!(&filter.allowed_vm_ids, Some(ids) if ids.is_empty()) {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, VM>(&format!(
        "SELECT {COLUMNS} FROM vms \
         WHERE ($1::vm_state IS NULL OR state = $1) \
           AND ($2::uuid[] IS NULL OR id = ANY($2)) \
           AND ($3::uuid[] IS NULL OR \
                id IN (SELECT vm_id FROM vm_tags WHERE tag_id = ANY($3))) \
         ORDER BY created_at DESC"
    ))
    .bind(filter.state)
    .bind(filter.allowed_vm_ids)
    .bind(filter.tag_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Insert a VM row (enrollment and admin creation both funnel here).
pub async fn create(pool: &PgPool, new: VmNew) -> Result<VM, DbError> {
    create_in(pool, new).await
}

/// Insert a VM row on any executor (a transaction, for enrollment).
pub async fn create_in<'e, E>(exec: E, new: VmNew) -> Result<VM, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let now = Utc::now();
    let row = sqlx::query_as::<_, VM>(&format!(
        "INSERT INTO vms (id, name, hostname, ip_address, arch, os_info, state, exec_mode, \
         worker_version, worker_secret_hash, enrollment_token_id, approved_by, \
         last_heartbeat_at, enrolled_at, approved_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16) \
         RETURNING {COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(&new.name)
    .bind(&new.hostname)
    .bind(&new.ip_address)
    .bind(new.arch)
    .bind(&new.os_info)
    .bind(new.state)
    .bind(new.exec_mode)
    .bind(&new.worker_version)
    .bind(&new.worker_secret_hash)
    .bind(new.enrollment_token_id)
    .bind(new.approved_by)
    .bind(new.last_heartbeat_at)
    .bind(new.enrolled_at)
    .bind(new.approved_at)
    .bind(now)
    .fetch_one(exec)
    .await?;
    Ok(row)
}

/// Partial update (identity / reported info / worker credential).
pub async fn update(pool: &PgPool, id: Uuid, patch: VmPatch) -> Result<Option<VM>, DbError> {
    let row = sqlx::query_as::<_, VM>(&format!(
        "UPDATE vms SET \
         name = COALESCE($2, name), \
         hostname = COALESCE($3, hostname), \
         ip_address = COALESCE($4, ip_address), \
         os_info = COALESCE($5, os_info), \
         worker_version = COALESCE($6, worker_version), \
         worker_secret_hash = COALESCE($7, worker_secret_hash), \
         updated_at = $8 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(patch.name)
    .bind(patch.hostname)
    .bind(patch.ip_address)
    .bind(patch.os_info)
    .bind(patch.worker_version)
    .bind(patch.worker_secret_hash)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record a worker heartbeat.
pub async fn update_heartbeat(
    pool: &PgPool,
    id: Uuid,
    at: DateTime<Utc>,
) -> Result<Option<VM>, DbError> {
    let row = sqlx::query_as::<_, VM>(&format!(
        "UPDATE vms SET last_heartbeat_at = $2, updated_at = $2 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(at)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Approve a PENDING VM (pending → active). Idempotent on already-approved
/// VMs; fails on revoked ones (parity with `vms_service.approve`).
pub async fn approve(
    pool: &PgPool,
    id: Uuid,
    approved_by: Option<Uuid>,
) -> Result<Option<VM>, DbError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, VM>(&format!(
        "SELECT {COLUMNS} FROM vms WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(mut vm) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    if vm.state == VMState::Revoked {
        tx.rollback().await?;
        return Err(DbError::Invalid("cannot approve a revoked VM".into()));
    }
    if vm.state == VMState::Pending {
        vm = sqlx::query_as::<_, VM>(&format!(
            "UPDATE vms SET state = 'active'::vm_state, approved_at = $2, approved_by = $3, \
             updated_at = $2 WHERE id = $1 RETURNING {COLUMNS}"
        ))
        .bind(id)
        .bind(Utc::now())
        .bind(approved_by)
        .fetch_one(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Some(vm))
}

/// Set the execution mode; the VM must already be approved (active/offline).
pub async fn set_exec_mode(pool: &PgPool, id: Uuid, mode: ExecMode) -> Result<Option<VM>, DbError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, VM>(&format!(
        "SELECT {COLUMNS} FROM vms WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(vm) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    if !matches!(vm.state, VMState::Active | VMState::Offline) {
        tx.rollback().await?;
        return Err(DbError::Invalid(
            "VM must be approved before changing exec mode".into(),
        ));
    }
    let vm = sqlx::query_as::<_, VM>(&format!(
        "UPDATE vms SET exec_mode = $2, updated_at = $3 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(mode)
    .bind(Utc::now())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(vm))
}

/// Free-form state transition (used by sweeps and tests).
pub async fn set_state(pool: &PgPool, id: Uuid, state: VMState) -> Result<Option<VM>, DbError> {
    let row = sqlx::query_as::<_, VM>(&format!(
        "UPDATE vms SET state = $2, updated_at = $3 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(state)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Revoke a VM: state → revoked and the worker credential is invalidated so it
/// can no longer authenticate (parity with `vms_service.revoke`).
pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<Option<VM>, DbError> {
    let row = sqlx::query_as::<_, VM>(&format!(
        "UPDATE vms SET state = 'revoked'::vm_state, worker_secret_hash = NULL, updated_at = $2 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Permanently remove a *revoked* VM and everything that references it.
/// The audit log is intentionally untouched (immutable history).
pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;
    let state: Option<(VMState,)> =
        sqlx::query_as("SELECT state FROM vms WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((state,)) = state else {
        tx.commit().await?;
        return Err(DbError::NotFound);
    };
    if state != VMState::Revoked {
        tx.rollback().await?;
        return Err(DbError::Invalid("only revoked VMs can be deleted".into()));
    }
    // Dependent rows without FKs to vms are cleared explicitly (parity with
    // vms_service.delete): tasks and schedules would otherwise dangle.
    sqlx::query("DELETE FROM tasks WHERE vm_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM vm_tags WHERE vm_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_vm_access WHERE vm_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM scheduled_commands WHERE target_vm_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM vms WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Mark ACTIVE VMs with a stale heartbeat as OFFLINE (one statement) and return
/// the VMs that transitioned, for notification fan-out. Mirrors
/// `sweep_offline_vms` in `app/services/tasks.py` (NULL heartbeats skipped).
pub async fn sweep_offline_vms(
    pool: &PgPool,
    heartbeat_offline_seconds: i64,
) -> Result<Vec<VM>, DbError> {
    let now = Utc::now();
    let rows = sqlx::query_as::<_, VM>(&format!(
        "UPDATE vms SET state = 'offline'::vm_state, updated_at = $1 \
         WHERE state = 'active'::vm_state \
           AND last_heartbeat_at IS NOT NULL \
           AND last_heartbeat_at < $1 - make_interval(secs => $2) \
         RETURNING {COLUMNS}"
    ))
    .bind(now)
    .bind(heartbeat_offline_seconds as f64)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_new_defaults_are_pending_whitelist() {
        let vm = VmNew::new("worker-1", WorkerArch::Amd64);
        assert_eq!(vm.state, VMState::Pending);
        assert_eq!(vm.exec_mode, ExecMode::Whitelist);
        assert!(vm.worker_secret_hash.is_none());
    }

    #[test]
    fn vm_json_keeps_column_names() {
        let mut vm = VmNew::new("worker-1", WorkerArch::Arm64);
        vm.os_info = serde_json::json!({"os": "linux"});
        let mut row = VM {
            id: Uuid::nil(),
            name: vm.name.clone(),
            hostname: vm.hostname.clone(),
            ip_address: vm.ip_address.clone(),
            arch: vm.arch,
            os_info: vm.os_info.clone(),
            state: vm.state,
            exec_mode: vm.exec_mode,
            worker_version: vm.worker_version.clone(),
            worker_secret_hash: vm.worker_secret_hash.clone(),
            enrollment_token_id: None,
            approved_by: None,
            last_heartbeat_at: None,
            enrolled_at: None,
            approved_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["arch"], "arm64");
        assert_eq!(v["os_info"]["os"], "linux");
        assert_eq!(v["exec_mode"], "whitelist");

        row.state = VMState::Active;
        assert!(row.is_active());
    }

    #[test]
    fn empty_allowed_ids_filter_is_flagged() {
        let f = VmListFilter {
            allowed_vm_ids: Some(vec![]),
            ..Default::default()
        };
        assert!(matches!(&f.allowed_vm_ids, Some(ids) if ids.is_empty()));
    }
}

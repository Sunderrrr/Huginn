//! `users` + `user_vm_access` — mirrors `app/models/user.py`,
//! `app/models/user_vm_access.py` and `app/services/users.py` lookups.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

use super::enums::UserRole;

const COLUMNS: &str = "id, username, email, password_hash, oidc_subject, ldap_dn, role, \
                      is_active, last_login_at, created_at, updated_at, totp_secret_enc, \
                      totp_enabled, totp_confirmed_at, totp_last_step";

/// Dashboard / API user account.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    /// Null for OIDC/LDAP-only accounts without a local address.
    pub email: Option<String>,
    /// Null for OIDC-only accounts.
    ///
    /// `skip_serializing`: the hash never leaves the data layer — a route
    /// that renders a `User` directly must not leak the credential material.
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub oidc_subject: Option<String>,
    /// Distinguished Name for LDAP-provisioned users (dedup key).
    pub ldap_dn: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// TOTP secret, Fernet-encrypted — never plaintext, and never
    /// serialized (`skip_serializing`): the row model is not a wire shape.
    #[serde(skip_serializing)]
    pub totp_secret_enc: Option<String>,
    pub totp_enabled: bool,
    pub totp_confirmed_at: Option<DateTime<Utc>>,
    /// Highest TOTP time-step already accepted (replay guard).
    pub totp_last_step: Option<i64>,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role.is_admin()
    }
}

/// Insert payload for `create`; id/timestamps are assigned here.
#[derive(Debug, Clone, Default)]
pub struct UserNew {
    pub username: String,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub oidc_subject: Option<String>,
    pub ldap_dn: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
}

impl UserNew {
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            is_active: true,
            ..Self::default()
        }
    }
}

/// Partial update: `None` leaves the column untouched (mirrors the
/// `UserUpdate` schema, where `email: None` means "keep").
#[derive(Debug, Clone, Default)]
pub struct UserPatch {
    pub email: Option<String>,
    pub role: Option<UserRole>,
    pub is_active: Option<bool>,
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!("SELECT {COLUMNS} FROM users WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn get_by_username(pool: &PgPool, username: &str) -> Result<Option<User>, DbError> {
    let row =
        sqlx::query_as::<_, User>(&format!("SELECT {COLUMNS} FROM users WHERE username = $1"))
            .bind(username)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

pub async fn get_by_oidc_subject(pool: &PgPool, subject: &str) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!(
        "SELECT {COLUMNS} FROM users WHERE oidc_subject = $1"
    ))
    .bind(subject)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn get_by_ldap_dn(pool: &PgPool, dn: &str) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!("SELECT {COLUMNS} FROM users WHERE ldap_dn = $1"))
        .bind(dn)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// All users, oldest first (matches `api/routes/users.py`).
pub async fn list_users(pool: &PgPool) -> Result<Vec<User>, DbError> {
    let rows = sqlx::query_as::<_, User>(&format!(
        "SELECT {COLUMNS} FROM users ORDER BY created_at ASC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Number of admin accounts (guards demoting/removing the last admin).
pub async fn count_admins(pool: &PgPool) -> Result<i64, DbError> {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE role = 'admin'::user_role")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// Create a user. `password_hash` is provided by the security layer — hashing
/// never happens here.
pub async fn create(pool: &PgPool, new: UserNew) -> Result<User, DbError> {
    let now = Utc::now();
    let row = sqlx::query_as::<_, User>(&format!(
        "INSERT INTO users (id, username, email, password_hash, oidc_subject, ldap_dn, role, \
         is_active, last_login_at, created_at, updated_at, totp_secret_enc, totp_enabled, \
         totp_confirmed_at, totp_last_step) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $9, NULL, false, NULL, NULL) \
         RETURNING {COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(&new.username)
    .bind(&new.email)
    .bind(&new.password_hash)
    .bind(&new.oidc_subject)
    .bind(&new.ldap_dn)
    .bind(new.role)
    .bind(new.is_active)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Partial profile update (role / is_active / email).
pub async fn update(pool: &PgPool, id: Uuid, patch: UserPatch) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!(
        "UPDATE users SET \
         email = COALESCE($2, email), \
         role = COALESCE($3, role), \
         is_active = COALESCE($4, is_active), \
         updated_at = $5 \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(patch.email)
    .bind(patch.role)
    .bind(patch.is_active)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Set (or clear, with `None`) the local password hash.
pub async fn update_password(
    pool: &PgPool,
    id: Uuid,
    password_hash: Option<&str>,
) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!(
        "UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(password_hash)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Link an OIDC subject to this account (SSO adoption of a local user).
pub async fn set_oidc_subject(
    pool: &PgPool,
    id: Uuid,
    subject: &str,
) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!(
        "UPDATE users SET oidc_subject = $2, updated_at = $3 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(subject)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Link an LDAP DN to this account.
pub async fn set_ldap_dn(pool: &PgPool, id: Uuid, dn: &str) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!(
        "UPDATE users SET ldap_dn = $2, updated_at = $3 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(dn)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record a successful login (and any re-hashed password done by the caller).
pub async fn touch_last_login(pool: &PgPool, id: Uuid) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!(
        "UPDATE users SET last_login_at = $2, updated_at = $2 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Enroll TOTP: store the encrypted secret and mark it enabled/confirmed.
pub async fn set_mfa(
    pool: &PgPool,
    id: Uuid,
    secret_enc: &str,
    enrolled_at: DateTime<Utc>,
) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!(
        "UPDATE users SET totp_secret_enc = $2, totp_enabled = true, totp_confirmed_at = $3, \
         updated_at = $4 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(secret_enc)
    .bind(enrolled_at)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Disable TOTP and clear every TOTP field (backup codes are cleared by
/// `webauthn::delete_backup_codes`).
pub async fn disable_mfa(pool: &PgPool, id: Uuid) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>(&format!(
        "UPDATE users SET totp_secret_enc = NULL, totp_enabled = false, totp_confirmed_at = NULL, \
         totp_last_step = NULL, updated_at = $2 WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Atomically advance `totp_last_step`, rejecting replays. Returns true iff
/// this call won the step (mirrors `mfa.claim_totp_step`).
pub async fn claim_totp_step(pool: &PgPool, id: Uuid, step: i64) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE users SET totp_last_step = $2, updated_at = $3 \
         WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(id)
    .bind(step)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// --- user_vm_access -------------------------------------------------------

/// Replace the set of VMs a user may access.
pub async fn replace_vm_access(
    pool: &PgPool,
    user_id: Uuid,
    vm_ids: &[Uuid],
) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM user_vm_access WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for vm_id in vm_ids {
        sqlx::query(
            "INSERT INTO user_vm_access (user_id, vm_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(vm_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// VM ids the user may access.
pub async fn vm_ids_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Uuid>, DbError> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT vm_id FROM user_vm_access WHERE user_id = $1 ORDER BY vm_id")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// User ids with access to a VM.
pub async fn user_ids_for_vm(pool: &PgPool, vm_id: Uuid) -> Result<Vec<Uuid>, DbError> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM user_vm_access WHERE vm_id = $1 ORDER BY user_id")
            .bind(vm_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_new_defaults_are_active_readonly() {
        let u = UserNew::new("alice");
        assert!(u.is_active);
        assert_eq!(u.role, UserRole::Readonly);
        assert!(u.password_hash.is_none());
    }

    #[test]
    fn user_json_is_snake_case() {
        let u = User {
            id: Uuid::nil(),
            username: "alice".into(),
            email: Some("a@b.c".into()),
            password_hash: None,
            oidc_subject: None,
            ldap_dn: None,
            role: UserRole::Admin,
            is_active: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            totp_secret_enc: None,
            totp_enabled: false,
            totp_confirmed_at: None,
            totp_last_step: None,
        };
        let v = serde_json::to_value(&u).unwrap();
        assert_eq!(v["username"], "alice");
        assert_eq!(v["role"], "admin");
        assert_eq!(v["totp_enabled"], false);
        assert!(v.get("password_hash").is_none());
        assert!(v.get("totp_secret_enc").is_none());
    }

    /// The credential material of a `User` must never reach a response body,
    /// even if a route renders the row model directly.
    #[test]
    fn credential_material_is_never_serialized() {
        let u = User {
            id: Uuid::nil(),
            username: "alice".into(),
            email: None,
            password_hash: Some("$argon2id$v=19$hash".into()),
            oidc_subject: None,
            ldap_dn: None,
            role: UserRole::Operator,
            is_active: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            totp_secret_enc: Some("gAAAA-encrypted-totp-secret".into()),
            totp_enabled: true,
            totp_confirmed_at: None,
            totp_last_step: None,
        };
        let serialized = serde_json::to_string(&u).unwrap();
        assert!(!serialized.contains("argon2"), "{serialized}");
        assert!(!serialized.contains("gAAAA"), "{serialized}");
        // The row still deserializes (the fields are only skipped on the way
        // out, never on the way in).
        let back: User = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.password_hash, None);
        assert_eq!(back.totp_secret_enc, None);
    }
}

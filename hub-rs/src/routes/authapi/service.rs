//! User/MFA service helpers (`app/services/{users,mfa}.py`): credential
//! checks, token/user projections, TOTP secret storage and backup codes.

use crate::db::DbError;
use crate::error::ApiError;
use crate::models::audit::{append_chained, AuditNew};
use crate::models::user::User;
use uuid::Uuid;

use super::schemas::{TokenResponse, UserOut};
use super::AuthState;

// ---------------------------------------------------------------------------
// Service helpers (app/services/{users,mfa}.py)
// ---------------------------------------------------------------------------

/// Data-layer failures surface as a bare 500 (L-2): the sqlx detail can
/// quote user data, SQL text and constraint names, so it goes to the server
/// log only — the client just gets "internal error". Callers that owe the
/// client a specific status map their DbError variant *before* this.
pub(crate) fn db_err(err: DbError) -> ApiError {
    tracing::warn!(error = %err, "database error");
    ApiError::internal("internal error")
}

/// Verify credentials. Always spends Argon2 work (even for unknown users or
/// accounts without a local password) to limit user enumeration —
/// `users_service.authenticate`. A successful password bumps `last_login_at`
/// and transparently re-hashes with current parameters.
pub(crate) async fn authenticate(
    state: &AuthState,
    username: &str,
    password: &str,
) -> Result<Option<User>, ApiError> {
    let user = crate::models::user::get_by_username(&state.pool, username)
        .await
        .map_err(db_err)?;
    let hash = user.as_ref().and_then(|u| u.password_hash.as_deref());
    if !crate::security::verify_password(password, hash) {
        return Ok(None);
    }
    let Some(user) = user.filter(|u| u.is_active) else {
        return Ok(None);
    };
    crate::models::user::touch_last_login(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    if let Some(hash) = user.password_hash.as_deref() {
        if crate::security::needs_rehash(hash) {
            let new_hash = crate::security::hash_password(password)
                .map_err(|e| ApiError::internal(e.to_string()))?;
            crate::models::user::update_password(&state.pool, user.id, Some(&new_hash))
                .await
                .map_err(db_err)?;
        }
    }
    Ok(Some(user))
}

/// Issue a fresh access token (`users_service.issue_token`).
pub(crate) fn issue_token(state: &AuthState, user: &User) -> Result<String, ApiError> {
    state
        .security
        .jwt()
        .create_access_token(
            &user.id.to_string(),
            user.role.as_str(),
            state.config.access_token_ttl_minutes,
        )
        .map_err(|e| ApiError::internal(e.to_string()))
}

/// `expires_in` of a fresh access token (`access_token_ttl_minutes * 60`).
pub(crate) fn token_expires_in(state: &AuthState) -> i64 {
    state.config.access_token_ttl_minutes * 60
}

pub(crate) fn token_response(state: &AuthState, user: &User) -> Result<TokenResponse, ApiError> {
    Ok(TokenResponse::new(
        issue_token(state, user)?,
        token_expires_in(state),
    ))
}

/// `UserOut` with `vm_ids` and the live passkey count (`auth.me`, `get_user`,
/// `list_users`, `reset_user_mfa`).
pub(crate) async fn user_out(state: &AuthState, user: &User) -> Result<UserOut, ApiError> {
    let vm_ids = crate::models::user::vm_ids_for_user(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    let passkey_count = crate::models::webauthn::count_credentials(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    Ok(UserOut {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        role: user.role,
        is_active: user.is_active,
        vm_ids,
        totp_enabled: user.totp_enabled,
        passkey_count,
    })
}

/// `UserOut` with `vm_ids` only. Faithful to the Python `users.py` responses
/// for create/update/vms, which `model_copy(update={"vm_ids": ...})` and thus
/// leave `passkey_count` at its `0` schema default (see PARITY_HUB.md).
pub(crate) async fn user_out_vms_only(state: &AuthState, user: &User) -> Result<UserOut, ApiError> {
    let vm_ids = crate::models::user::vm_ids_for_user(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    Ok(UserOut {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        role: user.role,
        is_active: user.is_active,
        vm_ids,
        totp_enabled: user.totp_enabled,
        passkey_count: 0,
    })
}

/// Set the profile email exactly as `auth.update_me` does (`user.email =
/// body.email or None`), including clearing it to `NULL`. The
/// `models::user::update` patch keeps NULL out (`COALESCE`), hence the direct
/// statement.
pub(crate) async fn set_user_email(
    state: &AuthState,
    user_id: Uuid,
    email: Option<String>,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET email = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(&email)
        .bind(chrono::Utc::now())
        .execute(&state.pool)
        .await
        .map_err(|e| db_err(DbError::from(e)))?;
    Ok(())
}

/// Store a *pending* TOTP secret (enrollment begun, not yet confirmed) —
/// `mfa.totp_enroll_begin` sets `user.totp_secret_enc` without enabling TOTP.
pub(crate) async fn set_pending_totp_secret(
    state: &AuthState,
    user_id: Uuid,
    secret_enc: &str,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET totp_secret_enc = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(secret_enc)
        .bind(chrono::Utc::now())
        .execute(&state.pool)
        .await
        .map_err(|e| db_err(DbError::from(e)))?;
    Ok(())
}

/// Append one chained audit entry (`app.core.audit.record`): the row hash is
/// computed while holding the chain's advisory lock.
pub(crate) async fn record_audit(
    state: &AuthState,
    mut new: AuditNew,
    source_ip: Option<String>,
) -> Result<(), ApiError> {
    new.source_ip = source_ip;
    append_chained(&state.pool, new, |entry, head| {
        let row_hash = crate::security::compute_row_hash(head, &entry.hash_fields());
        (head.to_owned(), row_hash)
    })
    .await
    .map_err(db_err)?;
    Ok(())
}

/// The TOTP secret at rest, Fernet-encrypted (`totp_service.encrypt_secret`).
pub(crate) fn encrypt_totp_secret(state: &AuthState, secret: &str) -> Result<String, ApiError> {
    state
        .security
        .fernet()
        .encrypt(secret)
        .map_err(|e| ApiError::internal(e.to_string()))
}

/// Decrypt the stored TOTP secret (`totp_service.decrypt_secret`). The caller
/// maps failure onto its own auth error (key rotated/corrupt must not 500).
pub(crate) fn decrypt_totp_secret(state: &AuthState, enc: &str) -> Result<String, ()> {
    state.security.fernet().decrypt(enc).map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Backup codes (app/services/mfa.py)
// ---------------------------------------------------------------------------

/// How many single-use recovery codes an enrollment generates.
pub(crate) const BACKUP_CODE_COUNT: usize = 10;

/// 10 single-use codes, formatted `xxxxx-xxxxx` from 10 hex chars
/// (`mfa.generate_backup_codes`).
pub(crate) fn generate_backup_codes() -> Vec<String> {
    use rand::RngCore;
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0u8; 5];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            format_backup_code(&crate::security::hex_encode(&bytes))
        })
        .collect()
}

/// `mfa._format_code`: 10 hex chars grouped as `xxxxx-xxxxx` for readability.
fn format_backup_code(raw_hex: &str) -> String {
    format!("{}-{}", &raw_hex[..5], &raw_hex[5..])
}

/// Hash a presented backup code the way `consume_backup_code` looks it up
/// (whitespace-stripped first).
pub(crate) fn backup_code_hash(state: &AuthState, code: &str) -> String {
    state.security.hash_secret(code.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::authapi::support;

    #[test]
    fn db_err_never_leaks_the_sqlx_detail() {
        // L-2: the client gets a bare 500 "internal error"; the sqlx detail
        // goes to the server log only.
        let err = db_err(DbError::Conflict("secret constraint detail".into()));
        assert_eq!(err.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.detail(), "internal error");
        assert!(!err.detail().contains("secret"));
    }

    // ---- backup codes -----------------------------------------------------

    #[test]
    fn backup_codes_are_ten_grouped_hex_codes() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        for code in &codes {
            assert_eq!(code.len(), 11, "xxxxx-xxxxx");
            let (a, b) = code.split_once('-').unwrap();
            assert_eq!(a.len(), 5);
            assert_eq!(b.len(), 5);
            assert!(code
                .chars()
                .filter(|c| *c != '-')
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), BACKUP_CODE_COUNT, "codes are unique");
    }

    #[tokio::test]
    async fn backup_code_hashing_strips_whitespace_like_python() {
        let state = support::test_state();
        // `secrets.token_hex(5)` → 10 hex chars, formatted `xxxxx-xxxxx`.
        let formatted = format_backup_code(&crate::security::hex_encode(b"hello"));
        assert_eq!(formatted, "68656-c6c6f");
        assert_eq!(
            backup_code_hash(&state, &formatted),
            backup_code_hash(&state, &format!("  {formatted}\t")),
            "lookup hashes the whitespace-stripped code"
        );
    }
}

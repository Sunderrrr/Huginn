//! TOTP second factor — enrollment and disabling
//! (`app/api/routes/mfa.py` `totp_enroll_*` / `totp_disable`).

use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::enums::ActorType;
use crate::models::user::User;

use super::backup_codes::store_backup_codes;
use super::{
    backup_code_hash, client_ip, db_err, decrypt_totp_secret, encrypt_totp_secret, enrolling_actor,
    generate_backup_codes, map_json_rejection, now_unix, peer_addr, present, record_audit,
    set_pending_totp_secret, token_response, validate_len, validate_optional_len, AuthState,
};

/// `TotpEnrollBeginResponse`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpEnrollBeginResponse {
    pub secret: String,
    pub otpauth_uri: String,
}

/// `TotpEnrollFinishRequest` (also the body of backup-code regeneration).
#[derive(Debug, Clone, Deserialize)]
pub struct TotpEnrollFinishRequest {
    pub code: String,
}

impl TotpEnrollFinishRequest {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        validate_len("code", &self.code, 10)
    }
}

/// `TotpDisableRequest` — re-authentication with a current second factor.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TotpDisableRequest {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub backup_code: Option<String>,
}

impl TotpDisableRequest {
    fn validate(&self) -> Result<(), ApiError> {
        validate_optional_len("code", &self.code, 10)?;
        validate_optional_len("backup_code", &self.backup_code, 16)
    }
}

/// `TotpEnrollFinishRequest`'s dict response: `backup_codes`, plus
/// `access_token` when the setup flow logged the admin in.
#[derive(Debug, Clone, Serialize)]
pub(super) struct TotpEnrollFinishResponse {
    backup_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/totp/enroll/begin
// ---------------------------------------------------------------------------

pub(super) async fn totp_enroll_begin(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Json<TotpEnrollBeginResponse>, ApiError> {
    let (user, _is_setup) = enrolling_actor(&state, &headers, true).await?;
    if user.totp_enabled {
        return Err(ApiError::conflict("TOTP already enabled"));
    }
    let secret = crate::security::generate_totp_secret();
    let secret_enc = encrypt_totp_secret(&state, &secret)?; // pending, not enabled
    set_pending_totp_secret(&state, user.id, &secret_enc).await?;
    record_audit(
        &state,
        AuditNew::new(ActorType::User, user.id.to_string(), "totp_enroll_begin"),
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    let otpauth_uri = crate::security::provisioning_uri(&secret, &user.username, "Huginn");
    Ok(Json(TotpEnrollBeginResponse {
        secret,
        otpauth_uri,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/totp/enroll/finish
// ---------------------------------------------------------------------------

pub(super) async fn totp_enroll_finish(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<TotpEnrollFinishRequest>, JsonRejection>,
) -> Result<Json<TotpEnrollFinishResponse>, ApiError> {
    // FastAPI solves the `enrolling_actor` dependency before validating the body.
    let (user, is_setup) = enrolling_actor(&state, &headers, true).await?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    if user.totp_enabled {
        return Err(ApiError::conflict("TOTP already enabled"));
    }
    let Some(secret_enc) = user.totp_secret_enc.clone() else {
        return Err(ApiError::bad_request("no pending enrollment"));
    };
    let secret = decrypt_totp_secret(&state, &secret_enc)
        .map_err(|_| ApiError::internal("cannot decrypt TOTP secret"))?;
    if !crate::security::verify_totp_code(
        &secret,
        &body.code,
        now_unix(),
        crate::security::TOTP_VALID_WINDOW,
    ) {
        return Err(ApiError::bad_request("invalid code"));
    }
    crate::models::user::set_mfa(&state.pool, user.id, &secret_enc, Utc::now())
        .await
        .map_err(db_err)?;
    let codes = generate_backup_codes();
    store_backup_codes(&state, &user, &codes).await?;
    record_audit(
        &state,
        AuditNew::new(ActorType::User, user.id.to_string(), "totp_enroll_complete"),
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    // Setup flow (admin first-time) came in with only a setup token → log them in.
    let access_token = if is_setup {
        Some(token_response(&state, &user)?.access_token)
    } else {
        None
    };
    Ok(Json(TotpEnrollFinishResponse {
        backup_codes: codes,
        access_token,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/totp/disable
// ---------------------------------------------------------------------------

pub(super) async fn totp_disable(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<TotpDisableRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let (user, _is_setup) = enrolling_actor(&state, &headers, false).await?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    if !user.totp_enabled || user.totp_secret_enc.is_none() {
        return Err(ApiError::bad_request("TOTP not enabled"));
    }
    // Re-authenticate with a *current second factor* — a valid TOTP code or an
    // unused backup code. A password alone is deliberately NOT sufficient: that
    // would let a stolen session + known password strip the second factor.
    let reauthed = if let Some(code) = present(&body.code) {
        match decrypt_totp_secret(&state, user.totp_secret_enc.as_deref().unwrap_or("")) {
            Ok(secret) => crate::security::verify_totp_code(
                &secret,
                code,
                now_unix(),
                crate::security::TOTP_VALID_WINDOW,
            ),
            Err(_) => false,
        }
    } else if let Some(code) = present(&body.backup_code) {
        let hash = backup_code_hash(&state, code);
        crate::models::webauthn::consume_backup_code(&state.pool, user.id, &hash)
            .await
            .map_err(db_err)?
    } else {
        false
    };
    if !reauthed {
        return Err(ApiError::unauthorized("valid second factor required"));
    }
    disable_totp(&state, &user).await?;
    record_audit(
        &state,
        AuditNew::new(ActorType::User, user.id.to_string(), "totp_disabled"),
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `mfa.disable_totp`: clear every TOTP field and the backup codes.
async fn disable_totp(state: &AuthState, user: &User) -> Result<(), ApiError> {
    crate::models::user::disable_mfa(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    crate::models::webauthn::delete_backup_codes(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::routes::authapi::support::test_state;

    // ---- TOTP verification at a frozen time -------------------------------

    #[tokio::test]
    async fn totp_codes_verify_at_a_frozen_time() {
        let state = test_state();
        let secret = crate::security::generate_totp_secret();

        // Secrets are Fernet-encrypted at rest and round-trip exactly.
        let enc = encrypt_totp_secret(&state, &secret).unwrap();
        assert_eq!(decrypt_totp_secret(&state, &enc).unwrap(), secret);
        assert!(
            decrypt_totp_secret(&state, "not-a-fernet-token").is_err(),
            "key rotated/corrupt is an auth error, not a 500"
        );

        let now = 1_700_000_000u64;
        let code = crate::security::totp_code_at(&secret, now).unwrap();
        let step = crate::security::current_step(now);

        // ±1 step window for clock skew (pyotp valid_window=1), then nothing.
        assert_eq!(
            crate::security::matched_step(&secret, &code, now),
            Some(step)
        );
        assert_eq!(
            crate::security::matched_step(&secret, &code, now - 30),
            Some(step)
        );
        assert_eq!(
            crate::security::matched_step(&secret, &code, now + 30),
            Some(step)
        );
        assert_eq!(
            crate::security::matched_step(&secret, &code, now - 60),
            None
        );
        assert_eq!(
            crate::security::matched_step(&secret, &code, now + 60),
            None
        );

        assert!(crate::security::verify_totp_code(
            &secret,
            &code,
            now,
            crate::security::TOTP_VALID_WINDOW
        ));
        assert!(!crate::security::verify_totp_code(
            &secret,
            &code,
            now - 60,
            crate::security::TOTP_VALID_WINDOW
        ));
        // Codes are normalized (spaces stripped) and must be digits.
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(crate::security::verify_totp_code(
            &secret,
            &spaced,
            now,
            crate::security::TOTP_VALID_WINDOW
        ));
        assert!(!crate::security::verify_totp_code(
            &secret,
            "abcdef",
            now,
            crate::security::TOTP_VALID_WINDOW
        ));
    }

    #[test]
    fn totp_enroll_finish_request_bounds_match_the_pydantic_field() {
        assert!(TotpEnrollFinishRequest {
            code: "0123456789".into()
        }
        .validate()
        .is_ok());
        assert!(TotpEnrollFinishRequest {
            code: "01234567890".into()
        }
        .validate()
        .is_err());
    }
}

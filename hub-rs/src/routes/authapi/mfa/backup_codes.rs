//! Single-use recovery codes (`app/services/mfa.py`): generation, storage as
//! HMAC hashes, and the regenerate endpoint.

use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::enums::ActorType;
use crate::models::user::User;

use super::totp::TotpEnrollFinishRequest;
use super::{
    client_ip, db_err, decrypt_totp_secret, enrolling_actor, generate_backup_codes,
    map_json_rejection, now_unix, peer_addr, record_audit, AuthState,
};

/// `BackupCodesResponse`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
}


// ---------------------------------------------------------------------------
// POST /api/auth/mfa/totp/backup-codes/regenerate
// ---------------------------------------------------------------------------

pub(super) async fn regenerate_backup_codes(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<TotpEnrollFinishRequest>, JsonRejection>,
) -> Result<Json<BackupCodesResponse>, ApiError> {
    let (user, _is_setup) = enrolling_actor(&state, &headers, false).await?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    if !user.totp_enabled || user.totp_secret_enc.is_none() {
        return Err(ApiError::bad_request("TOTP not enabled"));
    }
    let secret = decrypt_totp_secret(&state, user.totp_secret_enc.as_deref().unwrap_or(""))
        .map_err(|_| ApiError::internal("cannot decrypt TOTP secret"))?;
    if !crate::security::verify_totp_code(
        &secret,
        &body.code,
        now_unix(),
        crate::security::TOTP_VALID_WINDOW,
    ) {
        return Err(ApiError::unauthorized("invalid code"));
    }
    let codes = generate_backup_codes();
    store_backup_codes(&state, &user, &codes).await?;
    record_audit(
        &state,
        AuditNew::new(
            ActorType::User,
            user.id.to_string(),
            "backup_codes_regenerated",
        ),
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(Json(BackupCodesResponse {
        backup_codes: codes,
    }))
}


/// `mfa.store_backup_codes`: replace the user's codes with fresh HMAC hashes.
pub(super) async fn store_backup_codes(
    state: &AuthState,
    user: &User,
    codes: &[String],
) -> Result<(), ApiError> {
    let hashes: Vec<String> = codes
        .iter()
        .map(|c| state.security.hash_secret(c))
        .collect();
    crate::models::webauthn::replace_backup_codes(&state.pool, user.id, &hashes)
        .await
        .map_err(db_err)?;
    Ok(())
}


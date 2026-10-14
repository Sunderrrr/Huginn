//! Second-factor endpoints: TOTP enrollment/verification, backup codes and
//! WebAuthn passkeys — port of `hub/app/api/routes/mfa.py`.
//!
//! The two-step login works like the Python hub:
//!   1. `POST /api/auth/login` validates the password and, when a second factor
//!      is required, returns a short-lived *challenge token* (scope `mfa`)
//!      instead of an access token. Admins without any factor get an
//!      `mfa_setup` token.
//!   2. The client presents that token here. [`super::get_principal`] REJECTS
//!      these scoped tokens for the business API, so they are only ever usable
//!      on these routes.
//!
//! WebAuthn status (see `PARITY_HUB.md`): the four *ceremony* endpoints
//! (register begin/finish, login begin/finish) answer
//! `501 {"detail":"webauthn not yet implemented in hub-rs"}` — the
//! attestation/assertion verification of `services/webauthn.py` (py_webauthn)
//! needs the `webauthn-rs` port (phase 2). The *credential management*
//! endpoints (list/rename/delete) are fully ported: they are plain CRUD over
//! `webauthn_credentials` and keep working for passkeys registered through the
//! Python hub (the databases are interchangeable).

use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::enums::ActorType;
use crate::models::user::User;
use crate::security::jwt::MFA_SCOPE;

use super::{
    backup_code_hash, challenge_user, client_ip, db_err, decrypt_totp_secret, encrypt_totp_secret,
    enrolling_actor, generate_backup_codes, get_principal, map_json_rejection, peer_addr,
    record_audit, set_pending_totp_secret, token_response, AuthState, TokenResponse,
};

pub fn router() -> Router<AuthState> {
    Router::new()
        .route("/api/auth/mfa/verify", post(verify_mfa))
        .route("/api/auth/mfa/totp/enroll/begin", post(totp_enroll_begin))
        .route("/api/auth/mfa/totp/enroll/finish", post(totp_enroll_finish))
        .route("/api/auth/mfa/totp/disable", post(totp_disable))
        .route(
            "/api/auth/mfa/totp/backup-codes/regenerate",
            post(regenerate_backup_codes),
        )
        .route(
            "/api/auth/mfa/webauthn/register/begin",
            post(webauthn_register_begin),
        )
        .route(
            "/api/auth/mfa/webauthn/register/finish",
            post(webauthn_register_finish),
        )
        .route(
            "/api/auth/mfa/webauthn/login/begin",
            post(webauthn_login_begin),
        )
        .route(
            "/api/auth/mfa/webauthn/login/finish",
            post(webauthn_login_finish),
        )
        .route("/api/auth/mfa/webauthn/credentials", get(list_passkeys))
        .route(
            "/api/auth/mfa/webauthn/credentials/{cred_id}",
            axum::routing::put(rename_passkey).delete(delete_passkey),
        )
}

/// The detail of every not-yet-ported WebAuthn ceremony endpoint.
const WEBAUTHN_UNIMPLEMENTED: &str = "webauthn not yet implemented in hub-rs";

fn now_unix() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/auth.py)
// ---------------------------------------------------------------------------

/// `MfaVerifyRequest` — a TOTP code or a single-use backup code.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MfaVerifyRequest {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub backup_code: Option<String>,
}

impl MfaVerifyRequest {
    fn validate(&self) -> Result<(), ApiError> {
        validate_optional_len("code", &self.code, 10)?;
        validate_optional_len("backup_code", &self.backup_code, 16)
    }
}

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
    fn validate(&self) -> Result<(), ApiError> {
        validate_len("code", &self.code, 10)
    }
}

/// `BackupCodesResponse`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
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

/// `WebAuthnRegisterFinishRequest`.
#[derive(Debug, Clone, Deserialize)]
pub struct WebAuthnRegisterFinishRequest {
    #[serde(default)]
    pub name: String,
    pub credential: serde_json::Value,
}

impl WebAuthnRegisterFinishRequest {
    fn validate(&self) -> Result<(), ApiError> {
        validate_len("name", &self.name, 255)
    }
}

/// `WebAuthnRenameRequest`.
#[derive(Debug, Clone, Deserialize)]
pub struct WebAuthnRenameRequest {
    pub name: String,
}

impl WebAuthnRenameRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.name.is_empty() {
            return Err(ApiError::unprocessable_entity(
                "name must be at least 1 character",
            ));
        }
        validate_len("name", &self.name, 255)
    }
}

/// `WebAuthnLoginBeginRequest`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WebAuthnLoginBeginRequest {
    #[serde(default)]
    pub username: Option<String>,
}

impl WebAuthnLoginBeginRequest {
    fn validate(&self) -> Result<(), ApiError> {
        validate_optional_len("username", &self.username, 255)
    }
}

/// `WebAuthnLoginFinishRequest`.
#[derive(Debug, Clone, Deserialize)]
pub struct WebAuthnLoginFinishRequest {
    pub credential: serde_json::Value,
}

/// `WebAuthnCredentialOut`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebAuthnCredentialOut {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub transports: Option<serde_json::Value>,
}

impl From<crate::models::webauthn::WebAuthnCredential> for WebAuthnCredentialOut {
    fn from(cred: crate::models::webauthn::WebAuthnCredential) -> Self {
        Self {
            id: cred.id,
            name: cred.name,
            created_at: cred.created_at,
            last_used_at: cred.last_used_at,
            transports: cred.transports,
        }
    }
}

/// `TotpEnrollFinishRequest`'s dict response: `backup_codes`, plus
/// `access_token` when the setup flow logged the admin in.
#[derive(Debug, Clone, Serialize)]
struct TotpEnrollFinishResponse {
    backup_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
}

fn validate_len(field: &str, value: &str, max: usize) -> Result<(), ApiError> {
    if value.chars().count() > max {
        return Err(ApiError::unprocessable_entity(format!(
            "{field} must be at most {max} characters"
        )));
    }
    Ok(())
}

fn validate_optional_len(field: &str, value: &Option<String>, max: usize) -> Result<(), ApiError> {
    match value {
        Some(value) => validate_len(field, value, max),
        None => Ok(()),
    }
}

/// A non-empty optional body field (Python treats `""` as absent).
fn present(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/verify — two-step login verification
// ---------------------------------------------------------------------------

async fn verify_mfa(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<MfaVerifyRequest>, JsonRejection>,
) -> Result<Json<TokenResponse>, ApiError> {
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;

    let ip =
        client_ip(&headers, &state.config, peer_addr(peer)).unwrap_or_else(|| "unknown".into());
    let user = challenge_user(&state, &headers, MFA_SCOPE).await?;
    if !state.verify_limiter.allow(&format!("mfa:{ip}"))
        || !state.verify_limiter.allow(&format!("mfa:{}", user.id))
    {
        return Err(ApiError::too_many_requests("too many attempts; slow down"));
    }
    if !user.totp_enabled || user.totp_secret_enc.is_none() {
        return Err(ApiError::bad_request("TOTP not enabled"));
    }

    let mut ok = false;
    let mut method: Option<&str> = None;
    if let Some(code) = present(&body.code) {
        let secret = decrypt_totp_secret(&state, user.totp_secret_enc.as_deref().unwrap_or(""))
            .map_err(|_| ApiError::unauthorized("invalid code"))?;
        let step = crate::security::matched_step(&secret, code, now_unix());
        // Atomically claim the step → rejects replay even under concurrency.
        if let Some(step) = step {
            ok = crate::models::user::claim_totp_step(&state.pool, user.id, step as i64)
                .await
                .map_err(db_err)?;
            method = Some("totp");
        }
    } else if let Some(code) = present(&body.backup_code) {
        let hash = backup_code_hash(&state, code);
        ok = crate::models::webauthn::consume_backup_code(&state.pool, user.id, &hash)
            .await
            .map_err(db_err)?;
        method = Some("backup");
    }

    if !ok {
        record_audit(
            &state,
            AuditNew::new(ActorType::User, user.id.to_string(), "mfa_verify_failed"),
            Some(ip.clone()),
        )
        .await?;
        return Err(ApiError::unauthorized("invalid code"));
    }

    crate::models::user::touch_last_login(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    let mut new = AuditNew::new(ActorType::User, user.id.to_string(), "mfa_verify_success");
    new.detail = serde_json::json!({"method": method});
    record_audit(&state, new, Some(ip)).await?;
    Ok(Json(token_response(&state, &user)?))
}

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/totp/enroll/begin
// ---------------------------------------------------------------------------

async fn totp_enroll_begin(
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

async fn totp_enroll_finish(
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

async fn totp_disable(
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

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/totp/backup-codes/regenerate
// ---------------------------------------------------------------------------

async fn regenerate_backup_codes(
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

// ---------------------------------------------------------------------------
// WebAuthn / passkeys
// ---------------------------------------------------------------------------

/// `POST /api/auth/mfa/webauthn/register/begin` — phase 2 (ceremony crypto).
async fn webauthn_register_begin(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<StatusCode, ApiError> {
    let (_user, _is_setup) = enrolling_actor(&state, &headers, true).await?;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    Err(ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        WEBAUTHN_UNIMPLEMENTED,
    ))
}

/// `POST /api/auth/mfa/webauthn/register/finish` — phase 2 (ceremony crypto).
async fn webauthn_register_finish(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WebAuthnRegisterFinishRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let (_user, _is_setup) = enrolling_actor(&state, &headers, true).await?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    Err(ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        WEBAUTHN_UNIMPLEMENTED,
    ))
}

/// `POST /api/auth/mfa/webauthn/login/begin` — phase 2 (ceremony crypto).
/// Unauthenticated, like the Python login endpoints.
async fn webauthn_login_begin(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WebAuthnLoginBeginRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    Err(ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        WEBAUTHN_UNIMPLEMENTED,
    ))
}

/// `POST /api/auth/mfa/webauthn/login/finish` — phase 2 (ceremony crypto).
async fn webauthn_login_finish(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WebAuthnLoginFinishRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let _body = body.map_err(map_json_rejection)?.0;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    Err(ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        WEBAUTHN_UNIMPLEMENTED,
    ))
}

/// The per-IP guard the WebAuthn endpoints share (`mfa._webauthn_limiter`).
fn webauthn_guard(
    state: &AuthState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Result<(), ApiError> {
    let ip = client_ip(headers, &state.config, peer).unwrap_or_else(|| "unknown".into());
    if !state.webauthn_limiter.allow(&format!("wa:{ip}")) {
        return Err(ApiError::too_many_requests("too many attempts; slow down"));
    }
    Ok(())
}

/// `GET /api/auth/mfa/webauthn/credentials` — the caller's passkeys.
async fn list_passkeys(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Json<Vec<WebAuthnCredentialOut>>, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    let Some(user) = principal.user else {
        return Err(ApiError::not_found("no user for this principal"));
    };
    let creds = crate::models::webauthn::list_credentials(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    Ok(Json(creds.into_iter().map(Into::into).collect()))
}

/// `PUT /api/auth/mfa/webauthn/credentials/{cred_id}` — rename a passkey.
async fn rename_passkey(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(cred_id): Path<String>,
    body: Result<Json<WebAuthnRenameRequest>, JsonRejection>,
) -> Result<Json<WebAuthnCredentialOut>, ApiError> {
    // FastAPI solves `get_principal` before validating the path/body params.
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    let cred_id = parse_cred_id(&cred_id)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    let Some(user) = principal.user else {
        return Err(ApiError::not_found("no user for this principal"));
    };
    let cred = crate::models::webauthn::get_credential_by_id(&state.pool, cred_id)
        .await
        .map_err(db_err)?;
    let Some(cred) = cred.filter(|c| c.user_id == user.id) else {
        return Err(ApiError::not_found("passkey not found"));
    };
    let updated = crate::models::webauthn::rename_credential(&state.pool, cred.id, &body.name)
        .await
        .map_err(db_err)?
        .unwrap_or(cred);
    Ok(Json(updated.into()))
}

/// `DELETE /api/auth/mfa/webauthn/credentials/{cred_id}` — remove a passkey.
async fn delete_passkey(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(cred_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    let cred_id = parse_cred_id(&cred_id)?;
    let Some(user) = principal.user else {
        return Err(ApiError::not_found("no user for this principal"));
    };
    let cred = crate::models::webauthn::get_credential_by_id(&state.pool, cred_id)
        .await
        .map_err(db_err)?;
    let Some(cred) = cred.filter(|c| c.user_id == user.id) else {
        return Err(ApiError::not_found("passkey not found"));
    };
    // Lockout guard: a passwordless user with no TOTP must keep at least one key.
    if user.password_hash.is_none() && !user.totp_enabled {
        let remaining = crate::models::webauthn::count_credentials(&state.pool, user.id)
            .await
            .map_err(db_err)?;
        if remaining <= 1 {
            return Err(ApiError::bad_request(
                "cannot delete your only passkey; set a password or add another factor first",
            ));
        }
    }
    crate::models::webauthn::delete_credential(&state.pool, cred.id, user.id)
        .await
        .map_err(db_err)?;
    let mut new = AuditNew::new(ActorType::User, user.id.to_string(), "passkey_removed");
    new.detail = serde_json::json!({"name": cred.name});
    record_audit(
        &state,
        new,
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Path shape validation before auth (FastAPI validates params first).
fn parse_cred_id(raw: &str) -> Result<Uuid, ApiError> {
    raw.parse()
        .map_err(|_| ApiError::unprocessable_entity("cred_id must be a valid UUID"))
}

// ---------------------------------------------------------------------------
// MFA service helpers (app/services/mfa.py)
// ---------------------------------------------------------------------------

/// `mfa.store_backup_codes`: replace the user's codes with fresh HMAC hashes.
async fn store_backup_codes(
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::authapi::support::test_state;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(json!(null))
    }

    fn post(uri: &str, body: serde_json::Value) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

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

    // ---- schema validation ------------------------------------------------

    #[test]
    fn mfa_request_bounds_match_the_pydantic_fields() {
        assert!(MfaVerifyRequest::default().validate().is_ok());
        assert!(MfaVerifyRequest {
            code: Some("0123456789".into()),
            backup_code: Some("12345-67890".into())
        }
        .validate()
        .is_ok());
        assert!(MfaVerifyRequest {
            code: Some("01234567890".into()),
            backup_code: None
        }
        .validate()
        .is_err());
        assert!(
            MfaVerifyRequest {
                code: None,
                backup_code: Some("12345-67890123456".into())
            }
            .validate()
            .is_err(),
            "backup codes are capped at 16 characters"
        );

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

        assert!(WebAuthnRenameRequest { name: "key".into() }
            .validate()
            .is_ok());
        assert!(WebAuthnRenameRequest { name: "".into() }
            .validate()
            .is_err());
        assert!(WebAuthnRenameRequest {
            name: "x".repeat(256)
        }
        .validate()
        .is_err());
    }

    #[test]
    fn webauthn_credential_out_shape() {
        let out = WebAuthnCredentialOut {
            id: Uuid::nil(),
            name: "MacBook Touch ID".into(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            last_used_at: None,
            transports: Some(json!(["internal"])),
        };
        assert_eq!(
            serde_json::to_value(&out).unwrap(),
            json!({
                "id": "00000000-0000-0000-0000-000000000000",
                "name": "MacBook Touch ID",
                "created_at": "2024-01-01T00:00:00Z",
                "last_used_at": null,
                "transports": ["internal"],
            })
        );
    }

    // ---- HTTP-level (no database needed) ----------------------------------

    #[tokio::test]
    async fn verify_requires_a_challenge_token() {
        // No credentials at all.
        let response = crate::routes::authapi::router(test_state())
            .oneshot(post("/api/auth/mfa/verify", json!({"code": "123456"})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "challenge token required"})
        );

        // A plain access token is not an MFA challenge token.
        let state = test_state();
        let sub = Uuid::new_v4().to_string();
        let access = state
            .security
            .jwt()
            .create_access_token(&sub, "admin", 5)
            .unwrap();
        let mut request = post("/api/auth/mfa/verify", json!({"code": "123456"}));
        request
            .headers_mut()
            .insert("authorization", format!("Bearer {access}").parse().unwrap());
        let response = crate::routes::authapi::router(state)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "invalid challenge token"})
        );
    }

    #[tokio::test]
    async fn verify_validates_the_body_before_anything_else() {
        let response = crate::routes::authapi::router(test_state())
            .oneshot(post("/api/auth/mfa/verify", json!({"code": "01234567890"})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn webauthn_login_ceremonies_answer_501() {
        // Unauthenticated (the Python login endpoints are public): the stub is
        // what a client implementing phase 2 will find.
        let response = crate::routes::authapi::router(test_state())
            .oneshot(post("/api/auth/mfa/webauthn/login/begin", json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "webauthn not yet implemented in hub-rs"})
        );
    }

    #[tokio::test]
    async fn webauthn_registration_ceremonies_require_authentication() {
        // Registration is behind `enrolling_actor`: no token → 401, exactly
        // like the Python dependency order.
        let response = crate::routes::authapi::router(test_state())
            .oneshot(post("/api/auth/mfa/webauthn/register/begin", json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "authentication required"})
        );
    }

    #[tokio::test]
    async fn passkey_routes_reject_unauthenticated_calls_first() {
        // `get_principal` is a FastAPI dependency: it runs before the path/body
        // params are validated (see PARITY_HUB.md on error precedence).
        let response = crate::routes::authapi::router(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/auth/mfa/webauthn/credentials/not-a-uuid")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"name": "x"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

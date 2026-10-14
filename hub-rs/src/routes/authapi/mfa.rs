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
//! (register begin/finish, login begin/finish) are wired to
//! [`crate::services::webauthn`], which performs the attestation/assertion
//! verification (the `py_webauthn` port) over the same challenge/credential
//! storage as the Python hub — passkeys registered through either hub verify in
//! both. The *credential management* endpoints (list/rename/delete) are plain
//! CRUD over `webauthn_credentials`, ported unchanged.

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
use crate::services::webauthn::{self, AuthenticationOptions, RegistrationOptions};

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

/// `WebAuthnRegisterFinishRequest`'s dict response: `id` and `name`, plus
/// `access_token` when the setup flow logged the admin in (same key order).
#[derive(Debug, Clone, Serialize)]
struct WebAuthnRegisterFinishResponse {
    id: String,
    name: String,
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

/// `POST /api/auth/mfa/webauthn/register/begin` — registration options plus a
/// stored single-use challenge (`webauthn.begin_registration`).
async fn webauthn_register_begin(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Json<RegistrationOptions>, ApiError> {
    let (user, _is_setup) = enrolling_actor(&state, &headers, true).await?;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    let options = webauthn::begin_registration(&state.pool, &state.config, &user)
        .await
        .map_err(webauthn_bad_request)?;
    Ok(Json(options))
}

/// `POST /api/auth/mfa/webauthn/register/finish` — verify the attestation and
/// store the passkey (`webauthn.finish_registration`).
async fn webauthn_register_finish(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WebAuthnRegisterFinishRequest>, JsonRejection>,
) -> Result<Json<WebAuthnRegisterFinishResponse>, ApiError> {
    let (user, is_setup) = enrolling_actor(&state, &headers, true).await?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    let cred = webauthn::finish_registration(
        &state.pool,
        &state.config,
        &user,
        &body.name,
        &body.credential,
    )
    .await
    .map_err(webauthn_bad_request)?;
    let mut new = AuditNew::new(ActorType::User, user.id.to_string(), "passkey_added");
    new.detail = serde_json::json!({"name": cred.name, "aaguid": cred.aaguid});
    record_audit(
        &state,
        new,
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    // Setup flow (admin first-time) came in with only a setup token → log them in.
    let access_token = if is_setup {
        Some(token_response(&state, &user)?.access_token)
    } else {
        None
    };
    Ok(Json(WebAuthnRegisterFinishResponse {
        id: cred.id.to_string(),
        name: cred.name,
        access_token,
    }))
}

/// `POST /api/auth/mfa/webauthn/login/begin` — discoverable-credential options
/// plus a stored single-use challenge (`webauthn.begin_login`). Unauthenticated,
/// like the Python login endpoints.
async fn webauthn_login_begin(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WebAuthnLoginBeginRequest>, JsonRejection>,
) -> Result<Json<AuthenticationOptions>, ApiError> {
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    let options = webauthn::begin_login(&state.pool, &state.config, body.username.as_deref())
        .await
        .map_err(webauthn_bad_request)?;
    Ok(Json(options))
}

/// `POST /api/auth/mfa/webauthn/login/finish` — verify the assertion
/// (counter-based clone detection included) and issue an access token
/// (`webauthn.finish_login`).
async fn webauthn_login_finish(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WebAuthnLoginFinishRequest>, JsonRejection>,
) -> Result<Json<TokenResponse>, ApiError> {
    let body = body.map_err(map_json_rejection)?.0;
    let ip = client_ip(&headers, &state.config, peer_addr(peer)).unwrap_or_else(|| "unknown".into());
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    let user = match webauthn::finish_login(&state.pool, &state.config, &body.credential).await {
        Ok(user) => user,
        // Infrastructure failures stay 500s; ceremony failures are an audit
        // event plus the generic 401 (Python never leaks the reason).
        Err(webauthn::WebAuthnError::Db(err)) => return Err(db_err(err)),
        Err(exc) => {
            let mut new = AuditNew::new(ActorType::System, "webauthn", "webauthn_login_failed");
            new.detail = serde_json::json!({"reason": exc.to_string()});
            record_audit(&state, new, Some(ip)).await?;
            return Err(ApiError::unauthorized("passkey authentication failed"));
        }
    };
    crate::models::user::touch_last_login(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    record_audit(
        &state,
        AuditNew::new(ActorType::User, user.id.to_string(), "webauthn_login"),
        Some(ip),
    )
    .await?;
    Ok(Json(token_response(&state, &user)?))
}

/// `webauthn_service.WebAuthnError` → the `HTTPException(400, str(exc))` of the
/// begin/finish registration and login-begin handlers.
fn webauthn_bad_request(err: webauthn::WebAuthnError) -> ApiError {
    match err {
        webauthn::WebAuthnError::Db(err) => db_err(err),
        other => ApiError::bad_request(other.to_string()),
    }
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
    async fn webauthn_login_ceremonies_validate_the_body_first() {
        // The Python endpoints are public but schema-checked (pydantic → 422)
        // before anything else runs — including before the rate limiter.
        let response = crate::routes::authapi::router(test_state())
            .oneshot(post(
                "/api/auth/mfa/webauthn/login/begin",
                json!({"username": "x".repeat(256)}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
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

#[cfg(test)]
mod live_tests {
    //! Full WebAuthn ceremonies against a live PostgreSQL: the payloads are
    //! fabricated but cryptographically valid (real COSE keys, real
    //! signatures), so attestation/assertion verification runs for real.
    //! Skipped unless `HUGINN_TEST_DATABASE_URL` is set — `cargo test` stays
    //! green without a database, like `db.rs`/`models::live_tests`.
    //!
    //! Not covered here (documented in the handover report): a real browser
    //! driving `navigator.credentials.*`, and the `tpm`/`apple`/`android-*`
    //! attestation formats which are rejected by design.
    use super::*;
    use crate::config::Config;
    use crate::models::user::UserNew;
    use crate::services::webauthn::b64u_decode;
    use crate::services::webauthn::test_support::{
        attestation_object, auth_data_bytes, authentication_credential, client_data_json,
        registration_credential, FabricatedKey, ORIGIN, RP_ID,
    };
    use axum::body::Body;
    use ciborium::value::Value;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    /// UP|UV|AT — the flags a real passkey asserts during registration.
    const REG_FLAGS: u8 = 0x45;
    /// UP|UV — the flags a real passkey asserts during login.
    const AUTH_FLAGS: u8 = 0x05;

    fn wa_config() -> Config {
        Config {
            webauthn_rp_id: RP_ID.into(),
            webauthn_rp_name: "Huginn".into(),
            webauthn_origin: ORIGIN.into(),
            webauthn_user_verification: "preferred".into(),
            ..Config::default()
        }
    }

    async fn fresh_state(
        config: Config,
    ) -> Option<(AuthState, tokio::sync::MutexGuard<'static, ()>)> {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return None;
        };
        let guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = crate::db::connect(&url, 4).await.expect("connect");
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(&pool)
            .await
            .expect("drop schema");
        sqlx::query("CREATE SCHEMA public")
            .execute(&pool)
            .await
            .expect("create schema");
        crate::db::run_migrations(&pool).await.expect("migrations");
        Some((AuthState::new(pool, config), guard))
    }

    async fn make_user(state: &AuthState, username: &str) -> Uuid {
        crate::models::user::create(
            &state.pool,
            UserNew {
                username: username.into(),
                password_hash: Some(crate::security::hash_password("correct horse battery").unwrap()),
                role: crate::models::enums::UserRole::Readonly,
                is_active: true,
                ..UserNew::default()
            },
        )
        .await
        .unwrap()
        .id
    }

    fn request(
        method: &str,
        uri: &str,
        body: serde_json::Value,
        token: Option<&str>,
    ) -> axum::http::Request<Body> {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if !body.is_null() {
            builder = builder.header("content-type", "application/json");
        }
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder
            .body(Body::from(if body.is_null() {
                String::new()
            } else {
                body.to_string()
            }))
            .unwrap()
    }

    async fn send(
        state: &AuthState,
        request: axum::http::Request<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let response = crate::routes::authapi::router(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(json!(null));
        (status, body)
    }

    /// A registration payload bound to `challenge`, like a real authenticator.
    fn make_attestation(
        key: &FabricatedKey,
        challenge: &[u8],
        credential_id: &[u8],
        counter: u32,
    ) -> serde_json::Value {
        let aaguid = [0x22u8; 16];
        let auth_data = auth_data_bytes(
            RP_ID,
            REG_FLAGS,
            counter,
            Some((&aaguid, credential_id, key.cose())),
        );
        let cdj = client_data_json("webauthn.create", challenge, ORIGIN);
        let att = attestation_object("none", Value::Map(Vec::new()), &auth_data);
        registration_credential(credential_id, &cdj, &att, Some(json!(["internal"])))
    }

    /// An assertion bound to `challenge`, signed like a real authenticator.
    fn make_assertion(
        key: &FabricatedKey,
        challenge: &[u8],
        credential_id: &[u8],
        counter: u32,
    ) -> serde_json::Value {
        let auth_data = auth_data_bytes(RP_ID, AUTH_FLAGS, counter, None);
        let cdj = client_data_json("webauthn.get", challenge, ORIGIN);
        let mut signature_base = auth_data.clone();
        signature_base.extend_from_slice(&client_data_hash(&cdj));
        let signature = key.sign(&signature_base);
        authentication_credential(credential_id, &cdj, &auth_data, &signature)
    }

    fn challenge_bytes(options: &serde_json::Value) -> Vec<u8> {
        b64u_decode(options["challenge"].as_str().unwrap()).unwrap()
    }

    fn client_data_hash(cdj: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(cdj).to_vec()
    }

    #[tokio::test]
    async fn webauthn_register_and_login_ceremonies_end_to_end() {
        let Some((state, _guard)) = fresh_state(wa_config()).await else {
            return;
        };
        let user_id = make_user(&state, "pk-user").await;
        let token = state
            .security
            .jwt()
            .create_access_token(&user_id.to_string(), "readonly", 5)
            .unwrap();
        let auth = Some(token.as_str());
        let key = FabricatedKey::es256();
        let credential_id = b"live-test-credential-id-32byte";

        // --- register/begin: options mirror py_webauthn byte for byte.
        let (status, options) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/begin",
                json!({}),
                auth,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        assert_eq!(options["rp"], json!({"name": "Huginn", "id": RP_ID}));
        assert_eq!(
            options["user"]["id"],
            json!(crate::services::webauthn::b64u_encode(user_id.to_string().as_bytes()))
        );
        assert_eq!(
            options["pubKeyCredParams"],
            json!([
                {"type": "public-key", "alg": -8},
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257}
            ])
        );
        assert_eq!(options["timeout"], json!(60000));
        assert_eq!(
            options["authenticatorSelection"],
            json!({"residentKey": "preferred", "requireResidentKey": false, "userVerification": "preferred"})
        );
        assert_eq!(options["attestation"], json!("none"));

        // --- register/finish with a fabricated-but-valid attestation.
        let challenge = challenge_bytes(&options);
        let credential = make_attestation(&key, &challenge, credential_id, 0);
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/finish",
                json!({"name": "Test Key", "credential": credential}),
                auth,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["name"], json!("Test Key"));
        assert!(body["id"].is_string());
        assert!(body.get("access_token").is_none(), "no login outside setup flow");

        // --- challenge reuse is rejected (single-use claim in SQL).
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/finish",
                json!({"name": "Again", "credential": credential}),
                auth,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"detail": "unknown, used, or expired challenge"}));

        // --- wrong origin / wrong rp binding → generic verification failure.
        for (kind, cdj_origin, rp_id) in [
            ("origin", "https://evil.example.com", RP_ID),
            ("rp_id", ORIGIN, "other.example.com"),
        ] {
            let challenge = challenge_bytes(&options);
            let aaguid = [0x22u8; 16];
            let auth_data = auth_data_bytes(
                rp_id,
                REG_FLAGS,
                0,
                Some((&aaguid, credential_id, key.cose())),
            );
            let cdj = client_data_json("webauthn.create", &challenge, cdj_origin);
            let att_obj = attestation_object("none", Value::Map(Vec::new()), &auth_data);
            let att = registration_credential(credential_id, &cdj, &att_obj, None);
            let (status, body) = send(
                &state,
                request(
                    "POST",
                    "/api/auth/mfa/webauthn/register/finish",
                    json!({"name": kind, "credential": att}),
                    auth,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{kind}: {body}");
            assert_eq!(body, json!({"detail": "registration verification failed"}));
        }

        // --- login/begin (public, discoverable) → options without allowCredentials.
        let (status, options) = send(
            &state,
            request("POST", "/api/auth/mfa/webauthn/login/begin", json!({}), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        assert_eq!(options["rpId"], json!(RP_ID));
        assert_eq!(options["allowCredentials"], json!([]));

        // --- login/finish: counter 0 → 1 (both-zero start is legitimate).
        let challenge = challenge_bytes(&options);
        let credential = make_assertion(&key, &challenge, credential_id, 1);
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/login/finish",
                json!({"credential": credential}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["access_token"].is_string());
        assert_eq!(body["token_type"], json!("bearer"));

        // --- replaying the same (now consumed) challenge fails with the generic 401.
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/login/finish",
                json!({"credential": credential}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"detail": "passkey authentication failed"}));

        // --- clone detection: a counter that does not advance is rejected.
        let (status, options) = send(
            &state,
            request("POST", "/api/auth/mfa/webauthn/login/begin", json!({}), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let challenge = challenge_bytes(&options);
        let stale = make_assertion(&key, &challenge, credential_id, 1); // stored is 1
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/login/finish",
                json!({"credential": stale}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"detail": "passkey authentication failed"}));

        // --- an advancing counter logs in again.
        let (status, options) = send(
            &state,
            request("POST", "/api/auth/mfa/webauthn/login/begin", json!({}), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let challenge = challenge_bytes(&options);
        let advancing = make_assertion(&key, &challenge, credential_id, 2);
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/login/finish",
                json!({"credential": advancing}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn webauthn_challenges_are_bound_to_their_user() {
        let Some((state, _guard)) = fresh_state(wa_config()).await else {
            return;
        };
        let user_a = make_user(&state, "alice").await;
        let user_b = make_user(&state, "bob").await;
        let token_a = state
            .security
            .jwt()
            .create_access_token(&user_a.to_string(), "readonly", 5)
            .unwrap();
        let token_b = state
            .security
            .jwt()
            .create_access_token(&user_b.to_string(), "readonly", 5)
            .unwrap();

        let (status, options) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/begin",
                json!({}),
                Some(&token_a),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        let challenge = challenge_bytes(&options);
        let key = FabricatedKey::es256();
        let credential = make_attestation(&key, &challenge, b"alice-credential-id-32bytes!!", 0);

        // Bob cannot finish Alice's ceremony.
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/finish",
                json!({"name": "stolen", "credential": credential}),
                Some(&token_b),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"detail": "challenge does not belong to this user"}));
    }

    #[tokio::test]
    async fn webauthn_setup_flow_logs_the_admin_in() {
        let Some((state, _guard)) = fresh_state(wa_config()).await else {
            return;
        };
        let user_id = make_user(&state, "admin").await;
        let setup_token = state
            .security
            .jwt()
            .create_mfa_challenge_token(
                &user_id.to_string(),
                crate::security::jwt::MFA_SETUP_SCOPE,
                5,
            )
            .unwrap();

        let (status, options) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/begin",
                json!({}),
                Some(&setup_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        let challenge = challenge_bytes(&options);
        let key = FabricatedKey::es256();
        let credential = make_attestation(&key, &challenge, b"setup-credential-id-32bytes!!!", 0);
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/finish",
                json!({"name": "First passkey", "credential": credential}),
                Some(&setup_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // Setup flow (admin first-time) came in with only a setup token → login.
        assert!(body["access_token"].is_string());
    }

    #[tokio::test]
    async fn webauthn_not_configured_fails_closed() {
        // No rp_id/origin at all.
        let Some((state, _guard)) = fresh_state(Config::default()).await else {
            return;
        };
        let user_id = make_user(&state, "pk-user").await;
        let token = state
            .security
            .jwt()
            .create_access_token(&user_id.to_string(), "readonly", 5)
            .unwrap();
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/begin",
                json!({}),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"detail": "WebAuthn is not configured"}));
    }

    #[tokio::test]
    async fn webauthn_rejects_an_ip_rp_id() {
        let Some((state, _guard)) = fresh_state(Config {
            webauthn_rp_id: "192.0.2.13".into(),
            webauthn_origin: "https://192.0.2.13".into(),
            ..Config::default()
        })
        .await
        else {
            return;
        };
        let user_id = make_user(&state, "pk-user").await;
        let token = state
            .security
            .jwt()
            .create_access_token(&user_id.to_string(), "readonly", 5)
            .unwrap();
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/begin",
                json!({}),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            json!({"detail": "webauthn_rp_id must be a registrable domain, not an IP"})
        );
    }

    #[tokio::test]
    async fn webauthn_settings_row_overrides_the_env_config() {
        let Some((state, _guard)) = fresh_state(Config::default()).await else {
            return;
        };
        crate::models::setting::upsert(
            &state.pool,
            crate::models::setting::SettingValues {
                webauthn_rp_id: RP_ID.into(),
                webauthn_rp_name: "Fleet".into(),
                webauthn_origin: ORIGIN.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let user_id = make_user(&state, "pk-user").await;
        let token = state
            .security
            .jwt()
            .create_access_token(&user_id.to_string(), "readonly", 5)
            .unwrap();
        let (status, options) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/begin",
                json!({}),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        // DB row wins over env, exactly like `webauthn.rp_config`.
        assert_eq!(options["rp"], json!({"name": "Fleet", "id": RP_ID}));
    }
}

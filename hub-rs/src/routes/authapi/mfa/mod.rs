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

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;

use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::enums::ActorType;
use crate::security::jwt::MFA_SCOPE;

use self::backup_codes::regenerate_backup_codes;
use self::totp::{totp_disable, totp_enroll_begin, totp_enroll_finish};
use self::webauthn::{
    delete_passkey, list_passkeys, rename_passkey, webauthn_login_begin, webauthn_login_finish,
    webauthn_register_begin, webauthn_register_finish,
};
use super::{
    backup_code_hash, challenge_user, client_ip, db_err, decrypt_totp_secret, encrypt_totp_secret,
    enrolling_actor, generate_backup_codes, get_principal, map_json_rejection, peer_addr,
    record_audit, set_pending_totp_secret, token_response, AuthState, TokenResponse,
};

// ---------------------------------------------------------------------------
// Submodules — one per second factor
// ---------------------------------------------------------------------------

mod backup_codes;
mod totp;
mod webauthn;

#[cfg(test)]
pub(crate) mod live_tests;

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
// Tests
// ---------------------------------------------------------------------------

/// Shared request/response helpers for the route tests.
#[cfg(test)]
pub(crate) mod support {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::json;

    pub(crate) async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(json!(null))
    }

    pub(crate) fn post(uri: &str, body: serde_json::Value) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::support::{body_json, post};
    use super::*;
    use axum::http::StatusCode;
    use serde_json::json;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::routes::authapi::support::test_state;

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
}

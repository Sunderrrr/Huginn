//! Passkey (WebAuthn) management — the registration/login ceremonies and the
//! credential list (`app/api/routes/mfa.py` webauthn handlers).

use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::enums::ActorType;
use crate::services::webauthn::{self, AuthenticationOptions, RegistrationOptions};

use super::{
    client_ip, db_err, enrolling_actor, get_principal, map_json_rejection, peer_addr,
    purge_expired_webauthn_challenges, record_audit, token_response, validate_len,
    validate_optional_len, AuthState, TokenResponse,
};

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

/// `WebAuthnRegisterFinishRequest`'s dict response: `id` and `name`, plus
/// `access_token` when the setup flow logged the admin in (same key order).
#[derive(Debug, Clone, Serialize)]
pub(super) struct WebAuthnRegisterFinishResponse {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
}

// ---------------------------------------------------------------------------
// WebAuthn / passkeys
// ---------------------------------------------------------------------------

/// `POST /api/auth/mfa/webauthn/register/begin` — registration options plus a
/// stored single-use challenge (`webauthn.begin_registration`).
pub(super) async fn webauthn_register_begin(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Json<RegistrationOptions>, ApiError> {
    let (user, _is_setup) = enrolling_actor(&state, &headers, true).await?;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    // Opportunistic cleanup of the challenges that can no longer be used.
    purge_expired_webauthn_challenges(&state).await;
    let options = webauthn::begin_registration(&state.pool, &state.config, &user)
        .await
        .map_err(webauthn_bad_request)?;
    Ok(Json(options))
}

/// `POST /api/auth/mfa/webauthn/register/finish` — verify the attestation and
/// store the passkey (`webauthn.finish_registration`).
pub(super) async fn webauthn_register_finish(
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
pub(super) async fn webauthn_login_begin(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WebAuthnLoginBeginRequest>, JsonRejection>,
) -> Result<Json<AuthenticationOptions>, ApiError> {
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    webauthn_guard(&state, &headers, peer_addr(peer))?;
    // Opportunistic cleanup of the challenges that can no longer be used.
    purge_expired_webauthn_challenges(&state).await;
    let options = webauthn::begin_login(&state.pool, &state.config, body.username.as_deref())
        .await
        .map_err(webauthn_bad_request)?;
    Ok(Json(options))
}

/// `POST /api/auth/mfa/webauthn/login/finish` — verify the assertion
/// (counter-based clone detection included) and issue an access token
/// (`webauthn.finish_login`).
pub(super) async fn webauthn_login_finish(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WebAuthnLoginFinishRequest>, JsonRejection>,
) -> Result<Json<TokenResponse>, ApiError> {
    let body = body.map_err(map_json_rejection)?.0;
    let ip =
        client_ip(&headers, &state.config, peer_addr(peer)).unwrap_or_else(|| "unknown".into());
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
pub(super) async fn list_passkeys(
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
pub(super) async fn rename_passkey(
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
pub(super) async fn delete_passkey(
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
    // L-6: lockout guard — refuse to delete the last passkey of a user who has
    // neither a password nor active TOTP (they would be locked out). The count
    // and the delete are ONE statement, so two concurrent requests can no
    // longer each observe "more than one key" and both delete.
    if !crate::models::webauthn::delete_credential_guarded(&state.pool, cred.id, user.id)
        .await
        .map_err(db_err)?
    {
        return Err(ApiError::bad_request(
            "cannot delete your only passkey; set a password or add another factor first",
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::super::support::*;
    use super::*;
    use axum::body::Body;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::routes::authapi::support::test_state;

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

    #[test]
    fn webauthn_rename_request_bounds_match_the_pydantic_field() {
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

    // ---- HTTP-level (no database needed) ----------------------------------

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

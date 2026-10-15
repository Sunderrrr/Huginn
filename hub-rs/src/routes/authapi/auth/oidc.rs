//! OIDC / SSO login (`app/api/routes/auth.py` oidc handlers): the state/nonce
//! cookie dance, the authorization redirect and the callback exchange.

use axum::extract::{ConnectInfo, Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::enums::ActorType;
use crate::services::oidc::{self, OidcClient, OidcConfig};

use std::net::SocketAddr;

use super::super::RateLimiter;
use super::{client_ip, db_err, peer_addr, record_audit, token_response, AuthState};

// ---------------------------------------------------------------------------
// GET /api/auth/oidc/login + GET /api/auth/oidc/callback (OIDC / SSO)
// ---------------------------------------------------------------------------

/// `OIDCStartResponse` (`app/schemas/auth.py`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OIDCStartResponse {
    pub authorization_url: String,
    pub state: String,
}

/// Query for the OIDC callback (`?code=...&state=...`).
#[derive(Debug, Deserialize)]
pub(super) struct OidcCallbackQuery {
    code: String,
    state: String,
}

const OIDC_STATE_COOKIE: &str = "huginn_oidc_state";
const OIDC_NONCE_COOKIE: &str = "huginn_oidc_nonce";

/// Per-IP guard on the OIDC start/callback endpoints (10/minute — `auth._oidc_limiter`).
fn oidc_limiter() -> &'static RateLimiter {
    use std::sync::OnceLock;
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(10))
}

/// Prefer the admin-configured DB settings row; fall back to env config
/// (`auth._oidc_source`). Both sources expose the same OIDC attribute names, so
/// [`OidcConfig`] works with either.
async fn oidc_source(state: &AuthState) -> Result<OidcConfig, ApiError> {
    let row = crate::models::setting::get_settings_row(&state.pool)
        .await
        .map_err(db_err)?;
    Ok(match &row {
        Some(r) if r.oidc_enabled => OidcConfig::from_setting(r),
        _ => OidcConfig::from_config(&state.config),
    })
}

/// Read a named cookie from the `Cookie` request header.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

/// `_oidc_cookie_kwargs`: HttpOnly, Secure (prod), SameSite=Lax, Max-Age, Path=/.
fn set_cookie(name: &str, value: &str, is_prod: bool, max_age: i64) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}",
        secure = if is_prod { "; Secure" } else { "" }
    )
}

fn delete_cookie(name: &str, is_prod: bool) -> String {
    format!(
        "{name}=; Path=/; Max-Age=0{secure}",
        secure = if is_prod { "; Secure" } else { "" }
    )
}

fn append_set_cookie(map: &mut HeaderMap, value: String) -> Result<(), ApiError> {
    let hv =
        header::HeaderValue::from_str(&value).map_err(|_| ApiError::internal("invalid cookie"))?;
    map.append(header::SET_COOKIE, hv);
    Ok(())
}

pub(super) async fn oidc_login(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Response, ApiError> {
    let ip =
        client_ip(&headers, &state.config, peer_addr(peer)).unwrap_or_else(|| "unknown".into());
    if !oidc_limiter().allow(&format!("oidc:{ip}")) {
        return Err(ApiError::too_many_requests(
            "too many OIDC attempts; slow down",
        ));
    }
    let config = oidc_source(&state).await?;
    let client = OidcClient::new(config);
    if !client.is_enabled() {
        return Err(ApiError::not_found("OIDC is not enabled"));
    }
    let state_param = OidcClient::new_state();
    let nonce = OidcClient::new_nonce();
    let url = client
        .authorization_url(&state_param, &nonce)
        .await
        .map_err(|e| {
            tracing::warn!("OIDC authorization URL failed: {e}");
            ApiError::internal("OIDC configuration or discovery failed")
        })?;
    // Bind state (CSRF) and nonce (id_token replay protection) to the browser
    // via HttpOnly cookies, checked on the callback.
    let is_prod = state.config.is_prod();
    let mut resp_headers = HeaderMap::new();
    append_set_cookie(
        &mut resp_headers,
        set_cookie(OIDC_STATE_COOKIE, &state_param, is_prod, 600),
    )?;
    append_set_cookie(
        &mut resp_headers,
        set_cookie(OIDC_NONCE_COOKIE, &nonce, is_prod, 600),
    )?;
    let body = OIDCStartResponse {
        authorization_url: url,
        state: state_param,
    };
    Ok((StatusCode::OK, resp_headers, Json(body)).into_response())
}

pub(super) async fn oidc_callback(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<Response, ApiError> {
    let ip =
        client_ip(&headers, &state.config, peer_addr(peer)).unwrap_or_else(|| "unknown".into());
    if !oidc_limiter().allow(&format!("oidc:{ip}")) {
        return Err(ApiError::too_many_requests(
            "too many OIDC attempts; slow down",
        ));
    }
    // State (CSRF): the cookie we set at /oidc/login must match the query param.
    let state_ok = cookie_value(&headers, OIDC_STATE_COOKIE)
        .map(|cs| crate::security::constant_time_equals(&cs, &query.state))
        .unwrap_or(false);
    if !state_ok {
        return Err(ApiError::bad_request("invalid OIDC state"));
    }
    let nonce = cookie_value(&headers, OIDC_NONCE_COOKIE);

    let config = oidc_source(&state).await?;
    let client = OidcClient::new(config);
    let claims = client
        .exchange_code(&query.code, nonce.as_deref())
        .await
        .map_err(|e| {
            tracing::warn!("OIDC callback failed: {e}");
            ApiError::unauthorized("OIDC authentication failed")
        })?;

    let user = oidc::upsert_oidc_user(
        &state.pool,
        &claims.subject,
        &claims.username,
        claims.email.as_deref(),
    )
    .await
    .map_err(db_err)?;
    record_audit(
        &state,
        {
            let mut new = AuditNew::new(ActorType::User, user.id.to_string(), "login");
            new.detail = serde_json::json!({"method": "oidc"});
            new
        },
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;

    let token = token_response(&state, &user)?;
    let is_prod = state.config.is_prod();
    // If a SPA dashboard URL is configured, hand the token back via the URL
    // fragment (never logged by servers/proxies) and redirect the browser there.
    let post_login_redirect = {
        let src = client.config().post_login_redirect.as_str();
        if !src.is_empty() {
            src.to_owned()
        } else {
            state.config.oidc_post_login_redirect.clone()
        }
    };
    if !post_login_redirect.is_empty() {
        let mut resp_headers = HeaderMap::new();
        let location = format!("{post_login_redirect}#access_token={}", token.access_token);
        let hv = header::HeaderValue::from_str(&location)
            .map_err(|_| ApiError::internal("invalid redirect"))?;
        resp_headers.insert(header::LOCATION, hv);
        append_set_cookie(&mut resp_headers, delete_cookie(OIDC_STATE_COOKIE, is_prod))?;
        append_set_cookie(&mut resp_headers, delete_cookie(OIDC_NONCE_COOKIE, is_prod))?;
        return Ok((StatusCode::SEE_OTHER, resp_headers).into_response());
    }
    let mut resp_headers = HeaderMap::new();
    append_set_cookie(&mut resp_headers, delete_cookie(OIDC_STATE_COOKIE, is_prod))?;
    append_set_cookie(&mut resp_headers, delete_cookie(OIDC_NONCE_COOKIE, is_prod))?;
    Ok((StatusCode::OK, resp_headers, Json(token)).into_response())
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::*;
    use axum::body::Body;
    use serde_json::json;
    use tower::ServiceExt;

    // ---- OIDC callback state (CSRF) -------------------------------------

    #[tokio::test]
    async fn oidc_callback_rejects_a_missing_or_mismatched_state() {
        // The state check runs before any database or network work, so this
        // exercises the CSRF guard on the lazy pool. A cookie that does not
        // match the query param (or no cookie at all) must be rejected.
        for cookie in [None, Some("huginn_oidc_state=not-the-same")] {
            let mut builder = axum::http::Request::builder()
                .method("GET")
                .uri("/api/auth/oidc/callback?code=abc&state=expected");
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            let response = router_with_state()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                body_json(response).await,
                json!({"detail": "invalid OIDC state"})
            );
        }
    }
}

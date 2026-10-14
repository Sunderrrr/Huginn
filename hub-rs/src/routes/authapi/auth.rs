//! Authentication endpoints: local login, current user and logout —
//! port of `hub/app/api/routes/auth.py` (the OIDC endpoints are phase 2, see
//! `PARITY_HUB.md`).

use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::enums::ActorType;
use crate::models::setting::Setting;
use crate::security::jwt::{MFA_SCOPE, MFA_SETUP_SCOPE};
use crate::services::ldap::{self, LdapClient, LdapConfig};
use crate::services::oidc::{self, OidcClient, OidcConfig};

use super::{
    authenticate, client_ip, db_err, get_principal, map_json_rejection, peer_addr, record_audit,
    set_user_email, token_response, user_out, AuthState, TokenResponse, UserOut,
};

pub fn router() -> Router<AuthState> {
    Router::new()
        .route("/api/auth/config", get(auth_config))
        .route("/api/auth/login", post(login))
        .route("/api/auth/me", get(me).put(update_me))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/oidc/login", get(oidc_login))
        .route("/api/auth/oidc/callback", get(oidc_callback))
}

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/auth.py)
// ---------------------------------------------------------------------------

/// `LoginRequest`. Length caps bound Argon2 work (anti-DoS).
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl LoginRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.username.chars().count() > 255 {
            return Err(ApiError::unprocessable_entity(
                "username must be at most 255 characters",
            ));
        }
        if self.password.chars().count() > 128 {
            return Err(ApiError::unprocessable_entity(
                "password must be at most 128 characters",
            ));
        }
        Ok(())
    }
}

/// `LoginChallengeResponse` — returned by `/login` when a second factor (or
/// first-time setup) is needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginChallengeResponse {
    pub mfa_required: bool,
    pub mfa_setup_required: bool,
    pub challenge_token: String,
    pub methods: Vec<String>,
}

impl LoginChallengeResponse {
    /// Password OK, awaiting TOTP/backup verification (scope `mfa`).
    pub fn mfa_required(challenge_token: String) -> Self {
        Self {
            mfa_required: true,
            mfa_setup_required: false,
            challenge_token,
            methods: vec!["totp".into(), "backup".into()],
        }
    }

    /// Admin must enrol a factor before proceeding (scope `mfa_setup`).
    pub fn mfa_setup_required(challenge_token: String) -> Self {
        Self {
            mfa_required: false,
            mfa_setup_required: true,
            challenge_token,
            methods: vec!["totp".into(), "webauthn".into()],
        }
    }
}

/// `UpdateProfileRequest` (self-service, currently just email).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub email: Option<String>,
}

impl UpdateProfileRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if let Some(email) = &self.email {
            if email.chars().count() > 320 {
                return Err(ApiError::unprocessable_entity(
                    "email must be at most 320 characters",
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// GET /api/auth/config
// ---------------------------------------------------------------------------

/// What the login page needs to render itself. Public, unauthenticated: tells
/// the SPA which auth methods to show (SSO button + label, password form,
/// passkey button). No secrets here — only enable flags and the display name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthConfigResponse {
    pub oidc_enabled: bool,
    pub oidc_provider_name: String,
    pub password_login_enabled: bool,
    pub webauthn_enabled: bool,
}

/// `auth_config`'s exact dict logic: the DB settings row with env fallbacks.
pub(crate) fn auth_config_for(row: Option<&Setting>, config: &Config) -> AuthConfigResponse {
    let oidc_enabled = row.is_some_and(|r| {
        r.oidc_enabled && !r.oidc_issuer.is_empty() && !r.oidc_client_id.is_empty()
    });
    let name = row
        .map(|r| r.oidc_provider_name.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("SSO");
    // Env var force-enables (the documented "unsafe" escape hatch); the DB row
    // can also enable it. Either source counts.
    let allow_pw = config.allow_password_login || row.is_some_and(|r| r.allow_password_login);
    let password_login_enabled = !oidc_enabled || allow_pw;
    // Mirror webauthn.rp_config's DB→env fallback so the button shows whenever
    // passkeys are actually usable (RP id + origin configured by either source).
    let rp_id = non_empty(row.map(|r| r.webauthn_rp_id.as_str())).unwrap_or(&config.webauthn_rp_id);
    let rp_origin =
        non_empty(row.map(|r| r.webauthn_origin.as_str())).unwrap_or(&config.webauthn_origin);
    AuthConfigResponse {
        oidc_enabled,
        oidc_provider_name: name.to_owned(),
        password_login_enabled,
        webauthn_enabled: !rp_id.is_empty() && !rp_origin.is_empty(),
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|s| !s.is_empty())
}

async fn auth_config(State(state): State<AuthState>) -> Result<Json<AuthConfigResponse>, ApiError> {
    let row = crate::models::setting::get_settings_row(&state.pool)
        .await
        .map_err(db_err)?;
    Ok(Json(auth_config_for(row.as_ref(), &state.config)))
}

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------

/// First factor OK — branch on the second factor (`login`'s tail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginOutcome {
    /// User with TOTP enabled: challenge token (scope `mfa`).
    MfaChallenge,
    /// Admin without any factor (and `require_admin_mfa`): setup token.
    MfaSetupRequired,
    /// No second factor needed: issue an access token.
    IssueToken,
}

pub(crate) fn decide_second_factor(
    user: &crate::models::user::User,
    require_admin_mfa: bool,
    passkey_count: i64,
) -> LoginOutcome {
    if user.totp_enabled {
        return LoginOutcome::MfaChallenge;
    }
    let has_mfa = user.totp_enabled || passkey_count > 0;
    if user.is_admin() && require_admin_mfa && !has_mfa {
        return LoginOutcome::MfaSetupRequired;
    }
    LoginOutcome::IssueToken
}

/// `POST /login` answers with either shape (Python returns `TokenResponse |
/// LoginChallengeResponse`).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Token(TokenResponse),
    Challenge(LoginChallengeResponse),
}

async fn login(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Pydantic validates the body before the handler runs.
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;

    let ip =
        client_ip(&headers, &state.config, peer_addr(peer)).unwrap_or_else(|| "unknown".into());
    // Block only when too many *failed* attempts have accumulated for this IP,
    // so legitimate logins are never throttled but brute force is.
    if !state.login_limiter.check(&format!("login:{ip}")) {
        return Err(ApiError::too_many_requests(
            "too many failed login attempts; slow down",
        ));
    }

    let settings_row = crate::models::setting::get_settings_row(&state.pool)
        .await
        .map_err(db_err)?;
    let row = settings_row.as_ref();
    // SSO-first: when OIDC is active, the password form is disabled unless it's
    // re-enabled — via the env "unsafe" flag OR the admin-set DB row. With OIDC
    // off, password login is always available (no lockout).
    let oidc_enabled = row.is_some_and(|r| r.oidc_enabled && !r.oidc_issuer.is_empty());
    let allow_pw = state.config.allow_password_login || row.is_some_and(|r| r.allow_password_login);
    if oidc_enabled && !allow_pw {
        return Err(ApiError::forbidden("password login is disabled; use SSO"));
    }

    // Local password first — guarantees the bootstrap admin can always log in.
    // Fall back to LDAP when it is enabled and local auth did not match (`login`).
    let mut user = authenticate(&state, &body.username, &body.password).await?;
    let ldap_enabled = row.is_some_and(|r| r.ldap_enabled);
    if ldap::ldap_fallback_needed(user.is_some(), ldap_enabled) {
        let client = LdapClient::new(LdapConfig::from_setting(
            row.expect("ldap_enabled implies a row"),
        ));
        let (username, password) = (body.username.clone(), body.password.clone());
        // ldap3 is blocking — run it on a blocking thread (Python's
        // `run_in_threadpool(client.authenticate, ...)`).
        let claims = tokio::task::spawn_blocking(move || client.authenticate(&username, &password))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        if let Some(claims) = claims {
            user = Some(
                ldap::upsert_ldap_user(
                    &state.pool,
                    &claims.dn,
                    &claims.username,
                    claims.email.as_deref(),
                )
                .await
                .map_err(db_err)?,
            );
        }
    }
    let Some(user) = user else {
        // Count this failed attempt.
        state.login_limiter.allow(&format!("login:{ip}"));
        record_audit(
            &state,
            AuditNew::new(ActorType::System, body.username.clone(), "login_failed"),
            client_ip(&headers, &state.config, peer_addr(peer)),
        )
        .await?;
        return Err(ApiError::unauthorized("invalid credentials"));
    };

    // First factor OK — branch on the second factor.
    let require_admin_mfa = row
        .map(|r| r.require_admin_mfa)
        .unwrap_or(state.config.require_admin_mfa);

    if user.totp_enabled {
        record_audit(
            &state,
            AuditNew::new(
                ActorType::User,
                user.id.to_string(),
                "login_password_ok_mfa_pending",
            ),
            client_ip(&headers, &state.config, peer_addr(peer)),
        )
        .await?;
        let challenge_token = state
            .security
            .jwt()
            .create_mfa_challenge_token(
                &user.id.to_string(),
                MFA_SCOPE,
                state.config.mfa_challenge_ttl_minutes,
            )
            .map_err(|e| ApiError::internal(e.to_string()))?;
        return Ok(Json(LoginResponse::Challenge(
            LoginChallengeResponse::mfa_required(challenge_token),
        )));
    }

    let passkey_count = if user.is_admin() && require_admin_mfa {
        crate::models::webauthn::count_credentials(&state.pool, user.id)
            .await
            .map_err(db_err)?
    } else {
        0
    };
    match decide_second_factor(&user, require_admin_mfa, passkey_count) {
        // Admin without any factor must enrol before getting an access token.
        LoginOutcome::MfaSetupRequired => {
            record_audit(
                &state,
                AuditNew::new(
                    ActorType::User,
                    user.id.to_string(),
                    "login_password_ok_mfa_setup_required",
                ),
                client_ip(&headers, &state.config, peer_addr(peer)),
            )
            .await?;
            let challenge_token = state
                .security
                .jwt()
                .create_mfa_challenge_token(
                    &user.id.to_string(),
                    MFA_SETUP_SCOPE,
                    state.config.mfa_challenge_ttl_minutes,
                )
                .map_err(|e| ApiError::internal(e.to_string()))?;
            Ok(Json(LoginResponse::Challenge(
                LoginChallengeResponse::mfa_setup_required(challenge_token),
            )))
        }
        LoginOutcome::MfaChallenge | LoginOutcome::IssueToken => {
            record_audit(
                &state,
                AuditNew::new(ActorType::User, user.id.to_string(), "login"),
                client_ip(&headers, &state.config, peer_addr(peer)),
            )
            .await?;
            Ok(Json(LoginResponse::Token(token_response(&state, &user)?)))
        }
    }
}

// ---------------------------------------------------------------------------
// GET/PUT /api/auth/me
// ---------------------------------------------------------------------------

async fn me(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Json<UserOut>, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    let Some(user) = principal.user else {
        // Agent principal (MCP) has no user record.
        return Err(ApiError::not_found("no user for this principal"));
    };
    Ok(Json(user_out(&state, &user).await?))
}

/// Self-service profile update (currently just email).
async fn update_me(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<UpdateProfileRequest>, JsonRejection>,
) -> Result<Json<UserOut>, ApiError> {
    // FastAPI solves `get_principal` before validating the body.
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    let Some(mut user) = principal.user else {
        return Err(ApiError::not_found("no user for this principal"));
    };
    if body.email.is_some() {
        // `user.email = body.email or None` — an empty string clears it.
        let email = body.email.clone().filter(|s| !s.is_empty());
        set_user_email(&state, user.id, email.clone()).await?;
        user.email = email;
    }
    record_audit(
        &state,
        {
            let mut new = AuditNew::new(ActorType::User, user.id.to_string(), "profile_updated");
            new.detail = serde_json::json!({"fields": ["email"]});
            new
        },
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(Json(user_out(&state, &user).await?))
}

// ---------------------------------------------------------------------------
// POST /api/auth/logout
// ---------------------------------------------------------------------------

/// Record a logout. JWTs are short-lived and `is_active` is checked per
/// request, so there is no server-side blacklist; the client discards its
/// token. (The Python hub clears no cookie here either — the OIDC state
/// cookies are deleted on the OIDC callback.)
async fn logout(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<StatusCode, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    record_audit(
        &state,
        AuditNew::new(principal.actor_type, principal.actor_id, "logout"),
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

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
struct OidcCallbackQuery {
    code: String,
    state: String,
}

const OIDC_STATE_COOKIE: &str = "huginn_oidc_state";
const OIDC_NONCE_COOKIE: &str = "huginn_oidc_nonce";

/// Per-IP guard on the OIDC start/callback endpoints (10/minute — `auth._oidc_limiter`).
fn oidc_limiter() -> &'static super::RateLimiter {
    use std::sync::OnceLock;
    static LIMITER: OnceLock<super::RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| super::RateLimiter::new(10))
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

async fn oidc_login(
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

async fn oidc_callback(
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::enums::UserRole;
    use crate::routes::authapi::support::{sample_user, test_state};
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    fn router_with_state() -> Router {
        crate::routes::authapi::router(test_state())
    }

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

    // ---- /api/auth/config -------------------------------------------------

    #[test]
    fn auth_config_matches_the_python_dict_logic() {
        let config = Config::default();
        // No settings row: env-only.
        let out = auth_config_for(None, &config);
        assert!(!out.oidc_enabled);
        assert_eq!(out.oidc_provider_name, "SSO");
        assert!(out.password_login_enabled);
        assert!(!out.webauthn_enabled);

        let mut row = Setting {
            id: 1,
            oidc_enabled: true,
            oidc_issuer: "https://idp".into(),
            oidc_client_id: "cid".into(),
            oidc_provider_name: "Authentik".into(),
            ..empty_setting()
        };
        // OIDC active and password login not re-enabled.
        let out = auth_config_for(Some(&row), &config);
        assert!(out.oidc_enabled);
        assert_eq!(out.oidc_provider_name, "Authentik");
        assert!(!out.password_login_enabled);

        // Empty provider name falls back to "SSO".
        row.oidc_provider_name = String::new();
        assert_eq!(
            auth_config_for(Some(&row), &config).oidc_provider_name,
            "SSO"
        );

        // OIDC without issuer or client id is not enabled (and the exact
        // /config computation checks both).
        row.oidc_issuer = String::new();
        let out = auth_config_for(Some(&row), &config);
        assert!(!out.oidc_enabled);
        assert!(out.password_login_enabled);

        // Env escape hatch re-enables password login next to OIDC.
        row.oidc_issuer = "https://idp".into();
        let allow = Config {
            allow_password_login: true,
            ..Config::default()
        };
        assert!(auth_config_for(Some(&row), &allow).password_login_enabled);
        // ...or the DB row does.
        row.allow_password_login = true;
        assert!(auth_config_for(Some(&row), &config).password_login_enabled);

        // WebAuthn button: RP id + origin from row or env fallback.
        row.webauthn_rp_id = "example.com".into();
        row.webauthn_origin = "https://example.com".into();
        assert!(auth_config_for(Some(&row), &config).webauthn_enabled);
        row.webauthn_origin = String::new();
        assert!(!auth_config_for(Some(&row), &config).webauthn_enabled);
        let env_rp = Config {
            webauthn_rp_id: "example.com".into(),
            webauthn_origin: "https://example.com".into(),
            ..Config::default()
        };
        assert!(auth_config_for(None, &env_rp).webauthn_enabled);
    }

    fn empty_setting() -> Setting {
        // Only the fields auth_config reads are meaningful here.
        serde_json::from_value(json!({
            "id": 1,
            "target_worker_version": "", "target_release_repo": "",
            "allowed_release_domains": [], "updated_by": null,
            "updated_at": "2024-01-01T00:00:00Z",
            "oidc_enabled": false, "oidc_issuer": "", "oidc_client_id": "",
            "oidc_client_secret": null, "oidc_redirect_url": "",
            "oidc_post_login_redirect": "", "ldap_enabled": false,
            "ldap_server_url": "", "ldap_bind_dn": "", "ldap_bind_password": null,
            "ldap_user_search_base": "", "ldap_user_search_filter": "",
            "ldap_start_tls": false, "ldap_use_ldaps": false,
            "notifications_enabled": false, "discord_webhook_url": null,
            "generic_webhook_url": null, "notify_vm_offline": true,
            "notify_vm_recovered": false, "notify_task_failure": false,
            "auto_update_enabled": false, "oidc_provider_name": "SSO",
            "require_admin_mfa": true, "allow_password_login": false,
            "webauthn_rp_id": "", "webauthn_rp_name": "Huginn", "webauthn_origin": ""
        }))
        .unwrap()
    }

    // ---- login decision (auth.login's branches) ---------------------------

    #[test]
    fn login_branches_match_the_python_flow() {
        // Bad password → 401 invalid credentials (decided before this point).
        let user = sample_user(UserRole::Readonly);
        assert!(
            !crate::security::verify_password("wrong", user.password_hash.as_deref()),
            "wrong password never authenticates"
        );
        // Unknown user: comparable work, always false (no enumeration).
        assert!(!crate::security::verify_password(
            "correct horse battery",
            None
        ));

        // Good password + TOTP → challenge token (scope mfa).
        let mut totp_user = sample_user(UserRole::Operator);
        totp_user.totp_enabled = true;
        assert_eq!(
            decide_second_factor(&totp_user, true, 0),
            LoginOutcome::MfaChallenge
        );

        // Admin with no factor and require_admin_mfa → setup token (scope mfa_setup).
        let admin = sample_user(UserRole::Admin);
        assert_eq!(
            decide_second_factor(&admin, true, 0),
            LoginOutcome::MfaSetupRequired
        );
        // ...but not when MFA is not required, when a passkey exists, or for non-admins.
        assert_eq!(
            decide_second_factor(&admin, false, 0),
            LoginOutcome::IssueToken
        );
        assert_eq!(
            decide_second_factor(&admin, true, 1),
            LoginOutcome::IssueToken
        );
        assert_eq!(
            decide_second_factor(&sample_user(UserRole::Readonly), true, 0),
            LoginOutcome::IssueToken
        );
    }

    #[test]
    fn challenge_responses_serialize_all_defaulted_fields() {
        let resp = LoginChallengeResponse::mfa_required("ct".into());
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            json!({
                "mfa_required": true,
                "mfa_setup_required": false,
                "challenge_token": "ct",
                "methods": ["totp", "backup"],
            })
        );
        let setup = LoginChallengeResponse::mfa_setup_required("ct2".into());
        assert_eq!(
            serde_json::to_value(&setup).unwrap(),
            json!({
                "mfa_required": false,
                "mfa_setup_required": true,
                "challenge_token": "ct2",
                "methods": ["totp", "webauthn"],
            })
        );
    }

    #[test]
    fn login_response_is_one_of_the_two_python_shapes() {
        let token = LoginResponse::Token(TokenResponse::new("tok".into(), 3600));
        assert_eq!(
            serde_json::to_value(&token).unwrap(),
            json!({"access_token": "tok", "token_type": "bearer", "expires_in": 3600})
        );
        let challenge = LoginResponse::Challenge(LoginChallengeResponse::mfa_required("ct".into()));
        assert_eq!(
            serde_json::to_value(&challenge).unwrap()["mfa_required"],
            json!(true)
        );
    }

    // ---- request validation (pydantic caps → 422) -------------------------

    #[test]
    fn login_request_bounds() {
        let ok = LoginRequest {
            username: "a".repeat(255),
            password: "p".repeat(128),
        };
        assert!(ok.validate().is_ok());
        let long_name = LoginRequest {
            username: "a".repeat(256),
            password: "p".into(),
        };
        assert!(long_name.validate().is_err());
        let long_pw = LoginRequest {
            username: "a".into(),
            password: "p".repeat(129),
        };
        assert!(long_pw.validate().is_err());
    }

    #[test]
    fn profile_email_is_capped_at_320() {
        assert!(UpdateProfileRequest {
            email: Some("a".repeat(320))
        }
        .validate()
        .is_ok());
        assert!(UpdateProfileRequest {
            email: Some("a".repeat(321))
        }
        .validate()
        .is_err());
        assert!(UpdateProfileRequest::default().validate().is_ok());
    }

    // ---- HTTP-level (no database needed) ----------------------------------

    #[tokio::test]
    async fn login_rejects_bad_bodies_with_422() {
        let response = router_with_state()
            .oneshot(post("/api/auth/login", json!({"username": "a"})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let response = router_with_state()
            .oneshot(post(
                "/api/auth/login",
                json!({"username": "a", "password": "p".repeat(129)}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_throttles_after_five_failed_attempts() {
        let state = test_state();
        // Five failed attempts already accumulated for this IP (the limiter is
        // only consumed on failure — `auth.login`).
        for _ in 0..5 {
            assert!(state.login_limiter.allow("login:203.0.113.7"));
        }
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "203.0.113.7")
            .body(Body::from(
                json!({"username": "a", "password": "b"}).to_string(),
            ))
            .unwrap();
        let response = crate::routes::authapi::router(state)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "too many failed login attempts; slow down"})
        );
    }

    #[tokio::test]
    async fn me_and_logout_require_authentication() {
        let response = router_with_state()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/auth/me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "authentication required"})
        );

        let response = router_with_state()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/auth/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn me_rejects_mfa_scoped_tokens_and_expired_tokens() {
        let state = test_state();
        let sub = uuid::Uuid::new_v4().to_string();
        let challenge = state
            .security
            .jwt()
            .create_mfa_challenge_token(&sub, MFA_SCOPE, 5)
            .unwrap();
        let response = crate::routes::authapi::router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/auth/me")
                    .header("authorization", format!("Bearer {challenge}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "token not valid for API access"})
        );

        let expired = state
            .security
            .jwt()
            .create_access_token_at(&sub, "admin", -5, 1_700_000_000)
            .unwrap();
        let response = crate::routes::authapi::router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/auth/me")
                    .header("authorization", format!("Bearer {expired}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "invalid token"})
        );
    }
}

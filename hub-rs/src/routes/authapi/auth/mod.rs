//! Authentication endpoints: local login, current user and logout —
//! port of `hub/app/api/routes/auth.py` (the OIDC endpoints are phase 2, see
//! `PARITY_HUB.md`).

use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, State};
use axum::http::{HeaderMap, StatusCode};
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

use super::{
    authenticate, client_ip, db_err, get_principal, map_json_rejection, peer_addr, record_audit,
    set_user_email, token_response, user_out, AuthState, TokenResponse, UserOut,
};

// ---------------------------------------------------------------------------
// Submodules — auth flow split by function
// ---------------------------------------------------------------------------

mod oidc;
mod schemas;

use self::oidc::{oidc_callback, oidc_login};
use self::schemas::{LoginChallengeResponse, LoginRequest, UpdateProfileRequest};

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

/// Whether the configured LDAP transport is encrypted.
///
/// The bind-search-bind flow sends the service-account bind password **and**
/// the end user's password to the directory. Over a plain `ldap://` socket
/// both travel in clear text, so the LDAP fallback is refused in that case:
/// use `ldaps://` (or enable StartTLS) instead.
fn ldap_transport_is_encrypted(config: &LdapConfig) -> bool {
    if config.use_ldaps || config.start_tls {
        return true;
    }
    config
        .server_url
        .trim()
        .to_ascii_lowercase()
        .starts_with("ldaps://")
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
    // Two independent windows guard the password check:
    //  * per IP — the fast path against a single noisy source;
    //  * per account — the backstop against a distributed guess run (many
    //    source addresses, one account). Both only count *failed* attempts,
    //    so a legitimate login is never throttled, and the account window
    //    counts unknown accounts too (no user-enumeration oracle).
    let ip_key = format!("login:{ip}");
    let account_key = format!("login-account:{}", body.username);
    if !state.login_limiter.check(&ip_key) || !state.login_account_limiter.check(&account_key) {
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
        let ldap_config = LdapConfig::from_setting(row.expect("ldap_enabled implies a row"));
        // A plain `ldap://` connection would put the service-account bind
        // password AND the user's password on the wire in clear text. Refuse
        // the fallback instead of authenticating over an unencrypted channel.
        if !ldap_transport_is_encrypted(&ldap_config) {
            tracing::error!(
                "LDAP fallback refused: the configured transport is not encrypted \
                 (use ldaps:// or enable StartTLS)"
            );
            return Err(ApiError::internal(
                "LDAP transport is not encrypted; refusing to authenticate",
            ));
        }
        let client = LdapClient::new(ldap_config);
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
                .map_err(|e| match e {
                    // H-2: the directory username matches a local account
                    // that must not be auto-adopted → explicit 403, not a 500.
                    crate::services::oidc::ReconcileError::UsernameTaken => {
                        ApiError::forbidden(e.to_string())
                    }
                    crate::services::oidc::ReconcileError::Db(err) => db_err(err),
                })?,
            );
        }
    }
    let Some(user) = user else {
        // Count this failed attempt (per IP and per account).
        state.login_limiter.allow(&ip_key);
        state.login_account_limiter.allow(&account_key);
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
// Tests
// ---------------------------------------------------------------------------

/// Shared request/response helpers for the route tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::json;

    use crate::routes::authapi::support::test_state;

    pub(crate) fn router_with_state() -> Router {
        crate::routes::authapi::router(test_state())
    }

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
    use super::testing::{body_json, post, router_with_state};
    use super::*;
    use axum::body::Body;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::models::enums::UserRole;
    use crate::routes::authapi::support::{sample_user, test_state};

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
        Setting {
            id: 1,
            updated_at: chrono::Utc::now(),
            oidc_provider_name: "SSO".into(),
            require_admin_mfa: true,
            notify_vm_offline: true,
            backup_s3_retention_days: 30,
            ..Setting::default()
        }
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
        let mut state = test_state();
        // The deployment trusts the proxy-written X-Forwarded-For (H-1: the
        // fail-closed default is off, so the test opts in explicitly).
        state.config.trust_forwarded_for = true;
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

    /// The per-ACCOUNT window: a password-guess run spread over many source
    /// addresses is throttled as soon as one account accumulates too many
    /// failures, even though every individual address stays under the
    /// per-IP budget.
    #[tokio::test]
    async fn login_throttles_per_account_across_source_addresses() {
        let mut state = test_state();
        state.config.trust_forwarded_for = true;
        // The account window is already spent for "victim" — but no address
        // has spent the per-IP budget.
        for _ in 0..crate::routes::authapi::LOGIN_ACCOUNT_MAX_FAILURES {
            assert!(state.login_account_limiter.allow("login-account:victim"));
        }
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "203.0.113.99")
            .body(Body::from(
                json!({"username": "victim", "password": "b"}).to_string(),
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

    /// The LDAP fallback must never authenticate over a cleartext channel:
    /// the bind password and the user's password would both travel in the
    /// clear.
    #[test]
    fn ldap_fallback_requires_an_encrypted_transport() {
        let plain = LdapConfig {
            enabled: true,
            server_url: "ldap://dir.example.com:389".into(),
            ..ldap_config_stub()
        };
        assert!(!ldap_transport_is_encrypted(&plain));

        // LDAPS (either via the flag or the scheme) is encrypted.
        let ldaps = LdapConfig {
            use_ldaps: true,
            ..plain.clone()
        };
        assert!(ldap_transport_is_encrypted(&ldaps));
        let ldaps_scheme = LdapConfig {
            server_url: "ldaps://dir.example.com:636".into(),
            ..plain.clone()
        };
        assert!(ldap_transport_is_encrypted(&ldaps_scheme));

        // StartTLS upgrades a plain connection — encrypted.
        let starttls = LdapConfig {
            start_tls: true,
            ..plain.clone()
        };
        assert!(ldap_transport_is_encrypted(&starttls));

        // A scheme-less URL is refused too (fail closed).
        let schemeless = LdapConfig {
            server_url: "dir.example.com:389".into(),
            ..plain
        };
        assert!(!ldap_transport_is_encrypted(&schemeless));
    }

    fn ldap_config_stub() -> LdapConfig {
        LdapConfig {
            enabled: false,
            server_url: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            user_search_base: String::new(),
            user_search_filter: String::new(),
            start_tls: false,
            use_ldaps: false,
        }
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

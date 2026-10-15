//! OIDC / SSO client (port of `hub/app/core/oidc.py`).
//!
//! Minimal authorization-code flow built to the standard OIDC spec, so any
//! compliant IdP works. The discovery document and JWKS are fetched lazily and
//! cached per client instance; the ID token is verified against the provider's
//! JWKS (RS256 / ES256, `aud`, `iss`, `exp`) before any claim is trusted.
//!
//! Only the ID token is used for identity — matching the Python hub, which does
//! not call the userinfo endpoint (the ID token already carries `sub`,
//! `preferred_username` and `email`). No PKCE: the flow binds the login attempt
//! with a `nonce` (ID-token replay protection) and a `state` (CSRF), both handed
//! to the browser as HttpOnly cookies and checked on the callback.
//!
//! Secrets: `oidc_client_secret` is only ever sent to the token endpoint in the
//! POST body; it is never logged, serialized into responses, or echoed back.

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::models::setting::Setting;
use crate::models::user::{self, User, UserNew};

/// Matches Python's per-request HTTP timeout in `oidc.py`.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Submodules — ID token verification
// ---------------------------------------------------------------------------

mod verify;

use self::verify::{extract_claims, verify_id_token};

// ---------------------------------------------------------------------------
// Configuration source (env `Config` or DB `Setting`)
// ---------------------------------------------------------------------------

/// The OIDC settings a client needs. The DB row and the env `Config` expose the
/// same attribute names, so either source maps in here — mirroring the Python
/// `OIDCClient`, which works structurally with either `_oidc_source`.
#[derive(Clone, Default)]
pub struct OidcConfig {
    /// Raw `oidc_enabled` flag (the full `is_enabled` check adds issuer + id).
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub post_login_redirect: String,
}

/// Hand-written `Debug` that redacts `client_secret` so it can never leak into
/// logs or error output.
impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("enabled", &self.enabled)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .field("redirect_url", &self.redirect_url)
            .field("post_login_redirect", &self.post_login_redirect)
            .finish()
    }
}

impl OidcConfig {
    pub fn from_config(c: &Config) -> Self {
        Self {
            enabled: c.oidc_enabled,
            issuer: c.oidc_issuer.clone(),
            client_id: c.oidc_client_id.clone(),
            client_secret: c.oidc_client_secret.clone(),
            redirect_url: c.oidc_redirect_url.clone(),
            post_login_redirect: c.oidc_post_login_redirect.clone(),
        }
    }

    pub fn from_setting(s: &Setting) -> Self {
        Self {
            enabled: s.oidc_enabled,
            issuer: s.oidc_issuer.clone(),
            client_id: s.oidc_client_id.clone(),
            client_secret: s.oidc_client_secret.clone().unwrap_or_default(),
            redirect_url: s.oidc_redirect_url.clone(),
            post_login_redirect: s.oidc_post_login_redirect.clone(),
        }
    }

    /// `OIDCClient.enabled`: enabled AND issuer AND client id are all set.
    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.issuer.is_empty() && !self.client_id.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Errors and claims
// ---------------------------------------------------------------------------

/// Raised on any OIDC configuration or verification failure (`OIDCError`).
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("OIDC is not enabled or fully configured")]
    Disabled,
    #[error("discovery failed: {0}")]
    Discovery(String),
    #[error("token endpoint returned {0}")]
    TokenEndpoint(u16),
    #[error("no id_token in token response")]
    MissingIdToken,
    #[error("jwks endpoint returned {0}")]
    Jwks(u16),
    #[error("no matching JWKS key for id_token")]
    NoMatchingKey,
    #[error("unsupported id_token algorithm")]
    UnsupportedAlgorithm,
    #[error("id_token verification failed: {0}")]
    Verification(String),
    #[error("id_token nonce mismatch")]
    NonceMismatch,
    #[error("id_token missing 'sub'")]
    MissingSubject,
    #[error("http error: {0}")]
    Http(String),
}

/// The trusted identity extracted from a verified ID token (`OIDCClaims`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcClaims {
    pub subject: String,
    pub username: String,
    pub email: Option<String>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Minimal OIDC authorization-code client (`OIDCClient`).
#[derive(Debug, Clone)]
pub struct OidcClient {
    config: OidcConfig,
    http: reqwest::Client,
    /// Cached discovery document (per-instance, like the Python `_discovery`).
    discovery: std::sync::Arc<std::sync::Mutex<Option<serde_json::Value>>>,
}

impl OidcClient {
    pub fn new(config: OidcConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            // No redirect following (M-3): `client_secret` goes to the token
            // endpoint in the POST body — a 3xx would hand it to another host
            // (same policy as the webhook client,
            // services/notifications/webhook.rs).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            config,
            http,
            discovery: std::sync::Arc::default(),
        }
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// `OIDCClient.enabled`.
    pub fn is_enabled(&self) -> bool {
        self.config.is_enabled()
    }

    fn require_enabled(&self) -> Result<(), OidcError> {
        if self.is_enabled() {
            Ok(())
        } else {
            Err(OidcError::Disabled)
        }
    }

    /// `secrets.token_urlsafe(24)` → 24 random bytes, base64url (no pad).
    pub fn new_state() -> String {
        random_token()
    }

    /// `secrets.token_urlsafe(24)`.
    pub fn new_nonce() -> String {
        random_token()
    }

    /// Fetch (and cache) `/.well-known/openid-configuration`.
    async fn get_discovery(&self) -> Result<serde_json::Value, OidcError> {
        if let Some(d) = self
            .discovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Ok(d);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(OidcError::Discovery(format!(
                "status {}",
                resp.status().as_u16()
            )));
        }
        let doc: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        *self.discovery.lock().unwrap_or_else(|e| e.into_inner()) = Some(doc.clone());
        Ok(doc)
    }

    /// Build the authorization URL (`OIDCClient.authorization_url`).
    pub async fn authorization_url(&self, state: &str, nonce: &str) -> Result<String, OidcError> {
        self.require_enabled()?;
        let discovery = self.get_discovery().await?;
        let endpoint = discovery
            .get("authorization_endpoint")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| OidcError::Discovery("missing authorization_endpoint".into()))?;
        let params = [
            ("response_type", "code"),
            ("client_id", self.config.client_id.as_str()),
            ("redirect_uri", self.config.redirect_url.as_str()),
            ("scope", "openid profile email"),
            ("state", state),
            ("nonce", nonce),
        ];
        Ok(format!("{endpoint}?{}", form_encode(&params)))
    }

    /// Exchange the authorization code for tokens and verify the ID token
    /// (`OIDCClient.exchange_code`), returning the trusted claims.
    pub async fn exchange_code(
        &self,
        code: &str,
        nonce: Option<&str>,
    ) -> Result<OidcClaims, OidcError> {
        self.require_enabled()?;
        let discovery = self.get_discovery().await?;
        let token_endpoint = discovery
            .get("token_endpoint")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| OidcError::Discovery("missing token_endpoint".into()))?;
        let jwks_uri = discovery
            .get("jwks_uri")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| OidcError::Discovery("missing jwks_uri".into()))?;
        let issuer = discovery
            .get("issuer")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&self.config.issuer)
            .to_owned();

        // Token exchange (client_secret goes in the POST body only).
        let resp = self
            .http
            .post(token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.config.redirect_url.as_str()),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| OidcError::Http(e.to_string()))?;
        if resp.status() != reqwest::StatusCode::OK {
            return Err(OidcError::TokenEndpoint(resp.status().as_u16()));
        }
        let token: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OidcError::Http(e.to_string()))?;
        let id_token = token
            .get("id_token")
            .and_then(serde_json::Value::as_str)
            .ok_or(OidcError::MissingIdToken)?;

        // Fetch the JWKS (raw HTTP rather than any built-in loader, mirroring
        // the Python note about User-Agent rejections).
        let jwks_resp = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Http(e.to_string()))?;
        if jwks_resp.status() != reqwest::StatusCode::OK {
            return Err(OidcError::Jwks(jwks_resp.status().as_u16()));
        }
        let jwks: serde_json::Value = jwks_resp
            .json()
            .await
            .map_err(|e| OidcError::Http(e.to_string()))?;

        verify_id_token(id_token, &jwks, &issuer, &self.config.client_id, nonce)
    }
}

// ---------------------------------------------------------------------------
// User reconciliation (`users_service.upsert_oidc_user`)
// ---------------------------------------------------------------------------

/// Why a reconciled SSO/LDAP login could not produce a user
/// (`upsert_oidc_user` / `upsert_ldap_user`).
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// H-2 username-takeover guard: the existing local account with this
    /// username is not a bare password-less read-only account, so the SSO/LDAP
    /// identity must not adopt it — an admin has to link it manually.
    #[error("an account with this username already exists; ask an admin to link it manually")]
    UsernameTaken,
    /// Data-layer failure.
    #[error(transparent)]
    Db(#[from] crate::db::DbError),
}

/// How to reconcile a verified OIDC identity with the local user table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reconcile {
    /// Matched on the external key (reuse the account as-is).
    Reuse,
    /// Matched on `username` (an existing local user adopts the OIDC subject).
    Link,
    /// No match: create a new read-only, password-less account.
    Create,
}

/// Decide the reconciliation from the two lookups `upsert_oidc_user` performs:
/// by `oidc_subject`, then by `username`. (`upsert_ldap_user` is identical with
/// `ldap_dn` as the external key.)
pub(crate) fn decide_reconcile(
    by_external: Option<&User>,
    by_username: Option<&User>,
) -> Reconcile {
    if by_external.is_some() {
        Reconcile::Reuse
    } else if by_username.is_some() {
        Reconcile::Link
    } else {
        Reconcile::Create
    }
}

/// H-2 takeover guard: an existing local account may be *automatically* linked
/// to a verified SSO/LDAP identity only when it is a bare, password-less,
/// read-only account (one a previous SSO login created). An account with a
/// password or an elevated role — admin included — must be linked by an admin;
/// matching on username alone must never adopt it, or anyone controlling a
/// directory username could take over the local account.
pub(crate) fn auto_link_allowed(existing: &User) -> bool {
    existing.role == crate::models::enums::UserRole::Readonly && existing.password_hash.is_none()
}

/// Find or create a user from OIDC claims (`upsert_oidc_user`): match on
/// `oidc_subject`, else a *bare* existing local user with the same `username`
/// adopts the subject, else create a read-only password-less account. Always
/// bumps `last_login_at`.
///
/// H-2: the username branch refuses accounts that are not bare read-only
/// ones (see [`auto_link_allowed`]) — the caller surfaces that as 403.
pub async fn upsert_oidc_user(
    pool: &sqlx::PgPool,
    subject: &str,
    username: &str,
    email: Option<&str>,
) -> Result<User, ReconcileError> {
    let by_subject = user::get_by_oidc_subject(pool, subject).await?;
    let by_username = if by_subject.is_none() {
        user::get_by_username(pool, username).await?
    } else {
        None
    };
    let user = match decide_reconcile(by_subject.as_ref(), by_username.as_ref()) {
        Reconcile::Reuse => by_subject.expect("reuse implies a subject match"),
        Reconcile::Link => {
            let existing = by_username.expect("link implies a username match");
            if !auto_link_allowed(&existing) {
                return Err(ReconcileError::UsernameTaken);
            }
            user::set_oidc_subject(pool, existing.id, subject)
                .await?
                .unwrap_or(existing)
        }
        Reconcile::Create => {
            user::create(
                pool,
                UserNew {
                    username: username.to_owned(),
                    email: email.map(str::to_owned),
                    password_hash: None,
                    oidc_subject: Some(subject.to_owned()),
                    role: crate::models::enums::UserRole::Readonly,
                    is_active: true,
                    ..UserNew::default()
                },
            )
            .await?
        }
    };
    user::touch_last_login(pool, user.id).await?;
    Ok(user)
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// `secrets.token_urlsafe(24)`: 24 random bytes as unpadded base64url.
fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Percent-encode a query string like Python's `urlencode` (quote_plus): space
/// becomes `+`, every byte outside `A-Za-z0-9-_.` is `%XX`.
fn form_encode(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn quote_plus(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b' ' => out.push('+'),
            // Python's `quote`/`quote_plus` never escape `_.-~` or alphanumerics.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::verify::tests::gen_rsa;
    use super::*;
    use crate::models::enums::UserRole;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // ---- full exchange against a fake provider ---------------------------

    #[derive(Clone)]
    struct MockIdp {
        discovery: serde_json::Value,
        jwks: serde_json::Value,
        token: serde_json::Value,
    }

    async fn mock_discovery(
        axum::extract::State(s): axum::extract::State<MockIdp>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(s.discovery)
    }
    async fn mock_jwks(
        axum::extract::State(s): axum::extract::State<MockIdp>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(s.jwks)
    }
    async fn mock_token(
        axum::extract::State(s): axum::extract::State<MockIdp>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(s.token)
    }

    #[tokio::test]
    async fn exchange_code_runs_the_full_flow_against_a_mock_provider() {
        use axum::routing::{get, post};

        // Bind first so the issuer (== our base URL) is known before signing.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");

        let (key, jwk) = gen_rsa();
        let id_token = key.sign(
            "RS256",
            Some("rsa-key"),
            &serde_json::json!({
                "sub": "subject-1", "preferred_username": "alice", "email": "alice@example.com",
                "iss": issuer, "aud": "client-1", "nonce": "nonce-1",
                "iat": 1_700_000_000_i64, "exp": 4_000_000_000_i64,
            }),
        );

        let state = MockIdp {
            discovery: serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/auth"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            }),
            jwks: serde_json::json!({ "keys": [jwk] }),
            token: serde_json::json!({
                "id_token": id_token, "access_token": "at", "token_type": "Bearer",
            }),
        };
        let app = axum::Router::new()
            .route("/.well-known/openid-configuration", get(mock_discovery))
            .route("/jwks", get(mock_jwks))
            .route("/token", post(mock_token))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = OidcClient::new(OidcConfig {
            enabled: true,
            issuer,
            client_id: "client-1".into(),
            client_secret: "secret".into(),
            redirect_url: "http://localhost:8000/api/auth/oidc/callback".into(),
            post_login_redirect: String::new(),
        });

        // Happy path: discovery -> token exchange -> JWKS -> verified claims.
        let claims = client
            .exchange_code("the-code", Some("nonce-1"))
            .await
            .expect("exchange_code succeeds");
        assert_eq!(claims.subject, "subject-1");
        assert_eq!(claims.username, "alice");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));

        // A wrong nonce is rejected (replay protection).
        let err = client
            .exchange_code("the-code", Some("wrong-nonce"))
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::NonceMismatch));
    }

    /// M-3: a 3xx from the provider must surface as a typed error, never be
    /// followed — the token-endpoint POST carries `client_secret`, which a
    /// redirect would hand to another host.
    #[tokio::test]
    async fn redirect_responses_are_not_followed() {
        use axum::routing::{get, post};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");

        let (key, jwk) = gen_rsa();
        let id_token = key.sign(
            "RS256",
            Some("rsa-key"),
            &serde_json::json!({
                "sub": "subject-1", "preferred_username": "alice",
                "iss": issuer, "aud": "client-1", "nonce": "nonce-1",
                "iat": 1_700_000_000_i64, "exp": 4_000_000_000_i64,
            }),
        );
        let state = MockIdp {
            // The token endpoint sits behind a 302 whose target WOULD answer
            // a valid token response if the client followed it.
            discovery: serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/auth"),
                "token_endpoint": format!("{issuer}/redirect"),
                "jwks_uri": format!("{issuer}/jwks"),
            }),
            jwks: serde_json::json!({ "keys": [jwk] }),
            token: serde_json::json!({
                "id_token": id_token, "access_token": "at", "token_type": "Bearer",
            }),
        };
        async fn redirect_to_token() -> impl axum::response::IntoResponse {
            (axum::http::StatusCode::FOUND, [("location", "/token")])
        }
        let app = axum::Router::new()
            .route("/.well-known/openid-configuration", get(mock_discovery))
            .route("/jwks", get(mock_jwks))
            .route("/redirect", post(redirect_to_token))
            .route("/token", post(mock_token))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = OidcClient::new(OidcConfig {
            enabled: true,
            issuer,
            client_id: "client-1".into(),
            client_secret: "secret".into(),
            redirect_url: "http://localhost:8000/api/auth/oidc/callback".into(),
            post_login_redirect: String::new(),
        });

        // The 302 surfaces as the typed token-endpoint error — it is NOT
        // followed to /token (where the exchange would otherwise succeed and
        // the client_secret would have been re-sent).
        let err = client
            .exchange_code("the-code", Some("nonce-1"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, OidcError::TokenEndpoint(302)),
            "typed 3xx error, got {err:?}"
        );
    }

    // ---- reconciliation decisions ---------------------------------------

    #[test]
    fn reconcile_reuse_link_create() {
        let found = sample();
        assert_eq!(
            decide_reconcile(Some(&found), Some(&found)),
            Reconcile::Reuse,
            "subject match wins"
        );
        assert_eq!(
            decide_reconcile(None, Some(&found)),
            Reconcile::Link,
            "username match adopts the subject"
        );
        assert_eq!(decide_reconcile(None, None), Reconcile::Create);
    }

    // ---- H-2: username-takeover guard ------------------------------------

    #[test]
    fn auto_link_only_accepts_bare_readonly_accounts() {
        let mut existing = sample();
        assert!(
            auto_link_allowed(&existing),
            "a bare read-only account (SSO-created) auto-links"
        );
        existing.password_hash = Some("argon2id:...".into());
        assert!(
            !auto_link_allowed(&existing),
            "an account with a local password must be linked by an admin"
        );
        existing.password_hash = None;
        existing.role = UserRole::Operator;
        assert!(
            !auto_link_allowed(&existing),
            "operator must not be adopted"
        );
        existing.role = UserRole::Admin;
        assert!(!auto_link_allowed(&existing), "admin must never be adopted");
    }

    #[test]
    fn username_taken_error_is_explicit() {
        // The caller surfaces this message verbatim as a 403.
        assert_eq!(
            ReconcileError::UsernameTaken.to_string(),
            "an account with this username already exists; ask an admin to link it manually"
        );
    }

    fn sample() -> User {
        User {
            id: uuid::Uuid::new_v4(),
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            password_hash: None,
            oidc_subject: None,
            ldap_dn: None,
            role: UserRole::Readonly,
            is_active: true,
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            totp_secret_enc: None,
            totp_enabled: false,
            totp_confirmed_at: None,
            totp_last_step: None,
        }
    }

    /// End-to-end exercise of the Link guard against a live PostgreSQL
    /// (skipped unless `HUGINN_TEST_DATABASE_URL` is set — `cargo test` stays
    /// green without a database, like `models::live_tests`).
    #[tokio::test]
    async fn upsert_link_guard_refuses_to_adopt_real_accounts() {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return;
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

        // An SSO identity whose username matches a local ADMIN must be
        // refused — it may not adopt the account (H-2).
        let admin = user::create(
            &pool,
            UserNew {
                username: "admin".into(),
                password_hash: Some("h".into()),
                role: UserRole::Admin,
                is_active: true,
                ..UserNew::default()
            },
        )
        .await
        .unwrap();
        let err = upsert_oidc_user(&pool, "sub-admin", "admin", None)
            .await
            .unwrap_err();
        assert!(matches!(err, ReconcileError::UsernameTaken), "{err:?}");
        // The admin account was left untouched.
        let still = user::get_by_id(&pool, admin.id).await.unwrap().unwrap();
        assert!(still.oidc_subject.is_none());
        assert!(still.ldap_dn.is_none());

        // A read-only account WITH a local password is refused too.
        user::create(
            &pool,
            UserNew {
                username: "bob".into(),
                password_hash: Some("h".into()),
                role: UserRole::Readonly,
                is_active: true,
                ..UserNew::default()
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            upsert_oidc_user(&pool, "sub-bob", "bob", None)
                .await
                .unwrap_err(),
            ReconcileError::UsernameTaken
        ));

        // A bare read-only account (no password) IS auto-linked.
        let bare = user::create(
            &pool,
            UserNew {
                username: "carol".into(),
                password_hash: None,
                role: UserRole::Readonly,
                is_active: true,
                ..UserNew::default()
            },
        )
        .await
        .unwrap();
        let linked = upsert_oidc_user(&pool, "sub-carol", "carol", None)
            .await
            .unwrap();
        assert_eq!(linked.id, bare.id, "the existing account is reused");
        assert_eq!(linked.oidc_subject.as_deref(), Some("sub-carol"));

        // The same policy governs the LDAP fallback.
        assert!(matches!(
            crate::services::ldap::upsert_ldap_user(&pool, "uid=bob,dc=x", "bob", None)
                .await
                .unwrap_err(),
            ReconcileError::UsernameTaken
        ));
        let linked =
            crate::services::ldap::upsert_ldap_user(&pool, "uid=carol,dc=x", "carol", None)
                .await
                .unwrap();
        assert_eq!(linked.id, bare.id);
        assert_eq!(linked.ldap_dn.as_deref(), Some("uid=carol,dc=x"));

        drop(guard);
    }

    // ---- encoding --------------------------------------------------------

    #[test]
    fn quote_plus_matches_python_urlencode() {
        assert_eq!(quote_plus("openid profile email"), "openid+profile+email");
        assert_eq!(quote_plus("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(quote_plus("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(quote_plus("h\u{e9}llo"), "h%C3%A9llo");
    }

    #[test]
    fn authorization_url_encodes_all_params() {
        let params = [
            ("response_type", "code"),
            ("client_id", "client-1"),
            (
                "redirect_uri",
                "http://localhost:8000/api/auth/oidc/callback",
            ),
            ("scope", "openid profile email"),
            ("state", "st-1"),
            ("nonce", "n-1"),
        ];
        let qs = form_encode(&params);
        assert!(qs.contains("scope=openid+profile+email"));
        assert!(qs
            .contains("redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fapi%2Fauth%2Foidc%2Fcallback"));
        assert!(qs.contains("state=st-1"));
        assert!(qs.contains("nonce=n-1"));
    }

    #[test]
    fn enabled_requires_flag_and_issuer_and_client_id() {
        let mut cfg = OidcConfig::from_config(&Config::default());
        assert!(!cfg.is_enabled(), "disabled by default");
        cfg.enabled = true;
        assert!(!cfg.is_enabled(), "missing issuer + client id");
        cfg.issuer = "https://idp".into();
        assert!(!cfg.is_enabled(), "missing client id");
        cfg.client_id = "cid".into();
        assert!(cfg.is_enabled());
    }

    #[test]
    fn client_secret_never_appears_in_debug_output() {
        let cfg = OidcConfig {
            client_secret: "super-secret-value".into(),
            ..OidcConfig::from_config(&Config::default())
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("super-secret-value"),
            "client_secret leaked in Debug: {dbg}"
        );
    }
}

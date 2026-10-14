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
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::models::setting::Setting;
use crate::models::user::{self, User, UserNew};

/// Matches Python's per-request HTTP timeout in `oidc.py`.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

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
// ID token verification (pure, testable)
// ---------------------------------------------------------------------------

/// Verify an ID token against the provider's JWKS and return its claims
/// (`OIDCClient._verify_id_token`). Pure: the JWKS is passed in as data so the
/// whole verification is unit-testable without a network round-trip.
///
/// Signature: RS256 or ES256 only (the Python `["RS256", "ES256"]` allow-list).
/// Claims: `aud` == client id, `iss` == issuer, `exp` must be valid. When a
/// nonce was sent on the authorization request, it must come back unchanged.
pub(crate) fn verify_id_token(
    id_token: &str,
    jwks: &serde_json::Value,
    expected_iss: &str,
    expected_aud: &str,
    nonce: Option<&str>,
) -> Result<OidcClaims, OidcError> {
    let header = decode_header(id_token).map_err(|e| OidcError::Verification(e.to_string()))?;
    let alg = header.alg;
    if !matches!(alg, Algorithm::RS256 | Algorithm::ES256) {
        return Err(OidcError::UnsupportedAlgorithm);
    }
    let kid = header.kid;

    let key_set: JwkSet =
        serde_json::from_value(jwks.clone()).map_err(|e| OidcError::Verification(e.to_string()))?;
    // Mirror the Python key selection: pick the first key whose `kid` matches,
    // or (when the token carries no `kid`) simply the first key.
    let jwk: &Jwk = key_set
        .keys
        .iter()
        .find(|k| match (&kid, &k.common.key_id) {
            (None, _) => true,
            (Some(t), Some(k)) => t == k,
            (Some(_), None) => false,
        })
        .ok_or(OidcError::NoMatchingKey)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| OidcError::Verification(e.to_string()))?;

    let mut validation = Validation::new(alg);
    // Strict parity with PyJWT's default (no clock leeway).
    validation.leeway = 0;
    validation.set_audience(&[expected_aud]);
    validation.set_issuer(&[expected_iss]);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);

    let data = decode::<serde_json::Value>(id_token, &key, &validation)
        .map_err(|e| OidcError::Verification(e.to_string()))?;
    let claims = data.claims;

    // Bind the ID token to this login attempt (replay protection).
    if let Some(expected) = nonce {
        let got = claims.get("nonce").and_then(serde_json::Value::as_str);
        if got != Some(expected) {
            return Err(OidcError::NonceMismatch);
        }
    }
    extract_claims(&claims)
}

/// Map a verified token payload onto [`OidcClaims`]
/// (`_verify_id_token`'s tail): `sub` is required, `username` falls back from
/// `preferred_username` → `email` → `sub`.
pub(crate) fn extract_claims(claims: &serde_json::Value) -> Result<OidcClaims, OidcError> {
    let subject = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(OidcError::MissingSubject)?
        .to_owned();
    let email = claims
        .get("email")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let username = claims
        .get("preferred_username")
        .and_then(serde_json::Value::as_str)
        .or(email.as_deref())
        .unwrap_or(&subject)
        .to_owned();
    Ok(OidcClaims {
        subject,
        username,
        email,
    })
}

// ---------------------------------------------------------------------------
// User reconciliation (`users_service.upsert_oidc_user`)
// ---------------------------------------------------------------------------

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

/// Find or create a user from OIDC claims (`upsert_oidc_user`): match on
/// `oidc_subject`, else an existing local user with the same `username` adopts
/// the subject, else create a read-only password-less account. Always bumps
/// `last_login_at`.
pub async fn upsert_oidc_user(
    pool: &sqlx::PgPool,
    subject: &str,
    username: &str,
    email: Option<&str>,
) -> Result<User, crate::db::DbError> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::enums::UserRole;

    // Test keys (fixed, embedded — deterministic across runs). Generated once
    // with OpenSSL; only the public halves appear in the JWKS below.
    const RSA_PEM: &str = include_str!("../../tests/keys/oidc_rsa.pem");
    const EC_PEM: &str = include_str!("../../tests/keys/oidc_ec.pem");

    fn rsa_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA", "kid": "rsa-key", "alg": "RS256", "use": "sig",
            "n": include_str!("../../tests/keys/rsa_n.txt").trim(),
            "e": include_str!("../../tests/keys/rsa_e.txt").trim(),
        })
    }
    fn ec_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC", "kid": "ec-key", "alg": "ES256", "use": "sig", "crv": "P-256",
            "x": include_str!("../../tests/keys/ec_x.txt").trim(),
            "y": include_str!("../../tests/keys/ec_y.txt").trim(),
        })
    }

    fn sign(alg: Algorithm, kid: &str, payload: serde_json::Value, pem: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let mut header = Header::new(alg);
        header.kid = if kid.is_empty() {
            None
        } else {
            Some(kid.to_owned())
        };
        let enc = match alg {
            Algorithm::RS256 => EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            Algorithm::ES256 => EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
            _ => EncodingKey::from_secret(pem.as_bytes()),
        };
        encode(&header, &payload, &enc).unwrap()
    }

    fn base_payload() -> serde_json::Value {
        serde_json::json!({
            "sub": "subject-1",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "iss": "https://idp.example",
            "aud": "client-1",
            "iat": 1_700_000_000_i64,
            "exp": 4_000_000_000_i64,
        })
    }

    // ---- verification happy path -----------------------------------------

    #[test]
    fn verifies_rs256_and_es256_and_maps_claims() {
        for (alg, kid, pem, jwks) in [
            (Algorithm::RS256, "rsa-key", RSA_PEM, rsa_jwk()),
            (Algorithm::ES256, "ec-key", EC_PEM, ec_jwk()),
        ] {
            let token = sign(alg, kid, base_payload(), pem);
            let set = serde_json::json!({ "keys": [jwks] });
            let claims = verify_id_token(&token, &set, "https://idp.example", "client-1", None)
                .expect("valid token verifies");
            assert_eq!(claims.subject, "subject-1");
            assert_eq!(claims.username, "alice");
            assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        }
    }

    #[test]
    fn username_falls_back_to_email_then_sub() {
        // No preferred_username → email; neither → sub.
        let mut p = base_payload();
        p.as_object_mut().unwrap().remove("preferred_username");
        assert_eq!(extract_claims(&p).unwrap().username, "alice@example.com");
        p.as_object_mut().unwrap().remove("email");
        assert_eq!(extract_claims(&p).unwrap().username, "subject-1");
        assert_eq!(extract_claims(&p).unwrap().email, None);
    }

    // ---- verification rejections ----------------------------------------

    #[test]
    fn rejects_audience_mismatch_expired_and_bad_issuer() {
        let set = serde_json::json!({ "keys": [rsa_jwk()] });

        // aud mismatch.
        let mut p = base_payload();
        p["aud"] = serde_json::json!("other-client");
        let t = sign(Algorithm::RS256, "rsa-key", p, RSA_PEM);
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::Verification(_))
        ));

        // Expired.
        let mut p = base_payload();
        p["exp"] = serde_json::json!(1_700_000_000_i64 - 10_000);
        let t = sign(Algorithm::RS256, "rsa-key", p, RSA_PEM);
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::Verification(_))
        ));

        // Issuer mismatch.
        let t = sign(Algorithm::RS256, "rsa-key", base_payload(), RSA_PEM);
        assert!(matches!(
            verify_id_token(&t, &set, "https://evil.example", "client-1", None),
            Err(OidcError::Verification(_))
        ));
    }

    #[test]
    fn rejects_nonce_mismatch_and_missing_sub() {
        let set = serde_json::json!({ "keys": [rsa_jwk()] });
        let mut p = base_payload();
        p["nonce"] = serde_json::json!("right-nonce");
        let t = sign(Algorithm::RS256, "rsa-key", p, RSA_PEM);
        assert!(matches!(
            verify_id_token(
                &t,
                &set,
                "https://idp.example",
                "client-1",
                Some("wrong-nonce")
            ),
            Err(OidcError::NonceMismatch)
        ));
        // Matching nonce is fine.
        assert!(verify_id_token(
            &t,
            &set,
            "https://idp.example",
            "client-1",
            Some("right-nonce")
        )
        .is_ok());

        // Missing sub.
        let mut p = base_payload();
        p.as_object_mut().unwrap().remove("sub");
        let t = sign(Algorithm::RS256, "rsa-key", p, RSA_PEM);
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::MissingSubject)
        ));
    }

    #[test]
    fn rejects_unsupported_algorithm_and_untrusted_key() {
        let set = serde_json::json!({ "keys": [rsa_jwk()] });
        // HS256 is not in the allow-list.
        let t = sign(Algorithm::HS256, "rsa-key", base_payload(), "not-a-key");
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::UnsupportedAlgorithm)
        ));

        // A kid with no matching key → NoMatchingKey.
        let t = sign(Algorithm::RS256, "unknown-kid", base_payload(), RSA_PEM);
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::NoMatchingKey)
        ));
    }

    #[test]
    fn selects_key_by_kid_or_first_when_absent() {
        let both = serde_json::json!({ "keys": [ec_jwk(), rsa_jwk()] });
        // Token signed with the RSA key but a mixed set: the ec key is first,
        // the rsa key is picked by kid.
        let t = sign(Algorithm::RS256, "rsa-key", base_payload(), RSA_PEM);
        assert!(verify_id_token(&t, &both, "https://idp.example", "client-1", None).is_ok());

        // No kid on the token → the first key is used (here: ec). A token
        // signed with rsa would then fail to verify against the ec key.
        let t_no_kid = sign(Algorithm::RS256, "", base_payload(), RSA_PEM);
        assert!(matches!(
            verify_id_token(&t_no_kid, &both, "https://idp.example", "client-1", None),
            Err(OidcError::Verification(_))
        ));
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

    // ---- encoding --------------------------------------------------------

    #[test]
    fn quote_plus_matches_python_urlencode() {
        assert_eq!(quote_plus("openid profile email"), "openid+profile+email");
        assert_eq!(quote_plus("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(quote_plus("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(quote_plus("héllo"), "h%C3%A9llo");
    }

    #[test]
    fn authorization_url_encodes_all_params() {
        let cfg = OidcConfig {
            enabled: true,
            issuer: "https://idp.example".into(),
            client_id: "client-1".into(),
            redirect_url: "http://localhost:8000/api/auth/oidc/callback".into(),
            ..OidcConfig::default()
        };
        let client = OidcClient::new(cfg);
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
        assert!(client.is_enabled());
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
        // The config's Debug must not leak the secret into logs.
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

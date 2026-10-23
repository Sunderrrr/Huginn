//! WebAuthn (passkey) ceremonies — port of `hub/app/services/webauthn.py`.
//!
//! # Technical choice
//!
//! The Python hub wraps **py_webauthn** for the ceremony crypto and persists
//! what that library produces: challenges as base64url strings in
//! `webauthn_challenges`, credentials as **COSE public key bytes + sign_count**
//! in `webauthn_credentials`. `webauthn-rs` was evaluated and rejected: its
//! state machine wants to own the whole ceremony state (challenge, excluded
//! credentials, UV requirement…) serialized as its own opaque blob, which does
//! not fit the existing single-use challenge rows, and its `Credential` type is
//! not the raw COSE key blob the existing rows store. This module therefore
//! performs the verification **manually** over
//! `ciborium` (CBOR attestation objects / COSE keys) and the RustCrypto stack
//! (`p256` ES256, `rsa` RS256, `ed25519-dalek` EdDSA, `x509-cert` for the leaf
//! certificate of `x5c` attestation statements). Every check mirrors
//! `py_webauthn` step for step, so credentials registered through the Python
//! hub verify unchanged here — and vice versa.
//!
//! # Semantics (identical to the Python service)
//!
//! * challenges: 32 random bytes (`secrets.token_bytes(32)`), 5-minute TTL,
//!   consumed **exactly once** via [`models::webauthn::consume_challenge`]'s
//!   atomic claim (`webauthn._consume_challenge`).
//! * rp_id/origin come from the DB settings row with env fallback and the
//!   rp_id must be a registrable domain, never a bare IP
//!   (`webauthn._is_registrable_domain`).
//! * sign counters are persisted and checked to detect cloned authenticators;
//!   `webauthn_user_verification` (`preferred|discouraged|required`) decides
//!   whether the UV flag is mandatory.
//! * error strings match `webauthn.WebAuthnError` byte for byte — the routes
//!   surface them exactly like `mfa.py` does.
//!
//! # Attestation formats
//!
//! `none`, `packed` (self-attestation and `x5c`) and `fido-u2f` are verified.
//! `tpm` / `apple` / `android-key` / `android-safetynet` are rejected like any
//! unknown format (same outward 400 as py_webauthn's "Unsupported attestation
//! type"). This is deliberate: the options ask for `attestation: "none"`, so
//! browsers anonymize the attestation and answer with `fmt: "none"`; the extra
//! formats cover authenticators that pass their own statement through anyway.

use std::fmt;

use chrono::{Duration, Utc};
use rand::RngCore;
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::models::setting;
use crate::models::user::User;
use crate::models::webauthn::{self, CredentialNew, WebAuthnChallenge, WebAuthnCredential};

/// Challenge TTL (`webauthn._CHALLENGE_TTL = timedelta(minutes=5)`).
const CHALLENGE_TTL_MINUTES: i64 = 5;
/// Ceremony challenge size (`secrets.token_bytes(32)`).
const CHALLENGE_BYTES: usize = 32;
/// Default `timeout` of both options (py_webauthn defaults).
const CEREMONY_TIMEOUT_MS: u32 = 60_000;
// ---------------------------------------------------------------------------
// Errors — `webauthn.WebAuthnError` messages, byte for byte
// ---------------------------------------------------------------------------

/// Raised on any WebAuthn configuration or verification failure
/// (`webauthn.WebAuthnError`). The `Display` strings are what `mfa.py`
/// surfaces/logs, so they must stay identical.
#[derive(Debug)]
pub enum WebAuthnError {
    /// `WebAuthn is not configured`
    NotConfigured,
    /// `webauthn_rp_id must be a registrable domain, not an IP`
    BadRpId,
    /// `malformed credential` (clientDataJSON unusable)
    MalformedCredential,
    /// `unknown, used, or expired challenge`
    BadChallenge,
    /// `challenge does not belong to this user`
    ChallengeOwnerMismatch,
    /// `registration verification failed`
    RegistrationFailed,
    /// `authentication verification failed`
    AuthenticationFailed,
    /// `missing credential id`
    MissingCredentialId,
    /// `unknown credential`
    UnknownCredential,
    /// `sign counter regression (possible cloned authenticator)`
    CounterRegression,
    /// `user not found or inactive`
    UserInactive,
    /// Infrastructure failure (the routes map this to 500, not a WebAuthn error).
    Db(DbError),
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::NotConfigured => "WebAuthn is not configured",
            Self::BadRpId => "webauthn_rp_id must be a registrable domain, not an IP",
            Self::MalformedCredential => "malformed credential",
            Self::BadChallenge => "unknown, used, or expired challenge",
            Self::ChallengeOwnerMismatch => "challenge does not belong to this user",
            Self::RegistrationFailed => "registration verification failed",
            Self::AuthenticationFailed => "authentication verification failed",
            Self::MissingCredentialId => "missing credential id",
            Self::UnknownCredential => "unknown credential",
            Self::CounterRegression => "sign counter regression (possible cloned authenticator)",
            Self::UserInactive => "user not found or inactive",
            Self::Db(err) => return write!(f, "{err}"),
        };
        f.write_str(msg)
    }
}

impl std::error::Error for WebAuthnError {}

impl From<DbError> for WebAuthnError {
    fn from(err: DbError) -> Self {
        Self::Db(err)
    }
}

// ---------------------------------------------------------------------------
// Configuration (webauthn.rp_config, webauthn._uv, webauthn._is_registrable_domain)
// ---------------------------------------------------------------------------

/// The resolved relying-party identity (`rp_config`'s `(rp_id, rp_name, origin)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
}

impl RpConfig {
    /// `(rp_id, rp_name, origin)` from the DB settings row, falling back to env
    /// (`webauthn.rp_config`). Fails closed on a missing or non-domain rp_id.
    pub async fn resolve(pool: &sqlx::PgPool, config: &Config) -> Result<Self, WebAuthnError> {
        let row = setting::get_settings_row(pool).await?;
        let pick = |db: &str, env: &str| -> String {
            if db.is_empty() {
                env.to_owned()
            } else {
                db.to_owned()
            }
        };
        let (db_rp_id, db_rp_name, db_origin) = match &row {
            Some(row) => (
                row.webauthn_rp_id.as_str(),
                row.webauthn_rp_name.as_str(),
                row.webauthn_origin.as_str(),
            ),
            None => ("", "", ""),
        };
        let rp_id = pick(db_rp_id, &config.webauthn_rp_id);
        let origin = pick(db_origin, &config.webauthn_origin);
        let rp_name = {
            let name = pick(db_rp_name, &config.webauthn_rp_name);
            if name.is_empty() {
                "Huginn".to_owned()
            } else {
                name
            }
        };
        if rp_id.is_empty() || origin.is_empty() {
            return Err(WebAuthnError::NotConfigured);
        }
        if !is_registrable_domain(&rp_id) {
            return Err(WebAuthnError::BadRpId);
        }
        Ok(Self {
            rp_id,
            rp_name,
            origin,
        })
    }
}

/// `webauthn._is_registrable_domain`: rp_id must be a domain (with a dot),
/// never a bare IP or "localhost". Binding passkeys to an IP literal is
/// invalid per spec — we fail closed.
pub fn is_registrable_domain(rp_id: &str) -> bool {
    if rp_id.parse::<std::net::IpAddr>().is_ok() {
        return false; // bare IP
    }
    rp_id.contains('.') && rp_id != "localhost"
}

/// `webauthn._uv` — the configured `UserVerificationRequirement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerification {
    Required,
    Preferred,
    Discouraged,
}

impl UserVerification {
    /// Parse `webauthn_user_verification`; unknown values fall back to
    /// `preferred` like `UserVerificationRequirement(raw)` does on `ValueError`.
    pub fn from_config(raw: &str) -> Self {
        match raw.to_lowercase().as_str() {
            "required" => Self::Required,
            "discouraged" => Self::Discouraged,
            _ => Self::Preferred,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::Discouraged => "discouraged",
        }
    }

    /// `require_user_verification=_uv() == UserVerificationRequirement.REQUIRED`.
    pub fn require_user_verification(self) -> bool {
        self == Self::Required
    }
}

// ---------------------------------------------------------------------------
// base64url (py_webauthn helpers: bytes_to_base64url / base64url_to_bytes)
// ---------------------------------------------------------------------------

/// `bytes_to_base64url` — URL-safe, unpadded.
pub fn b64u_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `base64url_to_bytes` — padding optional, like Python's `urlsafe_b64decode`.
pub fn b64u_decode(value: &str) -> Result<Vec<u8>, ()> {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Ceremony orchestration (DB-touching; the crypto lives below)
// ---------------------------------------------------------------------------

fn random_challenge() -> Vec<u8> {
    let mut buf = vec![0u8; CHALLENGE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// `webauthn._store_challenge` — 5-minute TTL, single purpose, optional owner.
async fn store_challenge(
    pool: &sqlx::PgPool,
    challenge_b64: &str,
    user_id: Option<Uuid>,
    purpose: &str,
) -> Result<WebAuthnChallenge, WebAuthnError> {
    let expires_at = Utc::now() + Duration::minutes(CHALLENGE_TTL_MINUTES);
    Ok(webauthn::create_challenge(pool, challenge_b64, user_id, purpose, expires_at).await?)
}

/// `webauthn.begin_registration` — registration options plus a stored challenge.
pub async fn begin_registration(
    pool: &sqlx::PgPool,
    config: &Config,
    user: &User,
) -> Result<RegistrationOptions, WebAuthnError> {
    let rp = RpConfig::resolve(pool, config).await?;
    let existing = webauthn::list_credentials(pool, user.id).await?;
    let challenge_b64 = b64u_encode(&random_challenge());
    let uv = UserVerification::from_config(&config.webauthn_user_verification);
    let options = registration_options(&rp, uv, user, &challenge_b64, &existing);
    store_challenge(pool, &challenge_b64, Some(user.id), "register").await?;
    Ok(options)
}

/// `webauthn.finish_registration` — consume the challenge, verify the
/// attestation, persist the credential.
pub async fn finish_registration(
    pool: &sqlx::PgPool,
    config: &Config,
    user: &User,
    name: &str,
    credential: &serde_json::Value,
) -> Result<WebAuthnCredential, WebAuthnError> {
    let rp = RpConfig::resolve(pool, config).await?;
    let challenge_b64 = client_data_challenge(credential)?;
    let row = consume_challenge(pool, &challenge_b64, "register").await?;
    if row.user_id != Some(user.id) {
        return Err(WebAuthnError::ChallengeOwnerMismatch);
    }
    let expected_challenge =
        b64u_decode(&row.challenge).map_err(|_| WebAuthnError::MalformedCredential)?;
    let uv = UserVerification::from_config(&config.webauthn_user_verification);
    let verified = verify_registration(
        credential,
        &expected_challenge,
        &rp.rp_id,
        &rp.origin,
        uv.require_user_verification(),
    )?;

    let cred = webauthn::create_credential(
        pool,
        CredentialNew {
            user_id: user.id,
            // `name or "passkey"`.
            name: if name.is_empty() {
                "passkey".to_owned()
            } else {
                name.to_owned()
            },
            credential_id: b64u_encode(&verified.credential_id),
            public_key: verified.credential_public_key,
            sign_count: verified.sign_count,
            transports: raw_transports(credential),
            aaguid: Some(verified.aaguid),
        },
    )
    .await?;
    Ok(cred)
}

/// `webauthn.begin_login` — always usernameless/discoverable: we never disclose
/// an allowCredentials list, so the response can't be used to probe whether an
/// account exists. `username` is accepted and ignored, exactly like the Python
/// service.
pub async fn begin_login(
    pool: &sqlx::PgPool,
    config: &Config,
    _username: Option<&str>,
) -> Result<AuthenticationOptions, WebAuthnError> {
    let rp = RpConfig::resolve(pool, config).await?;
    let challenge_b64 = b64u_encode(&random_challenge());
    let uv = UserVerification::from_config(&config.webauthn_user_verification);
    let options = authentication_options(&rp, uv, &challenge_b64);
    store_challenge(pool, &challenge_b64, None, "login").await?;
    Ok(options)
}

/// `webauthn.finish_login` — consume the challenge, verify the assertion,
/// detect clones via the sign counter, return the account owner.
pub async fn finish_login(
    pool: &sqlx::PgPool,
    config: &Config,
    credential: &serde_json::Value,
) -> Result<User, WebAuthnError> {
    let rp = RpConfig::resolve(pool, config).await?;
    let challenge_b64 = client_data_challenge(credential)?;
    let row = consume_challenge(pool, &challenge_b64, "login").await?;

    let cred_id = credential
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(WebAuthnError::MissingCredentialId)?;
    let stored = webauthn::get_credential_by_credential_id(pool, cred_id)
        .await?
        .ok_or(WebAuthnError::UnknownCredential)?;

    let expected_challenge =
        b64u_decode(&row.challenge).map_err(|_| WebAuthnError::MalformedCredential)?;
    let uv = UserVerification::from_config(&config.webauthn_user_verification);
    let verified = verify_authentication(
        credential,
        &expected_challenge,
        &rp.rp_id,
        &rp.origin,
        &stored.public_key,
        stored.sign_count,
        uv.require_user_verification(),
    )?;

    // Clone detection: a non-zero counter that didn't advance signals a copy.
    check_sign_counter(verified.new_sign_count, stored.sign_count)?;
    webauthn::update_credential_usage(pool, stored.id, verified.new_sign_count, Utc::now()).await?;

    let user = crate::models::user::get_by_id(pool, stored.user_id)
        .await?
        .filter(|u| u.is_active)
        .ok_or(WebAuthnError::UserInactive)?;
    Ok(user)
}

/// `webauthn._consume_challenge` — the atomic single-use claim.
async fn consume_challenge(
    pool: &sqlx::PgPool,
    challenge_b64: &str,
    purpose: &str,
) -> Result<WebAuthnChallenge, WebAuthnError> {
    webauthn::consume_challenge(pool, challenge_b64, purpose)
        .await?
        .ok_or(WebAuthnError::BadChallenge)
}

/// `webauthn._client_data_challenge` — the base64url challenge string echoed
/// inside clientDataJSON (used to find the stored challenge row).
pub fn client_data_challenge(credential: &serde_json::Value) -> Result<String, WebAuthnError> {
    let cdj = credential
        .get("response")
        .and_then(|r| r.get("clientDataJSON"))
        .and_then(serde_json::Value::as_str)
        .ok_or(WebAuthnError::MalformedCredential)?;
    let bytes = b64u_decode(cdj).map_err(|_| WebAuthnError::MalformedCredential)?;
    let data: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| WebAuthnError::MalformedCredential)?;
    data.get("challenge")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(WebAuthnError::MalformedCredential)
}

/// `(credential.get("response", {}) or {}).get("transports")` — the raw client
/// value as the Python service stores it (`None`/absent → SQL NULL).
fn raw_transports(credential: &serde_json::Value) -> Option<serde_json::Value> {
    let value = credential.get("response")?.get("transports")?;
    if value.is_null() {
        None
    } else {
        Some(value.clone())
    }
}

// ---------------------------------------------------------------------------
// Submodules — ceremony stages split by function
// ---------------------------------------------------------------------------

mod assertion;
mod attestation;
mod helpers;
mod options;

#[cfg(test)]
pub(crate) mod test_support;

use assertion::check_sign_counter;
pub use assertion::{verify_authentication, VerifiedAuthentication};
pub use attestation::{verify_registration, VerifiedRegistration};
use options::{authentication_options, registration_options};
pub use options::{
    AuthenticationOptions, AuthenticatorSelection, CredParam, CredentialDescriptor,
    RegistrationOptions, RpEntity, UserEntity,
};

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use serde_json::json;

    #[test]
    fn user_verification_matches_the_python_enum() {
        assert_eq!(
            UserVerification::from_config("required"),
            UserVerification::Required
        );
        assert_eq!(
            UserVerification::from_config("REQUIRED"),
            UserVerification::Required
        );
        assert_eq!(
            UserVerification::from_config("preferred"),
            UserVerification::Preferred
        );
        assert_eq!(
            UserVerification::from_config("discouraged"),
            UserVerification::Discouraged
        );
        // Unknown values fail back to preferred (ValueError → PREFERRED).
        assert_eq!(
            UserVerification::from_config("sometimes"),
            UserVerification::Preferred
        );
        assert_eq!(
            UserVerification::from_config(""),
            UserVerification::Preferred
        );
        assert!(UserVerification::Required.require_user_verification());
        assert!(!UserVerification::Preferred.require_user_verification());
        assert!(!UserVerification::Discouraged.require_user_verification());
    }

    #[test]
    fn rp_id_must_be_a_registrable_domain() {
        assert!(is_registrable_domain("huginn.example.com"));
        assert!(is_registrable_domain("example.com"));
        assert!(!is_registrable_domain("192.0.2.1"));
        assert!(!is_registrable_domain("2001:db8::1"));
        assert!(!is_registrable_domain("localhost"));
        assert!(!is_registrable_domain("com"));
        assert!(!is_registrable_domain(""));
    }

    #[test]
    fn base64url_round_trips_like_py_webauthn() {
        assert_eq!(b64u_encode(b"\xfb\xff"), "-_8");
        assert_eq!(b64u_decode("-_8").unwrap(), b"\xfb\xff");
        // Padding is optional on input.
        assert_eq!(b64u_decode("YQ").unwrap(), b"a");
        assert_eq!(b64u_decode("YQ==").unwrap(), b"a");
        assert!(b64u_decode("!!not base64!!").is_err());
    }

    // ---- challenge extraction / malformed payloads ------------------------

    #[test]
    fn client_data_challenge_extraction_matches_the_python_service() {
        let challenge = b"the expected challenge bytes!!";
        let cdj = client_data_json("webauthn.get", challenge, ORIGIN);
        let credential = authentication_credential(b"id", &cdj, &[], &[]);
        assert_eq!(
            client_data_challenge(&credential).unwrap(),
            b64u_encode(challenge)
        );

        // Anything unusable is "malformed credential" (the Python precedence).
        for bad in [
            json!({}),
            json!({"response": {}}),
            json!({"response": {"clientDataJSON": "!!!"}}),
            json!({"response": {"clientDataJSON": b64u_encode(b"not json")}}),
            json!({"response": {"clientDataJSON": b64u_encode(b"[1,2,3]")}}),
            json!({"response": {"clientDataJSON": b64u_encode(br#"{"type":"x"}"#)}}),
            json!({"response": {"clientDataJSON": 42}}),
        ] {
            assert_eq!(
                client_data_challenge(&bad).unwrap_err().to_string(),
                "malformed credential",
                "payload: {bad}"
            );
        }
    }

    #[test]
    fn error_messages_match_the_python_webauthn_error_strings() {
        assert_eq!(
            WebAuthnError::NotConfigured.to_string(),
            "WebAuthn is not configured"
        );
        assert_eq!(
            WebAuthnError::BadRpId.to_string(),
            "webauthn_rp_id must be a registrable domain, not an IP"
        );
        assert_eq!(
            WebAuthnError::MalformedCredential.to_string(),
            "malformed credential"
        );
        assert_eq!(
            WebAuthnError::BadChallenge.to_string(),
            "unknown, used, or expired challenge"
        );
        assert_eq!(
            WebAuthnError::ChallengeOwnerMismatch.to_string(),
            "challenge does not belong to this user"
        );
        assert_eq!(
            WebAuthnError::RegistrationFailed.to_string(),
            "registration verification failed"
        );
        assert_eq!(
            WebAuthnError::AuthenticationFailed.to_string(),
            "authentication verification failed"
        );
        assert_eq!(
            WebAuthnError::MissingCredentialId.to_string(),
            "missing credential id"
        );
        assert_eq!(
            WebAuthnError::UnknownCredential.to_string(),
            "unknown credential"
        );
        assert_eq!(
            WebAuthnError::CounterRegression.to_string(),
            "sign counter regression (possible cloned authenticator)"
        );
        assert_eq!(
            WebAuthnError::UserInactive.to_string(),
            "user not found or inactive"
        );
    }
}

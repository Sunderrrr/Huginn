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

use chrono::{DateTime, Duration, Utc};
use ciborium::value::Value;
use rand::RngCore;
use serde::{Deserialize, Serialize};
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
            Self::CounterRegression => {
                "sign counter regression (possible cloned authenticator)"
            }
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
// Options wire shapes (py_webauthn `options_to_json`)
// ---------------------------------------------------------------------------
//
// Field order below is the Python dict insertion order of
// `options_to_json_dict`, so the JSON body is identical to the byte.

/// `PublicKeyCredentialRpEntity` as emitted by `options_to_json_dict` (`name`
/// first, then `id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpEntity {
    pub name: String,
    pub id: String,
}

/// `PublicKeyCredentialUserEntity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserEntity {
    /// base64url of the user handle — `str(user.id).encode()` in the Python hub.
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// One `pubKeyCredParams` entry (`{"type": "public-key", "alg": …}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredParam {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i64,
}

/// A `PublicKeyCredentialDescriptor` as emitted by `options_to_json_dict`
/// (`id` first, then `type`, then optional `transports`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

impl CredentialDescriptor {
    fn public_key(id: String) -> Self {
        Self {
            id,
            type_: "public-key".to_owned(),
            transports: None,
        }
    }
}

/// `AuthenticatorSelectionCriteria` as the service builds it: `resident_key`
/// preferred, `require_resident_key` false (the dataclass default is emitted),
/// `user_verification` from config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    #[serde(rename = "residentKey")]
    pub resident_key: String,
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: bool,
    #[serde(rename = "userVerification")]
    pub user_verification: String,
}

/// `PublicKeyCredentialCreationOptions` — `webauthn.generate_registration_options`
/// as called by `webauthn.begin_registration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationOptions {
    pub rp: RpEntity,
    pub user: UserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<CredParam>,
    pub timeout: u32,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: String,
}

/// `PublicKeyCredentialRequestOptions` — `webauthn.generate_authentication_options`
/// as called by `webauthn.begin_login` (always usernameless/discoverable, so
/// `allowCredentials` stays empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    pub challenge: String,
    pub timeout: u32,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: String,
}

/// `default_supported_pub_key_params` (EdDSA, ES256, RS256 — in that order).
fn pub_key_cred_params() -> Vec<CredParam> {
    [-8_i64, -7, -257]
        .iter()
        .map(|&alg| CredParam {
            type_: "public-key".to_owned(),
            alg,
        })
        .collect()
}

/// Build the registration options exactly like
/// `webauthn.generate_registration_options` + `options_to_json` for the
/// service's parameters (32-byte challenge, resident key preferred, attestation
/// none, no hints).
fn registration_options(
    rp: &RpConfig,
    uv: UserVerification,
    user: &User,
    challenge_b64: &str,
    existing: &[WebAuthnCredential],
) -> RegistrationOptions {
    RegistrationOptions {
        rp: RpEntity {
            name: rp.rp_name.clone(),
            id: rp.rp_id.clone(),
        },
        user: UserEntity {
            id: b64u_encode(user.id.to_string().as_bytes()),
            name: user.username.clone(),
            display_name: user.username.clone(),
        },
        challenge: challenge_b64.to_owned(),
        pub_key_cred_params: pub_key_cred_params(),
        timeout: CEREMONY_TIMEOUT_MS,
        exclude_credentials: existing
            .iter()
            .map(|c| {
                // Python: PublicKeyCredentialDescriptor(id=base64url_to_bytes(
                // credential_id)) → re-encoded by options_to_json; normalize the
                // same way so the bytes match whatever the stored spelling is.
                let raw = b64u_decode(&c.credential_id).unwrap_or_default();
                CredentialDescriptor::public_key(b64u_encode(&raw))
            })
            .collect(),
        authenticator_selection: AuthenticatorSelection {
            resident_key: "preferred".to_owned(),
            require_resident_key: false,
            user_verification: uv.as_str().to_owned(),
        },
        attestation: "none".to_owned(),
    }
}

/// Build the authentication options exactly like
/// `webauthn.generate_authentication_options` + `options_to_json`.
fn authentication_options(
    rp: &RpConfig,
    uv: UserVerification,
    challenge_b64: &str,
) -> AuthenticationOptions {
    AuthenticationOptions {
        challenge: challenge_b64.to_owned(),
        timeout: CEREMONY_TIMEOUT_MS,
        rp_id: rp.rp_id.clone(),
        allow_credentials: Vec::new(),
        user_verification: uv.as_str().to_owned(),
    }
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
    Ok(
        webauthn::create_challenge(pool, challenge_b64, user_id, purpose, expires_at).await?,
    )
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
    let expected_challenge = b64u_decode(&row.challenge).map_err(|_| WebAuthnError::MalformedCredential)?;
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

    let expected_challenge = b64u_decode(&row.challenge).map_err(|_| WebAuthnError::MalformedCredential)?;
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

/// `webauthn.finish_login`'s clone check, layered on top of the counter check
/// inside [`verify_authentication`]: a non-zero counter that didn't advance
/// signals a copied authenticator. The `0 → 0` case is legitimate (an
/// authenticator that never counts).
fn check_sign_counter(new_count: i64, stored_count: i64) -> Result<(), WebAuthnError> {
    if new_count <= stored_count && !(new_count == 0 && stored_count == 0) {
        return Err(WebAuthnError::CounterRegression);
    }
    Ok(())
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
// Verification core (py_webauthn verify_registration_response /
// verify_authentication_response)
// ---------------------------------------------------------------------------

/// What `webauthn.finish_registration` persists from a verified attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistration {
    pub credential_id: Vec<u8>,
    /// Canonical COSE key bytes (py_webauthn stores `encode_cbor(parse_cbor(k))`).
    pub credential_public_key: Vec<u8>,
    pub sign_count: i64,
    /// `aaguid_to_string` formatting: `xxxxxxxx-xxxx-…`.
    pub aaguid: String,
}

/// What `webauthn.finish_login` needs from a verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthentication {
    pub new_sign_count: i64,
    pub user_verified: bool,
}

/// py_webauthn's `AttestationStatement` fields checked by the `none` format.
const ATT_STMT_FIELDS: [&str; 7] = ["sig", "x5c", "response", "alg", "ver", "certInfo", "pubArea"];

/// `webauthn.verify_registration_response` for the service's parameters
/// (`require_user_presence=True`, `require_user_verification` from config).
/// Every failure is logged like Python's
/// `logger.warning("WebAuthn registration verification failed: %s", exc)` and
/// surfaces as [`WebAuthnError::RegistrationFailed`].
pub fn verify_registration(
    credential: &serde_json::Value,
    expected_challenge: &[u8],
    expected_rp_id: &str,
    expected_origin: &str,
    require_user_verification: bool,
) -> Result<VerifiedRegistration, WebAuthnError> {
    verify_registration_inner(
        credential,
        expected_challenge,
        expected_rp_id,
        expected_origin,
        require_user_verification,
    )
    .map_err(|reason| {
        tracing::warn!("WebAuthn registration verification failed: {reason}");
        WebAuthnError::RegistrationFailed
    })
}

fn verify_registration_inner(
    credential: &serde_json::Value,
    expected_challenge: &[u8],
    expected_rp_id: &str,
    expected_origin: &str,
    require_user_verification: bool,
) -> Result<VerifiedRegistration, String> {
    let cred = ParsedCredential::parse_registration(credential)?;

    if b64u_encode(&cred.raw_id) != cred.id {
        return Err("id and raw_id were not equivalent".into());
    }

    let client_data = parse_client_data_json(&cred.client_data_json)
        .map_err(|e| format!("clientDataJSON was malformed. See __cause__ for more info: {e}"))?;
    if client_data.type_ != "webauthn.create" {
        return Err(format!(
            "Unexpected client data type \"{}\", expected \"webauthn.create\"",
            client_data.type_
        ));
    }
    if expected_challenge != client_data.challenge {
        return Err("Client data challenge was not expected challenge".into());
    }
    if expected_origin != client_data.origin {
        return Err(format!(
            "Unexpected client data origin \"{}\", expected \"{expected_origin}\"",
            client_data.origin
        ));
    }
    check_token_binding(&client_data)?;

    let attestation = parse_attestation_object(&cred.attestation_object)
        .map_err(|e| format!("attestationObject was malformed. See __cause__ for more info: {e}"))?;
    let auth_data = &attestation.auth_data;

    let expected_rp_id_hash = sha256(expected_rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err("Unexpected RP ID hash".into());
    }
    if !auth_data.flag(FLAG_UP) {
        return Err(
            "User presence was required, but was not present during attestation".into(),
        );
    }
    if require_user_verification && !auth_data.flag(FLAG_UV) {
        return Err(
            "User verification is required but user was not verified during attestation".into(),
        );
    }

    let attested = auth_data
        .attested
        .as_ref()
        .ok_or_else(|| "Authenticator did not provide attested credential data".to_string())?;
    if attested.credential_id.is_empty() {
        return Err("Authenticator did not provide a credential ID".into());
    }
    if attested.credential_public_key.is_empty() {
        return Err("Authenticator did not provide a credential public key".into());
    }

    let decoded = decode_credential_public_key(&attested.credential_public_key)?;
    if !matches!(decoded.alg, -8 | -7 | -257) {
        return Err(format!(
            "Unsupported credential public key alg {}, expected one of: [-8, -7, -257]",
            decoded.alg
        ));
    }
    if !matches!(attestation.fmt.as_str(), "none" | "packed" | "fido-u2f") {
        return Err(format!(
            "Unsupported attestation type \"{}\"",
            attestation.fmt
        ));
    }

    verify_attestation(
        &attestation,
        auth_data,
        &cred.client_data_json,
        &attested.credential_public_key,
        &attested.credential_id,
    )?;

    Ok(VerifiedRegistration {
        credential_id: attested.credential_id.clone(),
        credential_public_key: attested.credential_public_key.clone(),
        sign_count: auth_data.sign_count,
        aaguid: aaguid_to_string(&attested.aaguid),
    })
}

/// `webauthn.verify_authentication_response` for the service's parameters.
/// Failures log like Python's
/// `logger.warning("WebAuthn authentication verification failed: %s", exc)` and
/// surface as [`WebAuthnError::AuthenticationFailed`].
pub fn verify_authentication(
    credential: &serde_json::Value,
    expected_challenge: &[u8],
    expected_rp_id: &str,
    expected_origin: &str,
    credential_public_key: &[u8],
    credential_current_sign_count: i64,
    require_user_verification: bool,
) -> Result<VerifiedAuthentication, WebAuthnError> {
    verify_authentication_inner(
        credential,
        expected_challenge,
        expected_rp_id,
        expected_origin,
        credential_public_key,
        credential_current_sign_count,
        require_user_verification,
    )
    .map_err(|reason| {
        tracing::warn!("WebAuthn authentication verification failed: {reason}");
        WebAuthnError::AuthenticationFailed
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_authentication_inner(
    credential: &serde_json::Value,
    expected_challenge: &[u8],
    expected_rp_id: &str,
    expected_origin: &str,
    credential_public_key: &[u8],
    credential_current_sign_count: i64,
    require_user_verification: bool,
) -> Result<VerifiedAuthentication, String> {
    let cred = ParsedCredential::parse_authentication(credential)?;

    if b64u_encode(&cred.raw_id) != cred.id {
        return Err("id and raw_id were not equivalent".into());
    }

    let client_data = parse_client_data_json(&cred.client_data_json)
        .map_err(|e| format!("clientDataJSON was malformed. See __cause__ for more info: {e}"))?;
    if client_data.type_ != "webauthn.get" {
        return Err(format!(
            "Unexpected client data type \"{}\", expected \"webauthn.get\"",
            client_data.type_
        ));
    }
    if expected_challenge != client_data.challenge {
        return Err("Client data challenge was not expected challenge".into());
    }
    if expected_origin != client_data.origin {
        return Err(format!(
            "Unexpected client data origin \"{}\", expected \"{expected_origin}\"",
            client_data.origin
        ));
    }
    check_token_binding(&client_data)?;

    let auth_data = parse_authenticator_data(&cred.authenticator_data)?;
    let expected_rp_id_hash = sha256(expected_rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err("Unexpected RP ID hash".into());
    }
    if !auth_data.flag(FLAG_UP) {
        return Err("User was not present during authentication".into());
    }
    if require_user_verification && !auth_data.flag(FLAG_UV) {
        return Err(
            "User verification is required but user was not verified during authentication".into(),
        );
    }

    let new_sign_count = auth_data.sign_count;
    // Replay/clone guard: a counter that did not advance is suspicious.
    if (new_sign_count > 0 || credential_current_sign_count > 0)
        && new_sign_count <= credential_current_sign_count
    {
        return Err(format!(
            "Response sign count of {new_sign_count} was not greater than current count of {credential_current_sign_count}"
        ));
    }

    let mut signature_base = cred.authenticator_data.clone();
    signature_base.extend_from_slice(&sha256(&cred.client_data_json));
    let decoded = decode_credential_public_key(credential_public_key)?;
    verify_signature(&decoded, &cred.signature, &signature_base)?;

    Ok(VerifiedAuthentication {
        new_sign_count,
        user_verified: auth_data.flag(FLAG_UV),
    })
}

// ---------------------------------------------------------------------------
// Credential / clientDataJSON parsing (py_webauthn helpers)
// ---------------------------------------------------------------------------

/// The subset of `parse_registration_credential_json` /
/// `parse_authentication_credential_json` the verifiers need.
struct ParsedCredential {
    id: String,
    raw_id: Vec<u8>,
    client_data_json: Vec<u8>,
    attestation_object: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("Credential missing required {key}"))
}

fn check_type_and_attachment(credential: &serde_json::Value) -> Result<(), String> {
    // `PublicKeyCredentialType(cred_type)` — only "public-key" exists.
    if credential.get("type").and_then(serde_json::Value::as_str) != Some("public-key") {
        return Err("Credential had unexpected type".into());
    }
    if let Some(attachment) = credential.get("authenticatorAttachment") {
        if let Some(attachment) = attachment.as_str() {
            if !matches!(attachment, "platform" | "cross-platform") {
                return Err("Credential had unexpected authenticatorAttachment".into());
            }
        }
    }
    Ok(())
}

impl ParsedCredential {
    fn parse_registration(credential: &serde_json::Value) -> Result<Self, String> {
        if !credential.is_object() {
            return Err("Credential was not a JSON object".into());
        }
        check_type_and_attachment(credential)?;
        let id = json_str(credential, "id")?.to_owned();
        let raw_id = b64u_decode(json_str(credential, "rawId")?)
            .map_err(|_| "Could not parse registration credential from JSON data".to_string())?;
        let response = credential
            .get("response")
            .filter(|r| r.is_object())
            .ok_or("Credential missing required response")?;
        let client_data_json = b64u_decode(json_str(response, "clientDataJSON")?)
            .map_err(|_| "Could not parse registration credential from JSON data".to_string())?;
        let attestation_object = b64u_decode(json_str(response, "attestationObject")?)
            .map_err(|_| "Could not parse registration credential from JSON data".to_string())?;
        Ok(Self {
            id,
            raw_id,
            client_data_json,
            attestation_object,
            authenticator_data: Vec::new(),
            signature: Vec::new(),
        })
    }

    fn parse_authentication(credential: &serde_json::Value) -> Result<Self, String> {
        if !credential.is_object() {
            return Err("Credential was not a JSON object".into());
        }
        check_type_and_attachment(credential)?;
        let id = json_str(credential, "id")?.to_owned();
        let raw_id = b64u_decode(json_str(credential, "rawId")?)
            .map_err(|_| "Could not parse authentication credential from JSON data".to_string())?;
        let response = credential
            .get("response")
            .filter(|r| r.is_object())
            .ok_or("Credential missing required response")?;
        // userHandle: a base64url string, or absent/null. Anything else is invalid.
        if let Some(handle) = response.get("userHandle") {
            if !handle.is_null() {
                if let Some(handle) = handle.as_str() {
                    b64u_decode(handle)
                        .map_err(|_| "Could not parse authentication credential from JSON data".to_string())?;
                } else {
                    return Err("Credential response had unexpected userHandle".into());
                }
            }
        }
        let client_data_json = b64u_decode(json_str(response, "clientDataJSON")?)
            .map_err(|_| "Could not parse authentication credential from JSON data".to_string())?;
        let authenticator_data = b64u_decode(json_str(response, "authenticatorData")?)
            .map_err(|_| "Could not parse authentication credential from JSON data".to_string())?;
        let signature = b64u_decode(json_str(response, "signature")?)
            .map_err(|_| "Could not parse authentication credential from JSON data".to_string())?;
        Ok(Self {
            id,
            raw_id,
            client_data_json,
            attestation_object: Vec::new(),
            authenticator_data,
            signature,
        })
    }
}

/// `webauthn.helpers.parse_client_data_json` (plus its `TokenBinding` quirks).
struct ClientData {
    type_: String,
    challenge: Vec<u8>,
    origin: String,
    /// The parsed token binding status, when it is one of the known values.
    token_binding: Option<String>,
}

fn parse_client_data_json(bytes: &[u8]) -> Result<ClientData, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "Unable to decode clientDataJSON bytes as JSON")?;
    if !value.is_object() {
        return Err("clientDataJSON was not a dict".into());
    }
    let type_ = json_str(&value, "type")
        .map_err(|_| "clientDataJSON missing required property \"type\"")?
        .to_owned();
    let challenge_raw = json_str(&value, "challenge")
        .map_err(|_| "clientDataJSON missing required property \"challenge\"")?;
    let challenge =
        b64u_decode(challenge_raw).map_err(|_| "Unable to decode clientDataJSON challenge")?;
    let origin = json_str(&value, "origin")
        .map_err(|_| "clientDataJSON missing required property \"origin\"")?
        .to_owned();

    // Some U2F devices set a string to `tokenBinding`, in which case ignore it.
    let mut token_binding = None;
    if let Some(binding) = value.get("tokenBinding") {
        if binding.is_object() {
            let status = binding
                .get("status")
                .and_then(serde_json::Value::as_str)
                .ok_or("token_binding missing required property \"status\"")?;
            // Unknown statuses are ignored completely (py_webauthn quirk).
            if matches!(status, "supported" | "present" | "not-supported") {
                token_binding = Some(status.to_owned());
            }
        }
    }
    Ok(ClientData {
        type_,
        challenge,
        origin,
        token_binding,
    })
}

/// `verify_*_response`'s token binding check: only "supported"/"present" pass.
fn check_token_binding(client_data: &ClientData) -> Result<(), String> {
    match client_data.token_binding.as_deref() {
        Some("supported") | Some("present") | None => Ok(()),
        Some(status) => Err(format!(
            "Unexpected token_binding status of \"{status}\", expected one of \"supported,present\""
        )),
    }
}

// ---------------------------------------------------------------------------
// Authenticator data + attestation object (CBOR via ciborium)
// ---------------------------------------------------------------------------

const FLAG_UP: u8 = 1 << 0;
const FLAG_UV: u8 = 1 << 2;
const FLAG_AT: u8 = 1 << 6;
const FLAG_ED: u8 = 1 << 7;

/// `webauthn.helpers.parse_authenticator_data`.
struct AttestedCredentialData {
    aaguid: Vec<u8>,
    credential_id: Vec<u8>,
    /// Canonical COSE key bytes (py_webauthn re-encodes what it parsed).
    credential_public_key: Vec<u8>,
}

struct AuthData {
    rp_id_hash: Vec<u8>,
    flags: u8,
    sign_count: i64,
    attested: Option<AttestedCredentialData>,
}

impl AuthData {
    fn flag(&self, bit: u8) -> bool {
        self.flags & bit != 0
    }
}

/// Decode one CBOR value, rejecting duplicate map keys the way
/// `parse_cbor(..., allow_duplicate_keys=False)` does (recursively).
fn cbor_decode_one(bytes: &[u8]) -> Result<(Value, usize), String> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|e| format!("Could not decode CBOR data: {e}"))?;
    reject_duplicate_keys(&value)?;
    Ok((value, cursor.position() as usize))
}

fn reject_duplicate_keys(value: &Value) -> Result<(), String> {
    match value {
        Value::Map(entries) => {
            for i in 0..entries.len() {
                for j in (i + 1)..entries.len() {
                    if entries[i].0 == entries[j].0 {
                        return Err("CBOR map contained duplicate keys".into());
                    }
                }
                reject_duplicate_keys(&entries[i].1)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for value in values {
                reject_duplicate_keys(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn cbor_encode(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .map_err(|e| format!("Could not encode CBOR data: {e}"))?;
    Ok(out)
}

/// Some authenticators incorrectly compose authData when using EdDSA: a CBOR
/// "Map of 3 items" (0xA3) should be "Map of 4 items" (0xA4). py_webauthn fixes
/// the byte on sight — mirror it (`parse_authenticator_data`).
const BAD_EDDSA_CBOR: [u8; 17] = [
    0xa3, 0x01, 0x63, 0x4f, 0x4b, 0x50, 0x03, 0x27, 0x20, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
    0x39,
];

fn parse_authenticator_data(val: &[u8]) -> Result<AuthData, String> {
    if val.len() < 37 {
        return Err(format!(
            "Authenticator data was {} bytes, expected at least 37 bytes",
            val.len()
        ));
    }
    let mut val = val.to_vec();
    let rp_id_hash = val[..32].to_vec();
    let flags = val[32];
    let sign_count = i64::from(u32::from_be_bytes(val[33..37].try_into().unwrap()));
    let mut pointer = 37;

    let mut attested = None;
    if flags & FLAG_AT != 0 {
        if val.len() < pointer + 18 {
            return Err("Authenticator data truncated in attested credential data".into());
        }
        let aaguid = val[pointer..pointer + 16].to_vec();
        pointer += 16;
        let credential_id_len = u16::from_be_bytes([val[pointer], val[pointer + 1]]) as usize;
        pointer += 2;
        if val.len() < pointer + credential_id_len {
            return Err("Authenticator data truncated in credential id".into());
        }
        let credential_id = val[pointer..pointer + credential_id_len].to_vec();
        pointer += credential_id_len;

        // The bad-EdDSA workaround mutates a copy, so decode from `val` after
        // applying it in place (Python replaces `val` wholesale).
        if val[pointer..].starts_with(&BAD_EDDSA_CBOR) {
            val[pointer] = 0xa4;
        }
        let (key, consumed) = cbor_decode_one(&val[pointer..])?;
        let credential_public_key = cbor_encode(&key)?;
        pointer += consumed;

        attested = Some(AttestedCredentialData {
            aaguid,
            credential_id,
            credential_public_key,
        });
    }

    if flags & FLAG_ED != 0 {
        let (_extensions, consumed) = cbor_decode_one(&val[pointer..])?;
        pointer += consumed;
    }

    if val.len() > pointer {
        return Err("Leftover bytes detected while parsing authenticator data".into());
    }

    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
    })
}

/// `webauthn.helpers.aaguid_to_string` (`"xxxxxxxx-xxxx-…"` GUID spelling).
fn aaguid_to_string(val: &[u8]) -> String {
    let hex: String = val.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// `webauthn.helpers.parse_attestation_object` (+ `parse_attestation_statement`).
struct AttestationObject {
    fmt: String,
    auth_data: AuthData,
    auth_data_bytes: Vec<u8>,
    /// The recognized `attStmt` fields (`sig`, `x5c`, `response`, `alg`,
    /// `ver`, `certInfo`, `pubArea`) that are present and non-null.
    att_stmt: Vec<(String, Value)>,
}

fn map_entries(value: &Value) -> Result<&Vec<(Value, Value)>, String> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err("CBOR value was not a map".into()),
    }
}

fn map_get<'a>(entries: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn parse_attestation_object(bytes: &[u8]) -> Result<AttestationObject, String> {
    let (value, _consumed) = cbor_decode_one(bytes)?;
    let entries = map_entries(&value)?;
    let fmt = map_get(entries, &Value::Text("fmt".into()))
        .and_then(Value::as_text)
        .ok_or("attestationObject missing required property \"fmt\"")?
        .to_owned();
    let auth_data_bytes = map_get(entries, &Value::Text("authData".into()))
        .and_then(Value::as_bytes)
        .ok_or("attestationObject missing required property \"authData\"")?
        .to_vec();
    let auth_data = parse_authenticator_data(&auth_data_bytes)?;

    // `parse_attestation_statement` only recognizes these keys; a field is
    // "set" when present AND non-null (Python: `field is not None`).
    let mut att_stmt = Vec::new();
    if let Some(stmt) = map_get(entries, &Value::Text("attStmt".into())) {
        let stmt_entries = map_entries(stmt)?;
        for field in ATT_STMT_FIELDS {
            if let Some(v) = map_get(stmt_entries, &Value::Text(field.into())) {
                if !matches!(v, Value::Null) {
                    att_stmt.push((field.to_owned(), v.clone()));
                }
            }
        }
    }
    Ok(AttestationObject {
        fmt,
        auth_data,
        auth_data_bytes,
        att_stmt,
    })
}

impl AttestationObject {
    fn att_stmt_get(&self, field: &str) -> Option<&Value> {
        self.att_stmt
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| v)
    }

    fn att_stmt_sig(&self) -> Result<&[u8], String> {
        self.att_stmt_get("sig")
            .and_then(|v| v.as_bytes().map(Vec::as_slice))
            .filter(|s| !s.is_empty())
            .ok_or("Attestation statement was missing signature".to_string())
    }

    fn att_stmt_alg(&self) -> Result<i64, String> {
        // Python: `if not attestation_statement.alg` — 0 is "missing".
        self.att_stmt_get("alg")
            .and_then(Value::as_integer)
            .and_then(|i| i64::try_from(i).ok())
            .filter(|&alg| alg != 0)
            .ok_or("Attestation statement was missing algorithm".to_string())
    }

    fn att_stmt_x5c(&self) -> Option<Vec<Vec<u8>>> {
        let certs = self.att_stmt_get("x5c")?.as_array()?;
        let certs: Option<Vec<Vec<u8>>> = certs
            .iter()
            .map(|v| v.as_bytes().cloned())
            .collect();
        certs.filter(|c| !c.is_empty())
    }
}

// ---------------------------------------------------------------------------
// COSE keys + signatures (decode_credential_public_key / verify_signature)
// ---------------------------------------------------------------------------

/// A decoded COSE credential public key (`DecodedEC2/RSA/OKPPublicKey`).
struct DecodedKey {
    alg: i64,
    key: KeyMaterial,
}

enum KeyMaterial {
    /// P-256 (`crv` 1), x/y 32 bytes each — also the raw `0x04` U2F spelling.
    Ec2 { x: Vec<u8>, y: Vec<u8> },
    /// Ed25519 (`crv` 6), x 32 bytes.
    Okp { x: Vec<u8> },
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

fn int_param(entries: &[(Value, Value)], label: i64) -> Option<i64> {
    map_get(entries, &Value::Integer(label.into()))
        .and_then(Value::as_integer)
        .and_then(|i| i64::try_from(i).ok())
}

fn bytes_param(entries: &[(Value, Value)], label: i64) -> Option<&Vec<u8>> {
    map_get(entries, &Value::Integer(label.into())).and_then(Value::as_bytes)
}

/// `webauthn.helpers.decode_credential_public_key` (OKP, EC2, RSA; the raw
/// uncompressed `0x04` point from old U2F keys included).
fn decode_credential_public_key(key: &[u8]) -> Result<DecodedKey, String> {
    // Old U2F security keys occasionally store an uncompressed ANSI X9.62 point.
    if key.first() == Some(&0x04) {
        if key.len() != 65 {
            return Err("Uncompressed EC2 key was not 65 bytes".into());
        }
        return Ok(DecodedKey {
            alg: -7,
            key: KeyMaterial::Ec2 {
                x: key[1..33].to_vec(),
                y: key[33..65].to_vec(),
            },
        });
    }

    let (value, _consumed) = cbor_decode_one(key)?;
    let entries = map_entries(&value)?;
    let kty = int_param(entries, 1).filter(|&k| k != 0).ok_or("Credential public key missing kty")?;
    let alg = int_param(entries, 3).filter(|&a| a != 0).ok_or("Credential public key missing alg")?;

    match kty {
        // OKP
        1 => {
            let crv = int_param(entries, -1).ok_or("OKP credential public key missing crv")?;
            let x = bytes_param(entries, -2)
                .filter(|x| !x.is_empty())
                .ok_or("OKP credential public key missing x")?;
            if alg != -8 || crv != 6 {
                return Err(format!(
                    "OKP public key with alg {alg} and crv {crv} is not supported"
                ));
            }
            Ok(DecodedKey {
                alg,
                key: KeyMaterial::Okp { x: x.clone() },
            })
        }
        // EC2
        2 => {
            let crv = int_param(entries, -1).ok_or("EC2 credential public key missing crv")?;
            let x = bytes_param(entries, -2)
                .filter(|x| !x.is_empty())
                .ok_or("EC2 credential public key missing x")?;
            let y = bytes_param(entries, -3)
                .filter(|y| !y.is_empty())
                .ok_or("EC2 credential public key missing y")?;
            if crv != 1 {
                return Err(format!("Unsupported EC2 curve {crv}, expected P-256"));
            }
            Ok(DecodedKey {
                alg,
                key: KeyMaterial::Ec2 {
                    x: x.clone(),
                    y: y.clone(),
                },
            })
        }
        // RSA
        3 => {
            let n = bytes_param(entries, -1)
                .filter(|n| !n.is_empty())
                .ok_or("RSA credential public key missing n")?;
            let e = bytes_param(entries, -2)
                .filter(|e| !e.is_empty())
                .ok_or("RSA credential public key missing e")?;
            Ok(DecodedKey {
                alg,
                key: KeyMaterial::Rsa {
                    n: n.clone(),
                    e: e.clone(),
                },
            })
        }
        other => Err(format!("Unsupported credential public key type \"{other}\"")),
    }
}

/// `webauthn.helpers.verify_signature` for the supported alg/key pairs:
/// ES256 (`-7`) with a DER ECDSA signature, RS256 (`-257`) PKCS#1 v1.5,
/// EdDSA (`-8`). `decoded_public_key.alg` selects the scheme, like Python.
fn verify_signature(decoded: &DecodedKey, signature: &[u8], data: &[u8]) -> Result<(), String> {
    match (&decoded.key, decoded.alg) {
        (KeyMaterial::Ec2 { x, y }, -7) => {
            use signature::Verifier;
            let key = p256_verifying_key(x, y)?;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|e| format!("Could not parse ECDSA signature: {e}"))?;
            key.verify(data, &sig)
                .map_err(|_| "Could not verify authentication signature".to_string())
        }
        (KeyMaterial::Rsa { n, e }, -257) => {
            let key = rsa_verifying_key(n, e)?;
            use rsa::pkcs1v15::Pkcs1v15Sign;
            // `rsa`'s PKCS#1 v1.5 scheme takes the *pre-hashed* message
            // (DigestInfo prefix is added internally) — same EMSA-PKCS1-v1_5
            // over SHA-256 as `cryptography`'s PKCS1v15()+SHA256 verify.
            let hashed = sha256(data);
            key.verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed, signature)
                .map_err(|_| "Could not verify authentication signature".to_string())
        }
        (KeyMaterial::Okp { x }, -8) => {
            let key = ed25519_verifying_key(x)?;
            let sig = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|e| format!("Could not parse Ed25519 signature: {e}"))?;
            key.verify_strict(data, &sig)
                .map_err(|_| "Could not verify authentication signature".to_string())
        }
        _ => Err(format!(
            "Unsupported public key for signature verification (alg {})",
            decoded.alg
        )),
    }
}

fn p256_verifying_key(x: &[u8], y: &[u8]) -> Result<p256::ecdsa::VerifyingKey, String> {
    if x.len() != 32 || y.len() != 32 {
        return Err("EC2 coordinates were not 32 bytes".into());
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    let point = p256::EncodedPoint::from_bytes(&point)
        .map_err(|e| format!("Could not parse EC2 point: {e}"))?;
    let key = p256::PublicKey::from_sec1_bytes(point.as_bytes())
        .map_err(|e| format!("EC2 point was not on the P-256 curve: {e}"))?;
    Ok(p256::ecdsa::VerifyingKey::from(key))
}

fn rsa_verifying_key(n: &[u8], e: &[u8]) -> Result<rsa::RsaPublicKey, String> {
    use rsa::{BigUint, RsaPublicKey};
    let n = BigUint::from_bytes_be(n);
    let e = BigUint::from_bytes_be(e);
    RsaPublicKey::new(n, e).map_err(|err| format!("Could not build RSA public key: {err}"))
}

fn ed25519_verifying_key(x: &[u8]) -> Result<ed25519_dalek::VerifyingKey, String> {
    let bytes: [u8; 32] = x
        .try_into()
        .map_err(|_| "Ed25519 public key was not 32 bytes".to_string())?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|err| format!("Could not build Ed25519 public key: {err}"))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Attestation statement verification (registration/formats/*)
// ---------------------------------------------------------------------------

fn verify_attestation(
    attestation: &AttestationObject,
    auth_data: &AuthData,
    client_data_json: &[u8],
    credential_public_key: &[u8],
    credential_id: &[u8],
) -> Result<(), String> {
    match attestation.fmt.as_str() {
        // "none": the attestation statement must not contain _anything_.
        "none" => {
            if !attestation.att_stmt.is_empty() {
                return Err("None attestation had unexpected attestation statement".into());
            }
            Ok(())
        }
        "packed" => verify_packed(attestation, auth_data, client_data_json, credential_public_key),
        "fido-u2f" => {
            verify_fido_u2f(attestation, auth_data, client_data_json, credential_public_key, credential_id)
        }
        other => Err(format!("Unsupported attestation type \"{other}\"")),
    }
}

/// `formats/packed.py`: signature over `authData || SHA256(clientDataJSON)`,
/// by the x5c leaf certificate or (self-attestation) the credential key.
fn verify_packed(
    attestation: &AttestationObject,
    _auth_data: &AuthData,
    client_data_json: &[u8],
    credential_public_key: &[u8],
) -> Result<(), String> {
    let sig = attestation.att_stmt_sig().map_err(|e| format!("{e} (Packed)"))?;
    let alg = attestation
        .att_stmt_alg()
        .map_err(|e| format!("{e} (Packed)"))?;

    let mut verification_data = attestation.auth_data_bytes.clone();
    verification_data.extend_from_slice(&sha256(client_data_json));

    if let Some(x5c) = attestation.att_stmt_x5c() {
        // Chain validation is a no-op without configured root certs, exactly
        // like `validate_certificate_chain` in the Python hub.
        let leaf = leaf_public_key(&x5c[0])
            .map_err(|e| format!("{e} (Packed)"))?;
        verify_spki_signature(&leaf, alg, sig, &verification_data)
            .map_err(|e| format!("{e} (Packed)"))
    } else {
        // Self attestation: the credential key must sign with its own alg.
        let decoded = decode_credential_public_key(credential_public_key)?;
        if decoded.alg != alg {
            return Err(format!(
                "Credential public key alg {} did not equal attestation statement alg {alg} (Packed|Self)",
                decoded.alg
            ));
        }
        verify_signature(&decoded, sig, &verification_data)
            .map_err(|e| format!("{e} (Packed|Self)"))
    }
}

/// `formats/fido_u2f.py`: signature over
/// `0x00 || rpIdHash || SHA256(clientDataJSON) || credentialId || 0x04||x||y`
/// by a single P-256 x5c leaf certificate.
fn verify_fido_u2f(
    attestation: &AttestationObject,
    auth_data: &AuthData,
    client_data_json: &[u8],
    credential_public_key: &[u8],
    credential_id: &[u8],
) -> Result<(), String> {
    let suffix = "(FIDO-U2F)";
    let sig = attestation.att_stmt_sig().map_err(|e| format!("{e} {suffix}"))?;
    let x5c = attestation
        .att_stmt_x5c()
        .ok_or_else(|| format!("Attestation statement was missing certificate {suffix}"))?;
    if x5c.len() > 1 {
        return Err(format!(
            "Attestation statement contained too many certificates {suffix}"
        ));
    }
    // FIDO spec requires the AAGUID in U2F attestations to be all zeroes.
    let aaguid = auth_data
        .attested
        .as_ref()
        .map(|a| aaguid_to_string(&a.aaguid))
        .unwrap_or_default();
    if aaguid != "00000000-0000-0000-0000-000000000000" {
        return Err(format!("AAGUID {aaguid} was not expected {suffix}"));
    }

    let leaf = leaf_public_key(&x5c[0]).map_err(|e| format!("{e} {suffix}"))?;
    // Leaf cert must be an EC P-256 certificate (raw SPKI point 65 bytes).
    if leaf.len() != 65 || leaf[0] != 0x04 {
        return Err(format!("Leaf cert was not an EC2 P-256 certificate {suffix}"));
    }

    let decoded = decode_credential_public_key(credential_public_key)?;
    let (x, y) = match &decoded.key {
        KeyMaterial::Ec2 { x, y } => (x, y),
        _ => return Err(format!("Credential public key was not EC2 {suffix}")),
    };

    let mut verification_data = vec![0x00];
    verification_data.extend_from_slice(&auth_data.rp_id_hash);
    verification_data.extend_from_slice(&sha256(client_data_json));
    verification_data.extend_from_slice(credential_id);
    verification_data.push(0x04);
    verification_data.extend_from_slice(x);
    verification_data.extend_from_slice(y);

    verify_spki_signature(&leaf, -7, sig, &verification_data)
        .map_err(|e| format!("{e} {suffix}"))
}

/// The raw `subjectPublicKey` BIT STRING of an x5c leaf certificate.
fn leaf_public_key(der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| format!("Could not parse x5c certificate: {e}"))?;
    Ok(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec(),
    )
}

/// Verify with an SPKI raw public key (the content of the BIT STRING), for the
/// attestation statement's `alg`.
fn verify_spki_signature(
    spki_key: &[u8],
    alg: i64,
    signature: &[u8],
    data: &[u8],
) -> Result<(), String> {
    match alg {
        -7 => {
            if spki_key.len() != 65 || spki_key[0] != 0x04 {
                return Err("Certificate key was not an uncompressed P-256 point".into());
            }
            let decoded = DecodedKey {
                alg: -7,
                key: KeyMaterial::Ec2 {
                    x: spki_key[1..33].to_vec(),
                    y: spki_key[33..65].to_vec(),
                },
            };
            verify_signature(&decoded, signature, data)
        }
        -257 => {
            use rsa::pkcs1v15::Pkcs1v15Sign;
            use x509_cert::der::Decode;
            // SPKI raw bytes are the PKCS#1 `RSAPublicKey` DER (`SEQUENCE { n, e }`).
            let pk = rsa::pkcs1::RsaPublicKey::from_der(spki_key)
                .map_err(|e| format!("Could not parse RSA certificate key: {e}"))?;
            let key = rsa_verifying_key(pk.modulus.as_bytes(), pk.public_exponent.as_bytes())?;
            let hashed = sha256(data);
            key.verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed, signature)
                .map_err(|_| "Could not verify attestation statement signature".to_string())
        }
        -8 => {
            if spki_key.len() != 32 {
                return Err("Certificate key was not an Ed25519 key".into());
            }
            let decoded = DecodedKey {
                alg: -8,
                key: KeyMaterial::Okp {
                    x: spki_key.to_vec(),
                },
            };
            verify_signature(&decoded, signature, data)
        }
        other => Err(format!("Unsupported attestation algorithm {other}")),
    }
}

// ---------------------------------------------------------------------------
// Tests — a software authenticator fabricates cryptographically valid payloads
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    //! A virtual authenticator for tests: registration and authentication
    //! payloads are built byte-for-byte like a real one would (COSE keys,
    //! authenticatorData, clientDataJSON, real signatures), so the verifiers
    //! are exercised for real instead of being mocked out.
    use super::*;

    pub(crate) const RP_ID: &str = "huginn.example.com";
    pub(crate) const ORIGIN: &str = "https://huginn.example.com";

    /// A software credential in each supported algorithm.
    pub(crate) enum FabricatedKey {
        Es256 {
            signing: p256::ecdsa::SigningKey,
            cose: Vec<u8>,
        },
        Ed25519 {
            signing: ed25519_dalek::SigningKey,
            cose: Vec<u8>,
        },
        Rs256 {
            signing: rsa::RsaPrivateKey,
            cose: Vec<u8>,
        },
    }

    impl FabricatedKey {
        /// ES256 — the algorithm every real passkey uses.
        pub(crate) fn es256() -> Self {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let signing = p256::ecdsa::SigningKey::from(secret.clone());
            let point = secret.public_key().to_encoded_point(false);
            let point = point.as_bytes();
            let cose = cose_ec2_key(&point[1..33], &point[33..65]);
            Self::Es256 { signing, cose }
        }

        /// EdDSA (Ed25519).
        pub(crate) fn ed25519() -> Self {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            let cose = cose_okp_key(signing.verifying_key().as_bytes());
            Self::Ed25519 { signing, cose }
        }

        /// RS256 (RSA-2048) — key generation is slow, so tests use it sparingly.
        pub(crate) fn rs256() -> Self {
            use rsa::traits::PublicKeyParts;
            let signing = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
            let public = signing.to_public_key();
            let cose = cose_rsa_key(
                &public.n().to_bytes_be(),
                &public.e().to_bytes_be(),
            );
            Self::Rs256 { signing, cose }
        }

        /// The COSE public key bytes a registration would store.
        pub(crate) fn cose(&self) -> &[u8] {
            match self {
                Self::Es256 { cose, .. }
                | Self::Ed25519 { cose, .. }
                | Self::Rs256 { cose, .. } => cose,
            }
        }

        /// Sign exactly like the authenticator would: DER ECDSA for ES256,
        /// raw 64-byte for EdDSA, PKCS#1 v1.5 for RS256.
        pub(crate) fn sign(&self, data: &[u8]) -> Vec<u8> {
            match self {
                Self::Es256 { signing, .. } => {
                    use signature::Signer;
                    let signature: p256::ecdsa::Signature = signing.sign(data);
                    signature.to_der().as_bytes().to_vec()
                }
                Self::Ed25519 { signing, .. } => {
                    use ed25519_dalek::Signer;
                    signing.sign(data).to_bytes().to_vec()
                }
                Self::Rs256 { signing, .. } => {
                    // `rsa`'s PKCS#1 v1.5 scheme signs the pre-hashed message.
                    let hashed = sha256(data);
                    signing
                        .sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed)
                        .unwrap()
                }
            }
        }
    }

    pub(crate) fn cbor_int_map(pairs: Vec<(i64, Value)>) -> Vec<u8> {
        let map = Value::Map(
            pairs
                .into_iter()
                .map(|(k, v)| (Value::Integer(k.into()), v))
                .collect(),
        );
        cbor_encode(&map).unwrap()
    }

    pub(crate) fn cose_ec2_key(x: &[u8], y: &[u8]) -> Vec<u8> {
        cbor_int_map(vec![
            (1, Value::Integer(2_i64.into())),  // kty: EC2
            (3, Value::Integer((-7_i64).into())), // alg: ES256
            (-1, Value::Integer(1_i64.into())), // crv: P-256
            (-2, Value::Bytes(x.to_vec())),
            (-3, Value::Bytes(y.to_vec())),
        ])
    }

    pub(crate) fn cose_okp_key(x: &[u8]) -> Vec<u8> {
        cbor_int_map(vec![
            (1, Value::Integer(1_i64.into())),   // kty: OKP
            (3, Value::Integer((-8_i64).into())), // alg: EdDSA
            (-1, Value::Integer(6_i64.into())),  // crv: Ed25519
            (-2, Value::Bytes(x.to_vec())),
        ])
    }

    pub(crate) fn cose_rsa_key(n: &[u8], e: &[u8]) -> Vec<u8> {
        cbor_int_map(vec![
            (1, Value::Integer(3_i64.into())),    // kty: RSA
            (3, Value::Integer((-257_i64).into())), // alg: RS256
            (-1, Value::Bytes(n.to_vec())),
            (-2, Value::Bytes(e.to_vec())),
        ])
    }

    /// `rpIdHash || flags || signCount [|| attestedCredentialData]`.
    pub(crate) fn auth_data_bytes(
        rp_id: &str,
        flags: u8,
        counter: u32,
        attested: Option<(&[u8], &[u8], &[u8])>,
    ) -> Vec<u8> {
        let mut out = sha256(rp_id.as_bytes());
        out.push(flags);
        out.extend_from_slice(&counter.to_be_bytes());
        if let Some((aaguid, credential_id, cose_key)) = attested {
            out.extend_from_slice(aaguid);
            out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
            out.extend_from_slice(credential_id);
            out.extend_from_slice(cose_key);
        }
        out
    }

    /// The collected client data the browser would produce.
    pub(crate) fn client_data_json(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        serde_json::json!({
            "type": kind,
            "challenge": b64u_encode(challenge),
            "origin": origin,
        })
        .to_string()
        .into_bytes()
    }

    /// The CBOR attestation object of `response.attestationObject`.
    pub(crate) fn attestation_object(fmt: &str, att_stmt: Value, auth_data: &[u8]) -> Vec<u8> {
        let map = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(fmt.into())),
            (
                Value::Text("authData".into()),
                Value::Bytes(auth_data.to_vec()),
            ),
            (Value::Text("attStmt".into()), att_stmt),
        ]);
        cbor_encode(&map).unwrap()
    }

    /// A `navigator.credentials.create()` return value (JSON form).
    pub(crate) fn registration_credential(
        raw_id: &[u8],
        client_data_json: &[u8],
        attestation_object: &[u8],
        transports: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut response = serde_json::json!({
            "clientDataJSON": b64u_encode(client_data_json),
            "attestationObject": b64u_encode(attestation_object),
        });
        if let Some(transports) = transports {
            response["transports"] = transports;
        }
        serde_json::json!({
            "id": b64u_encode(raw_id),
            "rawId": b64u_encode(raw_id),
            "type": "public-key",
            "response": response,
        })
    }

    /// A `navigator.credentials.get()` return value (JSON form).
    pub(crate) fn authentication_credential(
        raw_id: &[u8],
        client_data_json: &[u8],
        authenticator_data: &[u8],
        signature: &[u8],
    ) -> serde_json::Value {
        serde_json::json!({
            "id": b64u_encode(raw_id),
            "rawId": b64u_encode(raw_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u_encode(client_data_json),
                "authenticatorData": b64u_encode(authenticator_data),
                "signature": b64u_encode(signature),
                "userHandle": null,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use serde_json::json;

    fn sample_user() -> User {
        User {
            id: Uuid::parse_str("3b9f6a2e-8d47-4f2a-9c65-2f1e0b7a5d31").unwrap(),
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            password_hash: None,
            oidc_subject: None,
            ldap_dn: None,
            role: crate::models::enums::UserRole::Readonly,
            is_active: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            totp_secret_enc: None,
            totp_enabled: false,
            totp_confirmed_at: None,
            totp_last_step: None,
        }
    }

    fn sample_rp() -> RpConfig {
        RpConfig {
            rp_id: RP_ID.into(),
            rp_name: "Huginn".into(),
            origin: ORIGIN.into(),
        }
    }

    /// A complete `fmt: "none"` registration payload for `key`.
    fn registration_payload(
        key: &FabricatedKey,
        challenge: &[u8],
        counter: u32,
    ) -> (serde_json::Value, Vec<u8>) {
        let credential_id = b"credential-id-32-bytes-long!!";
        let aaguid = [0x11u8; 16];
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UP | FLAG_UV | FLAG_AT,
            counter,
            Some((&aaguid, credential_id, key.cose())),
        );
        let cdj = client_data_json("webauthn.create", challenge, ORIGIN);
        let att = attestation_object("none", Value::Map(Vec::new()), &auth_data);
        (
            registration_credential(credential_id, &cdj, &att, Some(json!(["internal"]))),
            credential_id.to_vec(),
        )
    }

    /// A complete assertion payload for `key`.
    fn assertion_payload(
        key: &FabricatedKey,
        challenge: &[u8],
        counter: u32,
    ) -> (serde_json::Value, Vec<u8>) {
        let credential_id = b"credential-id-32-bytes-long!!";
        let auth_data = auth_data_bytes(RP_ID, FLAG_UP | FLAG_UV, counter, None);
        let cdj = client_data_json("webauthn.get", challenge, ORIGIN);
        let mut signature_base = auth_data.clone();
        signature_base.extend_from_slice(&sha256(&cdj));
        let signature = key.sign(&signature_base);
        (
            authentication_credential(credential_id, &cdj, &auth_data, &signature),
            credential_id.to_vec(),
        )
    }

    // ---- options: byte-identical to py_webauthn's options_to_json ----------

    #[test]
    fn registration_options_match_py_webauthn_to_the_byte() {
        let user = sample_user();
        let existing = WebAuthnCredential {
            id: Uuid::nil(),
            user_id: user.id,
            name: "key".into(),
            credential_id: b64u_encode(b"already-registered"),
            public_key: vec![],
            sign_count: 0,
            transports: None,
            aaguid: None,
            last_used_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let options = registration_options(
            &sample_rp(),
            UserVerification::Preferred,
            &user,
            "Y2hhbGxlbmdl",
            &[existing],
        );
        let user_handle = b64u_encode(user.id.to_string().as_bytes());
        let expected = format!(
            concat!(
                r#"{{"rp":{{"name":"Huginn","id":"huginn.example.com"}},"#,
                r#""user":{{"id":"{user_handle}","name":"alice","displayName":"alice"}},"#,
                r#""challenge":"Y2hhbGxlbmdl","#,
                r#""pubKeyCredParams":[{{"type":"public-key","alg":-8}},"#,
                r#"{{"type":"public-key","alg":-7}},{{"type":"public-key","alg":-257}}],"#,
                r#""timeout":60000,"#,
                r#""excludeCredentials":[{{"id":"YWxyZWFkeS1yZWdpc3RlcmVk","type":"public-key"}}],"#,
                r#""authenticatorSelection":{{"residentKey":"preferred","#,
                r#""requireResidentKey":false,"userVerification":"preferred"}},"#,
                r#""attestation":"none"}}"#
            ),
            user_handle = user_handle
        );
        assert_eq!(serde_json::to_string(&options).unwrap(), expected);
    }

    #[test]
    fn authentication_options_match_py_webauthn_to_the_byte() {
        let options = authentication_options(
            &sample_rp(),
            UserVerification::Required,
            "Y2hhbGxlbmdl",
        );
        assert_eq!(
            serde_json::to_string(&options).unwrap(),
            r#"{"challenge":"Y2hhbGxlbmdl","timeout":60000,"rpId":"huginn.example.com","allowCredentials":[],"userVerification":"required"}"#
        );
    }

    #[test]
    fn user_verification_matches_the_python_enum() {
        assert_eq!(UserVerification::from_config("required"), UserVerification::Required);
        assert_eq!(UserVerification::from_config("REQUIRED"), UserVerification::Required);
        assert_eq!(UserVerification::from_config("preferred"), UserVerification::Preferred);
        assert_eq!(UserVerification::from_config("discouraged"), UserVerification::Discouraged);
        // Unknown values fail back to preferred (ValueError → PREFERRED).
        assert_eq!(UserVerification::from_config("sometimes"), UserVerification::Preferred);
        assert_eq!(UserVerification::from_config(""), UserVerification::Preferred);
        assert!(UserVerification::Required.require_user_verification());
        assert!(!UserVerification::Preferred.require_user_verification());
        assert!(!UserVerification::Discouraged.require_user_verification());
    }

    #[test]
    fn rp_id_must_be_a_registrable_domain() {
        assert!(is_registrable_domain("huginn.example.com"));
        assert!(is_registrable_domain("example.com"));
        assert!(!is_registrable_domain("192.0.2.13"));
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

    // ---- registration ceremony -------------------------------------------

    #[test]
    fn register_accepts_fabricated_attestations_in_every_supported_alg() {
        for key in [
            FabricatedKey::es256(),
            FabricatedKey::ed25519(),
            FabricatedKey::rs256(),
        ] {
            let challenge = b"a 32-byte registration challenge!";
            let (credential, credential_id) = registration_payload(&key, challenge, 7);
            let verified = verify_registration(&credential, challenge, RP_ID, ORIGIN, true)
                .expect("valid attestation must verify");
            assert_eq!(verified.credential_id, credential_id);
            assert_eq!(verified.credential_public_key, key.cose());
            assert_eq!(verified.sign_count, 7);
            assert_eq!(verified.aaguid, "11111111-1111-1111-1111-111111111111");
            // transports come through the raw client value (Python parity).
            assert_eq!(raw_transports(&credential), Some(json!(["internal"])));
        }
    }

    #[test]
    fn register_rejects_wrong_challenge_origin_rp_id_and_type() {
        let key = FabricatedKey::es256();
        let challenge = b"a 32-byte registration challenge!";
        let (credential, _) = registration_payload(&key, challenge, 0);

        assert!(matches!(
            verify_registration(&credential, b"another 32-byte challenge!!!!!!", RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, "https://evil.example.com", true),
            Err(WebAuthnError::RegistrationFailed)
        ));
        assert!(matches!(
            verify_registration(&credential, challenge, "other.example.com", ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));

        // A "webauthn.get" client data in a registration ceremony (signature
        // confusion) is rejected.
        let auth_data = auth_data_bytes(RP_ID, FLAG_UP | FLAG_UV | FLAG_AT, 0, None);
        let cdj = client_data_json("webauthn.get", challenge, ORIGIN);
        let att = attestation_object("none", Value::Map(Vec::new()), &auth_data);
        let confused = registration_credential(b"id", &cdj, &att, None);
        assert!(matches!(
            verify_registration(&confused, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));
    }

    #[test]
    fn register_enforces_user_presence_and_configuration_uv() {
        let key = FabricatedKey::es256();
        let challenge = b"a 32-byte registration challenge!";
        let credential_id = b"credential-id-32-bytes-long!!";
        let aaguid = [0x11u8; 16];

        // UV flag missing: fine unless the config requires it.
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UP | FLAG_AT,
            0,
            Some((&aaguid, credential_id, key.cose())),
        );
        let cdj = client_data_json("webauthn.create", challenge, ORIGIN);
        let att = attestation_object("none", Value::Map(Vec::new()), &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(verify_registration(&credential, challenge, RP_ID, ORIGIN, false).is_ok());
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));

        // UP flag missing: always rejected.
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UV | FLAG_AT,
            0,
            Some((&aaguid, credential_id, key.cose())),
        );
        let att = attestation_object("none", Value::Map(Vec::new()), &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));
    }

    #[test]
    fn register_rejects_tampered_attestations_and_unknown_formats() {
        let key = FabricatedKey::es256();
        let challenge = b"a 32-byte registration challenge!";
        let credential_id = b"credential-id-32-bytes-long!!";
        let aaguid = [0x11u8; 16];
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UP | FLAG_UV | FLAG_AT,
            0,
            Some((&aaguid, credential_id, key.cose())),
        );
        let cdj = client_data_json("webauthn.create", challenge, ORIGIN);

        // fmt "none" with anything in the attestation statement is rejected…
        for field in ["sig", "x5c", "response", "alg", "ver", "certInfo", "pubArea"] {
            let stmt = Value::Map(vec![(Value::Text(field.into()), Value::Integer(1_i64.into()))]);
            let att = attestation_object("none", stmt, &auth_data);
            let credential = registration_credential(credential_id, &cdj, &att, None);
            assert!(
                matches!(
                    verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
                    Err(WebAuthnError::RegistrationFailed)
                ),
                "attStmt.{field} must be rejected for fmt none"
            );
        }
        // …but a null field is "unset" (Python: `field is not None`).
        let stmt = Value::Map(vec![(Value::Text("sig".into()), Value::Null)]);
        let att = attestation_object("none", stmt, &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(verify_registration(&credential, challenge, RP_ID, ORIGIN, true).is_ok());

        // Formats we do not verify (tpm/apple/android-*) are rejected.
        let att = attestation_object("tpm", Value::Map(Vec::new()), &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));

        // An alg outside {-8, -7, -257} is rejected before storage.
        let weird_key = cbor_int_map(vec![
            (1, Value::Integer(2_i64.into())),
            (3, Value::Integer((-35_i64).into())), // ES384
            (-1, Value::Integer(1_i64.into())),
            (-2, Value::Bytes(vec![0; 32])),
            (-3, Value::Bytes(vec![0; 32])),
        ]);
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UP | FLAG_UV | FLAG_AT,
            0,
            Some((&aaguid, credential_id, &weird_key)),
        );
        let att = attestation_object("none", Value::Map(Vec::new()), &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));

        // id and rawId must be equivalent.
        let (mut credential, _) = registration_payload(&key, challenge, 0);
        credential["id"] = json!(b64u_encode(b"something-else"));
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));
    }

    #[test]
    fn register_accepts_packed_self_attestation_and_checks_its_signature() {
        let key = FabricatedKey::es256();
        let challenge = b"a 32-byte registration challenge!";
        let credential_id = b"credential-id-32-bytes-long!!";
        let aaguid = [0x11u8; 16];
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UP | FLAG_UV | FLAG_AT,
            0,
            Some((&aaguid, credential_id, key.cose())),
        );
        let cdj = client_data_json("webauthn.create", challenge, ORIGIN);

        let mut verification_data = auth_data.clone();
        verification_data.extend_from_slice(&sha256(&cdj));
        let signature = key.sign(&verification_data);

        let stmt = Value::Map(vec![
            (Value::Text("alg".into()), Value::Integer((-7_i64).into())),
            (Value::Text("sig".into()), Value::Bytes(signature.clone())),
        ]);
        let att = attestation_object("packed", stmt, &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(verify_registration(&credential, challenge, RP_ID, ORIGIN, true).is_ok());

        // A flipped signature byte fails.
        let mut bad = signature.clone();
        bad[0] ^= 0x01;
        let stmt = Value::Map(vec![
            (Value::Text("alg".into()), Value::Integer((-7_i64).into())),
            (Value::Text("sig".into()), Value::Bytes(bad)),
        ]);
        let att = attestation_object("packed", stmt, &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));

        // Self-attestation must use the credential key's own alg.
        let stmt = Value::Map(vec![
            (Value::Text("alg".into()), Value::Integer((-257_i64).into())),
            (Value::Text("sig".into()), Value::Bytes(signature)),
        ]);
        let att = attestation_object("packed", stmt, &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));
    }

    /// A self-signed X.509 leaf certificate + its P-256 signing key, for the
    /// `x5c` attestation paths.
    fn self_signed_leaf() -> (Vec<u8>, p256::ecdsa::SigningKey) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["webauthn.test".into()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let der = cert.der().to_vec();
        use p256::pkcs8::DecodePrivateKey;
        let secret = p256::SecretKey::from_pkcs8_pem(&key_pair.serialize_pem()).unwrap();
        (der, p256::ecdsa::SigningKey::from(secret))
    }

    #[test]
    fn register_accepts_packed_x5c_and_fido_u2f_attestations() {
        let (leaf_der, leaf_key) = self_signed_leaf();
        let challenge = b"a 32-byte registration challenge!";
        let credential_id = b"credential-id-32-bytes-long!!";
        let aaguid = [0x11u8; 16];
        let cdj = client_data_json("webauthn.create", challenge, ORIGIN);

        // packed with x5c: signed by the leaf certificate's key.
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UP | FLAG_UV | FLAG_AT,
            0,
            Some((&aaguid, credential_id, &cose_ec2_key(&[0x02; 32], &[0x03; 32]))),
        );
        let mut verification_data = auth_data.clone();
        verification_data.extend_from_slice(&sha256(&cdj));
        use signature::Signer;
        let signature: p256::ecdsa::Signature = leaf_key.sign(&verification_data);
        let signature = signature.to_der().as_bytes().to_vec();
        let stmt = Value::Map(vec![
            (Value::Text("alg".into()), Value::Integer((-7_i64).into())),
            (Value::Text("sig".into()), Value::Bytes(signature.clone())),
            (
                Value::Text("x5c".into()),
                Value::Array(vec![Value::Bytes(leaf_der.clone())]),
            ),
        ]);
        let att = attestation_object("packed", stmt, &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(verify_registration(&credential, challenge, RP_ID, ORIGIN, true).is_ok());

        // A signature by any other key fails.
        let stmt = Value::Map(vec![
            (Value::Text("alg".into()), Value::Integer((-7_i64).into())),
            (Value::Text("sig".into()), Value::Bytes(FabricatedKey::es256().sign(&verification_data))),
            (
                Value::Text("x5c".into()),
                Value::Array(vec![Value::Bytes(leaf_der.clone())]),
            ),
        ]);
        let att = attestation_object("packed", stmt, &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));

        // fido-u2f: zeroed AAGUID, single cert, signature over the U2F base.
        let key = FabricatedKey::es256();
        let zero_aaguid = [0u8; 16];
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UP | FLAG_UV | FLAG_AT,
            0,
            Some((&zero_aaguid, credential_id, key.cose())),
        );
        let decoded = decode_credential_public_key(key.cose()).unwrap();
        let (x, y) = match decoded.key {
            KeyMaterial::Ec2 { x, y } => (x, y),
            _ => unreachable!(),
        };
        let mut u2f_base = vec![0x00];
        u2f_base.extend_from_slice(&sha256(RP_ID.as_bytes()));
        u2f_base.extend_from_slice(&sha256(&cdj));
        u2f_base.extend_from_slice(credential_id);
        u2f_base.push(0x04);
        u2f_base.extend_from_slice(&x);
        u2f_base.extend_from_slice(&y);
        let u2f_sig: p256::ecdsa::Signature = leaf_key.sign(&u2f_base);
        let u2f_sig = u2f_sig.to_der().as_bytes().to_vec();
        let stmt = Value::Map(vec![
            (Value::Text("sig".into()), Value::Bytes(u2f_sig)),
            (
                Value::Text("x5c".into()),
                Value::Array(vec![Value::Bytes(leaf_der)]),
            ),
        ]);
        let att = attestation_object("fido-u2f", stmt.clone(), &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(verify_registration(&credential, challenge, RP_ID, ORIGIN, true).is_ok());

        // fido-u2f requires a zeroed AAGUID.
        let auth_data = auth_data_bytes(
            RP_ID,
            FLAG_UP | FLAG_UV | FLAG_AT,
            0,
            Some((&aaguid, credential_id, key.cose())),
        );
        let att = attestation_object("fido-u2f", stmt, &auth_data);
        let credential = registration_credential(credential_id, &cdj, &att, None);
        assert!(matches!(
            verify_registration(&credential, challenge, RP_ID, ORIGIN, true),
            Err(WebAuthnError::RegistrationFailed)
        ));
    }

    #[test]
    fn bad_eddsa_cbor_in_auth_data_is_repaired_like_py_webauthn() {
        // Real-world YubiKey vector (py_webauthn's test_parse_authenticator_data
        // .test_parses_bad_eddsa_auth_data): some authenticators declare a 3-item
        // CBOR map while writing 4 items when using Ed25519. py_webauthn patches
        // the length byte on sight so the row can be extracted and stored; the
        // key itself stays unverifiable (string kty/crv, array x) and is
        // rejected at key decoding exactly like `decode_credential_public_key`.
        let auth_data = hex_decode(concat!(
            "16B02DFBC3D4CCA37EBC2F6516659B12210DB9E1018AB9F13A9690638EA6FDA8",
            "45000000012FC0579F811347EAB116BB5A8DB9202A0080E82FE6BDE300E4ECC9",
            "3E0016448AD00FA6F28A011A6F87FF7B0CFCA499BEAF83344C3660B5ECABF72A",
            "3B2838A0CC7D87D3FA58292B53449CFF13AD69732D7521649D365CCBC5D0A0FA",
            "4B4E09EAE99537261F2F44093F8F4FD4CF5796E0FE58FF0615FFC5882836BBE7",
            "B99B08BE2986721C1C5A6AC7F32D3220D9B34D8DEE2FC9A301634F4B50032720",
            "67456432353531392198201618F6185918FA182E141875183A18841718521874",
            "187A18C51318D918C51883182D18ED181818EA188F182E187407185E18F41518",
            "CC18C9186D"
        ));
        let parsed = parse_authenticator_data(&auth_data).unwrap();
        let attested = parsed.attested.unwrap();
        assert_eq!(hex_encode(&attested.credential_id), "e82fe6bde300e4ecc93e0016448ad00fa6f28a011a6f87ff7b0cfca499beaf83344c3660b5ecabf72a3b2838a0cc7d87d3fa58292b53449cff13ad69732d7521649d365ccbc5d0a0fa4b4e09eae99537261f2f44093f8f4fd4cf5796e0fe58ff0615ffc5882836bbe7b99b08be2986721c1c5a6ac7f32d3220d9b34d8dee2fc9");
        // Stored exactly like py_webauthn: the repaired, re-encoded COSE bytes.
        assert_eq!(
            hex_encode(&attested.credential_public_key),
            "a401634f4b5003272067456432353531392198201618f6185918fa182e141875183a18841718521874187a18c51318d918c51883182d18ed181818ea188f182e187407185e18f41518cc18c9186d"
        );
        // …and the malformed key itself cannot verify anything (parity with
        // py_webauthn's `decode_credential_public_key` rejecting string kty).
        assert!(decode_credential_public_key(&attested.credential_public_key).is_err());
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ---- authentication ceremony -----------------------------------------

    #[test]
    fn login_accepts_fabricated_assertions_in_every_supported_alg() {
        let challenge = b"a 32-byte challenge for login!!!";
        for key in [
            FabricatedKey::es256(),
            FabricatedKey::ed25519(),
            FabricatedKey::rs256(),
        ] {
            let (credential, _id) = assertion_payload(&key, challenge, 8);
            let verified = verify_authentication(
                &credential,
                challenge,
                RP_ID,
                ORIGIN,
                key.cose(),
                7,
                true,
            )
            .expect("valid assertion must verify");
            assert_eq!(verified.new_sign_count, 8);
            assert!(verified.user_verified);
        }
    }

    #[test]
    fn login_rejects_tampered_assertions() {
        let challenge = b"a 32-byte challenge for login!!!";
        let key = FabricatedKey::es256();
        let (credential, _id) = assertion_payload(&key, challenge, 8);

        // Wrong stored key (a different credential's key).
        let other = FabricatedKey::es256();
        assert!(matches!(
            verify_authentication(&credential, challenge, RP_ID, ORIGIN, other.cose(), 7, true),
            Err(WebAuthnError::AuthenticationFailed)
        ));

        // Challenge, origin and rp_id hash binding.
        assert!(matches!(
            verify_authentication(
                &credential,
                b"another 32-byte challenge!!!!!!",
                RP_ID,
                ORIGIN,
                key.cose(),
                7,
                true
            ),
            Err(WebAuthnError::AuthenticationFailed)
        ));
        assert!(matches!(
            verify_authentication(
                &credential,
                challenge,
                RP_ID,
                "https://evil.example.com",
                key.cose(),
                7,
                true
            ),
            Err(WebAuthnError::AuthenticationFailed)
        ));
        assert!(matches!(
            verify_authentication(
                &credential,
                challenge,
                "other.example.com",
                ORIGIN,
                key.cose(),
                7,
                true
            ),
            Err(WebAuthnError::AuthenticationFailed)
        ));

        // A flipped signature byte fails.
        let mut tampered = credential.clone();
        let mut sig = b64u_decode(tampered["response"]["signature"].as_str().unwrap()).unwrap();
        sig[0] ^= 0x01;
        tampered["response"]["signature"] = json!(b64u_encode(&sig));
        assert!(matches!(
            verify_authentication(&tampered, challenge, RP_ID, ORIGIN, key.cose(), 7, true),
            Err(WebAuthnError::AuthenticationFailed)
        ));

        // Signature confusion: "webauthn.create" data in an assertion.
        let auth_data = auth_data_bytes(RP_ID, FLAG_UP | FLAG_UV, 8, None);
        let cdj = client_data_json("webauthn.create", challenge, ORIGIN);
        let mut signature_base = auth_data.clone();
        signature_base.extend_from_slice(&sha256(&cdj));
        let signature = key.sign(&signature_base);
        let confused = authentication_credential(b"id", &cdj, &auth_data, &signature);
        assert!(matches!(
            verify_authentication(&confused, challenge, RP_ID, ORIGIN, key.cose(), 7, true),
            Err(WebAuthnError::AuthenticationFailed)
        ));

        // id/rawId mismatch and missing UP flag.
        let (mut credential, _) = assertion_payload(&key, challenge, 8);
        credential["id"] = json!(b64u_encode(b"something-else"));
        assert!(matches!(
            verify_authentication(&credential, challenge, RP_ID, ORIGIN, key.cose(), 7, true),
            Err(WebAuthnError::AuthenticationFailed)
        ));
        let auth_data = auth_data_bytes(RP_ID, FLAG_UV, 8, None);
        let cdj = client_data_json("webauthn.get", challenge, ORIGIN);
        let mut signature_base = auth_data.clone();
        signature_base.extend_from_slice(&sha256(&cdj));
        let signature = key.sign(&signature_base);
        let no_presence = authentication_credential(b"id", &cdj, &auth_data, &signature);
        assert!(matches!(
            verify_authentication(&no_presence, challenge, RP_ID, ORIGIN, key.cose(), 7, true),
            Err(WebAuthnError::AuthenticationFailed)
        ));
    }

    #[test]
    fn login_enforces_the_configured_user_verification() {
        let challenge = b"a 32-byte challenge for login!!!";
        let key = FabricatedKey::es256();
        let auth_data = auth_data_bytes(RP_ID, FLAG_UP, 8, None); // no UV flag
        let cdj = client_data_json("webauthn.get", challenge, ORIGIN);
        let mut signature_base = auth_data.clone();
        signature_base.extend_from_slice(&sha256(&cdj));
        let signature = key.sign(&signature_base);
        let credential = authentication_credential(b"id", &cdj, &auth_data, &signature);
        assert!(verify_authentication(
            &credential,
            challenge,
            RP_ID,
            ORIGIN,
            key.cose(),
            7,
            false
        )
        .is_ok());
        assert!(matches!(
            verify_authentication(&credential, challenge, RP_ID, ORIGIN, key.cose(), 7, true),
            Err(WebAuthnError::AuthenticationFailed)
        ));
    }

    #[test]
    fn sign_counter_regressions_signal_clones() {
        let challenge = b"a 32-byte challenge for login!!!";
        let key = FabricatedKey::es256();

        // Verification mirrors py_webauthn: a counter that did not advance is
        // rejected whenever either side is non-zero.
        for (new, stored, ok) in [(8, 7, true), (7, 7, false), (6, 7, false), (0, 7, false), (0, 0, true), (1, 0, true)] {
            let (credential, _) = assertion_payload(&key, challenge, new);
            let result = verify_authentication(
                &credential,
                challenge,
                RP_ID,
                ORIGIN,
                key.cose(),
                stored,
                true,
            );
            assert_eq!(result.is_ok(), ok, "counter {new} vs stored {stored}");
        }

        // The service-level clone check (webauthn.finish_login) additionally
        // allows the 0→0 case and reports its own message.
        assert!(check_sign_counter(8, 7).is_ok());
        assert!(check_sign_counter(0, 0).is_ok());
        let err = check_sign_counter(7, 7).unwrap_err();
        assert_eq!(err.to_string(), "sign counter regression (possible cloned authenticator)");
        assert_eq!(check_sign_counter(6, 7).unwrap_err().to_string(), "sign counter regression (possible cloned authenticator)");
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
        assert_eq!(WebAuthnError::NotConfigured.to_string(), "WebAuthn is not configured");
        assert_eq!(
            WebAuthnError::BadRpId.to_string(),
            "webauthn_rp_id must be a registrable domain, not an IP"
        );
        assert_eq!(WebAuthnError::MalformedCredential.to_string(), "malformed credential");
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
        assert_eq!(WebAuthnError::MissingCredentialId.to_string(), "missing credential id");
        assert_eq!(WebAuthnError::UnknownCredential.to_string(), "unknown credential");
        assert_eq!(
            WebAuthnError::CounterRegression.to_string(),
            "sign counter regression (possible cloned authenticator)"
        );
        assert_eq!(WebAuthnError::UserInactive.to_string(), "user not found or inactive");
    }
}

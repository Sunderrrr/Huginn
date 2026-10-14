//! Security primitives — byte-compatible with the Python hub (`app/core`).
//!
//! Parity is enforced against [`security_vectors.json`](../../security_vectors.json),
//! which was generated from the Python implementation itself:
//!
//! | module   | Python counterpart                    |
//! |----------|---------------------------------------|
//! | [`password`] | `app/core/security.py` (Argon2id) |
//! | [`secret`]   | `app/core/security.py` (HMAC secrets) |
//! | [`jwt`]      | `app/core/jwt.py` (PyJWT HS256)   |
//! | [`fernet`]   | `app/services/totp.py` (`cryptography.fernet`) |
//! | [`totp`]     | `app/services/totp.py` (pyotp)    |
//! | [`audit`]    | `app/core/audit.py` (hash chain)  |
//!
//! Keys are injected explicitly: there are no hidden globals. Use [`init`] (or
//! [`SecurityConfig::new`]) to carry the configured keys, or pass keys straight
//! to the free functions.
// Facade re-exports: part of the inter-module contract of the migration
// (consumed by routes/tests landing in later commits).
#![allow(unused_imports)]
// The security API is consumed by the routes/services layers landing later in
// the migration; suppress dead-code noise in this self-contained module so
// `cargo clippy -- -D warnings` stays clean in the meantime.
#![allow(dead_code)]

pub mod audit;
pub mod fernet;
pub mod jwt;
pub mod password;
pub mod secret;
pub mod totp;

pub use audit::{canonical, compute_row_hash, verify_chain, AuditEntry, GENESIS_HASH};
pub use fernet::{
    decrypt as decrypt_secret, derive_key as derive_fernet_key,
    derive_key_b64 as derive_fernet_key_b64, encrypt as encrypt_secret, Fernet, FernetError,
};
pub use jwt::{
    create_access_token, create_access_token_at, create_mfa_challenge_token,
    create_mfa_challenge_token_at, decode_access_token, decode_access_token_at,
    decode_mfa_challenge_token, decode_mfa_challenge_token_at, Jwt, TokenError, MFA_SCOPE,
    MFA_SCOPES, MFA_SETUP_SCOPE,
};
pub use password::{
    hash_password, hash_password_with, needs_rehash, verify_password, PasswordError,
    PasswordParams, DEFAULT_PARAMS as PASSWORD_PARAMS,
};
pub use secret::{constant_time_equals, generate_secret, hash_secret, verify_secret};
pub use totp::{
    at as totp_code_at, current_step, generate_secret as generate_totp_secret, matched_step,
    provisioning_uri, verify as verify_totp_code, TotpError, DIGITS as TOTP_DIGITS,
    PERIOD as TOTP_PERIOD, VALID_WINDOW as TOTP_VALID_WINDOW,
};

/// Keys the security primitives need, injected at startup.
///
/// Mirrors the key-related fields of `app/config.py` settings; kept separate so
/// the primitives stay free of configuration/global state.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Dedicated key for reversible encryption of TOTP secrets at rest.
    pub mfa_encryption_key: String,
    /// HMAC-SHA256 key used to sign JWTs.
    pub jwt_secret: String,
    /// Key for the keyed HMAC-SHA256 of high-entropy secrets.
    pub secret_hash_key: String,
}

impl SecurityConfig {
    pub fn new(mfa_encryption_key: &str, jwt_secret: &str, secret_hash_key: &str) -> Self {
        Self {
            mfa_encryption_key: mfa_encryption_key.to_owned(),
            jwt_secret: jwt_secret.to_owned(),
            secret_hash_key: secret_hash_key.to_owned(),
        }
    }

    /// JWT issuer/verifier bound to `jwt_secret`.
    pub fn jwt(&self) -> Jwt {
        Jwt::new(&self.jwt_secret)
    }

    /// Fernet-compatible cipher derived from `mfa_encryption_key`.
    pub fn fernet(&self) -> Fernet {
        Fernet::new(&self.mfa_encryption_key)
    }

    /// Keyed HMAC-SHA256 of a high-entropy secret (hex).
    pub fn hash_secret(&self, secret: &str) -> String {
        secret::hash_secret(&self.secret_hash_key, secret)
    }

    /// Timing-safe check of a secret against its stored HMAC.
    pub fn verify_secret(&self, secret: &str, expected_hash: Option<&str>) -> bool {
        secret::verify_secret(&self.secret_hash_key, secret, expected_hash)
    }
}

/// Build the [`SecurityConfig`] from the three configured keys.
pub fn init(mfa_key: &str, jwt_secret: &str, secret_hash_key: &str) -> SecurityConfig {
    SecurityConfig::new(mfa_key, jwt_secret, secret_hash_key)
}

/// Lowercase hex encoding (Python `bytes.hex()`).
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../security_vectors.json")).unwrap()
    }

    /// `init()` wires the configured keys into every primitive.
    #[test]
    fn init_wires_keys() {
        let v = vectors();
        let cfg = init(
            v["fernet"]["mfa_key"].as_str().unwrap(),
            v["jwt"]["secret"].as_str().unwrap(),
            v["hmac_secret"]["key"].as_str().unwrap(),
        );
        assert_eq!(
            cfg.hash_secret(v["hmac_secret"]["secret"].as_str().unwrap()),
            v["hmac_secret"]["hex"].as_str().unwrap()
        );
        assert_eq!(
            derive_fernet_key_b64(&cfg.mfa_encryption_key),
            v["fernet"]["derived_key_b64"].as_str().unwrap()
        );
        let jwt = cfg.jwt();
        assert_eq!(
            jwt.decode_access_token_at(
                v["jwt"]["access_token"].as_str().unwrap(),
                v["jwt"]["access_payload"]["iat"].as_i64().unwrap()
            )
            .unwrap(),
            v["jwt"]["access_payload"]
        );
    }
}

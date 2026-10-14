//! High-entropy secrets (enrollment tokens, per-worker secrets).
//!
//! Parity with `app/core/security.py`: secrets are stored as a keyed
//! HMAC-SHA256 (hex) rather than a slow KDF, and every comparison is
//! timing-safe.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Number of random bytes for generated secrets (256-bit), like
/// `secrets.token_urlsafe(32)`.
const TOKEN_BYTES: usize = 32;

/// Keyed HMAC-SHA256 of a high-entropy secret, hex-encoded (lowercase).
pub fn hash_secret(key: &str, secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(secret.as_bytes());
    crate::security::hex_encode(&mac.finalize().into_bytes())
}

/// Timing-safe comparison of a secret against its stored HMAC.
///
/// The HMAC is always computed, even when `expected_hash` is `None`, so the
/// timing does not reveal whether the entity exists (parity with
/// `verify_secret()` in `app/core/security.py`).
pub fn verify_secret(key: &str, secret: &str, expected_hash: Option<&str>) -> bool {
    let candidate = hash_secret(key, secret);
    match expected_hash {
        None => {
            // Compare against a dummy of equal length to keep timing constant.
            let _ = constant_time_equals(&candidate, &candidate);
            false
        }
        Some(expected) => constant_time_equals(&candidate, expected),
    }
}

/// Return a new URL-safe random secret (32 random bytes, unpadded base64url —
/// byte-compatible with `secrets.token_urlsafe(32)`).
pub fn generate_secret() -> String {
    let mut buf = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Constant-time string equality (Python `hmac.compare_digest`).
pub fn constant_time_equals(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../security_vectors.json")).unwrap()
    }

    /// HMAC-SHA256 hex matches the Python-generated vector exactly.
    #[test]
    fn hmac_matches_python_vector() {
        let v = vectors();
        let h = &v["hmac_secret"];
        let key = h["key"].as_str().unwrap();
        let secret = h["secret"].as_str().unwrap();
        let expected = h["hex"].as_str().unwrap();

        assert_eq!(hash_secret(key, secret), expected);
        assert!(verify_secret(key, secret, Some(expected)));
        assert!(!verify_secret(key, "other-secret", Some(expected)));
        assert!(!verify_secret("other-key", secret, Some(expected)));
        // Missing expectation -> false, but the HMAC is still computed.
        assert!(!verify_secret(key, secret, None));
    }

    #[test]
    fn generated_secret_is_token_urlsafe() {
        let s = generate_secret();
        // 32 bytes -> 43 base64url chars without padding.
        assert_eq!(s.len(), 43);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(s, generate_secret());
    }

    #[test]
    fn constant_time_compare() {
        assert!(constant_time_equals("abc", "abc"));
        assert!(constant_time_equals("", ""));
        assert!(!constant_time_equals("abc", "abd"));
        assert!(!constant_time_equals("abc", "abcd"));
        assert!(!constant_time_equals("", "a"));
    }
}

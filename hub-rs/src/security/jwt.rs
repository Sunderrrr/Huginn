//! JWT issue/verify (HS256), PyJWT-compatible compact serialization.
//!
//! Byte parity with `app/core/jwt.py`:
//! - header `{"alg":"HS256","typ":"JWT"}`;
//! - payload claims serialized compactly in Python insertion order
//!   (`sub`, `role`|`scope`, `iat`, `exp`) so `create_*` reproduces
//!   `jwt.encode(...)` byte for byte;
//! - signature = HMAC-SHA256 over `header.payload`, unpadded base64url.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Scope for the intermediate token awaiting TOTP/backup verification.
pub const MFA_SCOPE: &str = "mfa";
/// Scope for the intermediate token of an admin who must enrol a factor.
pub const MFA_SETUP_SCOPE: &str = "mfa_setup";
/// The only scopes accepted on MFA challenge tokens.
pub const MFA_SCOPES: [&str; 2] = [MFA_SCOPE, MFA_SETUP_SCOPE];

const HS256_HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

/// Raised when a token is missing, malformed, or expired.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("token is malformed")]
    Malformed,
    #[error("unsupported token algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid token signature")]
    InvalidSignature,
    #[error("token payload is invalid")]
    InvalidPayload,
    #[error("signature has expired")]
    Expired,
    #[error("token is not yet valid (iat)")]
    Immature,
    #[error("wrong token scope")]
    WrongScope,
    #[error("invalid mfa scope: {0}")]
    InvalidScope(String),
}

/// JWT issuer/verifier bound to one secret.
#[derive(Debug, Clone)]
pub struct Jwt {
    secret: String,
}

impl Jwt {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Access token for `user_id` with the given role, valid `ttl_min` minutes.
    /// `epoch` is the user's session generation (see [`session_is_current`]).
    pub fn create_access_token(
        &self,
        user_id: &str,
        role: &str,
        ttl_min: i64,
        epoch: i64,
    ) -> Result<String, TokenError> {
        create_access_token(&self.secret, user_id, role, ttl_min, epoch)
    }

    /// [`Jwt::create_access_token`] with a fixed issuance time (testability).
    pub fn create_access_token_at(
        &self,
        user_id: &str,
        role: &str,
        ttl_min: i64,
        epoch: i64,
        now_unix: i64,
    ) -> Result<String, TokenError> {
        create_access_token_at(&self.secret, user_id, role, ttl_min, epoch, now_unix)
    }

    /// Decode and verify an access token (signature + `exp`/`iat`).
    pub fn decode_access_token(&self, token: &str) -> Result<Value, TokenError> {
        decode_access_token(&self.secret, token)
    }

    /// [`Jwt::decode_access_token`] against a fixed clock (testability).
    pub fn decode_access_token_at(&self, token: &str, now_unix: i64) -> Result<Value, TokenError> {
        decode_access_token_at(&self.secret, token, now_unix)
    }

    /// Short-lived token proving a completed first factor (or pending setup).
    pub fn create_mfa_challenge_token(
        &self,
        user_id: &str,
        scope: &str,
        ttl_min: i64,
    ) -> Result<String, TokenError> {
        create_mfa_challenge_token(&self.secret, user_id, scope, ttl_min)
    }

    /// [`Jwt::create_mfa_challenge_token`] with a fixed issuance time.
    pub fn create_mfa_challenge_token_at(
        &self,
        user_id: &str,
        scope: &str,
        ttl_min: i64,
        now_unix: i64,
    ) -> Result<String, TokenError> {
        create_mfa_challenge_token_at(&self.secret, user_id, scope, ttl_min, now_unix)
    }

    /// Decode and require the exact MFA scope.
    pub fn decode_mfa_challenge_token(
        &self,
        token: &str,
        expected_scope: &str,
    ) -> Result<Value, TokenError> {
        decode_mfa_challenge_token(&self.secret, token, expected_scope)
    }

    /// [`Jwt::decode_mfa_challenge_token`] against a fixed clock.
    pub fn decode_mfa_challenge_token_at(
        &self,
        token: &str,
        expected_scope: &str,
        now_unix: i64,
    ) -> Result<Value, TokenError> {
        decode_mfa_challenge_token_at(&self.secret, token, expected_scope, now_unix)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serialize a JSON string literal the way Python's `json.dumps` does
/// (ensure_ascii=True), so token payloads are byte-identical.
fn py_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7f => {
                let v = c as u32;
                if v > 0xffff {
                    let v = v - 0x10000;
                    out.push_str(&format!(
                        "\\u{:04x}\\u{:04x}",
                        0xd800 + (v >> 10),
                        0xdc00 + (v & 0x3ff)
                    ));
                } else {
                    out.push_str(&format!("\\u{v:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Sign a payload JSON literal as a compact HS256 JWT.
pub fn encode_hs256(secret: &str, payload_json: &str) -> Result<String, TokenError> {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HS256_HEADER.as_bytes()),
        URL_SAFE_NO_PAD.encode(payload_json.as_bytes())
    );
    let sig = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Access-token payload, compact, in PyJWT's claim order.
///
/// The `epoch` claim carries the user's session generation (audit finding
/// F-08): the hub compares it with `users.session_epoch` on every request,
/// so bumping that counter invalidates every token issued before it. It is
/// appended last, so the first four claims keep the reference layout.
fn access_payload(user_id: &str, role: &str, epoch: i64, iat: i64, exp: i64) -> String {
    format!(
        r#"{{"sub":{},"role":{},"iat":{iat},"exp":{exp},"epoch":{epoch}}}"#,
        py_json_string(user_id),
        py_json_string(role)
    )
}

/// The session epoch carried by a decoded token. A token issued before the
/// epoch existed carries none: it is treated as epoch 0, exactly like the
/// user's initial value.
pub fn session_epoch_of(payload: &serde_json::Value) -> i64 {
    payload
        .get("epoch")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

/// Whether a decoded token still matches the user's session epoch.
pub fn session_is_current(payload: &serde_json::Value, user_epoch: i64) -> bool {
    session_epoch_of(payload) == user_epoch
}

/// MFA-challenge payload, compact, in PyJWT's claim order.
fn challenge_payload(user_id: &str, scope: &str, iat: i64, exp: i64) -> String {
    format!(
        r#"{{"sub":{},"scope":{},"iat":{iat},"exp":{exp}}}"#,
        py_json_string(user_id),
        py_json_string(scope)
    )
}

/// Create an access token, valid `ttl_min` minutes from now. `epoch` is the
/// user's session generation (see [`session_is_current`]).
pub fn create_access_token(
    secret: &str,
    user_id: &str,
    role: &str,
    ttl_min: i64,
    epoch: i64,
) -> Result<String, TokenError> {
    create_access_token_at(secret, user_id, role, ttl_min, epoch, now_unix())
}

/// Create an access token issued at `now_unix`.
pub fn create_access_token_at(
    secret: &str,
    user_id: &str,
    role: &str,
    ttl_min: i64,
    epoch: i64,
    now_unix: i64,
) -> Result<String, TokenError> {
    let exp = now_unix + ttl_min * 60;
    encode_hs256(secret, &access_payload(user_id, role, epoch, now_unix, exp))
}

/// Create a short-lived MFA challenge token (`scope` must be [`MFA_SCOPE`] or
/// [`MFA_SETUP_SCOPE`]), valid `ttl_min` minutes from now.
pub fn create_mfa_challenge_token(
    secret: &str,
    user_id: &str,
    scope: &str,
    ttl_min: i64,
) -> Result<String, TokenError> {
    create_mfa_challenge_token_at(secret, user_id, scope, ttl_min, now_unix())
}

/// Create an MFA challenge token issued at `now_unix`.
pub fn create_mfa_challenge_token_at(
    secret: &str,
    user_id: &str,
    scope: &str,
    ttl_min: i64,
    now_unix: i64,
) -> Result<String, TokenError> {
    if !MFA_SCOPES.contains(&scope) {
        return Err(TokenError::InvalidScope(scope.to_owned()));
    }
    let exp = now_unix + ttl_min * 60;
    encode_hs256(secret, &challenge_payload(user_id, scope, now_unix, exp))
}

/// Decode and verify a token (signature, `exp`, `iat`) against the current time.
pub fn decode_access_token(secret: &str, token: &str) -> Result<Value, TokenError> {
    decode_access_token_at(secret, token, now_unix())
}

/// Decode and verify a token against a fixed clock.
pub fn decode_access_token_at(
    secret: &str,
    token: &str,
    now_unix: i64,
) -> Result<Value, TokenError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(TokenError::Malformed);
    }
    let header_bytes = b64url_decode(parts[0]).map_err(|_| TokenError::Malformed)?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| TokenError::Malformed)?;
    if header.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Err(TokenError::UnsupportedAlgorithm);
    }

    let sig = b64url_decode(parts[2]).map_err(|_| TokenError::Malformed)?;
    let expected = hmac_sha256(
        secret.as_bytes(),
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
    );
    if !bool::from(sig.as_slice().ct_eq(expected.as_slice())) {
        return Err(TokenError::InvalidSignature);
    }

    let payload_bytes = b64url_decode(parts[1]).map_err(|_| TokenError::Malformed)?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| TokenError::InvalidPayload)?;
    validate_claims(&payload, now_unix)?;
    Ok(payload)
}

/// Decode and require the exact MFA scope.
pub fn decode_mfa_challenge_token(
    secret: &str,
    token: &str,
    expected_scope: &str,
) -> Result<Value, TokenError> {
    decode_mfa_challenge_token_at(secret, token, expected_scope, now_unix())
}

/// [`decode_mfa_challenge_token`] against a fixed clock.
pub fn decode_mfa_challenge_token_at(
    secret: &str,
    token: &str,
    expected_scope: &str,
    now_unix: i64,
) -> Result<Value, TokenError> {
    let payload = decode_access_token_at(secret, token, now_unix)?;
    if payload.get("scope").and_then(Value::as_str) != Some(expected_scope) {
        return Err(TokenError::WrongScope);
    }
    Ok(payload)
}

/// Claim validation, matching PyJWT's default `verify_exp`/`verify_iat`.
///
/// `exp` is **mandatory** here (PyJWT would accept a token without one): a
/// token that carries no expiry is a credential that never expires, so the
/// verifier fails closed instead of silently treating the claim as
/// "valid forever". Every token this hub mints carries `exp`.
fn validate_claims(payload: &Value, now_unix: i64) -> Result<(), TokenError> {
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(TokenError::InvalidPayload)?;
    // PyJWT: expired when `exp + leeway < now` (leeway 0).
    if exp < now_unix {
        return Err(TokenError::Expired);
    }
    if let Some(iat) = payload.get("iat") {
        let iat = iat.as_i64().ok_or(TokenError::InvalidPayload)?;
        if iat > now_unix {
            return Err(TokenError::Immature);
        }
    }
    Ok(())
}

/// Unpadded base64url decode (padding tolerated).
fn b64url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../security_vectors.json")).unwrap()
    }

    fn jwt_vectors() -> serde_json::Value {
        vectors()["jwt"].clone()
    }

    /// The Python-issued tokens decode to their exact payloads.
    #[test]
    fn decodes_python_tokens() {
        let j = jwt_vectors();
        let secret = j["secret"].as_str().unwrap();
        // Issued at 1700000000, expire at 1700003600.
        let now = j["access_payload"]["iat"].as_i64().unwrap();

        let payload = decode_access_token_at(secret, j["access_token"].as_str().unwrap(), now)
            .expect("access token must decode");
        assert_eq!(payload, j["access_payload"]);

        let challenge = decode_access_token_at(secret, j["challenge_token"].as_str().unwrap(), now)
            .expect("challenge token must decode");
        assert_eq!(challenge, j["challenge_payload"]);
    }

    /// The session epoch travels with the token and is what the hub compares
    /// with `users.session_epoch` to revoke a session (F-08). A token issued
    /// before the epoch existed carries none: it counts as epoch 0.
    #[test]
    fn session_epoch_round_trips_and_defaults_to_zero() {
        let secret = "epoch-secret";
        let token = create_access_token_at(secret, "u", "admin", 5, 7, 1_700_000_000).unwrap();
        let payload = decode_access_token_at(secret, &token, 1_700_000_000).unwrap();
        assert_eq!(session_epoch_of(&payload), 7);
        assert!(session_is_current(&payload, 7));
        assert!(!session_is_current(&payload, 8));

        // A legacy payload without the claim is epoch 0.
        let legacy = serde_json::json!({"sub": "u", "role": "admin", "iat": 1, "exp": 9});
        assert_eq!(session_epoch_of(&legacy), 0);
        assert!(session_is_current(&legacy, 0));
        assert!(!session_is_current(&legacy, 1));
    }

    #[test]
    fn mfa_scope_is_enforced() {
        let j = jwt_vectors();
        let secret = j["secret"].as_str().unwrap();
        let token = j["challenge_token"].as_str().unwrap();
        let now = j["challenge_payload"]["iat"].as_i64().unwrap();

        let payload = decode_mfa_challenge_token_at(secret, token, MFA_SETUP_SCOPE, now).unwrap();
        assert_eq!(payload, j["challenge_payload"]);
        assert!(matches!(
            decode_mfa_challenge_token_at(secret, token, MFA_SCOPE, now),
            Err(TokenError::WrongScope)
        ));
    }

    /// The signature scheme stays byte-compatible with PyJWT: encoding the
    /// reference claim set produces exactly PyJWT's token.
    ///
    /// The claim SET itself now carries one extra claim — `epoch`, the
    /// user's session generation (audit finding F-08) — so the minted token
    /// is not byte-identical to the frozen reference any more. This is a
    /// deliberate divergence from the retired Python hub (the endpoint-level
    /// parity gate still passes: the harness normalizes JWTs to `<JWT>`).
    #[test]
    fn creates_python_identical_tokens() {
        let j = jwt_vectors();
        let secret = j["secret"].as_str().unwrap();
        let sub = j["access_payload"]["sub"].as_str().unwrap();
        let now = j["access_payload"]["iat"].as_i64().unwrap();
        let ttl = (j["access_payload"]["exp"].as_i64().unwrap() - now) / 60;

        // The encoder is unchanged: the reference claim set, in PyJWT's
        // order, still yields PyJWT's exact token.
        let reference_payload = format!(
            r#"{{"sub":"{sub}","role":"admin","iat":{now},"exp":{}}}"#,
            now + ttl * 60
        );
        assert_eq!(
            encode_hs256(secret, &reference_payload).unwrap(),
            j["access_token"].as_str().unwrap()
        );

        // The minted token additionally carries the session epoch.
        let access = create_access_token_at(secret, sub, "admin", ttl, 0, now).unwrap();
        let decoded = decode_access_token_at(secret, &access, now).unwrap();
        assert_eq!(decoded["sub"], sub);
        assert_eq!(decoded["role"], "admin");
        assert_eq!(decoded["epoch"], 0);

        let challenge =
            create_mfa_challenge_token_at(secret, sub, MFA_SETUP_SCOPE, ttl, now).unwrap();
        assert_eq!(challenge, j["challenge_token"].as_str().unwrap());
        assert_eq!(
            decode_mfa_challenge_token_at(secret, &challenge, MFA_SETUP_SCOPE, now).unwrap(),
            j["challenge_payload"]
        );

        // The struct-based API produces the same bytes.
        let jwt = Jwt::new(secret);
        assert_eq!(
            jwt.create_access_token_at(sub, "admin", ttl, 0, now)
                .unwrap(),
            access
        );
    }

    #[test]
    fn rejects_expired_tokens() {
        let j = jwt_vectors();
        let secret = j["secret"].as_str().unwrap();
        let token = j["access_token"].as_str().unwrap();
        let exp = j["access_payload"]["exp"].as_i64().unwrap();

        // Valid at `exp`, expired just after.
        assert!(decode_access_token_at(secret, token, exp).is_ok());
        assert!(matches!(
            decode_access_token_at(secret, token, exp + 1),
            Err(TokenError::Expired)
        ));
        // Against the real clock the 2023 vector token is long expired.
        assert!(matches!(
            decode_access_token(secret, token),
            Err(TokenError::Expired)
        ));
    }

    #[test]
    fn rejects_bad_signatures() {
        let j = jwt_vectors();
        let secret = j["secret"].as_str().unwrap();
        let token = j["access_token"].as_str().unwrap();
        let now = j["access_payload"]["iat"].as_i64().unwrap();

        // Wrong key.
        assert!(matches!(
            decode_access_token_at("other-secret", token, now),
            Err(TokenError::InvalidSignature)
        ));

        // Tampered payload (claims re-encoded, signature unchanged).
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload: Value = serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        payload["role"] = Value::String("user".to_owned());
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
            parts[2]
        );
        assert!(matches!(
            decode_access_token_at(secret, &tampered, now),
            Err(TokenError::InvalidSignature)
        ));

        // Tampered signature.
        let bad_sig = format!("{}.{}.{}", parts[0], parts[1], "AAAA");
        assert!(matches!(
            decode_access_token_at(secret, &bad_sig, now),
            Err(TokenError::InvalidSignature)
        ));

        // `alg: none` is never accepted: an empty signature is malformed...
        let none_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let unsigned = format!("{}.{}", none_header, parts[1]);
        assert!(matches!(
            decode_access_token_at(secret, &unsigned, now),
            Err(TokenError::Malformed)
        ));
        // ...and even with a signature segment attached, `none` is refused.
        let none_with_sig = format!("{}.{}.{}", none_header, parts[1], parts[2]);
        assert!(matches!(
            decode_access_token_at(secret, &none_with_sig, now),
            Err(TokenError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn rejects_malformed_tokens() {
        let j = jwt_vectors();
        let secret = j["secret"].as_str().unwrap();
        assert!(matches!(
            decode_access_token_at(secret, "not-a-token", 0),
            Err(TokenError::Malformed)
        ));
        assert!(matches!(
            decode_access_token_at(secret, "", 0),
            Err(TokenError::Malformed)
        ));
    }

    /// A token without an expiry would be a credential that never expires.
    /// The verifier fails closed on it instead of accepting it.
    #[test]
    fn rejects_tokens_without_an_expiry() {
        let j = jwt_vectors();
        let secret = j["secret"].as_str().unwrap();
        let now = j["access_payload"]["iat"].as_i64().unwrap();

        // Signed with the real key, but the payload carries no `exp`.
        let no_exp = encode_hs256(
            secret,
            r#"{"sub":"11111111-1111-1111-1111-111111111111","role":"admin","iat":1700000000}"#,
        )
        .unwrap();
        assert!(matches!(
            decode_access_token_at(secret, &no_exp, now),
            Err(TokenError::InvalidPayload)
        ));

        // Same for a challenge token: no `exp` → refused before the scope check.
        let no_exp_challenge = encode_hs256(
            secret,
            r#"{"sub":"11111111-1111-1111-1111-111111111111","scope":"mfa","iat":1700000000}"#,
        )
        .unwrap();
        assert!(matches!(
            decode_mfa_challenge_token_at(secret, &no_exp_challenge, MFA_SCOPE, now),
            Err(TokenError::InvalidPayload)
        ));

        // A non-numeric expiry is refused too.
        let bad_exp = encode_hs256(
            secret,
            r#"{"sub":"11111111-1111-1111-1111-111111111111","role":"admin","iat":1700000000,"exp":"soon"}"#,
        )
        .unwrap();
        assert!(matches!(
            decode_access_token_at(secret, &bad_exp, now),
            Err(TokenError::InvalidPayload)
        ));
    }

    #[test]
    fn rejects_invalid_mfa_scope() {
        assert!(matches!(
            create_mfa_challenge_token_at("s", "u", "admin", 5, 0),
            Err(TokenError::InvalidScope(_))
        ));
    }
}

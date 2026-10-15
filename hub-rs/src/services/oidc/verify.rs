//! ID token verification against the provider's JWKS (pure, testable).

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

use super::{OidcClaims, OidcError};

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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::models::enums::UserRole;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::json;

    // ---- ephemeral test keys (generated at runtime; nothing committed) ----

    pub(crate) fn b64url(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }

    #[allow(clippy::large_enum_variant)] // test-only helper; size is irrelevant
    pub(crate) enum TestKey {
        Rsa(rsa::RsaPrivateKey),
        Ec(p256::SecretKey),
    }

    impl TestKey {
        fn jwk(&self, kid: &str) -> serde_json::Value {
            match self {
                TestKey::Rsa(sk) => {
                    use rsa::traits::PublicKeyParts;
                    let pk = sk.to_public_key();
                    serde_json::json!({
                        "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
                        "n": b64url(&pk.n().to_bytes_be()),
                        "e": b64url(&pk.e().to_bytes_be()),
                    })
                }
                TestKey::Ec(sk) => {
                    use p256::elliptic_curve::sec1::ToEncodedPoint;
                    let point = sk.public_key().to_encoded_point(false);
                    let bytes = point.as_bytes();
                    serde_json::json!({
                        "kty": "EC", "kid": kid, "alg": "ES256", "use": "sig", "crv": "P-256",
                        "x": b64url(&bytes[1..33]),
                        "y": b64url(&bytes[33..65]),
                    })
                }
            }
        }

        pub(crate) fn sign(
            &self,
            alg: &str,
            kid: Option<&str>,
            payload: &serde_json::Value,
        ) -> String {
            let mut header = serde_json::json!({"alg": alg, "typ": "JWT"});
            if let Some(k) = kid {
                header["kid"] = serde_json::json!(k);
            }
            let h = b64url(&serde_json::to_vec(&header).unwrap());
            let p = b64url(&serde_json::to_vec(payload).unwrap());
            let signing_input = format!("{h}.{p}");
            let sig = match self {
                TestKey::Rsa(sk) => {
                    use rsa::pkcs1v15::Pkcs1v15Sign;
                    use sha2::Digest;
                    let digest = sha2::Sha256::digest(signing_input.as_bytes());
                    sk.sign(Pkcs1v15Sign::new::<sha2::Sha256>(), &digest)
                        .unwrap()
                }
                TestKey::Ec(sk) => {
                    use signature::Signer;
                    let signing = p256::ecdsa::SigningKey::from(sk.clone());
                    let sig: p256::ecdsa::Signature = signing.sign(signing_input.as_bytes());
                    sig.to_bytes().to_vec()
                }
            };
            format!("{signing_input}.{}", b64url(&sig))
        }
    }

    pub(crate) fn gen_rsa() -> (TestKey, serde_json::Value) {
        let key = TestKey::Rsa(rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap());
        let jwk = key.jwk("rsa-key");
        (key, jwk)
    }

    pub(crate) fn gen_ec() -> (TestKey, serde_json::Value) {
        let key = TestKey::Ec(p256::SecretKey::random(&mut rand::rngs::OsRng));
        let jwk = key.jwk("ec-key");
        (key, jwk)
    }

    /// A syntactically-valid HS256 token (rejected before any signature check).
    pub(crate) fn hs256_token(payload: &serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
        let h = b64url(&serde_json::to_vec(&header).unwrap());
        let p = b64url(&serde_json::to_vec(payload).unwrap());
        format!("{h}.{p}.{}", b64url(b"not-a-real-signature"))
    }

    pub(crate) fn base_payload() -> serde_json::Value {
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
        for (alg, key, jwk) in [
            ("RS256", gen_rsa().0, gen_rsa().1),
            ("ES256", gen_ec().0, gen_ec().1),
        ] {
            let _ = jwk;
            let kid = if alg == "RS256" { "rsa-key" } else { "ec-key" };
            let jwk = key.jwk(kid);
            let token = key.sign(alg, Some(kid), &base_payload());
            let set = serde_json::json!({ "keys": [jwk] });
            let claims = verify_id_token(&token, &set, "https://idp.example", "client-1", None)
                .expect("valid token verifies");
            assert_eq!(claims.subject, "subject-1");
            assert_eq!(claims.username, "alice");
            assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        }
    }

    #[test]
    fn username_falls_back_to_email_then_sub() {
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
        let (key, jwk) = gen_rsa();
        let set = serde_json::json!({ "keys": [jwk] });

        let mut p = base_payload();
        p["aud"] = serde_json::json!("other-client");
        let t = key.sign("RS256", Some("rsa-key"), &p);
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::Verification(_))
        ));

        let mut p = base_payload();
        p["exp"] = serde_json::json!(1_700_000_000_i64 - 10_000);
        let t = key.sign("RS256", Some("rsa-key"), &p);
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::Verification(_))
        ));

        let t = key.sign("RS256", Some("rsa-key"), &base_payload());
        assert!(matches!(
            verify_id_token(&t, &set, "https://evil.example", "client-1", None),
            Err(OidcError::Verification(_))
        ));
    }

    #[test]
    fn rejects_nonce_mismatch_and_missing_sub() {
        let (key, jwk) = gen_rsa();
        let set = serde_json::json!({ "keys": [jwk] });

        let mut p = base_payload();
        p["nonce"] = serde_json::json!("right-nonce");
        let t = key.sign("RS256", Some("rsa-key"), &p);
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
        assert!(verify_id_token(
            &t,
            &set,
            "https://idp.example",
            "client-1",
            Some("right-nonce")
        )
        .is_ok());

        let mut p = base_payload();
        p.as_object_mut().unwrap().remove("sub");
        let t = key.sign("RS256", Some("rsa-key"), &p);
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::MissingSubject)
        ));
    }

    #[test]
    fn rejects_unsupported_algorithm_and_untrusted_key() {
        let (key, jwk) = gen_rsa();
        let set = serde_json::json!({ "keys": [jwk] });

        let t = hs256_token(&base_payload());
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::UnsupportedAlgorithm)
        ));

        // A token whose kid matches no key in the set.
        let t = key.sign("RS256", Some("unknown-kid"), &base_payload());
        assert!(matches!(
            verify_id_token(&t, &set, "https://idp.example", "client-1", None),
            Err(OidcError::NoMatchingKey)
        ));
    }

    #[test]
    fn selects_key_by_kid_or_first_when_absent() {
        let (rsa_key, rsa_jwk) = gen_rsa();
        let (_ec_key, ec_jwk) = gen_ec();
        let both = serde_json::json!({ "keys": [ec_jwk, rsa_jwk] });

        // RSA-signed token picked by kid from a mixed set.
        let t = rsa_key.sign("RS256", Some("rsa-key"), &base_payload());
        assert!(verify_id_token(&t, &both, "https://idp.example", "client-1", None).is_ok());

        // No kid on the token → the first key (ec) is used; an RSA-signed token
        // then fails to verify against it.
        let t_no_kid = rsa_key.sign("RS256", None, &base_payload());
        assert!(matches!(
            verify_id_token(&t_no_kid, &both, "https://idp.example", "client-1", None),
            Err(OidcError::Verification(_))
        ));
    }
}

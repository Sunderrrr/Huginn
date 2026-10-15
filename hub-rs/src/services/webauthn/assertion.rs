//! Authentication assertion verification — `verify_authentication_response`
//! and the sign-counter / clone detection layered on top of it.

use crate::services::webauthn::WebAuthnError;

use super::helpers::{
    check_token_binding, decode_credential_public_key, parse_authenticator_data,
    parse_client_data_json, sha256, verify_signature, AuthData, ParsedCredential, FLAG_UP, FLAG_UV,
};
use super::{b64u_decode, b64u_encode};

/// What `webauthn.finish_login` needs from a verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthentication {
    pub new_sign_count: i64,
    pub user_verified: bool,
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

/// `webauthn.finish_login`'s clone check, layered on top of the counter check
/// inside [`verify_authentication`]: a non-zero counter that didn't advance
/// signals a copied authenticator. The `0 → 0` case is legitimate (an
/// authenticator that never counts).
pub(super) fn check_sign_counter(new_count: i64, stored_count: i64) -> Result<(), WebAuthnError> {
    if new_count <= stored_count && !(new_count == 0 && stored_count == 0) {
        return Err(WebAuthnError::CounterRegression);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::webauthn::test_support::*;
    use serde_json::json;

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
            let verified =
                verify_authentication(&credential, challenge, RP_ID, ORIGIN, key.cose(), 7, true)
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
        assert!(
            verify_authentication(&credential, challenge, RP_ID, ORIGIN, key.cose(), 7, false)
                .is_ok()
        );
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
        for (new, stored, ok) in [
            (8, 7, true),
            (7, 7, false),
            (6, 7, false),
            (0, 7, false),
            (0, 0, true),
            (1, 0, true),
        ] {
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
        assert_eq!(
            err.to_string(),
            "sign counter regression (possible cloned authenticator)"
        );
        assert_eq!(
            check_sign_counter(6, 7).unwrap_err().to_string(),
            "sign counter regression (possible cloned authenticator)"
        );
    }
}

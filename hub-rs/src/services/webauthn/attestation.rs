//! Registration attestation verification — `verify_registration_response`
//! plus the `none` / `packed` / `fido-u2f` attestation formats.

use crate::services::webauthn::WebAuthnError;

use super::helpers::{
    aaguid_to_string, check_token_binding, decode_credential_public_key, parse_attestation_object,
    parse_authenticator_data, parse_client_data_json, rsa_verifying_key, sha256, verify_signature,
    AttestationObject, AuthData, DecodedKey, KeyMaterial, ParsedCredential, FLAG_AT, FLAG_UP,
    FLAG_UV,
};
use super::{b64u_decode, b64u_encode};

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

    let attestation = parse_attestation_object(&cred.attestation_object).map_err(|e| {
        format!("attestationObject was malformed. See __cause__ for more info: {e}")
    })?;
    let auth_data = &attestation.auth_data;

    let expected_rp_id_hash = sha256(expected_rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err("Unexpected RP ID hash".into());
    }
    if !auth_data.flag(FLAG_UP) {
        return Err("User presence was required, but was not present during attestation".into());
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
        "packed" => verify_packed(
            attestation,
            auth_data,
            client_data_json,
            credential_public_key,
        ),
        "fido-u2f" => verify_fido_u2f(
            attestation,
            auth_data,
            client_data_json,
            credential_public_key,
            credential_id,
        ),
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
    let sig = attestation
        .att_stmt_sig()
        .map_err(|e| format!("{e} (Packed)"))?;
    let alg = attestation
        .att_stmt_alg()
        .map_err(|e| format!("{e} (Packed)"))?;

    let mut verification_data = attestation.auth_data_bytes.clone();
    verification_data.extend_from_slice(&sha256(client_data_json));

    if let Some(x5c) = attestation.att_stmt_x5c() {
        // Chain validation is a no-op without configured root certs, exactly
        // like `validate_certificate_chain` in the Python hub.
        let leaf = leaf_public_key(&x5c[0]).map_err(|e| format!("{e} (Packed)"))?;
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
    let sig = attestation
        .att_stmt_sig()
        .map_err(|e| format!("{e} {suffix}"))?;
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
        return Err(format!(
            "Leaf cert was not an EC2 P-256 certificate {suffix}"
        ));
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

    verify_spki_signature(&leaf, -7, sig, &verification_data).map_err(|e| format!("{e} {suffix}"))
}

/// The raw `subjectPublicKey` BIT STRING of an x5c leaf certificate.
fn leaf_public_key(der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| format!("Could not parse x5c certificate: {e}"))?;
    Ok(cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec())
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

#[cfg(test)]
mod tests {
    use super::super::raw_transports;
    use super::*;
    use crate::services::webauthn::test_support::*;
    use ciborium::value::Value;
    use serde_json::json;

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
            verify_registration(
                &credential,
                b"another 32-byte challenge!!!!!!",
                RP_ID,
                ORIGIN,
                true
            ),
            Err(WebAuthnError::RegistrationFailed)
        ));
        assert!(matches!(
            verify_registration(
                &credential,
                challenge,
                RP_ID,
                "https://evil.example.com",
                true
            ),
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
        for field in [
            "sig", "x5c", "response", "alg", "ver", "certInfo", "pubArea",
        ] {
            let stmt = Value::Map(vec![(
                Value::Text(field.into()),
                Value::Integer(1_i64.into()),
            )]);
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
            Some((
                &aaguid,
                credential_id,
                &cose_ec2_key(&[0x02; 32], &[0x03; 32]),
            )),
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
            (
                Value::Text("sig".into()),
                Value::Bytes(FabricatedKey::es256().sign(&verification_data)),
            ),
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
}

//! A virtual authenticator for tests: registration and authentication
//! payloads are built byte-for-byte like a real one would (COSE keys,
//! authenticatorData, clientDataJSON, real signatures), so the verifiers
//! are exercised for real instead of being mocked out.
use super::helpers::{cbor_encode, sha256, FLAG_AT, FLAG_UP, FLAG_UV};
use super::*;
use ciborium::value::Value;
use serde_json::json;

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
        let cose = cose_rsa_key(&public.n().to_bytes_be(), &public.e().to_bytes_be());
        Self::Rs256 { signing, cose }
    }

    /// The COSE public key bytes a registration would store.
    pub(crate) fn cose(&self) -> &[u8] {
        match self {
            Self::Es256 { cose, .. } | Self::Ed25519 { cose, .. } | Self::Rs256 { cose, .. } => {
                cose
            }
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
        (1, Value::Integer(2_i64.into())),    // kty: EC2
        (3, Value::Integer((-7_i64).into())), // alg: ES256
        (-1, Value::Integer(1_i64.into())),   // crv: P-256
        (-2, Value::Bytes(x.to_vec())),
        (-3, Value::Bytes(y.to_vec())),
    ])
}

pub(crate) fn cose_okp_key(x: &[u8]) -> Vec<u8> {
    cbor_int_map(vec![
        (1, Value::Integer(1_i64.into())),    // kty: OKP
        (3, Value::Integer((-8_i64).into())), // alg: EdDSA
        (-1, Value::Integer(6_i64.into())),   // crv: Ed25519
        (-2, Value::Bytes(x.to_vec())),
    ])
}

pub(crate) fn cose_rsa_key(n: &[u8], e: &[u8]) -> Vec<u8> {
    cbor_int_map(vec![
        (1, Value::Integer(3_i64.into())),      // kty: RSA
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

// ---- shared fixtures ------------------------------------------------

pub(crate) fn sample_user() -> User {
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

pub(crate) fn sample_rp() -> RpConfig {
    RpConfig {
        rp_id: RP_ID.into(),
        rp_name: "Huginn".into(),
        origin: ORIGIN.into(),
    }
}

/// A complete `fmt: "none"` registration payload for `key`.
pub(crate) fn registration_payload(
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
pub(crate) fn assertion_payload(
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

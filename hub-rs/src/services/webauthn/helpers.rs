//! Parsing helpers shared by the registration and login verifiers: credential
//! / `clientDataJSON` parsing, authenticator data and attestation-object CBOR,
//! COSE public keys and signature verification.

use ciborium::value::Value;

use super::b64u_decode;

/// The subset of `parse_registration_credential_json` /
/// `parse_authentication_credential_json` the verifiers need.
pub(super) struct ParsedCredential {
    pub(super) id: String,
    pub(super) raw_id: Vec<u8>,
    pub(super) client_data_json: Vec<u8>,
    pub(super) attestation_object: Vec<u8>,
    pub(super) authenticator_data: Vec<u8>,
    pub(super) signature: Vec<u8>,
}

pub(super) fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("Credential missing required {key}"))
}

pub(super) fn check_type_and_attachment(credential: &serde_json::Value) -> Result<(), String> {
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
    pub(super) fn parse_registration(credential: &serde_json::Value) -> Result<Self, String> {
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

    pub(super) fn parse_authentication(credential: &serde_json::Value) -> Result<Self, String> {
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
                    b64u_decode(handle).map_err(|_| {
                        "Could not parse authentication credential from JSON data".to_string()
                    })?;
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
pub(super) struct ClientData {
    pub(super) type_: String,
    pub(super) challenge: Vec<u8>,
    pub(super) origin: String,
    /// The parsed token binding status, when it is one of the known values.
    pub(super) token_binding: Option<String>,
}

pub(super) fn parse_client_data_json(bytes: &[u8]) -> Result<ClientData, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| "Unable to decode clientDataJSON bytes as JSON")?;
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
pub(super) fn check_token_binding(client_data: &ClientData) -> Result<(), String> {
    match client_data.token_binding.as_deref() {
        Some("supported") | Some("present") | None => Ok(()),
        Some(status) => Err(format!(
            "Unexpected token_binding status of \"{status}\", expected one of \"supported,present\""
        )),
    }
}

pub(super) const FLAG_UP: u8 = 1 << 0;
pub(super) const FLAG_UV: u8 = 1 << 2;
pub(super) const FLAG_AT: u8 = 1 << 6;
pub(super) const FLAG_ED: u8 = 1 << 7;

/// `webauthn.helpers.parse_authenticator_data`.
pub(super) struct AttestedCredentialData {
    pub(super) aaguid: Vec<u8>,
    pub(super) credential_id: Vec<u8>,
    /// Canonical COSE key bytes (py_webauthn re-encodes what it parsed).
    pub(super) credential_public_key: Vec<u8>,
}

pub(super) struct AuthData {
    pub(super) rp_id_hash: Vec<u8>,
    pub(super) flags: u8,
    pub(super) sign_count: i64,
    pub(super) attested: Option<AttestedCredentialData>,
}

impl AuthData {
    pub(super) fn flag(&self, bit: u8) -> bool {
        self.flags & bit != 0
    }
}

/// Decode one CBOR value, rejecting duplicate map keys the way
/// `parse_cbor(..., allow_duplicate_keys=False)` does (recursively).
pub(super) fn cbor_decode_one(bytes: &[u8]) -> Result<(Value, usize), String> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| format!("Could not decode CBOR data: {e}"))?;
    reject_duplicate_keys(&value)?;
    Ok((value, cursor.position() as usize))
}

pub(super) fn reject_duplicate_keys(value: &Value) -> Result<(), String> {
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

pub(super) fn cbor_encode(value: &Value) -> Result<Vec<u8>, String> {
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

pub(super) fn parse_authenticator_data(val: &[u8]) -> Result<AuthData, String> {
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
pub(super) fn aaguid_to_string(val: &[u8]) -> String {
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
pub(super) struct AttestationObject {
    pub(super) fmt: String,
    pub(super) auth_data: AuthData,
    pub(super) auth_data_bytes: Vec<u8>,
    /// The recognized `attStmt` fields (`sig`, `x5c`, `response`, `alg`,
    /// `ver`, `certInfo`, `pubArea`) that are present and non-null.
    pub(super) att_stmt: Vec<(String, Value)>,
}

pub(super) fn map_entries(value: &Value) -> Result<&Vec<(Value, Value)>, String> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err("CBOR value was not a map".into()),
    }
}

pub(super) fn map_get<'a>(entries: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// py_webauthn's `AttestationStatement` fields checked by the `none` format.
pub(super) const ATT_STMT_FIELDS: [&str; 7] = [
    "sig", "x5c", "response", "alg", "ver", "certInfo", "pubArea",
];

pub(super) fn parse_attestation_object(bytes: &[u8]) -> Result<AttestationObject, String> {
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
    pub(super) fn att_stmt_get(&self, field: &str) -> Option<&Value> {
        self.att_stmt
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| v)
    }

    pub(super) fn att_stmt_sig(&self) -> Result<&[u8], String> {
        self.att_stmt_get("sig")
            .and_then(|v| v.as_bytes().map(Vec::as_slice))
            .filter(|s| !s.is_empty())
            .ok_or("Attestation statement was missing signature".to_string())
    }

    pub(super) fn att_stmt_alg(&self) -> Result<i64, String> {
        // Python: `if not attestation_statement.alg` — 0 is "missing".
        self.att_stmt_get("alg")
            .and_then(Value::as_integer)
            .and_then(|i| i64::try_from(i).ok())
            .filter(|&alg| alg != 0)
            .ok_or("Attestation statement was missing algorithm".to_string())
    }

    pub(super) fn att_stmt_x5c(&self) -> Option<Vec<Vec<u8>>> {
        let certs = self.att_stmt_get("x5c")?.as_array()?;
        let certs: Option<Vec<Vec<u8>>> = certs.iter().map(|v| v.as_bytes().cloned()).collect();
        certs.filter(|c| !c.is_empty())
    }
}

/// A decoded COSE credential public key (`DecodedEC2/RSA/OKPPublicKey`).
pub(super) struct DecodedKey {
    pub(super) alg: i64,
    pub(super) key: KeyMaterial,
}

pub(super) enum KeyMaterial {
    /// P-256 (`crv` 1), x/y 32 bytes each — also the raw `0x04` U2F spelling.
    Ec2 {
        x: Vec<u8>,
        y: Vec<u8>,
    },
    /// Ed25519 (`crv` 6), x 32 bytes.
    Okp {
        x: Vec<u8>,
    },
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

pub(super) fn int_param(entries: &[(Value, Value)], label: i64) -> Option<i64> {
    map_get(entries, &Value::Integer(label.into()))
        .and_then(Value::as_integer)
        .and_then(|i| i64::try_from(i).ok())
}

pub(super) fn bytes_param(entries: &[(Value, Value)], label: i64) -> Option<&Vec<u8>> {
    map_get(entries, &Value::Integer(label.into())).and_then(Value::as_bytes)
}

/// `webauthn.helpers.decode_credential_public_key` (OKP, EC2, RSA; the raw
/// uncompressed `0x04` point from old U2F keys included).
pub(super) fn decode_credential_public_key(key: &[u8]) -> Result<DecodedKey, String> {
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
    let kty = int_param(entries, 1)
        .filter(|&k| k != 0)
        .ok_or("Credential public key missing kty")?;
    let alg = int_param(entries, 3)
        .filter(|&a| a != 0)
        .ok_or("Credential public key missing alg")?;

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
        other => Err(format!(
            "Unsupported credential public key type \"{other}\""
        )),
    }
}

/// `webauthn.helpers.verify_signature` for the supported alg/key pairs:
/// ES256 (`-7`) with a DER ECDSA signature, RS256 (`-257`) PKCS#1 v1.5,
/// EdDSA (`-8`). `decoded_public_key.alg` selects the scheme, like Python.
pub(super) fn verify_signature(
    decoded: &DecodedKey,
    signature: &[u8],
    data: &[u8],
) -> Result<(), String> {
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

pub(super) fn p256_verifying_key(x: &[u8], y: &[u8]) -> Result<p256::ecdsa::VerifyingKey, String> {
    use p256::elliptic_curve::sec1::FromSec1Point;
    if x.len() != 32 || y.len() != 32 {
        return Err("EC2 coordinates were not 32 bytes".into());
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    let point = p256::Sec1Point::from_bytes(&point)
        .map_err(|e| format!("Could not parse EC2 point: {e}"))?;
    let key = p256::PublicKey::from_sec1_bytes(point.as_bytes())
        .map_err(|e| format!("EC2 point was not on the P-256 curve: {e}"))?;
    Ok(p256::ecdsa::VerifyingKey::from(key))
}

pub(super) fn rsa_verifying_key(n: &[u8], e: &[u8]) -> Result<rsa::RsaPublicKey, String> {
    use rsa::{BigUint, RsaPublicKey};
    let n = BigUint::from_bytes_be(n);
    let e = BigUint::from_bytes_be(e);
    RsaPublicKey::new(n, e).map_err(|err| format!("Could not build RSA public key: {err}"))
}

pub(super) fn ed25519_verifying_key(x: &[u8]) -> Result<ed25519_dalek::VerifyingKey, String> {
    let bytes: [u8; 32] = x
        .try_into()
        .map_err(|_| "Ed25519 public key was not 32 bytes".to_string())?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|err| format!("Could not build Ed25519 public key: {err}"))
}

pub(super) fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

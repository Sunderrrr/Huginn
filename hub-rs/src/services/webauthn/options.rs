//! WebAuthn options wire shapes (`py_webauthn` `options_to_json`) and their
//! builders — the `PublicKeyCredential*Entity` structures the routes return.

use serde::{Deserialize, Serialize};

use crate::models::user::User;
use crate::models::webauthn::WebAuthnCredential;

use super::{b64u_decode, b64u_encode, RpConfig, UserVerification, CEREMONY_TIMEOUT_MS};

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
pub(super) fn registration_options(
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
pub(super) fn authentication_options(
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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::services::webauthn::test_support::*;
    use serde_json::json;

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
        let options =
            authentication_options(&sample_rp(), UserVerification::Required, "Y2hhbGxlbmdl");
        assert_eq!(
            serde_json::to_string(&options).unwrap(),
            r#"{"challenge":"Y2hhbGxlbmdl","timeout":60000,"rpId":"huginn.example.com","allowCredentials":[],"userVerification":"required"}"#
        );
    }
}

//! Wire schemas of the login/profile endpoints (`app/schemas/auth.py`).

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// `LoginRequest`. Length caps bound Argon2 work (anti-DoS).
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl LoginRequest {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        if self.username.chars().count() > 255 {
            return Err(ApiError::unprocessable_entity(
                "username must be at most 255 characters",
            ));
        }
        if self.password.chars().count() > 128 {
            return Err(ApiError::unprocessable_entity(
                "password must be at most 128 characters",
            ));
        }
        Ok(())
    }
}

/// `LoginChallengeResponse` — returned by `/login` when a second factor (or
/// first-time setup) is needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginChallengeResponse {
    pub mfa_required: bool,
    pub mfa_setup_required: bool,
    pub challenge_token: String,
    pub methods: Vec<String>,
}

impl LoginChallengeResponse {
    /// Password OK, awaiting TOTP/backup verification (scope `mfa`).
    pub fn mfa_required(challenge_token: String) -> Self {
        Self {
            mfa_required: true,
            mfa_setup_required: false,
            challenge_token,
            methods: vec!["totp".into(), "backup".into()],
        }
    }

    /// Admin must enrol a factor before proceeding (scope `mfa_setup`).
    pub fn mfa_setup_required(challenge_token: String) -> Self {
        Self {
            mfa_required: false,
            mfa_setup_required: true,
            challenge_token,
            methods: vec!["totp".into(), "webauthn".into()],
        }
    }
}

/// `UpdateProfileRequest` (self-service, currently just email).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub email: Option<String>,
}

impl UpdateProfileRequest {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        if let Some(email) = &self.email {
            if email.chars().count() > 320 {
                return Err(ApiError::unprocessable_entity(
                    "email must be at most 320 characters",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::TokenResponse;
    use super::super::LoginResponse;
    use super::*;
    use serde_json::json;

    #[test]
    fn challenge_responses_serialize_all_defaulted_fields() {
        let resp = LoginChallengeResponse::mfa_required("ct".into());
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            json!({
                "mfa_required": true,
                "mfa_setup_required": false,
                "challenge_token": "ct",
                "methods": ["totp", "backup"],
            })
        );
        let setup = LoginChallengeResponse::mfa_setup_required("ct2".into());
        assert_eq!(
            serde_json::to_value(&setup).unwrap(),
            json!({
                "mfa_required": false,
                "mfa_setup_required": true,
                "challenge_token": "ct2",
                "methods": ["totp", "webauthn"],
            })
        );
    }

    #[test]
    fn login_response_is_one_of_the_two_python_shapes() {
        let token = LoginResponse::Token(TokenResponse::new("tok".into(), 3600));
        assert_eq!(
            serde_json::to_value(&token).unwrap(),
            json!({"access_token": "tok", "token_type": "bearer", "expires_in": 3600})
        );
        let challenge = LoginResponse::Challenge(LoginChallengeResponse::mfa_required("ct".into()));
        assert_eq!(
            serde_json::to_value(&challenge).unwrap()["mfa_required"],
            json!(true)
        );
    }

    // ---- request validation (pydantic caps → 422) -------------------------

    #[test]
    fn login_request_bounds() {
        let ok = LoginRequest {
            username: "a".repeat(255),
            password: "p".repeat(128),
        };
        assert!(ok.validate().is_ok());
        let long_name = LoginRequest {
            username: "a".repeat(256),
            password: "p".into(),
        };
        assert!(long_name.validate().is_err());
        let long_pw = LoginRequest {
            username: "a".into(),
            password: "p".repeat(129),
        };
        assert!(long_pw.validate().is_err());
    }

    #[test]
    fn profile_email_is_capped_at_320() {
        assert!(UpdateProfileRequest {
            email: Some("a".repeat(320))
        }
        .validate()
        .is_ok());
        assert!(UpdateProfileRequest {
            email: Some("a".repeat(321))
        }
        .validate()
        .is_err());
        assert!(UpdateProfileRequest::default().validate().is_ok());
    }
}

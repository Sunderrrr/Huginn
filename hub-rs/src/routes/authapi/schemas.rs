//! Wire schemas shared by the auth and users routes
//! (`app/schemas/{auth,user}.py`).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::enums::UserRole;

/// `UserOut` — identical in `app/schemas/auth.py` and `app/schemas/user.py`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserOut {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    #[serde(default)]
    pub vm_ids: Vec<Uuid>,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub passkey_count: i64,
}

/// `TokenResponse` (`token_type` defaults to `"bearer"` in the Python schema).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

impl TokenResponse {
    pub fn new(access_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            token_type: "bearer".to_owned(),
            expires_in,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- UserOut shape ----------------------------------------------------

    #[test]
    fn user_out_serializes_like_the_pydantic_schema() {
        let out = UserOut {
            id: Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
            username: "alice".into(),
            email: None,
            role: UserRole::Admin,
            is_active: true,
            vm_ids: vec![Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap()],
            totp_enabled: true,
            passkey_count: 2,
        };
        assert_eq!(
            serde_json::to_value(&out).unwrap(),
            json!({
                "id": "00000000-0000-4000-8000-000000000001",
                "username": "alice",
                "email": null,
                "role": "admin",
                "is_active": true,
                "vm_ids": ["00000000-0000-4000-8000-000000000002"],
                "totp_enabled": true,
                "passkey_count": 2,
            })
        );
    }

    #[test]
    fn token_response_carries_the_bearer_type() {
        let resp = TokenResponse::new("tok".into(), 3600);
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            json!({"access_token": "tok", "token_type": "bearer", "expires_in": 3600})
        );
    }
}

//! `/api/enrollment-tokens` — port of `hub/app/api/routes/enrollment.py` +
//! the token half of `app/services/enrollment.py`.
//!
//! A token is a limited-use, revocable credential to join the fleet: `label`,
//! `ttl_seconds` (`0` = never expires), `max_uses` (`1` = one-time, `0` =
//! unlimited/reusable) and `auto_approve` (enrolled VMs come up ACTIVE instead
//! of PENDING). The plaintext secret is returned **exactly once**, at creation;
//! only its HMAC is stored (`security::hash_secret`) and the listing never
//! exposes it. Admin only, every mutation audited (`token_create`,
//! `token_revoke`).

use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use super::{
    audit_record, authenticate, enforce_body_size, json_body, path_uuid, peer_addr, AdminState,
    RouteError,
};
use crate::models::enrollment::{EnrollmentToken, EnrollmentTokenNew};

/// 30 days — the `Field(le=30 * 24 * 3600)` bound of `EnrollmentTokenCreate`.
pub const MAX_TTL_SECONDS: i64 = 30 * 24 * 3600;

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/enrollment.py)
// ---------------------------------------------------------------------------

/// `EnrollmentTokenCreate`. Unknown fields are ignored (pydantic's default),
/// which is why the parity harness can POST `{"name": ...}` safely.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentTokenCreate {
    #[serde(default)]
    pub label: String,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: i64,
    #[serde(default = "default_max_uses")]
    pub max_uses: i32,
    #[serde(default)]
    pub auto_approve: bool,
    #[serde(default)]
    pub install_browser: bool,
}

fn default_ttl() -> i64 {
    3600
}

fn default_max_uses() -> i32 {
    1
}

impl EnrollmentTokenCreate {
    pub fn validate(&self) -> Result<(), RouteError> {
        if self.label.chars().count() > 255 {
            return Err(RouteError::unprocessable_entity(
                "label must be at most 255 characters",
            ));
        }
        if !(0..=MAX_TTL_SECONDS).contains(&self.ttl_seconds) {
            return Err(RouteError::unprocessable_entity(format!(
                "ttl_seconds must be between 0 and {MAX_TTL_SECONDS}"
            )));
        }
        if !(0..=1000).contains(&self.max_uses) {
            return Err(RouteError::unprocessable_entity(
                "max_uses must be between 0 and 1000",
            ));
        }
        Ok(())
    }
}

/// `EnrollmentTokenOut` — no secret field, ever.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentTokenOut {
    pub id: Uuid,
    pub label: String,
    pub max_uses: i32,
    pub uses_count: i32,
    pub auto_approve: bool,
    pub install_browser: bool,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<&EnrollmentToken> for EnrollmentTokenOut {
    fn from(token: &EnrollmentToken) -> Self {
        Self {
            id: token.id,
            label: token.label.clone(),
            max_uses: token.max_uses,
            uses_count: token.uses_count,
            auto_approve: token.auto_approve,
            install_browser: token.install_browser,
            expires_at: token.expires_at,
            revoked_at: token.revoked_at,
            created_at: token.created_at,
        }
    }
}

/// `EnrollmentTokenCreated` — the plaintext token, returned exactly once.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentTokenCreated {
    pub id: Uuid,
    pub label: String,
    pub max_uses: i32,
    pub uses_count: i32,
    pub auto_approve: bool,
    pub install_browser: bool,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub token: String,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// The `/api/enrollment-tokens` router (prefix included).
pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/enrollment-tokens", get(list_tokens))
        .route("/api/enrollment-tokens", post(create_token))
        .route("/api/enrollment-tokens/{token_id}", delete(revoke_token))
}

/// `POST /api/enrollment-tokens` — admin only (201, plaintext shown once).
async fn create_token(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<EnrollmentTokenCreate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let body = json_body(body)?;
    body.validate()?;

    let plaintext = crate::security::generate_secret();
    let token = state
        .store
        .create_enrollment_token(EnrollmentTokenNew {
            token_hash: state.security.hash_secret(&plaintext),
            label: body.label.clone(),
            // The service falls back to the nil UUID for a user-less principal.
            created_by: caller
                .principal
                .user
                .as_ref()
                .map(|u| u.id)
                .unwrap_or(Uuid::nil()),
            ttl_seconds: body.ttl_seconds,
            max_uses: body.max_uses,
            auto_approve: body.auto_approve,
            install_browser: body.install_browser,
        })
        .await?;
    audit_record(
        &state,
        &caller,
        "token_create",
        serde_json::json!({
            "token_id": token.id.to_string(),
            "max_uses": body.max_uses,
            "auto_approve": body.auto_approve,
        }),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(EnrollmentTokenCreated {
            id: token.id,
            label: token.label,
            max_uses: token.max_uses,
            uses_count: token.uses_count,
            auto_approve: token.auto_approve,
            install_browser: token.install_browser,
            expires_at: token.expires_at,
            revoked_at: token.revoked_at,
            created_at: token.created_at,
            token: plaintext,
        }),
    ))
}

/// `GET /api/enrollment-tokens` — admin only, newest first (no secrets).
async fn list_tokens(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let tokens = state.store.list_enrollment_tokens().await?;
    Ok(Json(
        tokens
            .iter()
            .map(EnrollmentTokenOut::from)
            .collect::<Vec<_>>(),
    ))
}

/// `DELETE /api/enrollment-tokens/{token_id}` — admin only (204). Revocation
/// is idempotent: an already-revoked token still answers 204.
async fn revoke_token(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(token_id): Path<String>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let token_id = path_uuid(&token_id, "token id")?;

    if state
        .store
        .revoke_enrollment_token(token_id)
        .await?
        .is_none()
    {
        return Err(RouteError::not_found("token not found"));
    }
    audit_record(
        &state,
        &caller,
        "token_revoke",
        serde_json::json!({"token_id": token_id.to_string()}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::super::router;
    use super::super::testing::*;
    use super::*;
    use crate::models::user::User;
    use crate::models::UserRole;

    fn setup() -> (Arc<MockStore>, AdminState, User) {
        let store = Arc::new(MockStore::default());
        let state = test_state(store.clone());
        let admin = seed_user(&store, make_user("admin", UserRole::Admin));
        (store, state, admin)
    }

    fn auth(state: &AdminState, user: &User) -> (&'static str, String) {
        ("authorization", format!("Bearer {}", bearer(state, user)))
    }

    #[tokio::test]
    async fn create_returns_the_secret_exactly_once() {
        let (store, state, admin) = setup();
        let cred = auth(&state, &admin);

        // The parity harness posts `{"name": ...}`: unknown fields are ignored.
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/enrollment-tokens",
            json!({"name": "parity"}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        // Exact shape of EnrollmentTokenCreated.
        let mut keys: Vec<&str> = created
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "auto_approve",
                "created_at",
                "expires_at",
                "id",
                "install_browser",
                "label",
                "max_uses",
                "revoked_at",
                "token",
                "uses_count"
            ]
        );
        assert_eq!(created["label"], json!(""), "unknown `name` field ignored");
        assert_eq!(created["max_uses"], json!(1), "one-time by default");
        assert_eq!(created["uses_count"], json!(0));
        assert_eq!(created["auto_approve"], json!(false));
        assert!(created["revoked_at"].is_null());
        let plaintext = created["token"].as_str().unwrap().to_owned();
        assert!(!plaintext.is_empty());
        let id = created["id"].as_str().unwrap().to_owned();

        // The listing shows the token but never its secret.
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/enrollment-tokens",
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = body_json(response).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        let row = &listed[0];
        assert_eq!(row["id"], json!(id));
        assert!(row.get("token").is_none(), "plaintext must not be listed");
        assert!(
            row.get("token_hash").is_none(),
            "the HMAC must not be listed"
        );

        // Only the row's HMAC is stored — never the plaintext.
        let db = store.db.lock().unwrap();
        let stored = db.enrollment_tokens.values().next().unwrap();
        assert_ne!(stored.token_hash, plaintext);
        assert_eq!(stored.token_hash.len(), 64, "keyed HMAC-SHA256, hex");
    }

    #[tokio::test]
    async fn reusable_and_auto_approve_tokens() {
        let (_store, state, admin) = setup();
        let cred = auth(&state, &admin);

        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/enrollment-tokens",
            json!({"label": "ansible", "ttl_seconds": 0, "max_uses": 0, "auto_approve": true}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        assert_eq!(created["label"], json!("ansible"));
        assert_eq!(created["max_uses"], json!(0), "0 = unlimited uses");
        assert_eq!(created["auto_approve"], json!(true));
        assert!(created["expires_at"].is_string(), "0 ttl → far future");
    }

    #[tokio::test]
    async fn create_validates_bounds() {
        let (_store, state, admin) = setup();
        let cred = auth(&state, &admin);
        for (body, note) in [
            (json!({"ttl_seconds": -1}), "negative ttl"),
            (
                json!({"ttl_seconds": MAX_TTL_SECONDS + 1}),
                "ttl over 30 days",
            ),
            (json!({"max_uses": -1}), "negative uses"),
            (json!({"max_uses": 1001}), "over 1000 uses"),
            (json!({"label": "x".repeat(256)}), "long label"),
        ] {
            let app = router(state.clone());
            let request = json_request_with(
                "POST",
                "/api/enrollment-tokens",
                body,
                std::slice::from_ref(&cred),
            );
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{note}"
            );
        }
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_404s_on_unknown_ids() {
        let (store, state, admin) = setup();
        let cred = auth(&state, &admin);

        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/enrollment-tokens",
            json!({"label": "fleet"}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        let id = body_json(response).await["id"].as_str().unwrap().to_owned();

        // Revoke → 204, and again → still 204 (idempotent).
        for _ in 0..2 {
            let app = router(state.clone());
            let request = json_request_with(
                "DELETE",
                &format!("/api/enrollment-tokens/{id}"),
                serde_json::Value::Null,
                std::slice::from_ref(&cred),
            );
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        // Unknown id → 404.
        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/enrollment-tokens/{}", Uuid::new_v4()),
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "token not found"})
        );

        let db = store.db.lock().unwrap();
        let events: Vec<&str> = db.audit.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(events, vec!["token_create", "token_revoke", "token_revoke"]);
    }

    #[tokio::test]
    async fn enrollment_tokens_are_admin_only() {
        let (store, state, _admin) = setup();
        let operator = seed_user(&store, make_user("op", UserRole::Operator));
        for (method, path, body) in [
            (
                "GET",
                "/api/enrollment-tokens".to_owned(),
                serde_json::Value::Null,
            ),
            ("POST", "/api/enrollment-tokens".to_owned(), json!({})),
            (
                "DELETE",
                format!("/api/enrollment-tokens/{}", Uuid::new_v4()),
                serde_json::Value::Null,
            ),
        ] {
            let app = router(state.clone());
            let request = json_request_with(method, &path, body, &[auth(&state, &operator)]);
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
            assert_eq!(
                body_json(response).await,
                json!({"detail": "admin role required"})
            );
        }
    }
}

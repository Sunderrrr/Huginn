//! User management endpoints (admin only) — port of
//! `hub/app/api/routes/users.py`.

use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::audit::AuditNew;
use crate::models::enums::{ActorType, UserRole};
use crate::models::user::{User, UserNew, UserPatch};
use crate::security;

use super::{
    client_ip, db_err, get_principal, map_json_rejection, peer_addr, record_audit, require_admin,
    user_out, user_out_vms_only, AuthState, UserOut,
};

pub fn router() -> Router<AuthState> {
    Router::new()
        .route("/api/users", get(list_users).post(create_user))
        .route(
            "/api/users/{user_id}",
            get(get_user).put(update_user).delete(deactivate_user),
        )
        .route("/api/users/{user_id}/password", put(change_password))
        .route("/api/users/{user_id}/mfa/reset", post(reset_user_mfa))
        .route("/api/users/{user_id}/vms", put(set_user_vms))
}

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/user.py)
// ---------------------------------------------------------------------------

/// `UserCreate`.
#[derive(Debug, Clone, Deserialize)]
pub struct UserCreate {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role: UserRole,
    #[serde(default)]
    pub vm_ids: Vec<Uuid>,
}

impl UserCreate {
    fn validate(&self) -> Result<(), ApiError> {
        if self.username.is_empty() {
            return Err(ApiError::unprocessable_entity(
                "username must be at least 1 character",
            ));
        }
        if self.username.chars().count() > 255 {
            return Err(ApiError::unprocessable_entity(
                "username must be at most 255 characters",
            ));
        }
        let len = self.password.chars().count();
        if len < 12 {
            return Err(ApiError::unprocessable_entity(
                "password must be at least 12 characters",
            ));
        }
        if len > 128 {
            return Err(ApiError::unprocessable_entity(
                "password must be at most 128 characters",
            ));
        }
        Ok(())
    }
}

/// `UserUpdate` (`None` = leave untouched).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserUpdate {
    #[serde(default)]
    pub role: Option<UserRole>,
    #[serde(default)]
    pub is_active: Option<bool>,
    #[serde(default)]
    pub email: Option<String>,
}

/// `PasswordChange` — `old_password` is required for self-change, optional for
/// an admin reset.
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordChange {
    #[serde(default)]
    pub old_password: Option<String>,
    pub new_password: String,
}

impl PasswordChange {
    fn validate(&self) -> Result<(), ApiError> {
        let len = self.new_password.chars().count();
        if len < 12 {
            return Err(ApiError::unprocessable_entity(
                "new_password must be at least 12 characters",
            ));
        }
        if len > 128 {
            return Err(ApiError::unprocessable_entity(
                "new_password must be at most 128 characters",
            ));
        }
        Ok(())
    }
}

/// `UserVmAccessUpdate`.
#[derive(Debug, Clone, Deserialize)]
pub struct UserVmAccessUpdate {
    pub vm_ids: Vec<Uuid>,
}

/// Query of `POST /api/users/{user_id}/mfa/reset`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResetMfaQuery {
    #[serde(default)]
    pub include_passkeys: bool,
}

/// Path shape validation before anything else (FastAPI validates params).
fn parse_user_id(raw: &str) -> Result<Uuid, ApiError> {
    raw.parse()
        .map_err(|_| ApiError::unprocessable_entity("user_id must be a valid UUID"))
}

// ---------------------------------------------------------------------------
// Pure update semantics (users.update_user's change tracking)
// ---------------------------------------------------------------------------

/// Compute the column patch and the audit `detail` of `update_user`. Only
/// `role`/`is_active` are tracked in `changes` (the Python handler audits those
/// and silently applies `email`) — an email-only update records nothing.
fn user_update_effect(user: &User, body: &UserUpdate) -> (UserPatch, Option<serde_json::Value>) {
    let mut patch = UserPatch::default();
    let mut changes = serde_json::Map::new();
    if let Some(role) = body.role {
        changes.insert(
            "role".into(),
            serde_json::json!({"old": user.role.as_str(), "new": role.as_str()}),
        );
        patch.role = Some(role);
    }
    if let Some(is_active) = body.is_active {
        changes.insert(
            "is_active".into(),
            serde_json::json!({"old": user.is_active, "new": is_active}),
        );
        patch.is_active = Some(is_active);
    }
    if body.email.is_some() {
        patch.email = body.email.clone();
    }
    let detail = if changes.is_empty() {
        None
    } else {
        let mut detail = serde_json::Map::new();
        detail.insert("user_id".into(), serde_json::json!(user.id.to_string()));
        detail.extend(changes);
        Some(serde_json::Value::Object(detail))
    };
    (patch, detail)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/users` — all users, oldest first.
async fn list_users(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Json<Vec<UserOut>>, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    require_admin(&principal)?;
    let users = crate::models::user::list_users(&state.pool)
        .await
        .map_err(db_err)?;
    let mut out = Vec::with_capacity(users.len());
    for user in &users {
        out.push(user_out(&state, user).await?);
    }
    Ok(Json(out))
}

/// `POST /api/users` — create a user (201).
async fn create_user(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<UserCreate>, JsonRejection>,
) -> Result<(StatusCode, Json<UserOut>), ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    require_admin(&principal)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;

    let existing = crate::models::user::get_by_username(&state.pool, &body.username)
        .await
        .map_err(db_err)?;
    if existing.is_some() {
        return Err(ApiError::conflict("username already exists"));
    }
    let password_hash =
        security::hash_password(&body.password).map_err(|e| ApiError::internal(e.to_string()))?;
    let new = UserNew {
        username: body.username.clone(),
        email: body.email.clone(),
        password_hash: Some(password_hash),
        role: body.role,
        is_active: true,
        ..UserNew::default()
    };
    let user = crate::models::user::create(&state.pool, new)
        .await
        .map_err(|e| {
            // A concurrent create can still hit the unique index.
            if e.is_unique_violation() {
                ApiError::conflict("username already exists")
            } else {
                db_err(e)
            }
        })?;

    if !body.vm_ids.is_empty() {
        crate::models::user::replace_vm_access(&state.pool, user.id, &body.vm_ids)
            .await
            .map_err(db_err)?;
    }

    let mut new = AuditNew::new(ActorType::User, principal.actor_id.clone(), "user_created");
    new.detail = serde_json::json!({"username": user.username, "role": user.role.as_str()});
    record_audit(
        &state,
        new,
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(user_out_vms_only(&state, &user).await?),
    ))
}

/// `GET /api/users/{user_id}`.
async fn get_user(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(user_id): Path<String>,
) -> Result<Json<UserOut>, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    require_admin(&principal)?;
    let user_id = parse_user_id(&user_id)?;
    let user = get_user_or_404(&state, user_id).await?;
    Ok(Json(user_out(&state, &user).await?))
}

/// `PUT /api/users/{user_id}` — update role / is_active / email.
async fn update_user(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(user_id): Path<String>,
    body: Result<Json<UserUpdate>, JsonRejection>,
) -> Result<Json<UserOut>, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    require_admin(&principal)?;
    let user_id = parse_user_id(&user_id)?;
    let body = body.map_err(map_json_rejection)?.0;
    let user = get_user_or_404(&state, user_id).await?;
    // M-5: demoting or deactivating the last admin would lock the fleet out.
    if strips_admin(&user, &body) {
        ensure_not_last_admin(&state).await?;
    }
    let (patch, detail) = user_update_effect(&user, &body);
    let user = crate::models::user::update(&state.pool, user.id, patch)
        .await
        .map_err(db_err)?
        .unwrap_or(user);
    if let Some(detail) = detail {
        let mut new = AuditNew::new(ActorType::User, principal.actor_id.clone(), "user_updated");
        new.detail = detail;
        record_audit(
            &state,
            new,
            client_ip(&headers, &state.config, peer_addr(peer)),
        )
        .await?;
    }
    Ok(Json(user_out_vms_only(&state, &user).await?))
}

/// `DELETE /api/users/{user_id}` — soft-deactivate (204).
async fn deactivate_user(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(user_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    require_admin(&principal)?;
    let user_id = parse_user_id(&user_id)?;
    let user = get_user_or_404(&state, user_id).await?;
    if user.id.to_string() == principal.actor_id {
        return Err(ApiError::bad_request("cannot deactivate yourself"));
    }
    // M-5: deactivating the last admin would lock the fleet out (defense in
    // depth — the self-check above already covers the single-admin case).
    if user.role == UserRole::Admin {
        ensure_not_last_admin(&state).await?;
    }
    crate::models::user::update(
        &state.pool,
        user.id,
        UserPatch {
            is_active: Some(false),
            ..UserPatch::default()
        },
    )
    .await
    .map_err(db_err)?;
    let mut new = AuditNew::new(
        ActorType::User,
        principal.actor_id.clone(),
        "user_deactivated",
    );
    new.detail = serde_json::json!({"user_id": user_id.to_string()});
    record_audit(
        &state,
        new,
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/users/{user_id}/password` — self-change (old password required)
/// or admin reset.
async fn change_password(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(user_id): Path<String>,
    body: Result<Json<PasswordChange>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    let user_id = parse_user_id(&user_id)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    let user = get_user_or_404(&state, user_id).await?;

    // Self-change requires old_password; admin reset does not.
    let is_self = principal.user.as_ref().map(|u| u.id) == Some(user_id);
    if is_self {
        let Some(old_password) = body.old_password.as_deref().filter(|s| !s.is_empty()) else {
            return Err(ApiError::bad_request(
                "old_password required for self-change",
            ));
        };
        if !security::verify_password(old_password, user.password_hash.as_deref()) {
            return Err(ApiError::bad_request("incorrect old password"));
        }
    } else if !principal.is_admin() {
        return Err(ApiError::forbidden(
            "admin role required to reset other passwords",
        ));
    }

    let password_hash = security::hash_password(&body.new_password)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    crate::models::user::update_password(&state.pool, user.id, Some(&password_hash))
        .await
        .map_err(db_err)?;
    let actor_id = principal
        .user
        .as_ref()
        .map(|u| u.id.to_string())
        .unwrap_or_else(|| "unknown".into());
    let mut new = AuditNew::new(ActorType::User, actor_id, "password_changed");
    new.detail = serde_json::json!({"user_id": user_id.to_string(), "self": is_self});
    record_audit(
        &state,
        new,
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// `POST /api/users/{user_id}/mfa/reset` — clear a locked-out user's TOTP (and
/// optionally their passkeys). Only ever removes factors, so it cannot brick an
/// account.
async fn reset_user_mfa(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(user_id): Path<String>,
    Query(query): Query<ResetMfaQuery>,
) -> Result<Json<UserOut>, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    require_admin(&principal)?;
    let user_id = parse_user_id(&user_id)?;
    let user = get_user_or_404(&state, user_id).await?;

    // `disable_mfa` returns the refreshed row (TOTP fields cleared) — the
    // response mirrors the Python handler's mutated `user` instance.
    let user = crate::models::user::disable_mfa(&state.pool, user.id)
        .await
        .map_err(db_err)?
        .unwrap_or(user);
    crate::models::webauthn::delete_backup_codes(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    if query.include_passkeys {
        crate::models::webauthn::delete_credentials_for_user(&state.pool, user.id)
            .await
            .map_err(db_err)?;
    }

    let mut new = AuditNew::new(
        ActorType::User,
        principal.actor_id.clone(),
        "admin_mfa_reset",
    );
    new.detail = serde_json::json!({
        "user_id": user_id.to_string(),
        "include_passkeys": query.include_passkeys,
    });
    record_audit(
        &state,
        new,
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(Json(user_out(&state, &user).await?))
}

/// `PUT /api/users/{user_id}/vms` — replace the user's VM access set.
async fn set_user_vms(
    State(state): State<AuthState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(user_id): Path<String>,
    body: Result<Json<UserVmAccessUpdate>, JsonRejection>,
) -> Result<Json<UserOut>, ApiError> {
    let principal = get_principal(&state, &headers, peer_addr(peer)).await?;
    require_admin(&principal)?;
    let user_id = parse_user_id(&user_id)?;
    let body = body.map_err(map_json_rejection)?.0;
    let user = get_user_or_404(&state, user_id).await?;

    crate::models::user::replace_vm_access(&state.pool, user.id, &body.vm_ids)
        .await
        .map_err(db_err)?;
    let mut new = AuditNew::new(
        ActorType::User,
        principal.actor_id.clone(),
        "user_vm_access_changed",
    );
    new.detail = serde_json::json!({
        "user_id": user_id.to_string(),
        "vm_count": body.vm_ids.len(),
    });
    record_audit(
        &state,
        new,
        client_ip(&headers, &state.config, peer_addr(peer)),
    )
    .await?;
    Ok(Json(user_out_vms_only(&state, &user).await?))
}

/// `users._get_user_or_404`.
async fn get_user_or_404(state: &AuthState, user_id: Uuid) -> Result<User, ApiError> {
    let user = crate::models::user::get_by_id(&state.pool, user_id)
        .await
        .map_err(db_err)?;
    user.ok_or_else(|| ApiError::not_found("user not found"))
}

// ---------------------------------------------------------------------------
// M-5: last-admin guard
// ---------------------------------------------------------------------------

/// Whether this update strips the target's admin capability — a role drop to
/// operator/readonly or a deactivation (`is_active: false`).
fn strips_admin(user: &User, body: &UserUpdate) -> bool {
    user.role == UserRole::Admin
        && (body.role.is_some_and(|r| r != UserRole::Admin) || body.is_active == Some(false))
}

/// Refuse to demote or deactivate the only admin — the fleet would be locked
/// out of every admin operation (user management, settings, enrollment).
/// `count_admins` counts every admin row, so more than one must remain for
/// the change to go through.
async fn ensure_not_last_admin(state: &AuthState) -> Result<(), ApiError> {
    let admins = crate::models::user::count_admins(&state.pool)
        .await
        .map_err(db_err)?;
    if admins <= 1 {
        return Err(ApiError::bad_request(
            "cannot demote/deactivate the last admin",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::authapi::support::{sample_user, test_state};
    use axum::body::Body;
    use serde_json::json;
    use tower::ServiceExt;

    #[test]
    fn user_create_bounds_match_the_pydantic_fields() {
        let ok = UserCreate {
            username: "alice".into(),
            password: "p".repeat(12),
            email: None,
            role: UserRole::Readonly,
            vm_ids: vec![],
        };
        assert!(ok.validate().is_ok());

        let mut bad = UserCreate {
            username: String::new(),
            ..ok.clone()
        };
        assert!(bad.validate().is_err());
        bad.username = "a".repeat(256);
        assert!(bad.validate().is_err());

        bad = UserCreate {
            password: "short".into(),
            ..ok.clone()
        };
        assert!(bad.validate().is_err());
        bad = UserCreate {
            password: "p".repeat(129),
            ..ok
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn password_change_bounds() {
        assert!(PasswordChange {
            old_password: None,
            new_password: "p".repeat(12)
        }
        .validate()
        .is_ok());
        assert!(PasswordChange {
            old_password: Some("old".into()),
            new_password: "p".repeat(11)
        }
        .validate()
        .is_err());
        assert!(PasswordChange {
            old_password: None,
            new_password: "p".repeat(129)
        }
        .validate()
        .is_err());
    }

    #[test]
    fn update_effect_tracks_role_and_active_but_not_email() {
        let mut user = sample_user(UserRole::Readonly);

        // Role + is_active changes produce the Python `changes` detail.
        let body = UserUpdate {
            role: Some(UserRole::Admin),
            is_active: Some(false),
            email: None,
        };
        let (patch, detail) = user_update_effect(&user, &body);
        assert_eq!(patch.role, Some(UserRole::Admin));
        assert_eq!(patch.is_active, Some(false));
        assert_eq!(
            detail.unwrap(),
            json!({
                "user_id": user.id.to_string(),
                "role": {"old": "readonly", "new": "admin"},
                "is_active": {"old": true, "new": false},
            })
        );

        // Email-only updates record nothing (Python quirk, kept).
        let body = UserUpdate {
            role: None,
            is_active: None,
            email: Some("new@example.com".into()),
        };
        let (patch, detail) = user_update_effect(&user, &body);
        assert_eq!(patch.email.as_deref(), Some("new@example.com"));
        assert!(detail.is_none());

        // No fields → empty patch, no audit.
        let (patch, detail) = user_update_effect(&user, &UserUpdate::default());
        assert_eq!(patch.role, None);
        assert_eq!(patch.is_active, None);
        assert_eq!(patch.email, None);
        assert!(detail.is_none());

        user.role = UserRole::Operator;
        let body = UserUpdate {
            role: Some(UserRole::Admin),
            is_active: None,
            email: None,
        };
        let (_, detail) = user_update_effect(&user, &body);
        assert_eq!(
            detail.unwrap()["role"],
            json!({"old": "operator", "new": "admin"})
        );
    }

    #[tokio::test]
    async fn users_routes_require_authentication_first() {
        let response = crate::routes::authapi::router(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Dependencies run before body validation: 401 even for a bad body.
        let response = crate::routes::authapi::router(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"username": "a"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- M-5: last-admin guard ---------------------------------------------

    #[test]
    fn strips_admin_covers_role_drop_and_deactivation() {
        let admin = sample_user(UserRole::Admin);

        // Nothing changes → no guard.
        assert!(!strips_admin(
            &admin,
            &UserUpdate {
                role: None,
                is_active: None,
                email: None
            }
        ));
        assert!(!strips_admin(
            &admin,
            &UserUpdate {
                role: Some(UserRole::Admin),
                is_active: Some(true),
                email: None
            }
        ));
        // Role drop or deactivation of an admin → guard.
        assert!(strips_admin(
            &admin,
            &UserUpdate {
                role: Some(UserRole::Operator),
                is_active: None,
                email: None
            }
        ));
        assert!(strips_admin(
            &admin,
            &UserUpdate {
                role: Some(UserRole::Readonly),
                is_active: None,
                email: None
            }
        ));
        assert!(strips_admin(
            &admin,
            &UserUpdate {
                role: None,
                is_active: Some(false),
                email: None
            }
        ));
        // Non-admin targets never trip the guard.
        let operator = sample_user(UserRole::Operator);
        assert!(!strips_admin(
            &operator,
            &UserUpdate {
                role: Some(UserRole::Readonly),
                is_active: Some(false),
                email: None
            }
        ));
    }

    /// End-to-end exercise of the M-5 guard against a live PostgreSQL
    /// (skipped unless `HUGINN_TEST_DATABASE_URL` is set).
    #[tokio::test]
    async fn the_last_admin_cannot_be_demoted_or_deactivated() {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return;
        };
        let guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = crate::db::connect(&url, 4).await.expect("connect");
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(&pool)
            .await
            .expect("drop schema");
        sqlx::query("CREATE SCHEMA public")
            .execute(&pool)
            .await
            .expect("create schema");
        crate::db::run_migrations(&pool).await.expect("migrations");

        // The route state shares the migrated pool.
        let state = AuthState::new(pool.clone(), crate::config::Config::default());
        let make_admin = |username: &str| crate::models::user::UserNew {
            username: username.into(),
            password_hash: Some("h".into()),
            role: UserRole::Admin,
            is_active: true,
            ..Default::default()
        };
        let solo = crate::models::user::create(&pool, make_admin("solo")).await.unwrap();
        let token = state
            .security
            .jwt()
            .create_access_token(&solo.id.to_string(), "admin", 60)
            .unwrap();
        let request = |method: &str, user_id: uuid::Uuid, body: serde_json::Value| {
            axum::http::Request::builder()
                .method(method)
                .uri(format!("/api/users/{user_id}"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(if body.is_null() {
                    String::new()
                } else {
                    body.to_string()
                }))
                .unwrap()
        };
        async fn send(
            state: &AuthState,
            request: axum::http::Request<Body>,
        ) -> (StatusCode, serde_json::Value) {
            let response = crate::routes::authapi::router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let status = response.status();
            let bytes = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or(json!(null)),
            )
        }

        // One admin: self-demotion, self-deactivation via PUT are refused…
        for body in [
            json!({"role": "operator"}),
            json!({"is_active": false}),
        ] {
            let (status, resp) = send(&state, request("PUT", solo.id, body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(resp, json!({"detail": "cannot demote/deactivate the last admin"}));
        }
        // …and the admin row is still an active admin.
        let still = crate::models::user::get_by_id(&pool, solo.id)
            .await
            .unwrap()
            .unwrap();
        assert!(still.is_admin() && still.is_active);

        // A second admin: demotion and deactivation now go through.
        let second = crate::models::user::create(&pool, make_admin("second"))
            .await
            .unwrap();
        let (status, resp) = send(&state, request("PUT", second.id, json!({"role": "readonly"}))).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        assert_eq!(resp["role"], json!("readonly"));
        let (status, _) = send(&state, request("DELETE", second.id, json!(null))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Back to one admin: the guard fires again.
        let (status, resp) = send(&state, request("PUT", solo.id, json!({"role": "readonly"}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp, json!({"detail": "cannot demote/deactivate the last admin"}));

        drop(guard);
    }
}

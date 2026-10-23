//! Session revocation against a live PostgreSQL (audit finding F-08).
//!
//! The hub re-reads the user on every request; the `session_epoch` counter
//! is what turns "the credential was rotated" into "the sessions opened with
//! it are dead". These tests pin the behaviour: a logout, a password change
//! and an MFA reset each invalidate the tokens issued before them.
//!
//! Skipped unless `HUGINN_TEST_DATABASE_URL` is set.
use crate::config::Config;
use crate::models::enums::UserRole;
use crate::models::user::UserNew;
use crate::routes::authapi::AuthState;
use axum::body::Body;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery";

/// A clean database with the authapi router mounted.
async fn fresh_state() -> Option<(AuthState, tokio::sync::MutexGuard<'static, ()>)> {
    let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
        eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
        return None;
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
    let config = Config {
        // These tests are about the session epoch, not the second factor:
        // without it the login would answer `mfa_setup_required` instead of
        // an access token.
        require_admin_mfa: false,
        ..Config::default()
    };
    Some((AuthState::new(pool, config), guard))
}

async fn make_admin(state: &AuthState) -> Uuid {
    crate::models::user::create(
        &state.pool,
        UserNew {
            username: "admin".into(),
            password_hash: Some(crate::security::hash_password(PASSWORD).unwrap()),
            role: UserRole::Admin,
            is_active: true,
            ..UserNew::default()
        },
    )
    .await
    .unwrap()
    .id
}

fn request(
    method: &str,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> axum::http::Request<Body> {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

/// Log in and return the access token.
async fn login(state: &AuthState) -> String {
    let app = crate::routes::authapi::router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        request(
            "POST",
            "/api/auth/login",
            json!({"username": "admin", "password": PASSWORD}),
            None,
        ),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The status the API answers for `GET /api/auth/me` with this token.
async fn me_status(state: &AuthState, token: &str) -> StatusCode {
    let app = crate::routes::authapi::router(state.clone());
    let response =
        tower::ServiceExt::oneshot(app, request("GET", "/api/auth/me", json!({}), Some(token)))
            .await
            .unwrap();
    response.status()
}

#[tokio::test]
async fn a_token_works_until_the_session_is_revoked() {
    let Some((state, _guard)) = fresh_state().await else {
        return;
    };
    make_admin(&state).await;

    let token = login(&state).await;
    assert_eq!(me_status(&state, &token).await, StatusCode::OK);

    // Logging out ends the session for real: the epoch is bumped, so the
    // token that just authenticated is refused from now on.
    let app = crate::routes::authapi::router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        request("POST", "/api/auth/logout", json!({}), Some(&token)),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert_eq!(me_status(&state, &token).await, StatusCode::UNAUTHORIZED);

    // A new login works and carries the new epoch.
    let fresh = login(&state).await;
    assert_eq!(me_status(&state, &fresh).await, StatusCode::OK);
}

#[tokio::test]
async fn a_password_change_revokes_the_sessions_opened_with_the_old_one() {
    let Some((state, _guard)) = fresh_state().await else {
        return;
    };
    let user_id = make_admin(&state).await;

    let token = login(&state).await;
    assert_eq!(me_status(&state, &token).await, StatusCode::OK);

    // The user rotates their own password (old password required).
    let app = crate::routes::authapi::router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        request(
            "PUT",
            &format!("/api/users/{user_id}/password"),
            json!({"old_password": PASSWORD, "new_password": "a brand new passphrase"}),
            Some(&token),
        ),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The token issued with the old password is dead.
    assert_eq!(me_status(&state, &token).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_mfa_reset_revokes_the_sessions_opened_with_the_factor() {
    let Some((state, _guard)) = fresh_state().await else {
        return;
    };
    let user_id = make_admin(&state).await;

    let token = login(&state).await;
    assert_eq!(me_status(&state, &token).await, StatusCode::OK);

    // An admin resets the factors of the account (the compromised-factor
    // case): the sessions opened with it must die too.
    let app = crate::routes::authapi::router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        request(
            "POST",
            &format!("/api/users/{user_id}/mfa/reset"),
            json!({"include_passkeys": false}),
            Some(&token),
        ),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(me_status(&state, &token).await, StatusCode::UNAUTHORIZED);
}

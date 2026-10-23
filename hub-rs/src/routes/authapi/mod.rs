//! Authentication, MFA and user management — the `/api/auth` + `/api/users`
//! surface, ported from `hub/app/api/routes/{auth,mfa,users}.py` with the
//! request-authentication dependencies of `hub/app/api/deps.py`.
//!
//! | route                                              | Python handler            |
//! |----------------------------------------------------|---------------------------|
//! | `GET  /api/auth/config`                            | `auth_config`             |
//! | `POST /api/auth/login`                             | `login`                   |
//! | `GET/PUT /api/auth/me`                             | `me` / `update_me`        |
//! | `POST /api/auth/logout`                            | `logout`                  |
//! | `POST /api/auth/mfa/verify`                        | `verify_mfa`              |
//! | `POST /api/auth/mfa/totp/enroll/begin`             | `totp_enroll_begin`       |
//! | `POST /api/auth/mfa/totp/enroll/finish`            | `totp_enroll_finish`      |
//! | `POST /api/auth/mfa/totp/disable`                  | `totp_disable`            |
//! | `POST /api/auth/mfa/totp/backup-codes/regenerate`  | `regenerate_backup_codes` |
//! | `POST /api/auth/mfa/webauthn/register/begin`       | `webauthn_register_begin` |
//! | `POST /api/auth/mfa/webauthn/register/finish`      | `webauthn_register_finish` |
//! | `POST /api/auth/mfa/webauthn/login/begin`          | `webauthn_login_begin` |
//! | `POST /api/auth/mfa/webauthn/login/finish`         | `webauthn_login_finish` |
//! | `GET  /api/auth/mfa/webauthn/credentials`          | `list_passkeys`           |
//! | `PUT  /api/auth/mfa/webauthn/credentials/{cred_id}` | `rename_passkey`         |
//! | `DELETE /api/auth/mfa/webauthn/credentials/{cred_id}` | `delete_passkey`       |
//! | `GET/POST /api/users`                              | `list_users` / `create_user` |
//! | `GET/PUT/DELETE /api/users/{user_id}`              | `get_user` / `update_user` / `deactivate_user` |
//! | `PUT  /api/users/{user_id}/password`               | `change_password`         |
//! | `POST /api/users/{user_id}/mfa/reset`              | `reset_user_mfa`          |
//! | `PUT  /api/users/{user_id}/vms`                    | `set_user_vms`            |
//!
//! Two-step login works like the Python hub: `POST /api/auth/login` validates
//! the password and, when a second factor is required, returns a short-lived
//! *challenge token* (scope `mfa`) instead of an access token. Admins without
//! any factor get an `mfa_setup` token. [`get_principal`] REJECTS these scoped
//! tokens for the business API, so they are only ever usable on the MFA routes.
//!
//! All authentication methods are ported: passwords, TOTP + backup codes,
//! WebAuthn ceremonies (see `services/webauthn.rs`), OIDC/SSO
//! (`services/oidc.rs`) and the LDAP login fallback (`services/ldap.rs`).

pub mod auth;
pub mod mfa;
pub mod users;

use axum::extract::DefaultBodyLimit;
use axum::Router;

use crate::config::Config;
use crate::security::SecurityConfig;

use std::time::Duration;

/// How many failed password attempts a single account may accumulate inside
/// [`LOGIN_ACCOUNT_WINDOW`] before the login endpoint throttles it. The
/// per-IP window (5/minute) stays the fast path; this is the backstop against
/// a distributed guess run.
pub(crate) const LOGIN_ACCOUNT_MAX_FAILURES: u32 = 20;
/// The window of the per-account login guard.
pub(crate) const LOGIN_ACCOUNT_WINDOW: Duration = Duration::from_secs(5 * 60);

// ---------------------------------------------------------------------------
// State + router
// ---------------------------------------------------------------------------

/// Everything the auth/users routes need. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AuthState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub security: SecurityConfig,
    /// Per-IP brute-force guard on login (5 attempts/minute — `auth._login_limiter`).
    pub login_limiter: RateLimiter,
    /// Per-ACCOUNT brute-force guard on login (20 failures / 5 minutes).
    ///
    /// The per-IP window alone does not bound password guessing against a
    /// single account: an attacker with many source addresses (a botnet, an
    /// IPv6 range) gets a fresh budget per address. This second window is
    /// keyed by the *username* and counts the same failures, so the guess
    /// rate against one account stays bounded no matter where the requests
    /// come from. It counts failures for unknown accounts too, so it never
    /// becomes a user-enumeration oracle.
    pub login_account_limiter: RateLimiter,
    /// Per-IP/per-user guard on MFA verification (10/minute — `mfa._verify_limiter`).
    pub verify_limiter: RateLimiter,
    /// Per-IP guard on the WebAuthn endpoints (20/minute — `mfa._webauthn_limiter`).
    pub webauthn_limiter: RateLimiter,
    /// Per-IP guard on the OIDC start/callback endpoints (10/minute — `auth._oidc_limiter`).
    pub oidc_limiter: RateLimiter,
    /// Per-principal guard on execution endpoints (`deps._exec_limiter`).
    pub exec_limiter: RateLimiter,
}

impl AuthState {
    pub fn new(pool: sqlx::PgPool, config: Config) -> Self {
        let security = SecurityConfig::new(
            &config.mfa_encryption_key,
            &config.jwt_secret,
            &config.secret_hash_key,
        );
        Self {
            login_limiter: RateLimiter::new(5),
            login_account_limiter: RateLimiter::new_with_window(
                LOGIN_ACCOUNT_MAX_FAILURES,
                LOGIN_ACCOUNT_WINDOW,
            ),
            verify_limiter: RateLimiter::new(10),
            webauthn_limiter: RateLimiter::new(20),
            oidc_limiter: RateLimiter::new(10),
            exec_limiter: RateLimiter::new(config.rate_limit_exec_per_minute),
            pool,
            config,
            security,
        }
    }
}

/// The `/api/auth` + `/api/users` router (prefixes included, merge as-is).
pub fn router(state: AuthState) -> Router {
    let body_cap = state.config.max_body_bytes;
    auth::router()
        .merge(mfa::router())
        .merge(users::router())
        .layer(DefaultBodyLimit::max(body_cap))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Submodules — plumbing split by function
// ---------------------------------------------------------------------------

mod middleware;
mod principal;
mod schemas;
mod service;

pub(crate) use middleware::map_json_rejection;
pub use middleware::{client_ip, peer_addr, RateLimiter};
pub(crate) use principal::{challenge_user, enrolling_actor};
pub use principal::{get_principal, require_admin};
pub use schemas::{TokenResponse, UserOut};
pub(crate) use service::{
    authenticate, backup_code_hash, db_err, decrypt_totp_secret, encrypt_totp_secret,
    generate_backup_codes, purge_expired_webauthn_challenges, record_audit,
    set_pending_totp_secret, set_user_email, token_response, user_out, user_out_vms_only,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod support {
    use super::*;
    use uuid::Uuid;

    use crate::models::enums::UserRole;
    use crate::models::user::User;

    /// A minimal `User` row for unit tests.
    pub(crate) fn sample_user(role: UserRole) -> User {
        User {
            id: Uuid::new_v4(),
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            password_hash: Some(crate::security::hash_password("correct horse battery").unwrap()),
            oidc_subject: None,
            ldap_dn: None,
            role,
            is_active: true,
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            totp_secret_enc: None,
            totp_enabled: false,
            totp_confirmed_at: None,
            totp_last_step: None,
        }
    }

    /// A state wired to a lazy pool: only paths that never touch the database
    /// can be exercised through it (any query fails fast).
    pub(crate) fn test_state() -> AuthState {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        AuthState::new(pool, Config::default())
    }
}

#[cfg(test)]
mod live_tests {
    //! End-to-end exercise of the auth/MFA/users routes against a live
    //! PostgreSQL (skipped unless `HUGINN_TEST_DATABASE_URL` is set — `cargo
    //! test` stays green without a database, like `db.rs`/`models::live_tests`).

    use super::*;
    use crate::models::enums::UserRole;
    use crate::models::user::UserNew;
    use axum::body::Body;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;
    use uuid::Uuid;

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
        Some((AuthState::new(pool, Config::default()), guard))
    }

    async fn make_user(state: &AuthState, username: &str, password: &str, role: UserRole) -> Uuid {
        let password_hash = crate::security::hash_password(password).unwrap();
        crate::models::user::create(
            &state.pool,
            UserNew {
                username: username.into(),
                password_hash: Some(password_hash),
                role,
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
        request_from(method, uri, body, token, None)
    }

    /// Same as [`request`] but with an explicit `X-Forwarded-For` (the
    /// deployment behind the bundled proxy stamps the real client IP there).
    fn request_from(
        method: &str,
        uri: &str,
        body: serde_json::Value,
        token: Option<&str>,
        forwarded_for: Option<&str>,
    ) -> axum::http::Request<Body> {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if !body.is_null() {
            builder = builder.header("content-type", "application/json");
        }
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if let Some(ip) = forwarded_for {
            builder = builder.header("x-forwarded-for", ip);
        }
        builder
            .body(Body::from(if body.is_null() {
                String::new()
            } else {
                body.to_string()
            }))
            .unwrap()
    }

    async fn send(
        state: &AuthState,
        request: axum::http::Request<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let response = crate::routes::authapi::router(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(json!(null));
        (status, body)
    }

    #[tokio::test]
    async fn login_mfa_enrollment_and_verification_flows() {
        let Some((state, _guard)) = fresh_state().await else {
            return;
        };
        make_user(&state, "admin", "correct horse battery", UserRole::Admin).await;

        // Wrong password and unknown users both answer the same 401.
        for body in [
            json!({"username": "admin", "password": "wrong"}),
            json!({"username": "ghost", "password": "correct horse battery"}),
        ] {
            let (status, resp) = send(&state, request("POST", "/api/auth/login", body, None)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(resp, json!({"detail": "invalid credentials"}));
        }

        // Admin without a factor + require_admin_mfa → mfa_setup challenge.
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            resp,
            json!({
                "mfa_required": false,
                "mfa_setup_required": true,
                "challenge_token": resp["challenge_token"],
                "methods": ["totp", "webauthn"],
            })
        );
        let setup_token = resp["challenge_token"].as_str().unwrap().to_owned();
        state
            .security
            .jwt()
            .decode_mfa_challenge_token(&setup_token, crate::security::jwt::MFA_SETUP_SCOPE)
            .expect("setup token carries the mfa_setup scope");

        // The setup token is not an API token.
        let (status, resp) = send(
            &state,
            request("GET", "/api/auth/me", json!(null), Some(&setup_token)),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp, json!({"detail": "token not valid for API access"}));

        // TOTP enrollment, driven by the setup token.
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/totp/enroll/begin",
                json!({}),
                Some(&setup_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let secret = resp["secret"].as_str().unwrap().to_owned();
        assert_eq!(
            resp["otpauth_uri"],
            json!(format!(
                "otpauth://totp/Huginn:admin?secret={secret}&issuer=Huginn"
            ))
        );

        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let code = crate::security::totp_code_at(&secret, now).unwrap();

        // A wrong code refuses and keeps the pending enrollment.
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/totp/enroll/finish",
                json!({"code": "abcdef"}),
                Some(&setup_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp, json!({"detail": "invalid code"}));

        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/totp/enroll/finish",
                json!({"code": code}),
                Some(&setup_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let backup_codes = resp["backup_codes"].as_array().unwrap().clone();
        assert_eq!(
            backup_codes.len(),
            crate::routes::authapi::service::BACKUP_CODE_COUNT
        );
        assert!(
            resp["access_token"].is_string(),
            "the setup flow logs the admin in"
        );

        // Second factor is now required at login.
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["mfa_required"], json!(true));
        assert_eq!(resp["mfa_setup_required"], json!(false));
        assert_eq!(resp["methods"], json!(["totp", "backup"]));
        let challenge = resp["challenge_token"].as_str().unwrap().to_owned();

        // A bad code fails, the right one exchanges the challenge for a token.
        let (status, _) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"code": "abcdef"}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"code": code}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["token_type"], json!("bearer"));
        assert_eq!(resp["expires_in"], json!(3600));
        let access_token = resp["access_token"].as_str().unwrap().to_owned();

        // The access token works on the business API.
        let (status, resp) = send(
            &state,
            request("GET", "/api/auth/me", json!(null), Some(&access_token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["username"], json!("admin"));
        assert_eq!(resp["role"], json!("admin"));
        assert_eq!(resp["totp_enabled"], json!(true));
        assert_eq!(resp["passkey_count"], json!(0));

        // Replay: the claimed time-step cannot be spent twice.
        let (_, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        let challenge = resp["challenge_token"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"code": code}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp, json!({"detail": "invalid code"}));

        // Backup codes are single-use too.
        let code0 = backup_codes[0].as_str().unwrap().to_owned();
        let (_, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        let challenge = resp["challenge_token"].as_str().unwrap().to_owned();
        let (status, _) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"backup_code": code0}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        let challenge = resp["challenge_token"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"backup_code": code0}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp, json!({"detail": "invalid code"}));
    }

    /// A password-guess run spread over many source addresses must not get an
    /// unbounded budget against a single account: the per-account window
    /// throttles it even though every individual address stays under the
    /// per-IP budget.
    #[tokio::test]
    async fn login_is_throttled_per_account_across_source_addresses() {
        let Some((mut state, _guard)) = fresh_state().await else {
            return;
        };
        state.config.trust_forwarded_for = true;
        make_user(
            &state,
            "victim",
            "correct horse battery",
            UserRole::Readonly,
        )
        .await;

        let attempt = |ip: &str| {
            request_from(
                "POST",
                "/api/auth/login",
                json!({"username": "victim", "password": "wrong"}),
                None,
                Some(ip),
            )
        };
        // One failure per distinct source address.
        for i in 0..crate::routes::authapi::LOGIN_ACCOUNT_MAX_FAILURES {
            let (status, _) = send(&state, attempt(&format!("203.0.113.{i}"))).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}");
        }
        // The next attempt — from yet another address — is throttled.
        let (status, resp) = send(&state, attempt("198.51.100.7")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp,
            json!({"detail": "too many failed login attempts; slow down"})
        );
        // The account is locked for the rest of the window — the guard runs
        // BEFORE the password check, so a spent window also caps the Argon2
        // work an attacker can force on the hub.
        let (status, _) = send(
            &state,
            request_from(
                "POST",
                "/api/auth/login",
                json!({"username": "victim", "password": "correct horse battery"}),
                None,
                Some("198.51.100.8"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn users_crud_password_and_rbac_flows() {
        let Some((mut state, _guard)) = fresh_state().await else {
            return;
        };
        // No forced setup here: the admin logs straight in.
        state.config.require_admin_mfa = false;
        make_user(&state, "admin", "correct horse battery", UserRole::Admin).await;

        let login = |username: &str, password: &str| {
            request(
                "POST",
                "/api/auth/login",
                json!({"username": username, "password": password}),
                None,
            )
        };
        let (_, resp) = send(&state, login("admin", "correct horse battery")).await;
        let admin_token = resp["access_token"].as_str().unwrap().to_owned();

        // RBAC: an operator may not list users.
        make_user(&state, "olive", "olive-olive-olive", UserRole::Operator).await;
        let (_, resp) = send(&state, login("olive", "olive-olive-olive")).await;
        let olive_token = resp["access_token"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request("GET", "/api/users", json!(null), Some(&olive_token)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(resp, json!({"detail": "admin role required"}));

        // Create (201) and duplicate (409) and validation (422).
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/users",
                json!({"username": "eve", "password": "eve-eve-eve-eve", "role": "operator"}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(resp["username"], json!("eve"));
        assert_eq!(resp["role"], json!("operator"));
        assert_eq!(resp["passkey_count"], json!(0));
        let eve_id = resp["id"].as_str().unwrap().to_owned();
        assert_eq!(resp["vm_ids"], json!([]));

        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/users",
                json!({"username": "eve", "password": "eve-eve-eve-eve"}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(resp, json!({"detail": "username already exists"}));

        let (status, _) = send(
            &state,
            request(
                "POST",
                "/api/users",
                json!({"username": "short", "password": "short"}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Role update (with audit detail) and VM access.
        let vm = crate::models::vm::create(
            &state.pool,
            crate::models::vm::VmNew::new("vm-1", crate::models::enums::WorkerArch::Amd64),
        )
        .await
        .unwrap();
        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/vms"),
                json!({"vm_ids": [vm.id.to_string()]}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["vm_ids"], json!([vm.id.to_string()]));

        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}"),
                json!({"role": "readonly"}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["role"], json!("readonly"));
        let audit =
            crate::models::audit::list_filtered(&state.pool, None, Some("user_updated"), 10)
                .await
                .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(
            audit[0].detail["role"],
            json!({"old": "operator", "new": "readonly"})
        );

        // Self password change: old password required and checked.
        let (status, _) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/password"),
                json!({"new_password": "new-new-new-new"}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "unauthenticated");

        let (_, resp) = send(&state, login("eve", "eve-eve-eve-eve")).await;
        let eve_token = resp["access_token"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/password"),
                json!({"new_password": "new-new-new-new"}),
                Some(&eve_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            resp,
            json!({"detail": "old_password required for self-change"})
        );

        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/password"),
                json!({"old_password": "nope", "new_password": "new-new-new-new"}),
                Some(&eve_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp, json!({"detail": "incorrect old password"}));

        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/password"),
                json!({"old_password": "eve-eve-eve-eve", "new_password": "new-new-new-new"}),
                Some(&eve_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp, json!({"status": "ok"}));
        let (status, _) = send(&state, login("eve", "new-new-new-new")).await;
        assert_eq!(status, StatusCode::OK);

        // A non-admin may not reset someone else's password.
        let (_, resp) = send(
            &state,
            request("GET", "/api/auth/me", json!(null), Some(&admin_token)),
        )
        .await;
        let admin_id = resp["id"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{admin_id}/password"),
                json!({"new_password": "new-new-new-new"}),
                Some(&eve_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            resp,
            json!({"detail": "admin role required to reset other passwords"})
        );

        // Deactivation: self-delete refused, others disabled.
        let (status, resp) = send(
            &state,
            request(
                "DELETE",
                &format!("/api/users/{admin_id}"),
                json!(null),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp, json!({"detail": "cannot deactivate yourself"}));

        let (status, _) = send(
            &state,
            request(
                "DELETE",
                &format!("/api/users/{eve_id}"),
                json!(null),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, resp) = send(&state, login("eve", "new-new-new-new")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp, json!({"detail": "invalid credentials"}));
    }
}

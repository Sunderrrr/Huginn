//! Full WebAuthn ceremonies against a live PostgreSQL: the payloads are
//! fabricated but cryptographically valid (real COSE keys, real
//! signatures), so attestation/assertion verification runs for real.
//! Skipped unless `HUGINN_TEST_DATABASE_URL` is set — `cargo test` stays
//! green without a database, like `db.rs`/`models::live_tests`.
//!
//! Not covered here (documented in the handover report): a real browser
//! driving `navigator.credentials.*`, and the `tpm`/`apple`/`android-*`
//! attestation formats which are rejected by design.
use super::*;
use crate::config::Config;
use crate::models::user::UserNew;
use crate::services::webauthn::b64u_decode;
use crate::services::webauthn::test_support::{
    attestation_object, auth_data_bytes, authentication_credential, client_data_json,
    registration_credential, FabricatedKey, ORIGIN, RP_ID,
};
use axum::body::Body;
use axum::http::StatusCode;
use ciborium::value::Value;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

/// UP|UV|AT — the flags a real passkey asserts during registration.
const REG_FLAGS: u8 = 0x45;
/// UP|UV — the flags a real passkey asserts during login.
const AUTH_FLAGS: u8 = 0x05;

fn wa_config() -> Config {
    Config {
        webauthn_rp_id: RP_ID.into(),
        webauthn_rp_name: "Huginn".into(),
        webauthn_origin: ORIGIN.into(),
        webauthn_user_verification: "preferred".into(),
        ..Config::default()
    }
}

async fn fresh_state(config: Config) -> Option<(AuthState, tokio::sync::MutexGuard<'static, ()>)> {
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
    Some((AuthState::new(pool, config), guard))
}

async fn make_user(state: &AuthState, username: &str) -> Uuid {
    crate::models::user::create(
        &state.pool,
        UserNew {
            username: username.into(),
            password_hash: Some(crate::security::hash_password("correct horse battery").unwrap()),
            role: crate::models::enums::UserRole::Readonly,
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
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    if !body.is_null() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
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

/// A registration payload bound to `challenge`, like a real authenticator.
fn make_attestation(
    key: &FabricatedKey,
    challenge: &[u8],
    credential_id: &[u8],
    counter: u32,
) -> serde_json::Value {
    let aaguid = [0x22u8; 16];
    let auth_data = auth_data_bytes(
        RP_ID,
        REG_FLAGS,
        counter,
        Some((&aaguid, credential_id, key.cose())),
    );
    let cdj = client_data_json("webauthn.create", challenge, ORIGIN);
    let att = attestation_object("none", Value::Map(Vec::new()), &auth_data);
    registration_credential(credential_id, &cdj, &att, Some(json!(["internal"])))
}

/// An assertion bound to `challenge`, signed like a real authenticator.
fn make_assertion(
    key: &FabricatedKey,
    challenge: &[u8],
    credential_id: &[u8],
    counter: u32,
) -> serde_json::Value {
    let auth_data = auth_data_bytes(RP_ID, AUTH_FLAGS, counter, None);
    let cdj = client_data_json("webauthn.get", challenge, ORIGIN);
    let mut signature_base = auth_data.clone();
    signature_base.extend_from_slice(&client_data_hash(&cdj));
    let signature = key.sign(&signature_base);
    authentication_credential(credential_id, &cdj, &auth_data, &signature)
}

fn challenge_bytes(options: &serde_json::Value) -> Vec<u8> {
    b64u_decode(options["challenge"].as_str().unwrap()).unwrap()
}

fn client_data_hash(cdj: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(cdj).to_vec()
}

#[tokio::test]
async fn webauthn_register_and_login_ceremonies_end_to_end() {
    let Some((state, _guard)) = fresh_state(wa_config()).await else {
        return;
    };
    let user_id = make_user(&state, "pk-user").await;
    let token = state
        .security
        .jwt()
        .create_access_token(&user_id.to_string(), "readonly", 5, 0)
        .unwrap();
    let auth = Some(token.as_str());
    let key = FabricatedKey::es256();
    let credential_id = b"live-test-credential-id-32byte";

    // --- register/begin: options mirror py_webauthn byte for byte.
    let (status, options) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/begin",
            json!({}),
            auth,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    assert_eq!(options["rp"], json!({"name": "Huginn", "id": RP_ID}));
    assert_eq!(
        options["user"]["id"],
        json!(crate::services::webauthn::b64u_encode(
            user_id.to_string().as_bytes()
        ))
    );
    assert_eq!(
        options["pubKeyCredParams"],
        json!([
            {"type": "public-key", "alg": -8},
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257}
        ])
    );
    assert_eq!(options["timeout"], json!(60000));
    assert_eq!(
        options["authenticatorSelection"],
        json!({"residentKey": "preferred", "requireResidentKey": false, "userVerification": "preferred"})
    );
    assert_eq!(options["attestation"], json!("none"));

    // --- register/finish with a fabricated-but-valid attestation.
    let challenge = challenge_bytes(&options);
    let credential = make_attestation(&key, &challenge, credential_id, 0);
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/finish",
            json!({"name": "Test Key", "credential": credential}),
            auth,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], json!("Test Key"));
    assert!(body["id"].is_string());
    assert!(
        body.get("access_token").is_none(),
        "no login outside setup flow"
    );

    // --- challenge reuse is rejected (single-use claim in SQL).
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/finish",
            json!({"name": "Again", "credential": credential}),
            auth,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({"detail": "unknown, used, or expired challenge"})
    );

    // --- wrong origin / wrong rp binding → generic verification failure.
    // Each attempt gets a fresh ceremony: challenges are single-use.
    for (kind, cdj_origin, rp_id) in [
        ("origin", "https://evil.example.com", RP_ID),
        ("rp_id", ORIGIN, "other.example.com"),
    ] {
        let (status, options) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/begin",
                json!({}),
                auth,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        let challenge = challenge_bytes(&options);
        let aaguid = [0x22u8; 16];
        let auth_data = auth_data_bytes(
            rp_id,
            REG_FLAGS,
            0,
            Some((&aaguid, credential_id, key.cose())),
        );
        let cdj = client_data_json("webauthn.create", &challenge, cdj_origin);
        let att_obj = attestation_object("none", Value::Map(Vec::new()), &auth_data);
        let att = registration_credential(credential_id, &cdj, &att_obj, None);
        let (status, body) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/webauthn/register/finish",
                json!({"name": kind, "credential": att}),
                auth,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{kind}: {body}");
        assert_eq!(body, json!({"detail": "registration verification failed"}));
    }

    // --- login/begin (public, discoverable) → options without allowCredentials.
    let (status, options) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/login/begin",
            json!({}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    assert_eq!(options["rpId"], json!(RP_ID));
    assert_eq!(options["allowCredentials"], json!([]));

    // --- login/finish: counter 0 → 1 (both-zero start is legitimate).
    let challenge = challenge_bytes(&options);
    let credential = make_assertion(&key, &challenge, credential_id, 1);
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/login/finish",
            json!({"credential": credential}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], json!("bearer"));

    // --- replaying the same (now consumed) challenge fails with the generic 401.
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/login/finish",
            json!({"credential": credential}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"detail": "passkey authentication failed"}));

    // --- clone detection: a counter that does not advance is rejected.
    let (status, options) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/login/begin",
            json!({}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge = challenge_bytes(&options);
    let stale = make_assertion(&key, &challenge, credential_id, 1); // stored is 1
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/login/finish",
            json!({"credential": stale}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"detail": "passkey authentication failed"}));

    // --- an advancing counter logs in again.
    let (status, options) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/login/begin",
            json!({}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge = challenge_bytes(&options);
    let advancing = make_assertion(&key, &challenge, credential_id, 2);
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/login/finish",
            json!({"credential": advancing}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn webauthn_challenges_are_bound_to_their_user() {
    let Some((state, _guard)) = fresh_state(wa_config()).await else {
        return;
    };
    let user_a = make_user(&state, "alice").await;
    let user_b = make_user(&state, "bob").await;
    let token_a = state
        .security
        .jwt()
        .create_access_token(&user_a.to_string(), "readonly", 5, 0)
        .unwrap();
    let token_b = state
        .security
        .jwt()
        .create_access_token(&user_b.to_string(), "readonly", 5, 0)
        .unwrap();

    let (status, options) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/begin",
            json!({}),
            Some(&token_a),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let challenge = challenge_bytes(&options);
    let key = FabricatedKey::es256();
    let credential = make_attestation(&key, &challenge, b"alice-credential-id-32bytes!!", 0);

    // Bob cannot finish Alice's ceremony.
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/finish",
            json!({"name": "stolen", "credential": credential}),
            Some(&token_b),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({"detail": "challenge does not belong to this user"})
    );
}

/// Expired ceremony challenges must not pile up: every (unauthenticated)
/// `login/begin` inserts a row, and without a purge the table grows without
/// bound.
#[tokio::test]
async fn expired_webauthn_challenges_are_purged() {
    let Some((state, _guard)) = fresh_state(wa_config()).await else {
        return;
    };
    for (challenge, expires) in [
        ("expired-challenge", "now() - interval '1 hour'"),
        ("expired-challenge-2", "now() - interval '1 minute'"),
    ] {
        sqlx::query(&format!(
            "INSERT INTO webauthn_challenges \
             (id, challenge, user_id, purpose, expires_at, consumed_at, created_at, updated_at) \
             VALUES ($1, $2, NULL, 'login', {expires}, NULL, now(), now())"
        ))
        .bind(Uuid::new_v4())
        .bind(challenge)
        .execute(&state.pool)
        .await
        .expect("insert expired challenge");
    }
    let before: (i64,) = sqlx::query_as("SELECT count(*) FROM webauthn_challenges")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(before.0, 2);

    purge_expired_webauthn_challenges(&state).await;

    let after: (i64,) = sqlx::query_as("SELECT count(*) FROM webauthn_challenges")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(after.0, 0, "expired challenges are purged");
}

#[tokio::test]
async fn webauthn_setup_flow_logs_the_admin_in() {
    let Some((state, _guard)) = fresh_state(wa_config()).await else {
        return;
    };
    let user_id = make_user(&state, "admin").await;
    let setup_token = state
        .security
        .jwt()
        .create_mfa_challenge_token(
            &user_id.to_string(),
            crate::security::jwt::MFA_SETUP_SCOPE,
            5,
        )
        .unwrap();

    let (status, options) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/begin",
            json!({}),
            Some(&setup_token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let challenge = challenge_bytes(&options);
    let key = FabricatedKey::es256();
    let credential = make_attestation(&key, &challenge, b"setup-credential-id-32bytes!!!", 0);
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/finish",
            json!({"name": "First passkey", "credential": credential}),
            Some(&setup_token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Setup flow (admin first-time) came in with only a setup token → login.
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn webauthn_not_configured_fails_closed() {
    // No rp_id/origin at all.
    let Some((state, _guard)) = fresh_state(Config::default()).await else {
        return;
    };
    let user_id = make_user(&state, "pk-user").await;
    let token = state
        .security
        .jwt()
        .create_access_token(&user_id.to_string(), "readonly", 5, 0)
        .unwrap();
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/begin",
            json!({}),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"detail": "WebAuthn is not configured"}));
}

#[tokio::test]
async fn webauthn_rejects_an_ip_rp_id() {
    let Some((state, _guard)) = fresh_state(Config {
        webauthn_rp_id: "192.0.2.1".into(),
        webauthn_origin: "https://192.0.2.13".into(),
        ..Config::default()
    })
    .await
    else {
        return;
    };
    let user_id = make_user(&state, "pk-user").await;
    let token = state
        .security
        .jwt()
        .create_access_token(&user_id.to_string(), "readonly", 5, 0)
        .unwrap();
    let (status, body) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/begin",
            json!({}),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({"detail": "webauthn_rp_id must be a registrable domain, not an IP"})
    );
}

#[tokio::test]
async fn webauthn_settings_row_overrides_the_env_config() {
    let Some((state, _guard)) = fresh_state(Config::default()).await else {
        return;
    };
    crate::models::setting::upsert(
        &state.pool,
        crate::models::setting::SettingValues {
            webauthn_rp_id: RP_ID.into(),
            webauthn_rp_name: "Fleet".into(),
            webauthn_origin: ORIGIN.into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let user_id = make_user(&state, "pk-user").await;
    let token = state
        .security
        .jwt()
        .create_access_token(&user_id.to_string(), "readonly", 5, 0)
        .unwrap();
    let (status, options) = send(
        &state,
        request(
            "POST",
            "/api/auth/mfa/webauthn/register/begin",
            json!({}),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    // DB row wins over env, exactly like `webauthn.rp_config`.
    assert_eq!(options["rp"], json!({"name": "Fleet", "id": RP_ID}));
}

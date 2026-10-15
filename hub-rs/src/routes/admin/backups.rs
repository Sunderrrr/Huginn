//! `GET/POST/DELETE /api/backups` — database backups to S3-compatible storage.
//!
//! | route                  | behavior                                             |
//! |------------------------|------------------------------------------------------|
//! | `GET /api/backups`     | backup objects (name, size, date) + S3 config state   |
//! | `POST /api/backups`    | run a backup now → `{name, size, duration_ms}`        |
//! | `DELETE /api/backups/{name}` | delete one backup object                        |
//!
//! All three are **admin-only**, audited (`backup_created` / `backup_deleted`)
//! and rate-limited (backups are heavy: a full SQL export + an upload).
//!
//! The S3 secret key is write-only (`PUT /api/settings`): this API only ever
//! reports `secret_key_configured`, and no response body contains it.
//!
//! The routes own policy (settings → [`S3Config`], RBAC, audit, throttling);
//! the mechanics live behind [`BackupBackend`] so tests can substitute an
//! in-memory implementation. Production resolves [`PgBackup`] from
//! `Config::database_url` (lazy pool — listing/deleting never touches the
//! database).

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;

use super::{audit_record, authenticate, enforce_body_size, peer_addr, AdminState, RouteError};
use crate::models::setting::Setting;
use crate::routes::worker::RateLimiter;
use crate::services::backup::{
    is_valid_object_name, BackupBackend, BackupError, BackupObject, BackupOutcome, PgBackup,
    S3Config,
};

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/// The S3 configuration as the dashboard may see it — **never** the secret.
#[derive(Debug, Clone, Serialize)]
pub struct BackupConfigOut {
    pub enabled: bool,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub access_key: String,
    /// A secret key is stored (the value itself is write-only).
    pub secret_key_configured: bool,
    pub retention_days: i32,
}

impl BackupConfigOut {
    pub fn from_row(row: &Setting) -> Self {
        Self {
            enabled: row.backup_s3_enabled,
            endpoint: row.backup_s3_endpoint.clone(),
            region: row.backup_s3_region.clone(),
            bucket: row.backup_s3_bucket.clone(),
            prefix: row.backup_s3_prefix.clone(),
            access_key: row.backup_s3_access_key.clone(),
            secret_key_configured: row.backup_s3_secret_configured(),
            retention_days: row.backup_s3_retention_days,
        }
    }
}

/// `GET /api/backups` response.
#[derive(Debug, Clone, Serialize)]
pub struct BackupsOut {
    /// Bucket + credentials are all present (an invalid config is *not*
    /// configured — see [`S3Config::from_settings`]).
    pub configured: bool,
    pub config: BackupConfigOut,
    pub backups: Vec<BackupObject>,
}

// ---------------------------------------------------------------------------
// Rate limiting (fixed window per principal, like the execution endpoints)
// ---------------------------------------------------------------------------

/// Backup writes (export + upload / delete): 10 per minute and principal.
fn write_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(10))
}

/// Listing backups (the dashboard polls it): 60 per minute and principal.
fn read_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(60))
}

fn throttle(
    limiter: &'static RateLimiter,
    caller: &super::schemas::Caller,
) -> Result<(), RouteError> {
    let key = format!(
        "backups:{}:{}",
        caller.principal.actor_type.as_str(),
        caller.principal.actor_id
    );
    if limiter.allow(&key) {
        Ok(())
    } else {
        Err(RouteError::from(crate::error::ApiError::too_many_requests(
            "rate limit exceeded; slow down",
        )))
    }
}

// ---------------------------------------------------------------------------
// Router + handlers
// ---------------------------------------------------------------------------

/// The `/api/backups` router (prefix included).
pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/backups", get(list_backups_endpoint))
        .route("/api/backups", post(create_backup_endpoint))
        .route("/api/backups/{name}", delete(delete_backup_endpoint))
}

/// Settings → validated [`S3Config`] (400 with a precise detail on bad input).
fn s3_config(row: &Setting) -> Result<S3Config, RouteError> {
    S3Config::from_settings(row).map_err(|e| match e {
        BackupError::NotConfigured => RouteError::bad_request("backup storage is not configured"),
        BackupError::Config(detail) => RouteError::bad_request(detail),
        other => RouteError::bad_request(other.to_string()),
    })
}

/// Storage failures after the config is accepted: 500 with the (sanitized)
/// detail — the errors of `services::backup` never carry the secret key.
fn storage_error(err: BackupError) -> RouteError {
    RouteError::internal(err.to_string())
}

/// The backend to act on: the injected one in tests, otherwise [`PgBackup`]
/// over this hub's database.
fn resolve_backend(
    state: &AdminState,
    injected: Option<Extension<Arc<dyn BackupBackend>>>,
) -> Result<Arc<dyn BackupBackend>, RouteError> {
    if let Some(Extension(backend)) = injected {
        return Ok(backend);
    }
    match PgBackup::from_database_url(&state.config.database_url) {
        Ok(backup) => Ok(Arc::new(backup)),
        Err(e) => Err(RouteError::internal(e.to_string())),
    }
}

/// `GET /api/backups` — the backup objects plus the S3 configuration state.
/// Unconfigured storage is not an error: the dashboard gets
/// `configured: false` and an empty list.
async fn list_backups_endpoint(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    backend: Option<Extension<Arc<dyn BackupBackend>>>,
) -> Result<Response, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    throttle(read_limiter(), &caller)?;

    let Some(row) = state.store.get_settings().await? else {
        return Err(RouteError::not_found("settings not initialized"));
    };
    let config = BackupConfigOut::from_row(&row);
    if !S3Config::is_configured(&row) {
        return Ok(Json(BackupsOut {
            configured: false,
            config,
            backups: Vec::new(),
        })
        .into_response());
    }
    let cfg = s3_config(&row)?;
    let backend = resolve_backend(&state, backend)?;
    let mut backups = backend.list(&cfg).await.map_err(storage_error)?;
    backups.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(Json(BackupsOut {
        configured: true,
        config,
        backups,
    })
    .into_response())
}

/// `POST /api/backups` — run a backup now (201 + outcome, audited as
/// `backup_created`).
async fn create_backup_endpoint(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    backend: Option<Extension<Arc<dyn BackupBackend>>>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    throttle(write_limiter(), &caller)?;

    let Some(row) = state.store.get_settings().await? else {
        return Err(RouteError::not_found("settings not initialized"));
    };
    let cfg = s3_config(&row)?;
    let backend = resolve_backend(&state, backend)?;
    let outcome: BackupOutcome = backend.create(&cfg).await.map_err(storage_error)?;

    audit_record(
        &state,
        &caller,
        "backup_created",
        serde_json::json!({
            "name": outcome.name,
            "size": outcome.size,
            "duration_ms": outcome.duration_ms,
        }),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(outcome)))
}

/// `DELETE /api/backups/{name}` — delete one backup object (audited as
/// `backup_deleted`). Only names produced by the backup pipeline are accepted.
async fn delete_backup_endpoint(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(name): Path<String>,
    backend: Option<Extension<Arc<dyn BackupBackend>>>,
) -> Result<StatusCode, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    throttle(write_limiter(), &caller)?;

    if !is_valid_object_name(&name) {
        return Err(RouteError::bad_request("invalid backup name"));
    }
    let Some(row) = state.store.get_settings().await? else {
        return Err(RouteError::not_found("settings not initialized"));
    };
    let cfg = s3_config(&row)?;
    let backend = resolve_backend(&state, backend)?;
    backend.delete(&cfg, &name).await.map_err(storage_error)?;

    audit_record(
        &state,
        &caller,
        "backup_deleted",
        serde_json::json!({ "name": name }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::Utc;
    use serde_json::json;

    use super::super::router;
    use super::super::store::AdminStore;
    use super::super::testing::*;
    use super::*;
    use crate::models::setting::SettingValues;
    use crate::models::user::User;
    use crate::models::{ActorType, UserRole};
    use crate::services::backup::BackupFuture;

    /// In-memory [`BackupBackend`] recording what the routes asked for.
    #[derive(Default)]
    struct MockBackend {
        calls: Mutex<Vec<String>>,
        objects: Mutex<Vec<BackupObject>>,
        fail: bool,
    }

    impl BackupBackend for MockBackend {
        fn list<'a>(
            &'a self,
            _cfg: &'a S3Config,
        ) -> BackupFuture<'a, Result<Vec<BackupObject>, BackupError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push("list".into());
                if self.fail {
                    return Err(BackupError::Http {
                        status: 403,
                        code: "AccessDenied".into(),
                    });
                }
                Ok(self.objects.lock().unwrap().clone())
            })
        }

        fn create<'a>(
            &'a self,
            _cfg: &'a S3Config,
        ) -> BackupFuture<'a, Result<BackupOutcome, BackupError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push("create".into());
                if self.fail {
                    return Err(BackupError::Http {
                        status: 403,
                        code: "AccessDenied".into(),
                    });
                }
                Ok(BackupOutcome {
                    name: "huginn-db-20260101T031500Z.sql.gz".into(),
                    size: 2048,
                    duration_ms: 7,
                })
            })
        }

        fn delete<'a>(
            &'a self,
            _cfg: &'a S3Config,
            name: &'a str,
        ) -> BackupFuture<'a, Result<(), BackupError>> {
            let name = name.to_owned();
            Box::pin(async move {
                self.calls.lock().unwrap().push(format!("delete:{name}"));
                if self.fail {
                    return Err(BackupError::Http {
                        status: 403,
                        code: "AccessDenied".into(),
                    });
                }
                self.objects
                    .lock()
                    .unwrap()
                    .retain(|object| object.name != name);
                Ok(())
            })
        }
    }

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn setup() -> (Arc<MockStore>, AdminState, User) {
        let store = Arc::new(MockStore::default());
        seed_settings(&store);
        let state = test_state(store.clone());
        let admin = seed_user(&store, make_user("admin", UserRole::Admin));
        (store, state, admin)
    }

    /// Seed a fully configured S3 backup target.
    async fn seed_backup_settings(store: &MockStore) {
        let values = SettingValues {
            backup_s3_enabled: true,
            backup_s3_endpoint: "https://minio.example.com".into(),
            backup_s3_region: "eu-west-1".into(),
            backup_s3_bucket: "huginn-backups".into(),
            backup_s3_prefix: "db".into(),
            backup_s3_access_key: "AKIDEXAMPLE".into(),
            backup_s3_secret_key: Some(SECRET.into()),
            backup_s3_retention_days: 14,
            ..Default::default()
        };
        store.save_settings(values).await.unwrap();
    }

    fn bearer_for(state: &AdminState, user: &User) -> Vec<(&'static str, String)> {
        vec![("authorization", format!("Bearer {}", bearer(state, user)))]
    }

    /// `Extension` is layered on the router so the mock backend reaches the
    /// handlers (production has no layer and gets [`PgBackup`]).
    fn app_with_backend(state: AdminState, backend: Arc<MockBackend>) -> axum::Router {
        router(state).layer(Extension(backend as Arc<dyn BackupBackend>))
    }

    #[tokio::test]
    async fn list_returns_config_state_and_never_the_secret() {
        let (store, state, admin) = setup();
        seed_backup_settings(&store).await;
        let backend = Arc::new(MockBackend::default());
        backend.objects.lock().unwrap().push(BackupObject {
            name: "huginn-db-20260101T031500Z.sql.gz".into(),
            size: 2048,
            last_modified: Utc::now(),
        });

        let app = app_with_backend(state.clone(), backend.clone());
        let request = json_request_with(
            "GET",
            "/api/backups",
            json!(null),
            &bearer_for(&state, &admin),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;

        assert_eq!(body["configured"], json!(true));
        assert_eq!(body["config"]["enabled"], json!(true));
        assert_eq!(body["config"]["bucket"], json!("huginn-backups"));
        assert_eq!(body["config"]["prefix"], json!("db"));
        assert_eq!(
            body["config"]["endpoint"],
            json!("https://minio.example.com")
        );
        assert_eq!(body["config"]["retention_days"], json!(14));
        assert_eq!(body["config"]["secret_key_configured"], json!(true));
        assert_eq!(
            body["backups"][0]["name"],
            json!("huginn-db-20260101T031500Z.sql.gz")
        );
        assert_eq!(body["backups"][0]["size"], json!(2048));

        // The secret key appears nowhere in the payload.
        let rendered = serde_json::to_string(&body).unwrap();
        assert!(!rendered.contains(SECRET), "{rendered}");
    }

    #[tokio::test]
    async fn list_reports_unconfigured_storage_without_touching_the_backend() {
        let (_store, state, admin) = setup(); // default settings: no S3
        let backend = Arc::new(MockBackend::default());
        let app = app_with_backend(state.clone(), backend.clone());
        let request = json_request_with(
            "GET",
            "/api/backups",
            json!(null),
            &bearer_for(&state, &admin),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["configured"], json!(false));
        assert_eq!(body["backups"], json!([]));
        assert_eq!(body["config"]["secret_key_configured"], json!(false));
        assert!(backend.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_runs_a_backup_and_audits_it() {
        let (store, state, admin) = setup();
        seed_backup_settings(&store).await;
        let backend = Arc::new(MockBackend::default());
        let app = app_with_backend(state.clone(), backend.clone());
        let request = json_request_with(
            "POST",
            "/api/backups",
            json!({}),
            &bearer_for(&state, &admin),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = body_json(response).await;
        assert_eq!(body["name"], json!("huginn-db-20260101T031500Z.sql.gz"));
        assert_eq!(body["size"], json!(2048));
        assert_eq!(body["duration_ms"], json!(7));
        assert!(!serde_json::to_string(&body).unwrap().contains(SECRET));

        assert_eq!(
            backend.calls.lock().unwrap().as_slice(),
            ["create".to_owned()]
        );
        let db = store.db.lock().unwrap();
        let entry = db.audit.last().unwrap();
        assert_eq!(entry.event_type, "backup_created");
        assert_eq!(entry.actor_type, ActorType::User);
        assert_eq!(entry.actor_id, admin.id.to_string());
        assert_eq!(
            entry.detail["name"],
            json!("huginn-db-20260101T031500Z.sql.gz")
        );
        assert_eq!(entry.detail["size"], json!(2048));
    }

    #[tokio::test]
    async fn delete_removes_an_object_and_audits_it() {
        let (store, state, admin) = setup();
        seed_backup_settings(&store).await;
        let backend = Arc::new(MockBackend::default());
        backend.objects.lock().unwrap().push(BackupObject {
            name: "huginn-db-20260101T031500Z.sql.gz".into(),
            size: 1,
            last_modified: Utc::now(),
        });

        let app = app_with_backend(state.clone(), backend.clone());
        let request = json_request_with(
            "DELETE",
            "/api/backups/huginn-db-20260101T031500Z.sql.gz",
            json!(null),
            &bearer_for(&state, &admin),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(backend.objects.lock().unwrap().is_empty());

        let db = store.db.lock().unwrap();
        let entry = db.audit.last().unwrap();
        assert_eq!(entry.event_type, "backup_deleted");
        assert_eq!(
            entry.detail,
            json!({"name": "huginn-db-20260101T031500Z.sql.gz"})
        );
    }

    #[tokio::test]
    async fn delete_rejects_names_outside_the_backup_namespace() {
        let (store, state, admin) = setup();
        seed_backup_settings(&store).await;
        let backend = Arc::new(MockBackend::default());
        for name in [
            "not-a-backup.txt",
            "x.sql",
            "a..b.sql.gz",
            "h%C3%BCnion.sql.gz",
        ] {
            let app = app_with_backend(state.clone(), backend.clone());
            let request = json_request_with(
                "DELETE",
                &format!("/api/backups/{name}"),
                json!(null),
                &bearer_for(&state, &admin),
            );
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        }
        assert!(backend.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn storage_errors_surface_without_the_secret() {
        let (store, state, admin) = setup();
        seed_backup_settings(&store).await;
        let backend = Arc::new(MockBackend {
            fail: true,
            ..Default::default()
        });
        let app = app_with_backend(state.clone(), backend.clone());
        let request = json_request_with(
            "POST",
            "/api/backups",
            json!({}),
            &bearer_for(&state, &admin),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(response).await;
        assert_eq!(
            body["detail"],
            json!("backup storage returned HTTP 403: AccessDenied")
        );
        assert!(!serde_json::to_string(&body).unwrap().contains(SECRET));
    }

    #[tokio::test]
    async fn everything_is_admin_only() {
        let (store, state, admin) = setup();
        seed_backup_settings(&store).await;
        let ro = seed_user(&store, make_user("ro", UserRole::Readonly));
        let backend = Arc::new(MockBackend::default());
        for (method, uri) in [
            ("GET", "/api/backups"),
            ("POST", "/api/backups"),
            ("DELETE", "/api/backups/huginn-db-20260101T031500Z.sql.gz"),
        ] {
            let app = app_with_backend(state.clone(), backend.clone());
            let request = json_request_with(method, uri, json!({}), &bearer_for(&state, &ro));
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
        }
        assert!(backend.calls.lock().unwrap().is_empty());
        assert_eq!(store.db.lock().unwrap().audit.len(), 0);
        let _ = admin;
    }

    #[tokio::test]
    async fn writes_are_rate_limited_per_principal() {
        let (store, state, admin) = setup();
        seed_backup_settings(&store).await;
        let backend = Arc::new(MockBackend::default());
        let mut last = StatusCode::OK;
        for _ in 0..11 {
            let app = app_with_backend(state.clone(), backend.clone());
            let request = json_request_with(
                "POST",
                "/api/backups",
                json!({}),
                &bearer_for(&state, &admin),
            );
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            last = response.status();
        }
        // 10 writes per minute and principal: the 11th is throttled.
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    }
}

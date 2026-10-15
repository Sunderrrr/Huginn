//! `POST /api/worker/enroll` — token-authenticated worker registration.

use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, Extension, OriginalUri, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbError;
use crate::error::ApiError;
use crate::models::enrollment::EnrollVmParams;
use crate::models::task::ActionTaskNew;
use crate::models::{VMState, WorkerArch};

use super::{
    client_ip, db_err, enforce_body_size, enforce_tls, map_json_rejection, validate_ip_literal,
    validate_os_info, WorkerState,
};

/// `WorkerEnrollRequest`.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkerEnrollRequest {
    pub token: String,
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    pub arch: WorkerArch,
    #[serde(default)]
    pub os_info: serde_json::Value,
    #[serde(default)]
    pub worker_version: Option<String>,
}

impl WorkerEnrollRequest {
    /// The pydantic field validators of `WorkerEnrollRequest`.
    fn validate(&self) -> Result<(), ApiError> {
        let check_len = |field: &str, value: &Option<String>, max: usize| -> Result<(), ApiError> {
            if let Some(v) = value {
                if v.chars().count() > max {
                    return Err(ApiError::unprocessable_entity(format!(
                        "{field} must be at most {max} characters"
                    )));
                }
            }
            Ok(())
        };
        if self.name.chars().count() > 255 {
            return Err(ApiError::unprocessable_entity(
                "name must be at most 255 characters",
            ));
        }
        check_len("hostname", &self.hostname, 255)?;
        check_len("ip_address", &self.ip_address, 64)?;
        check_len("worker_version", &self.worker_version, 64)?;
        if let Some(ip) = &self.ip_address {
            validate_ip_literal(ip)?;
        }
        // `os_info` is optional in the Python schema: validate only when sent.
        if !self.os_info.is_null() {
            validate_os_info(&self.os_info)?;
        }
        Ok(())
    }
}

/// `WorkerEnrollResponse` (201).
#[derive(Debug, Clone, Serialize)]
pub struct WorkerEnrollResponse {
    pub worker_id: Uuid,
    /// Per-worker secret, delivered once over TLS at enrollment.
    pub worker_secret: String,
    pub state: String,
}

/// `POST /api/worker/enroll` — authenticate with the enrollment token and
/// register a new worker (201 with the one-time per-worker secret).
pub(super) async fn enroll(
    State(state): State<WorkerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<WorkerEnrollRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    enforce_tls(&headers, &uri, &state.config)?;
    let peer = peer.map(|Extension(ConnectInfo(addr))| addr);
    let ip = client_ip(&headers, &state.config, peer);
    // Minimal rate limit on the unauthenticated token endpoint (per client IP).
    if !state
        .enroll_limiter
        .allow(ip.as_deref().unwrap_or("unknown"))
    {
        return Err(ApiError::too_many_requests(
            "rate limit exceeded; slow down",
        ));
    }
    enforce_body_size(&headers, state.config.max_body_bytes)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;

    let ip_address = body.ip_address.clone().or(ip);
    let worker_secret = crate::security::generate_secret();
    let params = EnrollVmParams {
        name: body.name.clone(),
        hostname: body.hostname.clone(),
        ip_address,
        arch: body.arch,
        os_info: body.os_info.clone(),
        worker_version: body.worker_version.clone(),
        worker_secret_hash: state.security.hash_secret(&worker_secret),
    };
    let token_hash = state.security.hash_secret(&body.token);
    // Consume one token use + register the VM atomically. Bad tokens surface as
    // `DbError::Invalid("invalid or expired enrollment token")` → 401, exactly
    // like `enrollment_service.EnrollmentError` in the Python handler.
    let outcome = match crate::models::enrollment::create_vm_on_enroll(
        &state.pool,
        &token_hash,
        params,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(DbError::Invalid(detail)) => return Err(ApiError::unauthorized(detail)),
        Err(e) => return Err(db_err(e)),
    };
    let vm = outcome.vm;
    let auto_approved = vm.state == VMState::Active;

    // audit.record(...) lands with the audit module; log the same detail until
    // then (see INTEGRATION_NOTES.md).
    tracing::info!(
        target: "huginn.hub.audit",
        event_type = "enroll",
        vm_id = %vm.id,
        name = %vm.name,
        arch = vm.arch.as_str(),
        auto_approved,
        "worker enrolled"
    );

    // An auto-approved VM is active right away; queue a status + metrics refresh
    // so the dashboard shows live telemetry as soon as the worker starts
    // polling. Best-effort — never fail the enrollment.
    if auto_approved {
        for action in ["status", "metrics"] {
            let new = ActionTaskNew {
                vm_id: vm.id,
                action_name: action.to_owned(),
                params: serde_json::Value::Object(Default::default()),
                timeout_seconds: state.config.default_task_timeout_seconds as i64,
                created_by: "system:auto-approve".to_owned(),
                idempotency_key: None,
            };
            match crate::models::task::create_action_task(&state.pool, new).await {
                Ok(_) => state.events.notify_queue_on_commit(&vm.id.to_string()),
                Err(e) => {
                    tracing::warn!("could not queue {} refresh for vm {}: {}", action, vm.id, e)
                }
            }
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(WorkerEnrollResponse {
            worker_id: vm.id,
            worker_secret,
            state: vm.state.as_str().to_owned(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::router;
    use super::super::testing::*;
    use super::*;
    use crate::config::Config;
    use serde_json::json;
    use tower::ServiceExt;

    // ---- schemas -----------------------------------------------------------

    #[test]
    fn enroll_validation_matches_the_pydantic_validators() {
        let mut req = WorkerEnrollRequest {
            token: "t".into(),
            name: "w".into(),
            hostname: None,
            ip_address: None,
            arch: WorkerArch::Amd64,
            os_info: json!({}),
            worker_version: None,
        };
        assert!(req.validate().is_ok());

        req.name = "x".repeat(256);
        assert!(req.validate().is_err());
        req.name = "w".into();

        req.ip_address = Some("not-an-ip".into());
        assert!(req.validate().is_err());
        req.ip_address = Some("10.0.0.4".into());
        assert!(req.validate().is_ok());
        req.ip_address = Some("::1".into());
        assert!(req.validate().is_ok(), "IPv6 literals are valid");

        req.os_info = json!(1);
        assert!(req.validate().is_err(), "os_info must be a dict");
        req.os_info = json!({"k".repeat(65): "v"});
        assert!(req.validate().is_err(), "keys are capped at 64 chars");
        req.os_info = json!({"os": "x".repeat(257)});
        assert!(
            req.validate().is_err(),
            "string values are capped at 256 chars"
        );
        let many: serde_json::Map<String, serde_json::Value> =
            (0..21).map(|i| (format!("k{i}"), json!(1))).collect();
        req.os_info = serde_json::Value::Object(many);
        assert!(req.validate().is_err(), "at most 20 keys");
    }

    // ---- routes (pre-DB paths) --------------------------------------------

    #[tokio::test]
    async fn enroll_refuses_plaintext_when_tls_is_required() {
        let app = router(test_state(true));
        let mut request = json_request(
            "POST",
            "/api/worker/enroll",
            json!({"token": "t", "name": "w", "arch": "amd64"}),
        );
        request.headers_mut().remove("x-forwarded-proto");
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "TLS is required for worker communication"})
        );
    }

    #[tokio::test]
    async fn enroll_rejects_invalid_schema_before_touching_the_db() {
        let app = router(test_state(false));
        let response = app
            .oneshot(json_request(
                "POST",
                "/api/worker/enroll",
                json!({"token": "t", "name": "x".repeat(256), "arch": "amd64"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn enroll_rejects_oversized_bodies() {
        let app = router(test_state(false));
        let mut request = json_request(
            "POST",
            "/api/worker/enroll",
            json!({"token": "t", "name": "w", "arch": "amd64"}),
        );
        request
            .headers_mut()
            .insert("content-length", "70000".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "request body too large"})
        );
    }

    #[tokio::test]
    async fn enroll_rate_limits_per_client_ip() {
        // H-1: the throttle keys on the LAST forwarded hop — the one the
        // trusted proxy appended — never the client-controlled first entry.
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let config = Config {
            require_tls: false,
            trust_forwarded_for: true,
            ..Config::default()
        };
        let state = WorkerState::new(pool, config);
        state.enroll_limiter.allow("172.16.0.2");
        while state.enroll_limiter.allow("172.16.0.2") {}
        let app = router(state);
        let mut request = json_request(
            "POST",
            "/api/worker/enroll",
            json!({"token": "t", "name": "w", "arch": "amd64"}),
        );
        request.headers_mut().insert(
            "x-forwarded-for",
            "198.51.100.9, 172.16.0.2".parse().unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "rate limit exceeded; slow down"})
        );
    }
}

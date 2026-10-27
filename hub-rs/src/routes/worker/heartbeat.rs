//! `POST /api/worker/heartbeat` — liveness + version report, and the
//! best-effort auto-update task creation it triggers.

use axum::extract::{rejection::JsonRejection, OriginalUri, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::models::task::UpdateTaskNew;
use crate::models::vm::{VmPatch, VM};
use crate::models::VMState;

use super::{
    current_worker, db_err, enforce_body_size, enforce_tls, map_json_rejection,
    validate_ip_literal, WorkerState,
};

/// `HeartbeatRequest`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub worker_version: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    /// The Obscura engine version installed on the node (migrations/0009).
    /// `Some(None)` = the node reports NO engine; `None` = the field was not
    /// sent at all (a worker that predates the report) — the stored state is
    /// then left untouched instead of being overwritten with "not installed".
    /// The engine lives on the worker's filesystem, so this is the only way
    /// for the hub (and the dashboard) to know whether the node can run
    /// browser steps.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub browser_engine_version: Option<Option<String>>,
    /// Detailed OS identity. Missing means an older worker and preserves the
    /// existing value; the value is validated using enrollment's constraints.
    #[serde(default)]
    pub os_info: Option<serde_json::Value>,
}

/// Distinguish an absent field (`None`) from an explicit `null`
/// (`Some(None)`) — see [`HeartbeatRequest::browser_engine_version`].
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

impl HeartbeatRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if let Some(v) = &self.worker_version {
            if v.chars().count() > 64 {
                return Err(ApiError::unprocessable_entity(
                    "worker_version must be at most 64 characters",
                ));
            }
        }
        if let Some(ip) = &self.ip_address {
            if ip.chars().count() > 64 {
                return Err(ApiError::unprocessable_entity(
                    "ip_address must be at most 64 characters",
                ));
            }
            validate_ip_literal(ip)?;
        }
        if let Some(Some(v)) = &self.browser_engine_version {
            // A version tag: printable ASCII, bounded (it is stored and
            // shown in the dashboard).
            if v.is_empty() || v.chars().count() > 64 {
                return Err(ApiError::unprocessable_entity(
                    "browser_engine_version must be 1-64 characters",
                ));
            }
            if !v.chars().all(|c| ('\x21'..='\x7e').contains(&c)) {
                return Err(ApiError::unprocessable_entity(
                    "browser_engine_version must be printable ASCII without spaces",
                ));
            }
        }
        if let Some(os_info) = &self.os_info {
            super::validate_os_info(os_info)?;
        }
        Ok(())
    }
}

/// `HeartbeatResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatResponse {
    pub target_worker_version: String,
    pub exec_mode: String,
    pub allowed_release_domains: Vec<String>,
}

/// `POST /api/worker/heartbeat` — worker liveness + version report; returns
/// the desired target version.
pub(super) async fn heartbeat(
    State(state): State<WorkerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Result<Json<HeartbeatRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    enforce_tls(&headers, &uri, &state.config)?;
    enforce_body_size(&headers, state.config.max_body_bytes)?;
    // Authenticate BEFORE parsing the payload: an unauthenticated caller
    // must get 401/403 whatever it sends, never a 400 that tells it the
    // endpoint is alive and which part of its body was wrong.
    let vm = current_worker(&state, &headers).await?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;

    // Recover from OFFLINE on a fresh heartbeat.
    let recovered = vm.state == VMState::Offline;
    if recovered {
        crate::services::notifications::notify_vm_recovered(&state.pool, &vm).await;
    }

    crate::models::vm::update_heartbeat(&state.pool, vm.id, Utc::now())
        .await
        .map_err(db_err)?;
    // The engine state the worker reports (migrations/0009): a node with no
    // engine reports an explicit null, which the dashboard shows as "not
    // installed". A worker that does not report at all leaves the stored
    // state untouched (the field is absent).
    if let Some(reported) = &body.browser_engine_version {
        crate::models::vm::update_browser_engine_state(
            &state.pool,
            vm.id,
            reported.as_deref(),
            Utc::now(),
        )
        .await
        .map_err(db_err)?;
    }
    if body.worker_version.is_some() || body.ip_address.is_some() || body.os_info.is_some() {
        crate::models::vm::update(
            &state.pool,
            vm.id,
            VmPatch {
                worker_version: body.worker_version.clone(),
                ip_address: body.ip_address.clone(),
                os_info: body.os_info.clone(),
                ..Default::default()
            },
        )
        .await
        .map_err(db_err)?;
    }
    if recovered {
        crate::models::vm::set_state(&state.pool, vm.id, VMState::Active)
            .await
            .map_err(db_err)?;
        // Python then commits and notifies "vm_recovered" (best-effort
        // webhook); that notification module lands later — see
        // INTEGRATION_NOTES.md.
    }

    let row = crate::models::setting::get_settings_row(&state.pool)
        .await
        .map_err(db_err)?;
    let (target, allowed_domains) = match &row {
        Some(row) => (
            row.target_worker_version.clone(),
            row.allowed_release_domains_vec(),
        ),
        None => (state.config.target_worker_version.clone(), Vec::new()),
    };

    // Auto-update: if enabled and the worker is on a different version, queue an
    // update task (unless one is already in flight). Best-effort — never blocks
    // or fails the heartbeat.
    if let Some(row) = &row {
        if row.auto_update_enabled {
            if let Some(worker_version) = &body.worker_version {
                if *worker_version != target {
                    auto_queue_update(&state, &vm, &target, row, &allowed_domains).await;
                }
            }
        }
    }

    Ok(Json(HeartbeatResponse {
        target_worker_version: target,
        exec_mode: vm.exec_mode.as_str().to_owned(),
        allowed_release_domains: allowed_domains,
    }))
}

/// Best-effort auto-update task creation (never fails the heartbeat).
async fn auto_queue_update(
    state: &WorkerState,
    vm: &VM,
    target: &str,
    row: &crate::models::setting::Setting,
    allowed_domains: &[String],
) {
    let result: Result<(), String> = async {
        if crate::models::task::has_inflight_update(&state.pool, vm.id)
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(());
        }
        let urls = crate::services::versioning::build_release_urls(
            &row.target_release_repo,
            target,
            vm.arch,
            crate::services::versioning::WorkerOs::from_vm(vm),
            allowed_domains,
        )?;
        let new = UpdateTaskNew {
            vm_id: vm.id,
            target_version: target.to_owned(),
            urls,
            created_by: "auto-update".to_owned(),
        };
        crate::models::task::create_update_task(&state.pool, new)
            .await
            .map_err(|e| e.to_string())?;
        // The task is committed and visible: now the wake may fire.
        state.events.notify_queue_on_commit(&vm.id.to_string());
        Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::warn!("auto-update for vm {} failed: {}", vm.id, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::WorkerArch;

    #[test]
    fn heartbeat_validation_requires_ip_literals() {
        let ok = HeartbeatRequest {
            worker_version: Some("v1.2.3".into()),
            ip_address: Some("192.168.1.9".into()),
            browser_engine_version: None,
            os_info: None,
        };
        assert!(ok.validate().is_ok());
        let bad = HeartbeatRequest {
            worker_version: None,
            ip_address: Some("<script>".into()),
            browser_engine_version: None,
            os_info: None,
        };
        assert!(bad.validate().is_err());
    }

    /// The engine state is only trusted when it is a printable, bounded
    /// version tag.
    #[test]
    fn heartbeat_validation_checks_the_engine_version() {
        let ok = HeartbeatRequest {
            worker_version: None,
            ip_address: None,
            browser_engine_version: Some(Some("v0.2.5".into())),
            os_info: None,
        };
        assert!(ok.validate().is_ok());
        // Explicitly "no engine" is valid.
        let none = HeartbeatRequest {
            worker_version: None,
            ip_address: None,
            browser_engine_version: Some(None),
            os_info: None,
        };
        assert!(none.validate().is_ok());
        // A version with a space or a control character is refused.
        let bad = HeartbeatRequest {
            worker_version: None,
            ip_address: None,
            browser_engine_version: Some(Some("v0.2.5\nrm -rf /".into())),
            os_info: None,
        };
        assert!(bad.validate().is_err());
        let empty = HeartbeatRequest {
            worker_version: None,
            ip_address: None,
            browser_engine_version: Some(Some(String::new())),
            os_info: None,
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn heartbeat_accepts_bounded_os_details_and_rejects_invalid_shapes() {
        let valid = HeartbeatRequest {
            os_info: Some(serde_json::json!({
                "os": "windows",
                "arch": "amd64",
                "system": "Windows 11 Pro · 24H2 (build 26100)"
            })),
            ..Default::default()
        };
        assert!(valid.validate().is_ok());

        let invalid = HeartbeatRequest {
            os_info: Some(serde_json::json!([])),
            ..Default::default()
        };
        assert!(invalid.validate().is_err());

        let too_long = HeartbeatRequest {
            os_info: Some(serde_json::json!({"system": "x".repeat(257)})),
            ..Default::default()
        };
        assert!(too_long.validate().is_err());
    }

    // ---- release URLs ------------------------------------------------------

    #[test]
    fn release_urls_match_the_python_builder() {
        let domains = vec!["github.com".into(), "objects.githubusercontent.com".into()];
        let urls = crate::services::versioning::build_release_urls(
            "example/huginn",
            "v1.2.3",
            WorkerArch::Amd64,
            crate::services::versioning::WorkerOs::Linux,
            &domains,
        )
        .unwrap();
        assert_eq!(
            urls["binary_url"],
            "https://github.com/example/huginn/releases/download/v1.2.3/huginn-worker-linux-amd64"
        );
        assert_eq!(
            urls["checksums_url"],
            "https://github.com/example/huginn/releases/download/v1.2.3/checksums.txt"
        );
        assert_eq!(urls["asset_name"], "huginn-worker-linux-amd64");
        assert_eq!(urls["version"], "v1.2.3");

        let windows = crate::services::versioning::build_release_urls(
            "example/huginn",
            "v1.2.3",
            WorkerArch::Amd64,
            crate::services::versioning::WorkerOs::Windows,
            &domains,
        )
        .unwrap();
        assert_eq!(
            windows["binary_url"],
            "https://github.com/example/huginn/releases/download/v1.2.3/huginn-worker-windows-amd64.exe"
        );
        assert_eq!(windows["asset_name"], "huginn-worker-windows-amd64.exe");

        let self_hosted = crate::services::versioning::build_release_urls(
            "https://hub.example.com/dist/",
            "v2.0.0",
            WorkerArch::Arm64,
            crate::services::versioning::WorkerOs::Linux,
            &["hub.example.com".into()],
        )
        .unwrap();
        assert_eq!(
            self_hosted["binary_url"],
            "https://hub.example.com/dist/huginn-worker-linux-arm64"
        );

        let windows_self_hosted = crate::services::versioning::build_release_urls(
            "https://hub.example.com/dist/",
            "v2.0.0",
            WorkerArch::Amd64,
            crate::services::versioning::WorkerOs::Windows,
            &["hub.example.com".into()],
        )
        .unwrap();
        assert_eq!(
            windows_self_hosted["binary_url"],
            "https://hub.example.com/dist/huginn-worker-windows-amd64.exe"
        );
        assert_eq!(
            self_hosted["checksums_url"],
            "https://hub.example.com/dist/checksums.txt"
        );
    }

    #[test]
    fn release_urls_enforce_the_allowlist_and_shapes() {
        let domains = vec!["github.com".into()];
        assert!(crate::services::versioning::build_release_urls(
            "example/huginn",
            "v1.2.3",
            WorkerArch::Amd64,
            crate::services::versioning::WorkerOs::Linux,
            &domains
        )
        .is_ok());
        assert!(
            crate::services::versioning::build_release_urls(
                "example/huginn",
                "v1.2.3;rm -rf",
                WorkerArch::Amd64,
                crate::services::versioning::WorkerOs::Linux,
                &domains
            )
            .is_err(),
            "metacharacters in version"
        );
        assert!(
            crate::services::versioning::build_release_urls(
                "../etc/passwd",
                "v1",
                WorkerArch::Amd64,
                crate::services::versioning::WorkerOs::Linux,
                &domains
            )
            .is_err(),
            "invalid repo"
        );
        assert!(
            crate::services::versioning::build_release_urls(
                "https://evil.example.com/dist",
                "v1",
                WorkerArch::Amd64,
                crate::services::versioning::WorkerOs::Linux,
                &domains
            )
            .is_err(),
            "host not in allowlist"
        );
        assert!(
            crate::services::versioning::build_release_urls(
                "example/huginn",
                "v1",
                WorkerArch::Amd64,
                crate::services::versioning::WorkerOs::Linux,
                &[]
            )
            .is_err(),
            "empty allowlist rejects everything"
        );
    }
}

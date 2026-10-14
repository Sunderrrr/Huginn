//! Worker-facing API (`/api/worker`) — port of `hub/app/api/routes/worker.py`.
//!
//! | route                              | Python handler            |
//! |------------------------------------|---------------------------|
//! | `POST /api/worker/enroll`          | `enroll`                  |
//! | `POST /api/worker/heartbeat`       | `heartbeat`               |
//! | `GET  /api/worker/tasks/next`      | `next_task` (long-poll)   |
//! | `POST /api/worker/tasks/{id}/result` | `submit_result`         |
//!
//! Also ported here: worker authentication (`app/api/deps.py:current_worker`,
//! headers `X-Worker-Id`/`X-Worker-Secret` with a timing-safe secret check),
//! the TLS refusal (`worker.py:_enforce_tls`), the worker-facing request
//! schemas (`app/schemas/{enrollment,task}.py`), the request-body caps
//! (`app/main.py` global cap + `deps.enforce_body_size`'s 64 KB) and a minimal
//! fixed-window rate limiter (`app/core/ratelimit.py`) for the unauthenticated
//! enrollment endpoint.
//!
//! Task-creation services in the Python hub register queue wakes through
//! `task_events.notify_queue_on_commit`; since the Rust data layer commits
//! inside each call, the wake is fired here right after the creating call
//! returns — the exact "wake once the task is visible" ordering (see
//! `services::task_events`).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{
    rejection::JsonRejection, ConnectInfo, DefaultBodyLimit, Extension, OriginalUri, Path, Query,
    State,
};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::error::ApiError;
use crate::models::enrollment::EnrollVmParams;
use crate::models::task::{ActionTaskNew, SubmitResult, Task, UpdateTaskNew};
use crate::models::vm::{VmPatch, VM};
use crate::models::{TaskStatus, TaskType, VMState, WorkerArch};
use crate::security::SecurityConfig;
use crate::services::task_events::TaskEvents;

/// Long-poll cap (`worker.py:_MAX_WAIT_SECONDS`): a worker asking for more
/// still parks at most this long per request.
pub const MAX_WAIT_SECONDS: f64 = 25.0;

/// Pydantic `TaskResultSubmit` per-field bound (2× the truncation cap).
const MAX_RESULT_FIELD_CHARS: usize = 2_097_152;

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/enrollment.py + app/schemas/task.py)
// ---------------------------------------------------------------------------

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
        validate_os_info(&self.os_info)?;
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

/// `HeartbeatRequest`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub worker_version: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
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

/// `WorkerTask` — a task as handed to a worker for execution.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerTask {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub task_type: TaskType,
    pub action_name: Option<String>,
    pub payload: serde_json::Value,
}

impl From<Task> for WorkerTask {
    fn from(task: Task) -> Self {
        Self {
            id: task.id,
            task_type: task.task_type,
            action_name: task.action_name,
            payload: task.payload,
        }
    }
}

/// `TaskResultSubmit`.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskResultSubmit {
    pub status: TaskStatus,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout: Option<String>,
    #[serde(default)]
    pub stderr: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl TaskResultSubmit {
    fn validate(&self) -> Result<(), ApiError> {
        for (field, value) in [
            ("stdout", &self.stdout),
            ("stderr", &self.stderr),
            ("error", &self.error),
        ] {
            if let Some(v) = value {
                if v.chars().count() > MAX_RESULT_FIELD_CHARS {
                    return Err(ApiError::unprocessable_entity(format!(
                        "{field} must be at most {MAX_RESULT_FIELD_CHARS} characters"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Query for `GET /tasks/next` (`wait` defaults to 0.0, like the Python
/// handler's signature).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct NextTaskQuery {
    #[serde(default)]
    pub wait: f64,
}

fn validate_ip_literal(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::unprocessable_entity(
            "ip_address must be a valid IP literal",
        ));
    }
    Ok(())
}

/// `_validate_os_info`: at most 20 keys, keys ≤ 64 chars, string values ≤ 256.
fn validate_os_info(value: &serde_json::Value) -> Result<(), ApiError> {
    let Some(obj) = value.as_object() else {
        return Err(ApiError::unprocessable_entity(
            "os_info must be an object (dict)",
        ));
    };
    if obj.len() > 20 {
        return Err(ApiError::unprocessable_entity(
            "os_info has too many keys (max 20)",
        ));
    }
    for (k, v) in obj {
        if k.chars().count() > 64 {
            return Err(ApiError::unprocessable_entity(
                "os_info keys must be strings <= 64 chars",
            ));
        }
        if let Some(s) = v.as_str() {
            if s.chars().count() > 256 {
                return Err(ApiError::unprocessable_entity(
                    "os_info string values must be <= 256 chars",
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// State + router
// ---------------------------------------------------------------------------

/// Everything the worker routes need. Cheap to clone.
#[derive(Debug, Clone)]
pub struct WorkerState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub security: SecurityConfig,
    pub events: Arc<TaskEvents>,
    enroll_limiter: RateLimiter,
}

impl WorkerState {
    pub fn new(pool: sqlx::PgPool, config: Config) -> Self {
        let security = SecurityConfig::new(
            &config.mfa_encryption_key,
            &config.jwt_secret,
            &config.secret_hash_key,
        );
        let enroll_limiter = RateLimiter::new(config.rate_limit_exec_per_minute);
        Self {
            pool,
            config,
            security,
            events: TaskEvents::new(),
            enroll_limiter,
        }
    }
}

/// The `/api/worker` router (prefix included, so it can be merged as-is).
pub fn router(state: WorkerState) -> Router {
    // Global request-body cap, sized like `app/main.py`: the largest legitimate
    // body is a worker result carrying stdout+stderr each up to
    // `max_output_bytes`.
    let global_cap = state.config.max_output_bytes * 2 + 65_536;
    Router::new()
        .route("/api/worker/enroll", post(enroll))
        .route("/api/worker/heartbeat", post(heartbeat))
        .route("/api/worker/tasks/next", get(next_task))
        .route("/api/worker/tasks/{id}/result", post(submit_task_result))
        .layer(DefaultBodyLimit::max(global_cap))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/worker/enroll` — authenticate with the enrollment token and
/// register a new worker (201 with the one-time per-worker secret).
async fn enroll(
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

/// `POST /api/worker/heartbeat` — worker liveness + version report; returns
/// the desired target version.
async fn heartbeat(
    State(state): State<WorkerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Result<Json<HeartbeatRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    enforce_tls(&headers, &uri, &state.config)?;
    enforce_body_size(&headers, state.config.max_body_bytes)?;
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    let vm = current_worker(&state, &headers).await?;

    // Recover from OFFLINE on a fresh heartbeat.
    let recovered = vm.state == VMState::Offline;

    crate::models::vm::update_heartbeat(&state.pool, vm.id, Utc::now())
        .await
        .map_err(db_err)?;
    if body.worker_version.is_some() || body.ip_address.is_some() {
        crate::models::vm::update(
            &state.pool,
            vm.id,
            VmPatch {
                worker_version: body.worker_version.clone(),
                ip_address: body.ip_address.clone(),
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
        let urls = build_release_urls(&row.target_release_repo, target, vm.arch, allowed_domains)?;
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

/// `GET /api/worker/tasks/next` — hand the worker its next queued task.
///
/// With `wait>0` this long-polls: if the queue is empty it parks on the
/// in-process queue event (`services::task_events`) that fires the moment a
/// task for this VM becomes claimable, so pickup is instant and idle workers
/// cost zero database queries. After `wait` seconds (capped at
/// [`MAX_WAIT_SECONDS`]) without a task, `null` is returned.
///
/// Subscribe before the first claim so a task committed in the gap still wakes
/// us. If several workers of the same VM are parked, every wake re-claims and
/// `claim_next_task` (`FOR UPDATE SKIP LOCKED`) stays the transactional
/// arbiter: the first claim wins, the others find nothing and re-park.
async fn next_task(
    State(state): State<WorkerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    query: Result<Query<NextTaskQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<impl IntoResponse, ApiError> {
    enforce_tls(&headers, &uri, &state.config)?;
    let vm = current_worker(&state, &headers).await?;
    let query = query.map_err(|e| ApiError::unprocessable_entity(e.body_text()))?;
    let wait = clamp_wait(query.wait);

    // The long-poll records the heartbeat up front (Python sets
    // `vm.last_heartbeat_at` and commits the session inside the loop).
    crate::models::vm::update_heartbeat(&state.pool, vm.id, Utc::now())
        .await
        .map_err(db_err)?;

    let vm_id = vm.id;
    let task = long_poll(
        &state.events,
        &vm_id.to_string(),
        Duration::from_secs_f64(wait),
        Duration::from_secs_f64(MAX_WAIT_SECONDS),
        || {
            let pool = state.pool.clone();
            async move {
                crate::models::task::claim_next_task(&pool, vm_id)
                    .await
                    .map_err(db_err)
            }
        },
    )
    .await?;

    Ok(Json(task.map(WorkerTask::from)))
}

/// `POST /api/worker/tasks/{id}/result` — record a task result (204).
async fn submit_task_result(
    State(state): State<WorkerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    body: Result<Json<TaskResultSubmit>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    enforce_tls(&headers, &uri, &state.config)?;
    // The result body legitimately carries up to max_output_bytes per field;
    // only the global body cap (router layer) applies here.
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    // Path shape validation before auth (FastAPI validates params first).
    let task_id: Uuid = task_id
        .parse()
        .map_err(|_| ApiError::unprocessable_entity("task id must be a valid UUID"))?;
    let vm = current_worker(&state, &headers).await?;

    let res = SubmitResult {
        task_id,
        vm_id: vm.id,
        status: body.status,
        exit_code: body.exit_code,
        stdout: body.stdout.clone(),
        stderr: body.stderr.clone(),
        error: body.error.clone(),
        output_cap_bytes: state.config.max_output_bytes,
    };
    let task = crate::models::task::submit_result(&state.pool, res)
        .await
        .map_err(db_err)?;
    let Some(task) = task else {
        return Err(ApiError::not_found("task not found for this worker"));
    };

    // The result is committed (the data layer commits per call): now wake
    // anyone blocked in wait_for_terminal (e.g. an agent that called
    // /tasks/{id}/wait or an execute with wait=true).
    state.events.notify(&task_id.to_string());
    // A result that re-queues the task (status=pending) makes it claimable
    // again — wake this VM's parked long-polls too. The Python port gets this
    // from `notify_queue_on_commit` at task creation; the wake is only valid
    // once the re-queued row is committed, which it now is.
    if task.status == TaskStatus::Pending {
        state.events.notify_queue_on_commit(&vm.id.to_string());
    }
    // Push a live hint to connected dashboards (events.publish({"type":
    // "tasks"})) and notify external integrations on failure — both hook into
    // modules landing later, see INTEGRATION_NOTES.md.

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// The event-driven long-poll (testable state machine)
// ---------------------------------------------------------------------------

/// Hand out the next task for `vm_id`, parking up to `min(wait, max_wait)` on
/// the queue wake when the queue is empty. Returns `None` when the wait
/// expires without a claimable task.
///
/// `claim` is the transactional arbiter (e.g. `models::task::claim_next_task`):
/// it is called once up front and again after every wake. It runs its own short
/// transaction, so the read snapshot is dropped between checks — the reason the
/// Python loop calls `session.commit()` before parking.
pub(crate) async fn long_poll<T, F, Fut>(
    events: &Arc<TaskEvents>,
    vm_id: &str,
    wait: Duration,
    max_wait: Duration,
    mut claim: F,
) -> Result<Option<T>, ApiError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>, ApiError>>,
{
    // Subscribe BEFORE the first claim so a task committed in the gap still
    // wakes us instead of stalling until the wait elapses.
    let wake = events.subscribe_queue(vm_id);
    let mut task = claim().await?;
    let deadline = Instant::now() + wait.min(max_wait);
    while task.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if !wake.wait(remaining).await {
            break; // timed out
        }
        wake.clear(); // consume this wake round, like `wake.clear()` in Python
        task = claim().await?;
    }
    drop(wake); // unsubscribe (Python's `finally: unsubscribe_queue`)
    Ok(task)
}

/// `min(wait, MAX_WAIT_SECONDS)`, clamped to a sane non-negative value so a
/// negative/NaN `wait` degrades to "claim once" instead of panicking.
fn clamp_wait(wait: f64) -> f64 {
    if !wait.is_finite() {
        return 0.0;
    }
    wait.clamp(0.0, MAX_WAIT_SECONDS)
}

// ---------------------------------------------------------------------------
// Worker auth + request enforcement (app/api/deps.py + worker.py)
// ---------------------------------------------------------------------------

/// Authenticate a worker by its VM id + per-worker secret (timing-safe).
///
/// Mirrors `deps.current_worker`: 401 for missing/invalid credentials (the
/// secret is verified even when the VM is missing, so timing does not leak
/// existence), 403 for workers that are not approved yet.
async fn current_worker(state: &WorkerState, headers: &HeaderMap) -> Result<VM, ApiError> {
    let worker_id = header_str(headers, "x-worker-id").filter(|s| !s.is_empty());
    let worker_secret = header_str(headers, "x-worker-secret").filter(|s| !s.is_empty());
    let (Some(worker_id), Some(worker_secret)) = (worker_id, worker_secret) else {
        return Err(ApiError::unauthorized("worker credentials required"));
    };
    let Ok(vm_id) = worker_id.parse::<Uuid>() else {
        return Err(ApiError::unauthorized("invalid worker id"));
    };

    let vm = crate::models::vm::get_by_id(&state.pool, vm_id)
        .await
        .map_err(db_err)?;
    // Verify the secret even when the VM is missing to avoid leaking existence
    // via timing; verify_secret on a None hash is constant-ish and returns false.
    let secret_ok = state.security.verify_secret(
        worker_secret,
        vm.as_ref().and_then(|v| v.worker_secret_hash.as_deref()),
    );
    let Some(vm) = vm.filter(|_| secret_ok) else {
        return Err(ApiError::unauthorized("worker authentication failed"));
    };
    if !matches!(vm.state, VMState::Active | VMState::Offline) {
        // PENDING/REVOKED workers may not interact beyond enrollment.
        return Err(ApiError::forbidden("worker not approved"));
    }
    Ok(vm)
}

/// In prod, refuse plaintext hub<->worker traffic (`worker.py:_enforce_tls`).
fn enforce_tls(headers: &HeaderMap, uri: &Uri, config: &Config) -> Result<(), ApiError> {
    if !config.require_tls {
        return Ok(());
    }
    let forwarded = header_str(headers, "x-forwarded-proto")
        .map(|v| {
            v.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let scheme = if forwarded.is_empty() {
        uri.scheme()
            .map(|s| s.as_str())
            .unwrap_or("http")
            .to_ascii_lowercase()
    } else {
        forwarded
    };
    if scheme != "https" {
        return Err(ApiError::bad_request(
            "TLS is required for worker communication",
        ));
    }
    Ok(())
}

/// Reject oversized request bodies early (`deps.enforce_body_size`).
fn enforce_body_size(headers: &HeaderMap, max_body_bytes: usize) -> Result<(), ApiError> {
    if let Some(cl) = header_str(headers, "content-length") {
        if let Ok(len) = cl.trim().parse::<usize>() {
            if len > max_body_bytes {
                return Err(ApiError::payload_too_large("request body too large"));
            }
        }
    }
    Ok(())
}

/// Best-effort real client IP (`deps.client_ip`): when `trust_forwarded_for`
/// is set the first hop of `X-Forwarded-For` (the original client), otherwise
/// the peer address. The header is only honoured when explicitly trusted,
/// since clients could otherwise spoof it.
fn client_ip(headers: &HeaderMap, config: &Config, peer: Option<SocketAddr>) -> Option<String> {
    if config.trust_forwarded_for {
        if let Some(forwarded) = header_str(headers, "x-forwarded-for") {
            if let Some(first) = forwarded.split(',').map(str::trim).find(|s| !s.is_empty()) {
                return Some(first.to_owned());
            }
        }
    }
    peer.map(|p| p.ip().to_string())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Axum JSON rejections mapped onto FastAPI semantics: oversized bodies are
/// 413 ("request body too large", like the global body cap middleware), every
/// parse/shape failure is 422 (pydantic's status).
fn map_json_rejection(err: JsonRejection) -> ApiError {
    if err.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large("request body too large")
    } else {
        ApiError::unprocessable_entity(err.body_text())
    }
}

fn db_err(err: DbError) -> ApiError {
    ApiError::internal(err.to_string())
}

// ---------------------------------------------------------------------------
// Minimal rate limiter (app/core/ratelimit.py)
// ---------------------------------------------------------------------------

/// In-process fixed-window rate limiter. Sufficient for a single hub instance;
/// for a horizontally-scaled deployment back this with Redis.
type BucketMap =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, (Instant, u32)>>>;

#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    buckets: BucketMap,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_window: max_per_minute,
            window: Duration::from_secs(60),
            buckets: Arc::default(),
        }
    }

    /// Consume one slot for `key`; false when the window's budget is spent.
    pub fn allow(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let (start, count) = buckets.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(*start) >= self.window {
            *start = now;
            *count = 0;
        }
        if *count >= self.max_per_window {
            return false;
        }
        *count += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// Release URL construction (app/services/versioning.py)
// ---------------------------------------------------------------------------

/// SSRF-validated release URL object for update tasks — port of
/// `versioning.build_release_urls` (GitHub `owner/repo` mode or self-hosted
/// base-URL mode). This is the `urls` value `models::task::UpdateTaskNew`
/// expects; it should move to a shared `services::versioning` module when that
/// lands (INTEGRATION_NOTES.md).
fn build_release_urls(
    repo: &str,
    version: &str,
    arch: WorkerArch,
    allowed_domains: &[String],
) -> Result<serde_json::Value, String> {
    fn asset_name(arch: WorkerArch) -> String {
        format!("huginn-worker-linux-{}", arch.as_str())
    }
    if !valid_version(version) {
        return Err(format!("invalid version: {version:?}"));
    }
    let urls = if let Some(base) = repo
        .strip_prefix("https://")
        .or(repo.strip_prefix("http://"))
    {
        // Self-hosted mode: repo is a base URL.
        let scheme = if repo.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        let base = format!("{scheme}://{base}");
        let base = base.trim_end_matches('/');
        serde_json::json!({
            "binary_url": format!("{base}/{}", asset_name(arch)),
            "checksums_url": format!("{base}/checksums.txt"),
            "asset_name": asset_name(arch),
            "version": version,
        })
    } else {
        // GitHub releases mode: repo is owner/repo.
        if !valid_repo(repo) {
            return Err(format!("invalid repo: {repo:?}"));
        }
        let base = format!("https://github.com/{repo}/releases/download/{version}");
        serde_json::json!({
            "binary_url": format!("{base}/{}", asset_name(arch)),
            "checksums_url": format!("{base}/checksums.txt"),
            "asset_name": asset_name(arch),
            "version": version,
        })
    };
    validate_url_host(urls["binary_url"].as_str().unwrap(), allowed_domains)?;
    validate_url_host(urls["checksums_url"].as_str().unwrap(), allowed_domains)?;
    Ok(urls)
}

/// "owner/repo" — no path traversal, no userinfo, no metacharacters.
fn valid_repo(repo: &str) -> bool {
    let parts: Vec<&str> = repo.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        })
}

/// A tag like "v1.2.3" — same character class as `versioning._VERSION_RE`.
fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-'))
}

/// Every release URL host must be on the allowlist (defense in depth; the
/// worker enforces the same list on its side).
fn validate_url_host(url: &str, allowed_domains: &[String]) -> Result<(), String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(format!("release URL must be http or https: {url:?}"));
    };
    if scheme != "https" && scheme != "http" {
        return Err(format!("release URL must be http or https: {url:?}"));
    }
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    if !allowed_domains
        .iter()
        .any(|d| d.trim().to_ascii_lowercase() == host)
    {
        return Err(format!("release host {host:?} not in allowlist"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    fn test_state(require_tls: bool) -> WorkerState {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let config = Config {
            require_tls,
            ..Config::default()
        };
        WorkerState::new(pool, config)
    }

    fn json_request(method: &str, uri: &str, body: serde_json::Value) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-forwarded-proto", "https")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(json!(null))
    }

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

    #[test]
    fn result_fields_are_capped_at_two_mebibytes() {
        let mut body = TaskResultSubmit {
            status: TaskStatus::Succeeded,
            exit_code: Some(0),
            stdout: Some("ok".into()),
            stderr: None,
            error: None,
        };
        assert!(body.validate().is_ok());
        body.stdout = Some("x".repeat(MAX_RESULT_FIELD_CHARS + 1));
        assert!(body.validate().is_err());
    }

    #[test]
    fn heartbeat_validation_requires_ip_literals() {
        let ok = HeartbeatRequest {
            worker_version: Some("v1.2.3".into()),
            ip_address: Some("192.168.1.9".into()),
        };
        assert!(ok.validate().is_ok());
        let bad = HeartbeatRequest {
            worker_version: None,
            ip_address: Some("<script>".into()),
        };
        assert!(bad.validate().is_err());
    }

    // ---- enforcement helpers ----------------------------------------------

    #[test]
    fn enforce_tls_matches_the_python_helper() {
        let config = Config {
            require_tls: true,
            ..Config::default()
        };
        let uri = Uri::from_static("http://hub/api/worker/heartbeat");

        let mut headers = HeaderMap::new();
        assert!(
            enforce_tls(&headers, &uri, &config).is_err(),
            "no proto → http → refused"
        );

        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(enforce_tls(&headers, &uri, &config).is_ok());

        headers.insert("x-forwarded-proto", "https, http".parse().unwrap());
        assert!(
            enforce_tls(&headers, &uri, &config).is_ok(),
            "first hop wins"
        );

        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(enforce_tls(&headers, &uri, &config).is_err());

        headers.insert("x-forwarded-proto", "HTTPS".parse().unwrap());
        assert!(
            enforce_tls(&headers, &uri, &config).is_ok(),
            "case-insensitive"
        );

        let dev = Config {
            require_tls: false,
            ..Config::default()
        };
        assert!(enforce_tls(&HeaderMap::new(), &uri, &dev).is_ok());
    }

    #[test]
    fn client_ip_honours_trust_forwarded_for() {
        let mut config = Config::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.7, 172.16.0.2".parse().unwrap(),
        );
        let peer: SocketAddr = "10.0.0.1:4321".parse().unwrap();

        config.trust_forwarded_for = true;
        assert_eq!(
            client_ip(&headers, &config, Some(peer)).as_deref(),
            Some("203.0.113.7")
        );
        config.trust_forwarded_for = false;
        assert_eq!(
            client_ip(&headers, &config, Some(peer)).as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(client_ip(&headers, &config, None), None);
    }

    #[test]
    fn body_cap_rejects_oversized_content_length() {
        let mut headers = HeaderMap::new();
        assert!(enforce_body_size(&headers, 65_536).is_ok());
        headers.insert("content-length", "65536".parse().unwrap());
        assert!(
            enforce_body_size(&headers, 65_536).is_ok(),
            "at the cap is fine"
        );
        headers.insert("content-length", "65537".parse().unwrap());
        let err = enforce_body_size(&headers, 65_536).unwrap_err();
        assert_eq!(err.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn rate_limiter_is_a_fixed_window() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.allow("ip"));
        assert!(limiter.allow("ip"));
        assert!(limiter.allow("ip"));
        assert!(!limiter.allow("ip"), "budget spent");
        assert!(limiter.allow("other"), "budgets are per key");
    }

    // ---- release URLs ------------------------------------------------------

    #[test]
    fn release_urls_match_the_python_builder() {
        let domains = vec!["github.com".into(), "objects.githubusercontent.com".into()];
        let urls =
            build_release_urls("Sunderrrr/Huginn", "v1.2.3", WorkerArch::Amd64, &domains).unwrap();
        assert_eq!(
            urls["binary_url"],
            "https://github.com/Sunderrrr/Huginn/releases/download/v1.2.3/huginn-worker-linux-amd64"
        );
        assert_eq!(
            urls["checksums_url"],
            "https://github.com/Sunderrrr/Huginn/releases/download/v1.2.3/checksums.txt"
        );
        assert_eq!(urls["asset_name"], "huginn-worker-linux-amd64");
        assert_eq!(urls["version"], "v1.2.3");

        let self_hosted = build_release_urls(
            "https://hub.example.com/dist/",
            "v2.0.0",
            WorkerArch::Arm64,
            &["hub.example.com".into()],
        )
        .unwrap();
        assert_eq!(
            self_hosted["binary_url"],
            "https://hub.example.com/dist/huginn-worker-linux-arm64"
        );
        assert_eq!(
            self_hosted["checksums_url"],
            "https://hub.example.com/dist/checksums.txt"
        );
    }

    #[test]
    fn release_urls_enforce_the_allowlist_and_shapes() {
        let domains = vec!["github.com".into()];
        assert!(
            build_release_urls("Sunderrrr/Huginn", "v1.2.3", WorkerArch::Amd64, &domains).is_ok()
        );
        assert!(
            build_release_urls(
                "Sunderrrr/Huginn",
                "v1.2.3;rm -rf",
                WorkerArch::Amd64,
                &domains
            )
            .is_err(),
            "metacharacters in version"
        );
        assert!(
            build_release_urls("../etc/passwd", "v1", WorkerArch::Amd64, &domains).is_err(),
            "invalid repo"
        );
        assert!(
            build_release_urls(
                "https://evil.example.com/dist",
                "v1",
                WorkerArch::Amd64,
                &domains
            )
            .is_err(),
            "host not in allowlist"
        );
        assert!(
            build_release_urls("Sunderrrr/Huginn", "v1", WorkerArch::Amd64, &[]).is_err(),
            "empty allowlist rejects everything"
        );
    }

    // ---- long-poll state machine -------------------------------------------

    fn no_error<T>(
        value: Option<T>,
    ) -> impl FnMut() -> std::future::Ready<Result<Option<T>, ApiError>> {
        let mut value = Some(value);
        move || std::future::ready(Ok(value.take().flatten()))
    }

    #[tokio::test]
    async fn long_poll_claims_once_when_a_task_is_available() {
        let events = TaskEvents::new();
        let claims = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task = long_poll(
            &events,
            "vm-1",
            Duration::from_secs(5),
            Duration::from_secs(5),
            {
                let claims = Arc::clone(&claims);
                move || {
                    claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Ok(Some("task")) }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(task, Some("task"));
        assert_eq!(claims.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn long_poll_wakes_on_queue_event_and_reclaims() {
        let events = TaskEvents::new();
        let queue = Arc::new(std::sync::Mutex::new(None::<&'static str>));
        let claims = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let driver = {
            let events = Arc::clone(&events);
            let queue = Arc::clone(&queue);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                // The task becomes visible with its COMMIT, then the wake fires
                // (notify_queue_on_commit discipline).
                *queue.lock().unwrap() = Some("task");
                events.notify_queue("vm-1");
            })
        };

        let task = long_poll(
            &events,
            "vm-1",
            Duration::from_secs(5),
            Duration::from_secs(5),
            {
                let queue = Arc::clone(&queue);
                let claims = Arc::clone(&claims);
                move || {
                    let n = claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let queue = Arc::clone(&queue);
                    // First claim misses (the task is not committed yet) — the
                    // wake is what makes it claimable.
                    async move {
                        Ok(if n == 0 {
                            None
                        } else {
                            queue.lock().unwrap().take()
                        })
                    }
                }
            },
        )
        .await
        .unwrap();

        driver.await.unwrap();
        assert_eq!(task, Some("task"));
        assert_eq!(
            claims.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "claim after the wake"
        );
    }

    #[tokio::test]
    async fn long_poll_times_out_with_none() {
        let events = TaskEvents::new();
        let claims = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Instant::now();
        let task: Option<&str> = long_poll(
            &events,
            "vm-1",
            Duration::from_millis(50),
            Duration::from_millis(50),
            {
                let claims = Arc::clone(&claims);
                move || {
                    claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Ok(None) }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(task, None);
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "parks the full wait"
        );
        assert_eq!(claims.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn long_poll_caps_the_wait_at_max_wait() {
        let events = TaskEvents::new();
        let started = Instant::now();
        let task: Option<&str> = long_poll(
            &events,
            "vm-1",
            Duration::from_secs(3600), // asks for an hour...
            Duration::from_millis(50), // ...but is capped
            no_error(None),
        )
        .await
        .unwrap();
        assert_eq!(task, None);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "returns at the cap"
        );
    }

    #[tokio::test]
    async fn long_poll_with_zero_wait_claims_exactly_once() {
        let events = TaskEvents::new();
        let claims = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task: Option<&str> = long_poll(&events, "vm-1", Duration::ZERO, Duration::ZERO, {
            let claims = Arc::clone(&claims);
            move || {
                claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move { Ok(None) }
            }
        })
        .await
        .unwrap();
        assert_eq!(task, None);
        assert_eq!(claims.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_long_polls_never_double_deliver_a_task() {
        // Two workers of one VM poll at once over a single queued task: the
        // claim is the transactional arbiter, so exactly one gets it.
        let events = TaskEvents::new();
        let queue = Arc::new(std::sync::Mutex::new(Some("task")));

        let poll = {
            let events = Arc::clone(&events);
            let queue = Arc::clone(&queue);
            move || {
                let events = Arc::clone(&events);
                let queue = Arc::clone(&queue);
                tokio::spawn(async move {
                    long_poll(
                        &events,
                        "vm-1",
                        Duration::from_millis(200),
                        Duration::from_millis(200),
                        {
                            let queue = Arc::clone(&queue);
                            move || {
                                let queue = Arc::clone(&queue);
                                async move { Ok(queue.lock().unwrap().take()) }
                            }
                        },
                    )
                    .await
                })
            }
        };

        let (a, b) = tokio::join!(poll(), poll());
        let results = [a.unwrap(), b.unwrap()];
        let winners = results
            .iter()
            .filter(|r| r.as_ref().unwrap().is_some())
            .count();
        assert_eq!(winners, 1, "exactly one worker receives the task");
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
        let state = test_state(false);
        state.enroll_limiter.allow("198.51.100.9");
        while state.enroll_limiter.allow("198.51.100.9") {}
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

    #[tokio::test]
    async fn worker_endpoints_require_credentials() {
        let app = router(test_state(false));
        let response = app
            .oneshot(json_request("POST", "/api/worker/heartbeat", json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "worker credentials required"})
        );
    }

    #[tokio::test]
    async fn malformed_worker_id_is_401() {
        let app = router(test_state(false));
        let mut request = json_request("POST", "/api/worker/heartbeat", json!({}));
        request
            .headers_mut()
            .insert("x-worker-id", "not-a-uuid".parse().unwrap());
        request
            .headers_mut()
            .insert("x-worker-secret", "s3cret".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "invalid worker id"})
        );
    }

    #[tokio::test]
    async fn tasks_next_requires_credentials() {
        let app = router(test_state(false));
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/api/worker/tasks/next?wait=1")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn result_route_validates_the_task_id_before_the_db() {
        let app = router(test_state(false));
        let mut request = json_request(
            "POST",
            "/api/worker/tasks/not-a-uuid/result",
            json!({"status": "succeeded"}),
        );
        request
            .headers_mut()
            .insert("x-worker-id", Uuid::new_v4().to_string().parse().unwrap());
        request
            .headers_mut()
            .insert("x-worker-secret", "s3cret".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        // Bad body → 422 before auth/DB; with a valid body this same request
        // would fall through to worker authentication.
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn clamp_wait_needs_no_awkward_values() {
        assert_eq!(clamp_wait(0.0), 0.0);
        assert_eq!(clamp_wait(5.0), 5.0);
        assert_eq!(clamp_wait(1_000.0), MAX_WAIT_SECONDS);
        assert_eq!(clamp_wait(-3.0), 0.0);
        assert_eq!(clamp_wait(f64::NAN), 0.0);
    }
}

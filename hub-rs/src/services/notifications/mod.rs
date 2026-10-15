//! Best-effort outbound notifications for fleet events (port of
//! `hub/app/services/notifications.py`) — Discord webhook + generic webhook.
//!
//! A webhook outage must never break the sweep loop, a heartbeat or a worker
//! result submission: every failure is logged as a warning and swallowed, and
//! each call is hard-bounded by [`NOTIFY_BUDGET`] (5 s wall clock for the
//! settings read *and* every delivery). The public functions return `()` and
//! cannot fail.
//!
//! # PUBLIC API — call sites for the assembly layer
//!
//! ```ignore
//! // 1. sweep: a VM just went OFFLINE (models::vm::sweep_offline_vms returned it)
//! //    e.g. in the offline sweeper, after the sweep commits:
//! //        for vm in &transitioned {
//! //            notifications::notify_vm_offline(pool, vm).await;
//! //        }
//! pub async fn notify_vm_offline(pool: &PgPool, vm: &VM);
//!
//! // 2. heartbeat: an OFFLINE VM is back (state observed offline -> active)
//! //    e.g. at the end of POST /api/worker/heartbeat once the state flip commits
//! pub async fn notify_vm_recovered(pool: &PgPool, vm: &VM);
//!
//! // 3. submit_result: a failed task result (status ∈ failed | timeout | dead_letter)
//! //    e.g. at the end of POST /api/worker/tasks/{id}/result
//! pub async fn notify_task_failure(pool: &PgPool, vm: &VM, task: &Task);
//! ```
//!
//! Each call reads the `settings` singleton row exactly once (no cache), checks
//! `notifications_enabled` plus the per-event toggle (`notify_vm_offline`,
//! `notify_vm_recovered`, `notify_task_failure`), then fans out. `task` is the
//! task row *as updated by the result* (status/error/exit_code feed the
//! message); the call site decides which statuses are worth an alert — this
//! module sends whatever it is handed.
//!
//! The calls are `async` and awaited, but bounded: worst case 5 s and only when
//! a webhook hangs. For a strict zero-latency call site (e.g. the worker
//! heartbeat handler), spawn it:
//!
//! ```ignore
//! let (pool, vm) = (pool.clone(), vm.clone());
//! tokio::spawn(async move { notifications::notify_vm_recovered(&pool, &vm).await });
//! ```
//!
//! # Destinations
//!
//! - `discord_webhook_url` — Discord webhook `POST {"content": "<message>"}`
//!   (emoji + VM name + event + details, Discord-flavoured markdown).
//! - `generic_webhook_url` — structured JSON, key-for-key compatible with the
//!   Python hub so existing consumers keep working:
//!   `{"event": "vm_offline", "message": "...", "vm": {"id", "name"} | null,
//!   "task": {"id", "status"} | null, "ts": "<RFC 3339>"}`.
//!
//! Both may be set: the event goes to both (concurrently). Empty/whitespace
//! URLs mean "not configured" (the dashboard sends `""` when the field is
//! cleared).
//!
//! # URL policy (deliberate deviation from the Python hub)
//!
//! The Python hub POSTed to whatever URL was configured. Webhook URLs carry
//! secret tokens in their path (Discord) or query string, so this port accepts
//! **HTTPS only**, plus `http://` strictly for loopback hosts
//! (`127.0.0.0/8`, `localhost`, `::1`) — that is what the tests use. Any other
//! `http://` URL is refused with a warning (and nothing is sent); other
//! schemes are refused outright. Redirects are never followed (a 3xx would
//! hand the secret URL to another host).
//!
//! # Secret hygiene
//!
//! No secret ever reaches the logs: URLs are logged as `scheme://host` only
//! (see [`describe_url`]) and `reqwest` errors are stripped of their URL with
//! `without_url()` before being formatted.

use std::time::Duration;

use chrono::Utc;
use serde_json::Value;
use sqlx::PgPool;
use tracing::warn;

use crate::models::setting::{self, Setting};
use crate::models::task::Task;
use crate::models::vm::VM;

use self::discord::{discord_payload, message};
use self::webhook::{
    configured, deliver, generic_payload, http_client, DeliveryOutcome, Destination,
};

// ---------------------------------------------------------------------------
// Submodules — one per destination format
// ---------------------------------------------------------------------------

mod discord;
mod webhook;

/// Hard wall-clock budget for one notification call: settings read + every
/// delivery (the destinations are posted concurrently). Best-effort means the
/// caller is never held longer than this.
const NOTIFY_BUDGET: Duration = Duration::from_secs(5);

/// Log target (matches the Python logger `huginn.hub.notifications`).
const LOG_TARGET: &str = "huginn.hub.notifications";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A VM just transitioned to OFFLINE (offline sweeper). Best-effort: bounded
/// by 5 s, never returns an error.
pub async fn notify_vm_offline(pool: &PgPool, vm: &VM) {
    notify(
        pool,
        FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(vm),
            task: None,
        },
    )
    .await
}

/// An OFFLINE VM is back (heartbeat observed the recovery). Best-effort:
/// bounded by 5 s, never returns an error.
pub async fn notify_vm_recovered(pool: &PgPool, vm: &VM) {
    notify(
        pool,
        FleetEvent {
            kind: EventKind::VmRecovered,
            vm: Some(vm),
            task: None,
        },
    )
    .await
}

/// A task result in a failed state (`failed` / `timeout` / `dead_letter` — the
/// call site decides). `task` is the updated task row. Best-effort: bounded by
/// 5 s, never returns an error.
pub async fn notify_task_failure(pool: &PgPool, vm: &VM, task: &Task) {
    notify(
        pool,
        FleetEvent {
            kind: EventKind::TaskFailure,
            vm: Some(vm),
            task: Some(task),
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Event plumbing
// ---------------------------------------------------------------------------

/// The three fleet events, keyed exactly like the Python `_EVENTS` map (the
/// key is also the `event` field of the generic webhook payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventKind {
    VmOffline,
    VmRecovered,
    TaskFailure,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            EventKind::VmOffline => "vm_offline",
            EventKind::VmRecovered => "vm_recovered",
            EventKind::TaskFailure => "task_failure",
        }
    }

    /// `notifications_enabled` master switch AND the per-event toggle.
    fn enabled_in(self, s: &Setting) -> bool {
        s.notifications_enabled
            && match self {
                EventKind::VmOffline => s.notify_vm_offline,
                EventKind::VmRecovered => s.notify_vm_recovered,
                EventKind::TaskFailure => s.notify_task_failure,
            }
    }
}

/// One notification: the event kind plus the rows it is about (either may be
/// absent in degenerate calls; the Python signature allowed `None` too).
struct FleetEvent<'a> {
    kind: EventKind,
    vm: Option<&'a VM>,
    task: Option<&'a Task>,
}

/// Load the settings row, dispatch, and swallow everything. The whole call is
/// capped by [`NOTIFY_BUDGET`]; a hung settings read or webhook only ever
/// produces a warning.
async fn notify(pool: &PgPool, event: FleetEvent<'_>) {
    let kind = event.kind.as_str();
    let work = async {
        let settings = match setting::get_settings_row(pool).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                warn!(
                    target: LOG_TARGET,
                    event = kind,
                    "notification skipped: no settings row"
                );
                return;
            }
            Err(e) => {
                warn!(
                    target: LOG_TARGET,
                    event = kind,
                    error = %e,
                    "notification skipped: settings read failed"
                );
                return;
            }
        };
        // The report is intentionally dropped: it is logged as it happens and
        // never surfaces to the caller.
        let _report = dispatch(&settings, &event, NOTIFY_BUDGET).await;
    };
    if tokio::time::timeout(NOTIFY_BUDGET, work).await.is_err() {
        warn!(
            target: LOG_TARGET,
            event = kind,
            "notification dispatch exceeded its budget and was abandoned"
        );
    }
}

/// Fan the event out to every enabled, configured destination.
///
/// `budget` bounds every request (the destinations are posted concurrently, so
/// the call itself is bounded by roughly `budget`). Returns the per-destination
/// report: empty when the event is disabled or no destination is configured.
async fn dispatch(
    settings: &Setting,
    event: &FleetEvent<'_>,
    budget: Duration,
) -> Vec<DeliveryOutcome> {
    if !event.kind.enabled_in(settings) {
        return Vec::new();
    }
    let text = message(event);
    let ts = Utc::now().to_rfc3339();

    let discord_url = configured(settings.discord_webhook_url.as_deref());
    let generic_url = configured(settings.generic_webhook_url.as_deref());
    if discord_url.is_none() && generic_url.is_none() {
        return Vec::new();
    }

    let client = http_client();
    let discord_body = discord_payload(&text);
    let generic_body = generic_payload(event, &text, &ts);

    // Concurrent fan-out: one hung webhook cannot eat the budget of the other.
    let discord = async {
        match discord_url {
            None => None,
            Some(url) => Some(
                deliver(
                    client,
                    Destination::Discord,
                    url,
                    &discord_body,
                    budget,
                    event,
                )
                .await,
            ),
        }
    };
    let generic = async {
        match generic_url {
            None => None,
            Some(url) => Some(
                deliver(
                    client,
                    Destination::Generic,
                    url,
                    &generic_body,
                    budget,
                    event,
                )
                .await,
            ),
        }
    };
    let (d, g) = tokio::join!(discord, generic);
    d.into_iter().chain(g).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A throwaway local HTTP server that records what was posted to it.
#[cfg(test)]
pub(crate) mod testing {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use chrono::{DateTime, Utc};
    use serde_json::json;
    use uuid::Uuid;

    use crate::models::enums::{ExecMode, TaskStatus, TaskType, VMState, WorkerArch};

    use super::*;

    // -----------------------------------------------------------------------
    // Test doubles
    // -----------------------------------------------------------------------

    #[derive(Debug, Clone)]
    pub(crate) struct Recorded {
        pub(crate) method: String,
        pub(crate) path: String,
        pub(crate) content_type: String,
        pub(crate) body: String,
    }

    /// Minimal webhook double (the `wiremock` role, hand-rolled so the crate
    /// takes on no new dev-dependency): one std thread on a `TcpListener`,
    /// records every request, answers with a fixed status — optionally after a
    /// delay, to simulate a hung webhook.
    pub(crate) struct MockWebhook {
        base: String,
        requests: Arc<Mutex<Vec<Recorded>>>,
    }

    impl MockWebhook {
        pub(crate) fn start() -> Self {
            Self::start_with(200, Duration::ZERO)
        }

        pub(crate) fn start_with(status: u16, delay: Duration) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock webhook");
            let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&requests);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    if let Some(recorded) = read_request(&mut stream) {
                        seen.lock().unwrap().push(recorded);
                    }
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    );
                    let _ = stream.flush();
                }
            });
            Self { base, requests }
        }

        pub(crate) fn url(&self, path: &str) -> String {
            format!("{}{}", self.base, path)
        }

        pub(crate) fn requests(&self) -> Vec<Recorded> {
            self.requests.lock().unwrap().clone()
        }
    }

    /// Read one HTTP/1.1 request (start line + headers + `Content-Length` body).
    fn read_request(stream: &mut std::net::TcpStream) -> Option<Recorded> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let content_length = head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() < head_end + 4 + content_length {
                continue;
            }
            let body = String::from_utf8_lossy(&buf[head_end + 4..head_end + 4 + content_length])
                .to_string();
            let mut lines = head.lines();
            let start = lines.next().unwrap_or_default();
            let mut parts = start.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let path = parts.next().unwrap_or_default().to_string();
            let content_type = head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            return Some(Recorded {
                method,
                path,
                content_type,
                body,
            });
        }
        None
    }

    pub(crate) fn sample_vm() -> VM {
        VM {
            id: Uuid::parse_str("00000000-0000-4000-8000-0000000000aa").unwrap(),
            name: "worker-1".into(),
            hostname: Some("worker-1.lan".into()),
            ip_address: Some("10.0.0.5".into()),
            arch: WorkerArch::Amd64,
            os_info: json!({"os": "linux"}),
            state: VMState::Active,
            exec_mode: ExecMode::Whitelist,
            worker_version: Some("1.0.0".into()),
            worker_secret_hash: Some("deadbeef".into()),
            enrollment_token_id: None,
            approved_by: None,
            last_heartbeat_at: Some(Utc::now()),
            enrolled_at: None,
            approved_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub(crate) fn sample_task(status: TaskStatus) -> Task {
        Task {
            id: Uuid::parse_str("00000000-0000-4000-8000-0000000000bb").unwrap(),
            vm_id: Uuid::parse_str("00000000-0000-4000-8000-0000000000aa").unwrap(),
            task_type: TaskType::Action,
            action_name: Some("reboot".into()),
            payload: json!({"action": "reboot", "params": {}, "timeout": 60}),
            status,
            stdout: None,
            stderr: None,
            exit_code: Some(2),
            error: Some("boom".into()),
            retries: 0,
            created_by: "user:alice".into(),
            idempotency_key: None,
            dispatched_at: None,
            started_at: None,
            finished_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub(crate) fn enabled_settings() -> Setting {
        let mut s = base_settings_row();
        s.notifications_enabled = true;
        s.notify_vm_offline = true;
        s.notify_vm_recovered = true;
        s.notify_task_failure = true;
        s
    }

    /// A settings row in its SQL defaults (all toggles explicit for clarity).
    pub(crate) fn base_settings_row() -> Setting {
        Setting {
            id: 1,
            target_worker_version: String::new(),
            target_release_repo: String::new(),
            allowed_release_domains: json!([]),
            updated_by: None,
            updated_at: Utc::now(),
            oidc_enabled: false,
            oidc_issuer: String::new(),
            oidc_client_id: String::new(),
            oidc_client_secret: None,
            oidc_redirect_url: String::new(),
            oidc_post_login_redirect: String::new(),
            ldap_enabled: false,
            ldap_server_url: String::new(),
            ldap_bind_dn: String::new(),
            ldap_bind_password: None,
            ldap_user_search_base: String::new(),
            ldap_user_search_filter: String::new(),
            ldap_start_tls: false,
            ldap_use_ldaps: false,
            notifications_enabled: false,
            discord_webhook_url: None,
            generic_webhook_url: None,
            notify_vm_offline: true,
            notify_vm_recovered: false,
            notify_task_failure: false,
            auto_update_enabled: false,
            oidc_provider_name: "SSO".into(),
            require_admin_mfa: true,
            allow_password_login: false,
            webauthn_rp_id: String::new(),
            webauthn_rp_name: "Huginn".into(),
            webauthn_origin: String::new(),
            backup_s3_enabled: false,
            backup_s3_endpoint: String::new(),
            backup_s3_region: String::new(),
            backup_s3_bucket: String::new(),
            backup_s3_prefix: String::new(),
            backup_s3_access_key: String::new(),
            backup_s3_secret_key: None,
            backup_s3_retention_days: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::models::enums::{TaskStatus, WorkerArch};

    #[tokio::test]
    async fn both_destinations_receive_their_formats() {
        let server = MockWebhook::start();
        let mut settings = enabled_settings();
        settings.discord_webhook_url = Some(server.url("/discord"));
        settings.generic_webhook_url = Some(server.url("/generic"));
        let vm = sample_vm();
        let event = FleetEvent {
            kind: EventKind::VmRecovered,
            vm: Some(&vm),
            task: None,
        };
        let outcomes = dispatch(&settings, &event, Duration::from_secs(5)).await;
        assert_eq!(
            outcomes.len(),
            2,
            "both destinations were attempted: {outcomes:?}"
        );

        let mut requests = server.requests();
        requests.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(requests.len(), 2);
        // /discord gets {"content": ...}, /generic the structured payload.
        let discord: Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(
            discord["content"],
            "🟢 VM recovered: **worker-1** is back online"
        );
        let generic: Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(generic["event"], "vm_recovered");
        assert!(generic["task"].is_null());
    }

    #[tokio::test]
    async fn disabled_master_switch_sends_nothing() {
        let server = MockWebhook::start();
        let mut settings = enabled_settings();
        settings.notifications_enabled = false;
        settings.discord_webhook_url = Some(server.url("/discord"));
        let vm = sample_vm();
        let event = FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(&vm),
            task: None,
        };
        let outcomes = dispatch(&settings, &event, Duration::from_secs(5)).await;
        assert!(outcomes.is_empty());
        assert!(server.requests().is_empty());
    }

    #[tokio::test]
    async fn disabled_event_toggle_sends_nothing() {
        let server = MockWebhook::start();
        // SQL defaults: notify_vm_recovered = false, notify_task_failure = false.
        let mut settings = base_settings_row();
        settings.notifications_enabled = true;
        settings.discord_webhook_url = Some(server.url("/discord"));
        let vm = sample_vm();
        let task = sample_task(TaskStatus::Failed);
        for event in [
            FleetEvent {
                kind: EventKind::VmRecovered,
                vm: Some(&vm),
                task: None,
            },
            FleetEvent {
                kind: EventKind::TaskFailure,
                vm: Some(&vm),
                task: Some(&task),
            },
        ] {
            let outcomes = dispatch(&settings, &event, Duration::from_secs(5)).await;
            assert!(outcomes.is_empty(), "{:?}", event.kind);
        }
        assert!(server.requests().is_empty());
    }

    #[tokio::test]
    async fn unconfigured_urls_send_nothing() {
        let settings = enabled_settings(); // both URLs unset
        let vm = sample_vm();
        let event = FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(&vm),
            task: None,
        };
        assert!(dispatch(&settings, &event, Duration::from_secs(5))
            .await
            .is_empty());

        // Empty strings (the dashboard's "cleared field") are unset too.
        let mut settings = enabled_settings();
        settings.discord_webhook_url = Some(String::new());
        settings.generic_webhook_url = Some("   ".into());
        assert!(dispatch(&settings, &event, Duration::from_secs(5))
            .await
            .is_empty());
    }

    // -----------------------------------------------------------------------
    // End-to-end through the settings row (live PostgreSQL, skipped without
    // HUGINN_TEST_DATABASE_URL — `cargo test` stays green without a database).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn notify_vm_offline_end_to_end() {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return;
        };
        let _guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = crate::db::connect(&url, 2).await.expect("connect");
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(&pool)
            .await
            .expect("drop schema");
        sqlx::query("CREATE SCHEMA public")
            .execute(&pool)
            .await
            .expect("create schema");
        crate::db::run_migrations(&pool).await.expect("migrations");

        let server = MockWebhook::start();
        let values = crate::models::setting::SettingValues {
            notifications_enabled: true,
            discord_webhook_url: Some(server.url("/discord")),
            generic_webhook_url: Some(server.url("/generic")),
            notify_vm_offline: true,
            ..Default::default()
        };
        crate::models::setting::upsert(&pool, values)
            .await
            .expect("settings");

        let vm = crate::models::vm::create(
            &pool,
            crate::models::vm::VmNew::new("worker-e2e", WorkerArch::Amd64),
        )
        .await
        .expect("vm");

        notify_vm_offline(&pool, &vm).await;

        let mut requests = server.requests();
        requests.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(requests.len(), 2, "both destinations notified");
        // Sorted by path: [0] = /discord, [1] = /generic.
        let discord: Value = serde_json::from_str(&requests[0].body).unwrap();
        assert!(discord["content"]
            .as_str()
            .unwrap()
            .contains("🔴 VM went offline"));
        let generic: Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(generic["event"], "vm_offline");
        assert_eq!(generic["vm"]["name"], "worker-e2e");
    }
}

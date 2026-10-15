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

use std::sync::OnceLock;
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};
use sqlx::PgPool;
use tracing::warn;

use crate::models::setting::{self, Setting};
use crate::models::task::Task;
use crate::models::vm::VM;

/// Hard wall-clock budget for one notification call: settings read + every
/// delivery (the destinations are posted concurrently). Best-effort means the
/// caller is never held longer than this.
const NOTIFY_BUDGET: Duration = Duration::from_secs(5);

/// Discord hard limit for `content` (characters).
const DISCORD_CONTENT_LIMIT: usize = 2000;

/// How much of a task `error` is quoted in the human message.
const ERROR_EXCERPT_CHARS: usize = 200;

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

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

/// Which configured webhook a delivery went to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Destination {
    Discord,
    Generic,
}

impl Destination {
    fn as_str(self) -> &'static str {
        match self {
            Destination::Discord => "discord",
            Destination::Generic => "generic",
        }
    }
}

/// Why a destination URL was refused (nothing was sent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectReason {
    NotAUrl,
    /// `http://` to a non-loopback host — see the module docs.
    InsecureHttp,
    UnsupportedScheme,
}

impl RejectReason {
    fn as_str(self) -> &'static str {
        match self {
            RejectReason::NotAUrl => "unparsable URL",
            RejectReason::InsecureHttp => "http:// to a non-loopback host (https:// required)",
            RejectReason::UnsupportedScheme => "unsupported scheme (https:// required)",
        }
    }
}

/// Why a send failed (kept free of URLs/exception text so it is safe to log or
/// assert on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailReason {
    Timeout,
    Status(u16),
    Network,
}

/// Per-destination outcome, only used for logging and tests — the public API
/// discards it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryOutcome {
    /// 2xx answer.
    Sent { dest: Destination, status: u16 },
    /// URL refused by the policy; nothing was sent.
    Rejected {
        dest: Destination,
        reason: RejectReason,
    },
    /// Transport error, timeout, or non-2xx answer.
    Failed {
        dest: Destination,
        reason: FailReason,
    },
}

/// Shared HTTP client: no redirect following (a webhook URL carries a secret
/// token; a 3xx would hand it to another host) and no default timeout — each
/// request carries its own, so the caller's budget governs.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("huginn-hub/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default()
    })
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
    let discord_body = json!({ "content": text });
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

/// POST one payload to one destination, classifying the outcome and logging
/// every problem as a warning (never raising).
async fn deliver(
    client: &reqwest::Client,
    dest: Destination,
    url: &str,
    body: &Value,
    budget: Duration,
    event: &FleetEvent<'_>,
) -> DeliveryOutcome {
    let event_name = event.kind.as_str();
    let target = match check_webhook_url(url) {
        Ok(target) => target,
        Err(reason) => {
            warn!(
                target: LOG_TARGET,
                event = event_name,
                dest = dest.as_str(),
                url = %describe_url(url),
                reason = reason.as_str(),
                "webhook URL refused"
            );
            return DeliveryOutcome::Rejected { dest, reason };
        }
    };
    match post_json(client, target, body, budget).await {
        Ok(status) if (200..300).contains(&status) => DeliveryOutcome::Sent { dest, status },
        Ok(status) => {
            warn!(
                target: LOG_TARGET,
                event = event_name,
                dest = dest.as_str(),
                url = %describe_url(target),
                status,
                "webhook POST returned a non-2xx status"
            );
            DeliveryOutcome::Failed {
                dest,
                reason: FailReason::Status(status),
            }
        }
        Err(reason) => {
            let reason_str = match reason {
                FailReason::Timeout => "timeout",
                FailReason::Network => "network error",
                FailReason::Status(_) => "request failed",
            };
            warn!(
                target: LOG_TARGET,
                event = event_name,
                dest = dest.as_str(),
                url = %describe_url(target),
                reason = reason_str,
                "notification POST failed"
            );
            DeliveryOutcome::Failed { dest, reason }
        }
    }
}

/// POST `body` as JSON with a per-request timeout. The error is stripped of
/// its URL before it can reach a log (`reqwest` formats the full URL — secret
/// token included — into its `Display`).
async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
    budget: Duration,
) -> Result<u16, FailReason> {
    let result = client.post(url).timeout(budget).json(body).send().await;
    match result {
        Ok(resp) => Ok(resp.status().as_u16()),
        Err(e) => {
            let reason = if e.is_timeout() {
                FailReason::Timeout
            } else {
                FailReason::Network
            };
            // `without_url()` keeps the webhook URL (and its token) out of the
            // warning.
            let e = e.without_url();
            warn!(
                target: LOG_TARGET,
                error = %e,
                "notification POST failed (transport)"
            );
            Err(reason)
        }
    }
}

// ---------------------------------------------------------------------------
// URL policy
// ---------------------------------------------------------------------------

/// `Some(url)` when the setting is actually configured (empty/whitespace means
/// unset — the dashboard sends `""` for cleared fields).
fn configured(url: Option<&str>) -> Option<&str> {
    let url = url?.trim();
    if url.is_empty() {
        None
    } else {
        Some(url)
    }
}

/// Extract the authority's host from `scheme://[user@]host[:port][/...]`
/// (case preserved; the policy comparisons are case-insensitive).
fn authority_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if hostport.starts_with('[') {
        // IPv6 literal: keep the brackets, drop any port.
        let end = hostport.find(']')?;
        return Some(&hostport[..=end]);
    }
    Some(hostport.split(':').next().unwrap_or(hostport))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.starts_with("127.") || host == "[::1]"
}

/// Webhook URL policy: HTTPS everywhere, `http://` tolerated for loopback only
/// (what the tests exercise). Returns the URL unchanged on success.
fn check_webhook_url(url: &str) -> Result<&str, RejectReason> {
    let Some((scheme, host)) = url
        .split_once("://")
        .and_then(|(s, _)| authority_host(url).map(|h| (s, h)))
    else {
        return Err(RejectReason::NotAUrl);
    };
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(url);
    }
    if scheme.eq_ignore_ascii_case("http") {
        return if is_loopback_host(host) {
            Ok(url)
        } else {
            Err(RejectReason::InsecureHttp)
        };
    }
    Err(RejectReason::UnsupportedScheme)
}

/// Safe URL label for logs: `scheme://host` only — never the path or query,
/// where Discord tokens and generic-webhook secrets live. Unparsable input is
/// never echoed (it may itself be a secret).
fn describe_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, _)) => match authority_host(url) {
            Some(host) => format!("{scheme}://{host}"),
            None => "<unparsable>".to_string(),
        },
        None => "<unparsable>".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Messages and payloads
// ---------------------------------------------------------------------------

/// Human-readable one-liner — Python `_message` wording (Discord-flavoured
/// markdown), with extra task detail (exit code, error excerpt) for
/// `task_failure`.
fn message(event: &FleetEvent<'_>) -> String {
    let name = event.vm.map_or("?", |v| v.name.as_str());
    let text = match event.kind {
        EventKind::VmOffline => {
            let ip = event
                .vm
                .and_then(|v| v.ip_address.as_deref())
                .unwrap_or("?");
            format!("🔴 VM went offline: **{name}** ({ip})")
        }
        EventKind::VmRecovered => {
            format!("🟢 VM recovered: **{name}** is back online")
        }
        EventKind::TaskFailure => {
            let task = event.task;
            let action = task
                .and_then(|t| t.action_name.as_deref())
                .filter(|a| !a.is_empty())
                .or_else(|| task.map(|t| t.task_type.as_str()))
                .unwrap_or("task");
            let status = task.map_or("failed", |t| t.status.as_str());
            let mut text = format!("⚠️ Task failed: `{action}` on **{name}** ({status})");
            if let Some(t) = task {
                if let Some(code) = t.exit_code {
                    text.push_str(&format!(", exit code {code}"));
                }
                if let Some(err) = t.error.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
                    text.push_str(&format!(" — {}", truncate_chars(err, ERROR_EXCERPT_CHARS)));
                }
            }
            text
        }
    };
    truncate_chars(&text, DISCORD_CONTENT_LIMIT)
}

/// Generic webhook body — key-for-key with the Python hub
/// (`event` / `message` / `vm` / `task` / `ts`) so existing consumers keep
/// parsing it.
fn generic_payload(event: &FleetEvent<'_>, text: &str, ts: &str) -> Value {
    json!({
        "event": event.kind.as_str(),
        "message": text,
        "vm": event.vm.map(|v| json!({ "id": v.id.to_string(), "name": v.name })),
        "task": event.task.map(|t| json!({ "id": t.id.to_string(), "status": t.status.as_str() })),
        "ts": ts,
    })
}

/// Truncate to `max` characters (never splitting a code point), marking the
/// cut with an ellipsis.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use crate::models::enums::{ExecMode, TaskStatus, TaskType, VMState, WorkerArch};

    use super::*;

    // -----------------------------------------------------------------------
    // Test doubles
    // -----------------------------------------------------------------------

    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        path: String,
        content_type: String,
        body: String,
    }

    /// Minimal webhook double (the `wiremock` role, hand-rolled so the crate
    /// takes on no new dev-dependency): one std thread on a `TcpListener`,
    /// records every request, answers with a fixed status — optionally after a
    /// delay, to simulate a hung webhook.
    struct MockWebhook {
        base: String,
        requests: Arc<Mutex<Vec<Recorded>>>,
    }

    impl MockWebhook {
        fn start() -> Self {
            Self::start_with(200, Duration::ZERO)
        }

        fn start_with(status: u16, delay: Duration) -> Self {
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

        fn url(&self, path: &str) -> String {
            format!("{}{}", self.base, path)
        }

        fn requests(&self) -> Vec<Recorded> {
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

    fn sample_vm() -> VM {
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

    fn sample_task(status: TaskStatus) -> Task {
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

    fn enabled_settings() -> Setting {
        let mut s = base_settings_row();
        s.notifications_enabled = true;
        s.notify_vm_offline = true;
        s.notify_vm_recovered = true;
        s.notify_task_failure = true;
        s
    }

    /// A settings row in its SQL defaults (all toggles explicit for clarity).
    fn base_settings_row() -> Setting {
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
        }
    }

    // -----------------------------------------------------------------------
    // Messages and payloads (Python `_message` / `notify` parity)
    // -----------------------------------------------------------------------

    #[test]
    fn messages_match_python_wording() {
        let vm = sample_vm();
        let task = sample_task(TaskStatus::Failed);
        let offline = FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(&vm),
            task: None,
        };
        assert_eq!(
            message(&offline),
            "🔴 VM went offline: **worker-1** (10.0.0.5)"
        );

        let recovered = FleetEvent {
            kind: EventKind::VmRecovered,
            vm: Some(&vm),
            task: None,
        };
        assert_eq!(
            message(&recovered),
            "🟢 VM recovered: **worker-1** is back online"
        );

        // Task details are quoted: action + status (Python), plus exit code and
        // error excerpt (this port).
        let failure = FleetEvent {
            kind: EventKind::TaskFailure,
            vm: Some(&vm),
            task: Some(&task),
        };
        assert_eq!(
            message(&failure),
            "⚠️ Task failed: `reboot` on **worker-1** (failed), exit code 2 — boom"
        );
    }

    #[test]
    fn task_failure_message_falls_back_to_task_type() {
        let vm = sample_vm();
        let mut task = sample_task(TaskStatus::Timeout);
        task.action_name = None;
        task.exit_code = None;
        task.error = None;
        let event = FleetEvent {
            kind: EventKind::TaskFailure,
            vm: Some(&vm),
            task: Some(&task),
        };
        assert_eq!(
            message(&event),
            "⚠️ Task failed: `action` on **worker-1** (timeout)"
        );
    }

    #[test]
    fn generic_payload_matches_python_shape() {
        let vm = sample_vm();
        let task = sample_task(TaskStatus::Failed);
        let event = FleetEvent {
            kind: EventKind::TaskFailure,
            vm: Some(&vm),
            task: Some(&task),
        };
        let body = generic_payload(&event, "msg", "2026-10-15T00:00:00+00:00");
        assert_eq!(body["event"], "task_failure");
        assert_eq!(body["message"], "msg");
        assert_eq!(body["vm"]["id"], "00000000-0000-4000-8000-0000000000aa");
        assert_eq!(body["vm"]["name"], "worker-1");
        assert_eq!(body["task"]["id"], "00000000-0000-4000-8000-0000000000bb");
        assert_eq!(body["task"]["status"], "failed");
        assert_eq!(body["ts"], "2026-10-15T00:00:00+00:00");

        // vm_offline: `task` is null (Python parity).
        let event = FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(&vm),
            task: None,
        };
        let body = generic_payload(&event, "m", "t");
        assert_eq!(body["event"], "vm_offline");
        assert!(body["task"].is_null());
    }

    // -----------------------------------------------------------------------
    // URL policy + secret hygiene
    // -----------------------------------------------------------------------

    #[test]
    fn webhook_url_policy() {
        // HTTPS is always fine.
        assert!(check_webhook_url("https://discord.com/api/webhooks/1/tok").is_ok());
        // http:// is tolerated for loopback only (the tests' mock webhook).
        assert!(check_webhook_url("http://127.0.0.1:9999/hook").is_ok());
        assert!(check_webhook_url("http://localhost:9999/hook").is_ok());
        assert!(check_webhook_url("http://[::1]:9999/hook").is_ok());
        // http:// anywhere else is refused (Python accepted it — deliberate
        // hardening).
        assert_eq!(
            check_webhook_url("http://example.com/hook"),
            Err(RejectReason::InsecureHttp)
        );
        assert_eq!(
            check_webhook_url("http://10.0.0.5/hook"),
            Err(RejectReason::InsecureHttp)
        );
        // Other schemes and garbage.
        assert_eq!(
            check_webhook_url("ftp://example.com/hook"),
            Err(RejectReason::UnsupportedScheme)
        );
        assert_eq!(
            check_webhook_url("discord.com/api/webhooks/1/tok"),
            Err(RejectReason::NotAUrl)
        );
    }

    #[test]
    fn describe_url_never_leaks_path_query_or_input() {
        assert_eq!(
            describe_url("https://discord.com/api/webhooks/123456/SUPER-SECRET-TOKEN"),
            "https://discord.com"
        );
        assert_eq!(
            describe_url("https://hooks.example.com/hook?token=SUPER-SECRET-TOKEN"),
            "https://hooks.example.com"
        );
        // Unparsable input is never echoed (it may itself be a secret).
        assert_eq!(describe_url("SUPER-SECRET-TOKEN"), "<unparsable>");
    }

    #[test]
    fn empty_urls_are_not_configured() {
        assert_eq!(configured(None), None);
        assert_eq!(configured(Some("")), None);
        assert_eq!(configured(Some("   ")), None);
        assert_eq!(configured(Some(" https://x/y ")), Some("https://x/y"));
    }

    // -----------------------------------------------------------------------
    // Delivery (mock webhook)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn discord_delivery_posts_content_json() {
        let server = MockWebhook::start();
        let mut settings = enabled_settings();
        settings.discord_webhook_url = Some(server.url("/discord"));
        let vm = sample_vm();
        let event = FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(&vm),
            task: None,
        };
        let outcomes = dispatch(&settings, &event, Duration::from_secs(5)).await;
        assert_eq!(
            outcomes,
            vec![DeliveryOutcome::Sent {
                dest: Destination::Discord,
                status: 200
            }]
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].path, "/discord");
        assert!(requests[0].content_type.starts_with("application/json"));
        let body: Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(
            body["content"],
            "🔴 VM went offline: **worker-1** (10.0.0.5)"
        );
    }

    #[tokio::test]
    async fn generic_delivery_matches_python_shape() {
        let server = MockWebhook::start();
        let mut settings = enabled_settings();
        settings.generic_webhook_url = Some(server.url("/hook"));
        let vm = sample_vm();
        let task = sample_task(TaskStatus::Failed);
        let event = FleetEvent {
            kind: EventKind::TaskFailure,
            vm: Some(&vm),
            task: Some(&task),
        };
        let outcomes = dispatch(&settings, &event, Duration::from_secs(5)).await;
        assert_eq!(
            outcomes,
            vec![DeliveryOutcome::Sent {
                dest: Destination::Generic,
                status: 200
            }]
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/hook");
        let body: Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(body["event"], "task_failure");
        assert_eq!(
            body["message"],
            "⚠️ Task failed: `reboot` on **worker-1** (failed), exit code 2 — boom"
        );
        assert_eq!(body["vm"]["id"], vm.id.to_string());
        assert_eq!(body["vm"]["name"], "worker-1");
        assert_eq!(body["task"]["id"], task.id.to_string());
        assert_eq!(body["task"]["status"], "failed");
        // `ts` is a parseable RFC 3339 instant.
        let ts = body["ts"].as_str().unwrap();
        assert!(DateTime::parse_from_rfc3339(ts).is_ok());
    }

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

    #[tokio::test]
    async fn insecure_http_url_is_refused_and_never_sent() {
        let server = MockWebhook::start();
        let mut settings = enabled_settings();
        // Not loopback: refused even though it resolves fine.
        settings.discord_webhook_url = Some("http://10.255.255.1/hook".into());
        let vm = sample_vm();
        let event = FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(&vm),
            task: None,
        };
        let outcomes = dispatch(&settings, &event, Duration::from_secs(5)).await;
        assert_eq!(
            outcomes,
            vec![DeliveryOutcome::Rejected {
                dest: Destination::Discord,
                reason: RejectReason::InsecureHttp
            }]
        );
        // Nothing was sent to the configured-but-refused destination...
        assert!(server.requests().is_empty());

        // ...and the loopback exception is what the tests themselves rely on:
        settings.discord_webhook_url = Some(server.url("/discord"));
        let outcomes = dispatch(&settings, &event, Duration::from_secs(5)).await;
        assert!(matches!(
            outcomes.as_slice(),
            [DeliveryOutcome::Sent {
                dest: Destination::Discord,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn slow_webhook_times_out_without_error() {
        // The webhook hangs for 5 s; the budget is 250 ms. The call must come
        // back quickly, classify the failure as a timeout, and surface nothing.
        let server = MockWebhook::start_with(200, Duration::from_secs(5));
        let mut settings = enabled_settings();
        settings.generic_webhook_url = Some(server.url("/hook"));
        let vm = sample_vm();
        let event = FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(&vm),
            task: None,
        };
        let started = Instant::now();
        let outcomes = dispatch(&settings, &event, Duration::from_millis(250)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "non-blocking: came back in {:?}",
            started.elapsed()
        );
        assert_eq!(
            outcomes,
            vec![DeliveryOutcome::Failed {
                dest: Destination::Generic,
                reason: FailReason::Timeout
            }]
        );
    }

    #[tokio::test]
    async fn non_2xx_answer_is_classified_as_failure() {
        let server = MockWebhook::start_with(500, Duration::ZERO);
        let mut settings = enabled_settings();
        settings.discord_webhook_url = Some(server.url("/discord"));
        let vm = sample_vm();
        let event = FleetEvent {
            kind: EventKind::VmOffline,
            vm: Some(&vm),
            task: None,
        };
        let outcomes = dispatch(&settings, &event, Duration::from_secs(5)).await;
        assert_eq!(
            outcomes,
            vec![DeliveryOutcome::Failed {
                dest: Destination::Discord,
                reason: FailReason::Status(500)
            }]
        );
        assert_eq!(server.requests().len(), 1);
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

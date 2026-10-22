//! Task/queue event services (port of `hub/app/core/task_events.py`).
//!
//! [`task_events`] is the in-process notifier that connects task creation,
//! result submission and the worker long-poll: waiters park on per-VM queue
//! wakes and per-task completion wakes instead of polling the database.
// Facade re-exports of the event bus (shared contract of routes/*).
#![allow(unused_imports)]
// The wake API is consumed by the routes/services layers landing later in the
// migration (sweepers, /tasks/{id}/wait); suppress dead-code noise in this
// self-contained module so `cargo clippy -- -D warnings` stays clean meanwhile.
#![allow(dead_code)]

pub mod task_events;

pub use task_events::{PendingQueueWakes, QueueWaiter, TaskEvents, TaskWaiter};
pub mod backup;
pub mod browser_engine;
pub mod ldap;
pub mod metrics;
pub mod notifications;
pub mod oidc;
pub mod versioning;
pub mod webauthn;

/// True for loopback targets: `localhost` (case-insensitive) or any loopback
/// IP literal (IPv4 `127.0.0.0/8`, IPv6 `::1`), brackets stripped. The host is
/// PARSED as an IP — a DNS name that merely looks like one (`127.evil.com`)
/// does not parse and is not loopback (L-1). Shared by the webhook URL policy
/// (services/notifications) and the S3 endpoint validation
/// (services/backup).
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

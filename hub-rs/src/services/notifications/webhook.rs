//! Webhook delivery machinery shared by the destinations: URL policy
//! (HTTPS everywhere, secrets never logged), the POST transport with its
//! per-request timeout, and the generic-webhook body shape.

use std::sync::OnceLock;
use std::time::Duration;

use serde_json::{json, Value};
use tracing::warn;

use super::{EventKind, FleetEvent, LOG_TARGET};

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

/// Which configured webhook a delivery went to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Destination {
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
pub(super) enum RejectReason {
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
pub(super) enum FailReason {
    Timeout,
    Status(u16),
    Network,
}

/// Per-destination outcome, only used for logging and tests — the public API
/// discards it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeliveryOutcome {
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
pub(super) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("huginn-hub/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default()
    })
}

/// POST one payload to one destination, classifying the outcome and logging
/// every problem as a warning (never raising).
pub(super) async fn deliver(
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
pub(super) async fn post_json(
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
pub(super) fn configured(url: Option<&str>) -> Option<&str> {
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

/// Webhook URL policy: HTTPS everywhere, `http://` tolerated for loopback only
/// (what the tests exercise — the loopback test uses the shared IP-parsing
/// helper `crate::services::is_loopback_host`, L-1: `127.evil.com` is a DNS
/// name, not an IP, and the old `starts_with("127.")` check would have
/// tolerated it). Returns the URL unchanged on success.
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
        return if crate::services::is_loopback_host(host) {
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

/// Generic webhook body — key-for-key with the Python hub
/// (`event` / `message` / `vm` / `task` / `ts`) so existing consumers keep
/// parsing it.
pub(super) fn generic_payload(event: &FleetEvent<'_>, text: &str, ts: &str) -> Value {
    json!({
        "event": event.kind.as_str(),
        "message": text,
        "vm": event.vm.map(|v| json!({ "id": v.id.to_string(), "name": v.name })),
        "task": event.task.map(|t| json!({ "id": t.id.to_string(), "status": t.status.as_str() })),
        "ts": ts,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::super::dispatch;
    use super::super::testing::*;
    use super::*;
    use chrono::DateTime;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::models::enums::TaskStatus;

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
        // L-1: a DNS name that merely LOOKS like an IP is not loopback — the
        // host must parse as an IP literal, `127.evil.com` does not.
        assert_eq!(
            check_webhook_url("http://127.evil.com:9999/hook"),
            Err(RejectReason::InsecureHttp)
        );
        assert_eq!(
            check_webhook_url("http://127.0.0.1.evil.com:9999/hook"),
            Err(RejectReason::InsecureHttp)
        );
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
    fn shared_loopback_helper_parses_ips_instead_of_prefixes() {
        // The shared helper (services/mod.rs) backs both the webhook policy
        // and the S3 endpoint validation (L-1).
        for host in [
            "127.0.0.1",
            "127.255.0.1",
            "localhost",
            "LOCALHOST",
            "[::1]",
        ] {
            assert!(crate::services::is_loopback_host(host), "{host}");
        }
        for host in [
            "127.evil.com",
            "127.0.0.1.evil.com",
            "10.0.0.1",
            "evil.com",
            "",
        ] {
            assert!(!crate::services::is_loopback_host(host), "{host}");
        }
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
}

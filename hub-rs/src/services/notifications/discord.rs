//! Discord destination: the message wording (Python `_message`, Discord
//! markdown) and the `{"content": ...}` body shape.

use serde_json::{json, Value};

use super::{EventKind, FleetEvent};

/// Discord hard limit for `content` (characters).
const DISCORD_CONTENT_LIMIT: usize = 2000;

/// How much of a task `error` is quoted in the human message.
const ERROR_EXCERPT_CHARS: usize = 200;

/// Human-readable one-liner — Python `_message` wording (Discord-flavoured
/// markdown), with extra task detail (exit code, error excerpt) for
/// `task_failure`.
pub(super) fn message(event: &FleetEvent<'_>) -> String {
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

/// Discord webhook body — `{"content": ...}`.
pub(super) fn discord_payload(text: &str) -> Value {
    json!({ "content": text })
}

/// Truncate to `max` characters (never splitting a code point), marking the
/// cut with an ellipsis.
pub(super) fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::dispatch;
    use super::super::testing::*;
    use super::super::webhook::{DeliveryOutcome, Destination};
    use super::*;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::models::enums::TaskStatus;

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
}

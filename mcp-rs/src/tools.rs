//! The 9 MCP tools and their hub delegation. Mirrors mcp/app/server.py tool
//! by tool (signatures, docstrings, result shaping). No business logic is
//! duplicated here; `_resolve_vm` accepts an id or a name.

use crate::hub_client::{CallCtx, HubClient, HubError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub const INSTRUCTIONS: &str = r#"Huginn — fleet control. How to use these tools as designed:

1. Start with list_vms(brief=true) for a compact roster (id, name, state, mode).
   Target a VM by name or id (name is case-sensitive).
2. Act with execute_action (built-ins: status, metrics, restart_service{service},
   list_upgradable_packages, apt_upgrade, update_worker; plus admin custom commands
   — discover them with list_actions(vm_id)). execute_command (free shell) works
   ONLY on a VM in 'unrestricted' mode. If an action is refused, check the mode
   with get_vm_status.
3. Waiting on a task — IMPORTANT: do NOT poll get_task in a loop. Either pass
   wait=true to execute_action/execute_command to get the result inline, or, after
   launching with wait=false, call wait_for_task(task_id) ONCE — it blocks
   server-side and returns the instant the worker reports a result. Only if it
   returns still-running (timeout) should you call wait_for_task again. get_task is
   for a single one-off status check, not for busy-waiting.
4. Every action is audited and attributed to your user. Stay within scope.
"#;

/// Strict identifier validation before any value is interpolated into a hub
/// URL (defense in depth: task_id/vm_id are validated as UUIDs or conservative
/// name tokens; `state` as a lowercase slug). Prevents path/query injection
/// even though the hub re-validates.
fn safe_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn safe_slug(v: &str) -> bool {
    !v.is_empty() && v.len() <= 32 && v.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

/// Structured tool error, matching the Python `{"error": {"status", "detail"}}`.
pub fn tool_error(status: u16, detail: impl Into<String>) -> Value {
    json!({"error": {"status": status, "detail": detail.into()}})
}

fn from_hub_error(e: HubError) -> Value {
    tool_error(e.status_code, e.detail)
}

/// Accepts a VM id **or name** and returns the id. Names are stable across
/// re-enrollment (which mints a new id), so an agent can refer to
/// `"web-01"` instead of a UUID that may have changed. Returns a structured
/// error dict if a name is unknown or ambiguous.
async fn resolve_vm(hub: &HubClient, ctx: &CallCtx, vm: &str) -> Result<String, Value> {
    if uuid::Uuid::parse_str(vm).is_ok() {
        return Ok(vm.to_string());
    }
    let vms = match hub.list_vms(ctx, None).await {
        Ok(v) => v,
        Err(e) => return Err(from_hub_error(e)),
    };
    let Some(list) = vms.as_array() else {
        return Err(vms); // propagate a hub error
    };
    // Exact match first; fall back to case-insensitive.
    let mut matches: Vec<&Value> = list
        .iter()
        .filter(|v| v.get("name").and_then(Value::as_str) == Some(vm))
        .collect();
    if matches.is_empty() {
        let lower = vm.to_lowercase();
        matches = list
            .iter()
            .filter(|v| {
                v.get("name")
                    .and_then(Value::as_str)
                    .map(|n| n.to_lowercase() == lower)
                    .unwrap_or(false)
            })
            .collect();
    }
    if matches.is_empty() {
        return Err(tool_error(404, format!("no VM named {vm:?}")));
    }
    // Prefer the active record if a name was reused across re-enrollments.
    let mut chosen: Vec<&&Value> = matches
        .iter()
        .filter(|v| v.get("state").and_then(Value::as_str) == Some("active"))
        .collect();
    if chosen.is_empty() {
        chosen = matches.iter().collect();
    }
    if chosen.len() > 1 {
        return Err(tool_error(
            409,
            format!("{:?} matches {} VMs; use the id", vm, chosen.len()),
        ));
    }
    chosen[0]
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| tool_error(500, "VM record has no id"))
}

fn brief_action(a: &Value) -> Value {
    json!({
        "name": a.get("name"),
        "description": a.get("description"),
        "commands": a.get("commands"),
    })
}

/// Dispatches one tool call and returns its JSON result value.
/// Mirrors the Python tool bodies exactly.
pub async fn call_tool(
    hub: Arc<HubClient>,
    ctx: &CallCtx,
    name: &str,
    args: &HashMap<String, Value>,
) -> Value {
    match name {
        "list_vms" => {
            let state = args.get("state").and_then(Value::as_str);
            if let Some(st) = state {
                if !safe_slug(st) {
                    return tool_error(400, "invalid state filter");
                }
            }
            let brief = args.get("brief").and_then(Value::as_bool).unwrap_or(false);
            match hub.list_vms(ctx, state).await {
                Err(e) => from_hub_error(e),
                Ok(vms) => {
                    if brief {
                        if let Some(list) = vms.as_array() {
                            return Value::Array(
                                list.iter()
                                    .map(|v| {
                                        json!({
                                            "id": v.get("id"),
                                            "name": v.get("name"),
                                            "state": v.get("state"),
                                            "mode": v.get("exec_mode"),
                                        })
                                    })
                                    .collect(),
                            );
                        }
                    }
                    vms
                }
            }
        }
        "get_vm_status" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            match resolve_vm(&hub, ctx, vm).await {
                Err(e) => e,
                Ok(id) => match hub.get_vm(ctx, &id).await {
                    Ok(v) => v,
                    Err(e) => from_hub_error(e),
                },
            }
        }
        "list_actions" => {
            let vm_id = args.get("vm_id").and_then(Value::as_str);
            let actions = match hub.list_actions(ctx).await {
                Ok(v) => v,
                Err(e) => return from_hub_error(e),
            };
            let Some(list) = actions.as_array() else {
                return actions;
            };
            let enabled: Vec<Value> = list
                .iter()
                .filter(|a| a.get("enabled").and_then(Value::as_bool).unwrap_or(false))
                .cloned()
                .collect();
            let Some(vm) = vm_id else {
                return Value::Array(enabled.iter().map(brief_action).collect());
            };
            let id = match resolve_vm(&hub, ctx, vm).await {
                Ok(id) => id,
                Err(e) => return e,
            };
            let vm_obj = match hub.get_vm(ctx, &id).await {
                Ok(v) => v,
                Err(e) => return from_hub_error(e),
            };
            let mode = vm_obj
                .get("exec_mode")
                .and_then(Value::as_str)
                .unwrap_or("");
            if mode != "custom" && mode != "unrestricted" {
                return Value::Array(vec![]); // VM can't run custom commands
            }
            let vm_tags: Vec<String> = vm_obj
                .get("tags")
                .and_then(Value::as_array)
                .map(|t| {
                    t.iter()
                        .filter_map(|x| x.get("id").and_then(Value::as_str).map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            Value::Array(
                enabled
                    .iter()
                    .filter(|a| {
                        a.get("tag_ids")
                            .and_then(Value::as_array)
                            .map(|ids| {
                                ids.iter()
                                    .filter_map(Value::as_str)
                                    .any(|id| vm_tags.iter().any(|t| t == id))
                            })
                            .unwrap_or(false)
                    })
                    .map(brief_action)
                    .collect(),
            )
        }
        "execute_action" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            let Some(action) = args.get("action").and_then(Value::as_str) else {
                return tool_error(400, "action is required");
            };
            let wait = args.get("wait").and_then(Value::as_bool).unwrap_or(false);
            let params: HashMap<String, String> = args
                .get("params")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            match resolve_vm(&hub, ctx, vm).await {
                Err(e) => e,
                Ok(id) => match hub.execute_action(ctx, &id, action, &params, wait).await {
                    Ok(v) => v,
                    Err(e) => from_hub_error(e),
                },
            }
        }
        "execute_command" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            let Some(command) = args.get("command").and_then(Value::as_str) else {
                return tool_error(400, "command is required");
            };
            let wait = args.get("wait").and_then(Value::as_bool).unwrap_or(false);
            match resolve_vm(&hub, ctx, vm).await {
                Err(e) => e,
                Ok(id) => match hub.execute_command(ctx, &id, command, wait).await {
                    Ok(v) => v,
                    Err(e) => from_hub_error(e),
                },
            }
        }
        "trigger_update" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            match resolve_vm(&hub, ctx, vm).await {
                Err(e) => e,
                Ok(id) => match hub.trigger_update(ctx, &id).await {
                    Ok(v) => v,
                    Err(e) => from_hub_error(e),
                },
            }
        }
        "get_task" => {
            let Some(task_id) = args.get("task_id").and_then(Value::as_str) else {
                return tool_error(400, "task_id is required");
            };
            if !safe_id(task_id) {
                return tool_error(400, "invalid task_id");
            }
            match hub.get_task(ctx, task_id).await {
                Ok(v) => v,
                Err(e) => from_hub_error(e),
            }
        }
        "wait_for_task" => {
            let Some(task_id) = args.get("task_id").and_then(Value::as_str) else {
                return tool_error(400, "task_id is required");
            };
            let timeout = args
                .get("timeout")
                .and_then(Value::as_u64)
                .unwrap_or(60)
                .min(3600);
            if !safe_id(task_id) {
                return tool_error(400, "invalid task_id");
            }
            match hub.wait_task(ctx, task_id, timeout).await {
                Ok(v) => v,
                Err(e) => from_hub_error(e),
            }
        }
        "get_audit_log" => {
            let vm_id = args.get("vm_id").and_then(Value::as_str);
            let event_type = args.get("event_type").and_then(Value::as_str);
            if let Some(v) = vm_id {
                if !safe_id(v) {
                    return tool_error(400, "invalid vm_id");
                }
            }
            if let Some(e) = event_type {
                if !safe_slug(e) {
                    return tool_error(400, "invalid event_type");
                }
            }
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(100)
                .min(1000);
            match hub.get_audit_log(ctx, vm_id, event_type, limit).await {
                Ok(v) => v,
                Err(e) => from_hub_error(e),
            }
        }
        other => tool_error(404, format!("unknown tool: {other:?}")),
    }
}

/// JSON schemas for `tools/list` (derived from the Python signatures).
pub fn tool_definitions() -> Value {
    json!([
        {
            "name": "list_vms",
            "description": "List fleet VMs. Optionally filter by state: pending, active, offline, revoked.\n\nWith ``brief=true`` each VM is reduced to just id, name, state, and mode —\na compact roster ideal for a session-opening overview (far fewer tokens).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "state": {"type": "string", "description": "pending | active | offline | revoked"},
                    "brief": {"type": "boolean"}
                }
            }
        },
        {
            "name": "get_vm_status",
            "description": "Get a single VM's full status (state, mode, worker version, heartbeat).\n\n``vm_id`` may be a VM id or its name.",
            "inputSchema": {
                "type": "object",
                "properties": {"vm_id": {"type": "string"}},
                "required": ["vm_id"]
            }
        },
        {
            "name": "list_actions",
            "description": "List admin-defined custom commands (fixed argv, run in 'custom' exec mode).\n\nThese run via ``execute_action`` like built-in actions. With ``vm_id`` (id or\nname), returns only the commands runnable on that VM right now — i.e. the VM\nis in custom/unrestricted mode and carries one of the command's tags.",
            "inputSchema": {
                "type": "object",
                "properties": {"vm_id": {"type": "string"}}
            }
        },
        {
            "name": "execute_action",
            "description": "Run an action on a VM (``vm_id`` may be a VM id or its name).\n\nBuilt-in actions: status, metrics, restart_service (param: service),\nlist_upgradable_packages, apt_upgrade, update_worker. Admin-defined custom\ncommands (see ``list_actions``) run the same way by name. With ``wait=true``\nthe call blocks briefly and returns the result inline (prefer this for short\nactions). Otherwise it returns a task — then call wait_for_task(task_id) once;\ndo NOT poll get_task in a loop.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm_id": {"type": "string"},
                    "action": {"type": "string"},
                    "params": {"type": "object", "additionalProperties": {"type": "string"}},
                    "wait": {"type": "boolean"}
                },
                "required": ["vm_id", "action"]
            }
        },
        {
            "name": "execute_command",
            "description": "Run a free-form shell command on a VM (``vm_id`` may be a VM id or its name).\n\nOnly permitted when the VM is in 'unrestricted' mode (enabled by an admin in\nthe dashboard). Subject to the same auth, rate-limit, and audit rules as the\ndashboard. With ``wait=true`` the result is returned inline; otherwise call\nwait_for_task(task_id) once — do NOT poll get_task in a loop.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm_id": {"type": "string"},
                    "command": {"type": "string"},
                    "wait": {"type": "boolean"}
                },
                "required": ["vm_id", "command"]
            }
        },
        {
            "name": "trigger_update",
            "description": "Trigger a worker self-update on a VM toward the hub's target version.\n\n``vm_id`` may be a VM id or its name.",
            "inputSchema": {
                "type": "object",
                "properties": {"vm_id": {"type": "string"}},
                "required": ["vm_id"]
            }
        },
        {
            "name": "get_task",
            "description": "Fetch a task's current status/result ONCE (a single snapshot).\n\nTo await a still-running task, use wait_for_task(task_id) instead of calling\nthis repeatedly — looping on get_task busy-waits and wastes calls.",
            "inputSchema": {
                "type": "object",
                "properties": {"task_id": {"type": "string"}},
                "required": ["task_id"]
            }
        },
        {
            "name": "wait_for_task",
            "description": "Block until a task finishes (succeeded/failed/timeout) or ``timeout``\nseconds pass, then return it — instead of polling get_task in a loop.\n\nIdeal after launching a long action/command with wait=false: the call returns\nthe instant the worker reports a result. If still running when the timeout\nelapses, the task's current state is returned; just call again to keep waiting.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "timeout": {"type": "integer", "default": 60}
                },
                "required": ["task_id"]
            }
        },
        {
            "name": "get_audit_log",
            "description": "Read recent audit-log entries, optionally filtered by VM or event type.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm_id": {"type": "string"},
                    "event_type": {"type": "string"},
                    "limit": {"type": "integer", "default": 100}
                }
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(id: &str, name: &str, state: &str) -> Value {
        json!({"id": id, "name": name, "state": state, "exec_mode": "whitelist"})
    }

    #[test]
    fn identifier_guards_reject_injection() {
        assert!(!safe_id("../api/admin"));
        assert!(!safe_id("abc?x=1"));
        assert!(!safe_id("abc&y=2"));
        assert!(!safe_id(""));
        assert!(!safe_id("a".repeat(200).as_str()));
        assert!(safe_id("55555555-5555-5555-5555-555555555555"));
        assert!(safe_id("web-01"));
        assert!(!safe_slug("ACTIVE"));
        assert!(!safe_slug("a&b"));
        assert!(safe_slug("active"));
    }

    #[tokio::test]
    async fn resolve_vm_variants() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/vms"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    vm("11111111-1111-1111-1111-111111111111", "web-01", "active"),
                    vm(
                        "22222222-2222-2222-2222-222222222222",
                        "VM-Plane-Global",
                        "active"
                    ),
                    vm("33333333-3333-3333-3333-333333333333", "dup", "revoked"),
                    vm("44444444-4444-4444-4444-444444444444", "dup", "active")
                ])),
            )
            .mount(&server)
            .await;

        let settings = crate::config::Settings {
            hub_url: server.uri(),
            service_token: "svc".into(),
            transport: "stdio".into(),
            host: "127.0.0.1".into(),
            port: 0,
            trust_proxy: false,
        };
        let hub = HubClient::new(&settings);
        let ctx = CallCtx::default();

        // UUID → passthrough
        assert_eq!(
            resolve_vm(&hub, &ctx, "55555555-5555-5555-5555-555555555555")
                .await
                .unwrap(),
            "55555555-5555-5555-5555-555555555555"
        );
        // exact name
        assert_eq!(
            resolve_vm(&hub, &ctx, "web-01").await.unwrap(),
            "11111111-1111-1111-1111-111111111111"
        );
        // case-insensitive fallback
        assert_eq!(
            resolve_vm(&hub, &ctx, "vm-plane-global").await.unwrap(),
            "22222222-2222-2222-2222-222222222222"
        );
        // prefers active on re-enrollment reuse
        assert_eq!(
            resolve_vm(&hub, &ctx, "dup").await.unwrap(),
            "44444444-4444-4444-4444-444444444444"
        );
        // unknown → 404
        let err = resolve_vm(&hub, &ctx, "ghost").await.unwrap_err();
        assert_eq!(err["error"]["status"], 404);

        // ambiguous (two active with same name) → 409
        let server2 = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/vms"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    vm("6", "twin", "active"),
                    vm("7", "twin", "active")
                ])),
            )
            .mount(&server2)
            .await;
        let settings2 = crate::config::Settings {
            hub_url: server2.uri(),
            service_token: "svc".into(),
            transport: "stdio".into(),
            host: "127.0.0.1".into(),
            port: 0,
            trust_proxy: false,
        };
        let hub2 = HubClient::new(&settings2);
        let err = resolve_vm(&hub2, &ctx, "twin").await.unwrap_err();
        assert_eq!(err["error"]["status"], 409);
    }
}

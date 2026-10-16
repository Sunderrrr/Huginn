//! The 13 MCP tools and their hub delegation. Mirrors mcp/app/server.py tool
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
5. Browser automation (Linux VMs only): browser_start executes a sequence of steps
   on a headless browser (navigate → click → type → eval → screenshot). For a
   quick page text, use browser_navigate. For a screenshot, use browser_screenshot.
   The Obscura engine must first be installed with browser_install (admin) and
   the VM's browser capability enabled by an admin (dashboard) — a 403
   "browser automation is disabled" means that step is missing.
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

/// Browser automation guards (defense in depth — the hub re-validates every
/// step; these fail fast before any hub call). Exact step contract — see
/// docs/browser.md: navigate{url}, click{selector}, type{selector,text},
/// eval{js}, screenshot{format,quality}, get_text, get_html,
/// wait_for{selector,timeout_ms}.
const BROWSER_MAX_STEPS: usize = 50;
const BROWSER_MAX_URL: usize = 2048;
const BROWSER_MAX_SELECTOR: usize = 512;
const BROWSER_MAX_TEXT_BYTES: usize = 10 * 1024;
const BROWSER_MAX_JS_BYTES: usize = 64 * 1024;
const BROWSER_TIMEOUT_MIN_SECS: u64 = 1;
const BROWSER_TIMEOUT_MAX_SECS: u64 = 300;
const BROWSER_SCREENSHOT_QUALITY_DEFAULT: u64 = 80;

/// http(s) URLs only, non-empty, bounded length, no control characters —
/// refuses file://, javascript:, data: and friends before a step ever
/// reaches a worker.
fn safe_url(u: &str) -> bool {
    let rest = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"))
        .unwrap_or("");
    !rest.is_empty() && u.len() <= BROWSER_MAX_URL && !u.chars().any(|c| c.is_control())
}

/// Validates a browser step sequence BEFORE it is sent to the hub: non-empty
/// array, at most 50 steps, known actions, per-field caps (url http(s) ≤ 2048
/// chars, selector ≤ 512 chars, text ≤ 10 KiB, js ≤ 64 KiB). Returns the
/// structured error dict for the first invalid step.
fn validate_steps(steps: &Value) -> Result<(), Value> {
    let Some(list) = steps.as_array() else {
        return Err(tool_error(400, "steps must be a non-empty array"));
    };
    if list.is_empty() {
        return Err(tool_error(400, "steps must be a non-empty array"));
    }
    if list.len() > BROWSER_MAX_STEPS {
        return Err(tool_error(
            400,
            format!("too many steps: {} (max {BROWSER_MAX_STEPS})", list.len()),
        ));
    }
    for (i, step) in list.iter().enumerate() {
        let n = i + 1;
        let Some(obj) = step.as_object() else {
            return Err(tool_error(400, format!("step {n} must be an object")));
        };
        let field = |name: &str| obj.get(name).and_then(Value::as_str);
        match field("action").unwrap_or("") {
            "navigate" => {
                let Some(url) = field("url") else {
                    return Err(tool_error(400, format!("step {n}: navigate requires url")));
                };
                if !safe_url(url) {
                    return Err(tool_error(
                        400,
                        format!(
                            "step {n}: url must be http(s):// and at most {BROWSER_MAX_URL} chars"
                        ),
                    ));
                }
            }
            "click" | "wait_for" => {
                let Some(sel) = field("selector") else {
                    return Err(tool_error(400, format!("step {n}: selector is required")));
                };
                if sel.len() > BROWSER_MAX_SELECTOR {
                    return Err(tool_error(
                        400,
                        format!("step {n}: selector exceeds {BROWSER_MAX_SELECTOR} chars"),
                    ));
                }
            }
            "type" => {
                let Some(sel) = field("selector") else {
                    return Err(tool_error(400, format!("step {n}: type requires selector")));
                };
                if sel.len() > BROWSER_MAX_SELECTOR {
                    return Err(tool_error(
                        400,
                        format!("step {n}: selector exceeds {BROWSER_MAX_SELECTOR} chars"),
                    ));
                }
                let Some(text) = field("text") else {
                    return Err(tool_error(400, format!("step {n}: type requires text")));
                };
                if text.len() > BROWSER_MAX_TEXT_BYTES {
                    return Err(tool_error(
                        400,
                        format!(
                            "step {n}: text exceeds {} KiB",
                            BROWSER_MAX_TEXT_BYTES / 1024
                        ),
                    ));
                }
            }
            "eval" => {
                let Some(js) = field("js") else {
                    return Err(tool_error(400, format!("step {n}: eval requires js")));
                };
                if js.len() > BROWSER_MAX_JS_BYTES {
                    return Err(tool_error(
                        400,
                        format!("step {n}: js exceeds {} KiB", BROWSER_MAX_JS_BYTES / 1024),
                    ));
                }
            }
            // Parameterless steps; screenshot params are validated hub-side.
            "screenshot" | "get_text" | "get_html" => {}
            other => {
                return Err(tool_error(
                    400,
                    format!("step {n}: unknown action {other:?}"),
                ));
            }
        }
    }
    Ok(())
}

/// Browser task budget in seconds: default 120, allowed 1-300.
fn browser_timeout(args: &HashMap<String, Value>) -> Result<u64, Value> {
    let t = args.get("timeout").and_then(Value::as_u64).unwrap_or(120);
    if (BROWSER_TIMEOUT_MIN_SECS..=BROWSER_TIMEOUT_MAX_SECS).contains(&t) {
        Ok(t)
    } else {
        Err(tool_error(
            400,
            format!(
                "timeout must be {BROWSER_TIMEOUT_MIN_SECS}-{BROWSER_TIMEOUT_MAX_SECS} seconds"
            ),
        ))
    }
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

/// Shared tail of the browser tools: resolve the VM (id or name), run the
/// step sequence on the hub, and return the task with its results.
async fn run_browser_steps(
    hub: &HubClient,
    ctx: &CallCtx,
    vm: &str,
    steps: Value,
    timeout: u64,
) -> Value {
    match resolve_vm(hub, ctx, vm).await {
        Err(e) => e,
        Ok(id) => match hub.execute_browser(ctx, &id, steps, timeout).await {
            Ok(v) => v,
            Err(e) => from_hub_error(e),
        },
    }
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
        "browser_install" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            // The hub route is admin-only (RBAC enforced hub-side, audited);
            // the engine coordinates (version + SHA-256) are hub-pinned.
            match resolve_vm(&hub, ctx, vm).await {
                Err(e) => e,
                Ok(id) => match hub.install_browser_engine(ctx, &id).await {
                    Ok(v) => v,
                    Err(e) => from_hub_error(e),
                },
            }
        }
        "browser_start" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            let Some(steps) = args.get("steps") else {
                return tool_error(400, "steps is required");
            };
            if let Err(e) = validate_steps(steps) {
                return e;
            }
            let timeout = match browser_timeout(args) {
                Ok(t) => t,
                Err(e) => return e,
            };
            run_browser_steps(&hub, ctx, vm, steps.clone(), timeout).await
        }
        "browser_navigate" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            let Some(url) = args.get("url").and_then(Value::as_str) else {
                return tool_error(400, "url is required");
            };
            if !safe_url(url) {
                return tool_error(
                    400,
                    format!("url must be http(s):// and at most {BROWSER_MAX_URL} chars"),
                );
            }
            let timeout = match browser_timeout(args) {
                Ok(t) => t,
                Err(e) => return e,
            };
            // Shortcut: one navigate step, then read the page text.
            let steps = json!([{"action": "navigate", "url": url}, {"action": "get_text"}]);
            run_browser_steps(&hub, ctx, vm, steps, timeout).await
        }
        "browser_screenshot" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            let Some(url) = args.get("url").and_then(Value::as_str) else {
                return tool_error(400, "url is required");
            };
            if !safe_url(url) {
                return tool_error(
                    400,
                    format!("url must be http(s):// and at most {BROWSER_MAX_URL} chars"),
                );
            }
            let quality = match args.get("quality") {
                None => BROWSER_SCREENSHOT_QUALITY_DEFAULT,
                Some(v) => match v.as_u64() {
                    Some(q) if (1..=100).contains(&q) => q,
                    _ => return tool_error(400, "quality must be an integer between 1 and 100"),
                },
            };
            let timeout = match browser_timeout(args) {
                Ok(t) => t,
                Err(e) => return e,
            };
            // Shortcut: navigate, then capture a JPEG screenshot.
            let steps = json!([
                {"action": "navigate", "url": url},
                {"action": "screenshot", "format": "jpeg", "quality": quality},
            ]);
            run_browser_steps(&hub, ctx, vm, steps, timeout).await
        }
        "browser_eval" => {
            let Some(vm) = args.get("vm_id").and_then(Value::as_str) else {
                return tool_error(400, "vm_id is required");
            };
            let Some(url) = args.get("url").and_then(Value::as_str) else {
                return tool_error(400, "url is required");
            };
            if !safe_url(url) {
                return tool_error(
                    400,
                    format!("url must be http(s):// and at most {BROWSER_MAX_URL} chars"),
                );
            }
            let Some(js) = args.get("js").and_then(Value::as_str) else {
                return tool_error(400, "js is required");
            };
            if js.len() > BROWSER_MAX_JS_BYTES {
                return tool_error(
                    400,
                    format!("js exceeds {} KiB", BROWSER_MAX_JS_BYTES / 1024),
                );
            }
            let timeout = match browser_timeout(args) {
                Ok(t) => t,
                Err(e) => return e,
            };
            // Shortcut: navigate, then evaluate the JavaScript.
            let steps = json!([{"action": "navigate", "url": url}, {"action": "eval", "js": js}]);
            run_browser_steps(&hub, ctx, vm, steps, timeout).await
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
        },
        {
            "name": "browser_install",
            "description": "Install the pinned Obscura headless-browser engine on a VM's worker\n(admin only; Linux VMs only). Downloads the hub-pinned release\n(~70 MB) from GitHub, verifies its SHA-256, installs it under the\nHuginn-managed directory with its Apache-2.0 license, and smoke-tests\n``obscura --version``. Run this once before browser_start and friends —\nand make sure the VM's browser capability is enabled by an admin\n(dashboard), else browser tasks answer 403 \"browser automation is\ndisabled\".\n\nReturns the created task; poll it with get_task for the install result.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm_id": {"type": "string", "description": "VM id or name"}
                },
                "required": ["vm_id"]
            }
        },
        {
            "name": "browser_start",
            "description": "Open a headless browser on a VM and execute a sequence of steps in one tab\n(``vm_id`` may be a VM id or its name; Linux VMs only — the browser capability\nmust be enabled on the VM by an admin).\n\nSteps run in order: navigate{url}, click{selector}, type{selector,text},\neval{js}, screenshot{format,quality}, get_text, get_html,\nwait_for{selector,timeout_ms}. Example:\n\n    steps=[{\"action\":\"navigate\",\"url\":\"https://example.com\"},\n           {\"action\":\"type\",\"selector\":\"#q\",\"text\":\"rust\"},\n           {\"action\":\"click\",\"selector\":\"#go\"},\n           {\"action\":\"get_text\"}]\n\nReturns the task with the step results inline — page text/HTML, eval results,\nand the screenshot as base64 in stdout when requested.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm_id": {"type": "string"},
                    "steps": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "1-50 steps, e.g. {\"action\":\"navigate\",\"url\":\"https://example.com\"}"
                    },
                    "timeout": {"type": "integer", "default": 120, "description": "seconds (1-300)"}
                },
                "required": ["vm_id", "steps"]
            }
        },
        {
            "name": "browser_navigate",
            "description": "Load a URL in a headless browser on a VM and return the page's text\n(``vm_id`` may be a VM id or its name; Linux VMs only — the browser capability\nmust be enabled on the VM by an admin).\n\nShortcut for browser_start with a single navigate + get_text step sequence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm_id": {"type": "string"},
                    "url": {"type": "string", "description": "http(s) URL to load"},
                    "timeout": {"type": "integer", "default": 120, "description": "seconds (1-300)"}
                },
                "required": ["vm_id", "url"]
            }
        },
        {
            "name": "browser_screenshot",
            "description": "Take a screenshot of a web page on a VM: navigate to the URL, capture a JPEG,\nand return it as base64 in the task result's stdout (``vm_id`` may be a VM id\nor its name; Linux VMs only — the browser capability must be enabled on the VM\nby an admin).\n\nShortcut for browser_start with a navigate + screenshot step sequence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm_id": {"type": "string"},
                    "url": {"type": "string", "description": "http(s) URL to capture"},
                    "quality": {"type": "integer", "default": 80, "description": "JPEG quality (1-100)"},
                    "timeout": {"type": "integer", "default": 120, "description": "seconds (1-300)"}
                },
                "required": ["vm_id", "url"]
            }
        },
        {
            "name": "browser_eval",
            "description": "Run JavaScript on a web page on a VM: navigate to the URL, evaluate ``js``,\nand return the result (``vm_id`` may be a VM id or its name; Linux VMs only —\nthe browser capability must be enabled on the VM by an admin).\n\nShortcut for browser_start with a navigate + eval step sequence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm_id": {"type": "string"},
                    "url": {"type": "string", "description": "http(s) URL to load"},
                    "js": {"type": "string", "description": "JavaScript to evaluate (max 64 KiB)"},
                    "timeout": {"type": "integer", "default": 120, "description": "seconds (1-300)"}
                },
                "required": ["vm_id", "url", "js"]
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

    fn test_settings(hub_url: String) -> crate::config::Settings {
        crate::config::Settings {
            hub_url,
            service_token: "svc".into(),
            transport: "stdio".into(),
            host: "127.0.0.1".into(),
            port: 0,
            trust_proxy: false,
        }
    }

    fn tool_args(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn browser_url_guards() {
        assert!(safe_url("http://example.com"));
        assert!(safe_url("https://example.com/docs?q=rust#top"));
        assert!(!safe_url("file:///etc/passwd"), "file:// must be refused");
        assert!(
            !safe_url("javascript:alert(1)"),
            "javascript: must be refused"
        );
        assert!(!safe_url("data:text/html,<h1>hi"));
        assert!(!safe_url("ftp://example.com"));
        assert!(!safe_url("https://"), "scheme with no host");
        assert!(!safe_url(""));
        let ok = format!("https://{}", "a".repeat(BROWSER_MAX_URL - 8));
        assert_eq!(ok.len(), BROWSER_MAX_URL);
        assert!(safe_url(&ok), "exactly 2048 chars is accepted");
        let too_long = format!("https://{}", "a".repeat(BROWSER_MAX_URL - 7));
        assert!(!safe_url(&too_long), "over 2048 chars must be refused");
        assert!(!safe_url("http://ex\nample.com"), "control chars");
    }

    #[tokio::test]
    async fn browser_start_rejects_invalid_steps() {
        // Dead hub + UUID vm_id: resolve_vm never calls the hub, so a 400 can
        // only come from local validation; a 0 means the (valid) call tried
        // the hub and hit the dead port.
        let hub = Arc::new(HubClient::new(&test_settings("http://127.0.0.1:1".into())));
        let ctx = CallCtx::default();
        let vm = json!("55555555-5555-5555-5555-555555555555");

        let call = |pairs: &[(&str, Value)]| {
            let (hub, ctx) = (hub.clone(), ctx.clone());
            let args = tool_args(pairs);
            async move { call_tool(hub, &ctx, "browser_start", &args).await }
        };

        // missing steps
        assert_eq!(call(&[("vm_id", vm.clone())]).await["error"]["status"], 400);
        // empty steps
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", json!([]))]).await["error"]["status"],
            400
        );
        // steps not an array
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", json!("get_text"))]).await["error"]["status"],
            400
        );
        // > 50 steps
        let too_many: Vec<Value> = (0..=50).map(|_| json!({"action": "get_text"})).collect();
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", json!(too_many))]).await["error"]["status"],
            400
        );
        // a non-object step
        let junk = json!(["get_text"]);
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", junk)]).await["error"]["status"],
            400
        );
        // unknown action
        let unknown = json!([{"action": "format_disk"}]);
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", unknown)]).await["error"]["status"],
            400
        );
        // navigate with a non-http(s) url
        let bad_url = json!([{"action": "navigate", "url": "file:///etc/passwd"}]);
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", bad_url)]).await["error"]["status"],
            400
        );
        // selector over 512 chars
        let long_sel =
            json!([{"action": "click", "selector": "a".repeat(BROWSER_MAX_SELECTOR + 1)}]);
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", long_sel)]).await["error"]["status"],
            400
        );
        // text over 10 KiB
        let long_text = json!([
            {"action": "type", "selector": "#q", "text": "x".repeat(BROWSER_MAX_TEXT_BYTES + 1)}
        ]);
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", long_text)]).await["error"]["status"],
            400
        );
        // js over 64 KiB
        let long_js = json!([{"action": "eval", "js": "1".repeat(BROWSER_MAX_JS_BYTES + 1)}]);
        assert_eq!(
            call(&[("vm_id", vm.clone()), ("steps", long_js)]).await["error"]["status"],
            400
        );
        // timeout out of range (0 and 301)
        let ok_steps = json!([{"action": "get_text"}]);
        for bad in [0u64, 301] {
            assert_eq!(
                call(&[
                    ("vm_id", vm.clone()),
                    ("steps", ok_steps.clone()),
                    ("timeout", json!(bad))
                ])
                .await["error"]["status"],
                400,
                "timeout {bad} must be refused"
            );
        }
        // boundary values pass validation and reach the hub (status 0: dead hub)
        let fifty: Vec<Value> = (0..BROWSER_MAX_STEPS)
            .map(|i| json!({"action": "navigate", "url": format!("https://example.com/{i}")}))
            .collect();
        let max_js = json!([
            {"action": "navigate", "url": "https://example.com"},
            {"action": "eval", "js": "0".repeat(BROWSER_MAX_JS_BYTES)}
        ]);
        for steps in [json!(fifty), max_js] {
            assert_eq!(
                call(&[
                    ("vm_id", vm.clone()),
                    ("steps", steps),
                    ("timeout", json!(BROWSER_TIMEOUT_MAX_SECS))
                ])
                .await["error"]["status"],
                0,
                "valid input must reach the hub (dead hub → status 0)"
            );
        }
    }

    #[tokio::test]
    async fn browser_shortcut_input_guards() {
        let hub = Arc::new(HubClient::new(&test_settings("http://127.0.0.1:1".into())));
        let ctx = CallCtx::default();
        let vm = json!("55555555-5555-5555-5555-555555555555");

        // navigate: file:// refused
        assert_eq!(
            call_tool(
                hub.clone(),
                &ctx,
                "browser_navigate",
                &tool_args(&[("vm_id", vm.clone()), ("url", json!("file:///etc/passwd"))])
            )
            .await["error"]["status"],
            400
        );
        // navigate: missing url
        assert_eq!(
            call_tool(
                hub.clone(),
                &ctx,
                "browser_navigate",
                &tool_args(&[("vm_id", vm.clone())])
            )
            .await["error"]["status"],
            400
        );
        // screenshot: quality out of range / not an integer
        for bad in [json!(0), json!(101), json!("high")] {
            assert_eq!(
                call_tool(
                    hub.clone(),
                    &ctx,
                    "browser_screenshot",
                    &tool_args(&[
                        ("vm_id", vm.clone()),
                        ("url", json!("https://example.com")),
                        ("quality", bad.clone())
                    ])
                )
                .await["error"]["status"],
                400,
                "quality {bad} must be refused"
            );
        }
        // eval: js missing / oversized
        assert_eq!(
            call_tool(
                hub.clone(),
                &ctx,
                "browser_eval",
                &tool_args(&[("vm_id", vm.clone()), ("url", json!("https://example.com"))])
            )
            .await["error"]["status"],
            400
        );
        assert_eq!(
            call_tool(
                hub.clone(),
                &ctx,
                "browser_eval",
                &tool_args(&[
                    ("vm_id", vm.clone()),
                    ("url", json!("https://example.com")),
                    ("js", json!("0".repeat(BROWSER_MAX_JS_BYTES + 1)))
                ])
            )
            .await["error"]["status"],
            400
        );
    }

    #[tokio::test]
    async fn browser_start_posts_steps_and_obo_to_hub() {
        let server = wiremock::MockServer::start().await;
        let steps = json!([
            {"action": "navigate", "url": "https://example.com"},
            {"action": "type", "selector": "#q", "text": "rust lang"},
            {"action": "click", "selector": "#go"},
            {"action": "get_text"}
        ]);
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/vms/55555555-5555-5555-5555-555555555555/browser",
            ))
            .and(wiremock::matchers::body_json(json!({
                "steps": steps,
                "timeout": 120
            })))
            .and(wiremock::matchers::header(
                "X-MCP-On-Behalf-Of",
                "user-token-1",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "t-browser-1",
                    "status": "succeeded",
                    "result": {"stdout": "rust lang results"}
                })),
            )
            .mount(&server)
            .await;

        let hub = Arc::new(HubClient::new(&test_settings(server.uri())));
        let ctx = CallCtx {
            obo_token: Some("user-token-1".into()),
            client_ip: None,
        };
        let out = call_tool(
            hub,
            &ctx,
            "browser_start",
            &tool_args(&[
                ("vm_id", json!("55555555-5555-5555-5555-555555555555")),
                ("steps", steps),
            ]),
        )
        .await;
        assert_eq!(out["status"], "succeeded");
        assert_eq!(out["result"]["stdout"], "rust lang results");
    }

    #[tokio::test]
    async fn browser_navigate_is_a_navigate_get_text_shortcut() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/vms"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([vm(
                    "11111111-1111-1111-1111-111111111111",
                    "web-01",
                    "active"
                )])),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/vms/11111111-1111-1111-1111-111111111111/browser",
            ))
            .and(wiremock::matchers::body_json(json!({
                "steps": [
                    {"action": "navigate", "url": "https://example.com"},
                    {"action": "get_text"}
                ],
                "timeout": 45
            })))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "t1",
                    "status": "succeeded",
                    "result": {"stdout": "Example Domain"}
                })),
            )
            .mount(&server)
            .await;

        let hub = Arc::new(HubClient::new(&test_settings(server.uri())));
        let ctx = CallCtx::default();
        let out = call_tool(
            hub,
            &ctx,
            "browser_navigate",
            &tool_args(&[
                ("vm_id", json!("web-01")),
                ("url", json!("https://example.com")),
                ("timeout", json!(45)),
            ]),
        )
        .await;
        assert_eq!(out["result"]["stdout"], "Example Domain");
    }

    /// `browser_install` resolves the VM by name and POSTs the (bodyless)
    /// install route — the coordinates stay hub-pinned.
    #[tokio::test]
    async fn browser_install_posts_the_install_route() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/vms"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([vm(
                    "11111111-1111-1111-1111-111111111111",
                    "web-01",
                    "active"
                )])),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/vms/11111111-1111-1111-1111-111111111111/browser-install",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(202).set_body_json(serde_json::json!({
                    "id": "t9",
                    "type": "browser_install",
                    "status": "pending"
                })),
            )
            .mount(&server)
            .await;

        let hub = Arc::new(HubClient::new(&test_settings(server.uri())));
        let ctx = CallCtx::default();
        let out = call_tool(
            hub,
            &ctx,
            "browser_install",
            &tool_args(&[("vm_id", json!("web-01"))]),
        )
        .await;
        assert_eq!(out["type"], "browser_install");
        assert_eq!(out["status"], "pending");

        // No vm_id → 400 before any hub call.
        let hub = Arc::new(HubClient::new(&test_settings(server.uri())));
        let out = call_tool(hub, &ctx, "browser_install", &HashMap::new()).await;
        assert_eq!(out["error"]["status"], 400);
    }

    #[tokio::test]
    async fn browser_screenshot_posts_navigate_screenshot_steps() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/vms/55555555-5555-5555-5555-555555555555/browser",
            ))
            .and(wiremock::matchers::body_json(json!({
                "steps": [
                    {"action": "navigate", "url": "https://example.com"},
                    {"action": "screenshot", "format": "jpeg", "quality": 80}
                ],
                "timeout": 120
            })))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "t2",
                    "status": "succeeded",
                    "result": {"stdout": "<base64 jpeg>"}
                })),
            )
            .mount(&server)
            .await;

        let hub = Arc::new(HubClient::new(&test_settings(server.uri())));
        let ctx = CallCtx::default();
        // No quality/timeout: defaults (80 / 120) must be sent.
        let out = call_tool(
            hub,
            &ctx,
            "browser_screenshot",
            &tool_args(&[
                ("vm_id", json!("55555555-5555-5555-5555-555555555555")),
                ("url", json!("https://example.com")),
            ]),
        )
        .await;
        assert_eq!(out["result"]["stdout"], "<base64 jpeg>");
    }

    #[tokio::test]
    async fn browser_eval_posts_navigate_eval_steps() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/vms/55555555-5555-5555-5555-555555555555/browser",
            ))
            .and(wiremock::matchers::body_json(json!({
                "steps": [
                    {"action": "navigate", "url": "https://example.com"},
                    {"action": "eval", "js": "document.title"}
                ],
                "timeout": 90
            })))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "t3",
                    "status": "succeeded",
                    "result": {"stdout": "Example Domain"}
                })),
            )
            .mount(&server)
            .await;

        let hub = Arc::new(HubClient::new(&test_settings(server.uri())));
        let ctx = CallCtx::default();
        let out = call_tool(
            hub,
            &ctx,
            "browser_eval",
            &tool_args(&[
                ("vm_id", json!("55555555-5555-5555-5555-555555555555")),
                ("url", json!("https://example.com")),
                ("js", json!("document.title")),
                ("timeout", json!(90)),
            ]),
        )
        .await;
        assert_eq!(out["result"]["stdout"], "Example Domain");
    }
}

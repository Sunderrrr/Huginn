//! JSON-RPC 2.0 + MCP message handling (initialize, ping, tools/list,
//! tools/call). Stateless: every request is handled independently.

use crate::hub_client::{CallCtx, HubClient};
use crate::tools;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub const PROTOCOL_VERSION: &str = "2025-03-26";

pub struct AppState {
    pub hub: Arc<HubClient>,
    pub validator: Arc<crate::auth::TokenValidator>,
    /// Forwarded-IP headers are honored only behind a stamping edge proxy.
    pub trust_proxy: bool,
}

fn error_obj(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

fn result_obj(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// Handles a single JSON-RPC message. Returns None for notifications
/// (no response), matching the spec.
pub async fn handle_message(state: &AppState, ctx: &CallCtx, msg: &Value) -> Option<Value> {
    if msg.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(error_obj(
            msg.get("id").cloned().unwrap_or(Value::Null),
            -32600,
            "invalid request",
        ));
    }
    let id = msg.get("id").cloned();
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        // A message without a method and with an id is invalid.
        return Some(error_obj(
            id.unwrap_or(Value::Null),
            -32600,
            "invalid request",
        ));
    };
    let Some(id) = id else {
        return None; // notification — never answered
    };
    let params = msg
        .get("params")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));

    match method {
        "initialize" => {
            // Echo the client's requested protocol version when provided, as
            // most servers do for compatibility.
            let version = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(PROTOCOL_VERSION)
                .to_string();
            Some(result_obj(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "Huginn", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": tools::INSTRUCTIONS,
                }),
            ))
        }
        "ping" => Some(result_obj(id, json!({}))),
        "tools/list" => Some(result_obj(id, json!({"tools": tools::tool_definitions()}))),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() {
                return Some(error_obj(id, -32602, "missing tool name"));
            }
            let args: HashMap<String, Value> = params
                .get("arguments")
                .and_then(Value::as_object)
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            let result = tools::call_tool(state.hub.clone(), ctx, name, &args).await;
            // A structured tool error dict is returned as content with
            // isError=true, like FastMCP's error mapping.
            let is_error = result.get("error").is_some();
            Some(result_obj(
                id,
                json!({
                    "content": [{"type": "text", "text": result.to_string()}],
                    "isError": is_error,
                }),
            ))
        }
        other => Some(error_obj(id, -32601, &format!("method not found: {other}"))),
    }
}

/// Handles a parsed body that may be a single message or a batch.
pub async fn handle_body(state: &AppState, ctx: &CallCtx, body: &Value) -> Option<Value> {
    match body {
        Value::Array(items) => {
            // A 4 MiB body can pack ~40k messages; each may hit the hub
            // (slow tools, 300s waits) — bound the batch.
            const MAX_BATCH: usize = 32;
            if items.len() > MAX_BATCH {
                return Some(error_obj(
                    Value::Null,
                    -32600,
                    &format!("batch too large: {} items (max {MAX_BATCH})", items.len()),
                ));
            }
            let mut responses = Vec::new();
            for item in items {
                if let Some(resp) = handle_message(state, ctx, item).await {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                None // batch of notifications only
            } else {
                Some(Value::Array(responses))
            }
        }
        other => handle_message(state, ctx, other).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        let settings = crate::config::Settings {
            hub_url: "http://127.0.0.1:1".into(),
            service_token: "svc".into(),
            transport: "stdio".into(),
            host: "127.0.0.1".into(),
            port: 0,
            trust_proxy: false,
        };
        AppState {
            hub: Arc::new(HubClient::new(&settings)),
            validator: Arc::new(crate::auth::TokenValidator::new(Arc::new(HubClient::new(
                &settings,
            )))),
            trust_proxy: false,
        }
    }

    #[tokio::test]
    async fn initialize_and_lists_tools() {
        let s = state();
        let ctx = CallCtx::default();
        let init = serde_json::from_str::<Value>(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
        )
        .unwrap();
        let resp = handle_message(&s, &ctx, &init).await.unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "Huginn");

        let list =
            serde_json::from_str::<Value>(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
                .unwrap();
        let resp = handle_message(&s, &ctx, &list).await.unwrap();
        let tools_arr = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools_arr.len(), 14, "14 tools expected");
        let names: Vec<&str> = tools_arr
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        for expected in [
            "list_vms",
            "get_vm_status",
            "list_actions",
            "execute_action",
            "execute_command",
            "trigger_update",
            "get_task",
            "wait_for_task",
            "get_audit_log",
            "browser_start",
            "browser_navigate",
            "browser_screenshot",
            "browser_eval",
        ] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
    }

    #[tokio::test]
    async fn notifications_get_no_response() {
        let s = state();
        let ctx = CallCtx::default();
        let n = serde_json::from_str::<Value>(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .unwrap();
        assert!(handle_message(&s, &ctx, &n).await.is_none());
    }

    #[tokio::test]
    async fn unknown_method_errors() {
        let s = state();
        let ctx = CallCtx::default();
        let m =
            serde_json::from_str::<Value>(r#"{"jsonrpc":"2.0","id":9,"method":"nope"}"#).unwrap();
        let resp = handle_message(&s, &ctx, &m).await.unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }
}

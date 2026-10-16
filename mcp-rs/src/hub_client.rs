//! Typed façade over the hub REST API. Mirrors mcp/app/hub_client.py:
//! every call forwards the end-user identity (on-behalf-of) and the
//! originating client IP so actions are attributed and audited correctly.

use crate::config::Settings;
use reqwest::Method;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

pub struct HubClient {
    base_url: String,
    service_token: String,
    http: reqwest::Client,
}

/// Error surfaced from the hub (status + detail).
#[derive(Debug, Clone)]
pub struct HubError {
    pub status_code: u16,
    pub detail: String,
}

/// Per-request identity forwarded to the hub.
#[derive(Debug, Clone, Default)]
pub struct CallCtx {
    pub obo_token: Option<String>,
    pub client_ip: Option<String>,
}

impl HubClient {
    pub fn new(settings: &Settings) -> Self {
        Self {
            base_url: settings.hub_url.trim_end_matches('/').to_string(),
            service_token: settings.service_token.clone(),
            http: reqwest::Client::builder()
                .timeout(crate::config::HUB_TIMEOUT)
                .build()
                .expect("reqwest client"),
        }
    }

    /// `GET /api/mcp/whoami` — validates a presented per-user MCP token.
    pub async fn whoami(
        &self,
        presented: &str,
        client_ip: Option<&str>,
    ) -> Result<Value, HubError> {
        let mut headers = vec![
            (
                "X-MCP-Service-Token".to_string(),
                self.service_token.clone(),
            ),
            ("X-MCP-On-Behalf-Of".to_string(), presented.to_string()),
        ];
        if let Some(ip) = client_ip {
            headers.push(("X-Forwarded-For".to_string(), ip.to_string()));
        }
        self.request_with_timeout(
            Method::GET,
            "/api/mcp/whoami",
            None,
            &headers,
            false,
            crate::config::WHOAMI_TIMEOUT,
        )
        .await
    }

    pub async fn list_vms(&self, ctx: &CallCtx, state: Option<&str>) -> Result<Value, HubError> {
        let path = match state {
            Some(s) => format!("/api/vms?state={s}"),
            None => "/api/vms".to_string(),
        };
        self.get(ctx, &path).await
    }

    pub async fn get_vm(&self, ctx: &CallCtx, vm_id: &str) -> Result<Value, HubError> {
        self.get(ctx, &format!("/api/vms/{vm_id}")).await
    }

    pub async fn execute_action(
        &self,
        ctx: &CallCtx,
        vm_id: &str,
        action: &str,
        params: &HashMap<String, String>,
        wait: bool,
    ) -> Result<Value, HubError> {
        let body = serde_json::json!({"action": action, "params": params, "wait": wait});
        self.post(ctx, &format!("/api/vms/{vm_id}/actions"), &body)
            .await
    }

    pub async fn execute_command(
        &self,
        ctx: &CallCtx,
        vm_id: &str,
        command: &str,
        wait: bool,
    ) -> Result<Value, HubError> {
        let body = serde_json::json!({"command": command, "wait": wait});
        self.post(ctx, &format!("/api/vms/{vm_id}/commands"), &body)
            .await
    }

    /// `POST /api/vms/{vm_id}/browser` — run a headless-browser step sequence
    /// (task type `browser`). The hub holds the request until the worker
    /// finishes the steps — up to `timeout` seconds — and returns the task
    /// with its results inline (page text/HTML, eval results, screenshot
    /// base64 in stdout), so the per-request budget must cover the whole run,
    /// not the default 30s hub timeout.
    pub async fn execute_browser(
        &self,
        ctx: &CallCtx,
        vm_id: &str,
        steps: Value,
        timeout: u64,
    ) -> Result<Value, HubError> {
        let body = serde_json::json!({"steps": steps, "timeout": timeout});
        // Like wait_task: cap the window defensively (the tools validate
        // 1-300) and add slack for worker pickup, obscura startup, and
        // result submission.
        let budget = Duration::from_secs(timeout.min(300) + 30);
        let headers = ctx_headers(ctx);
        self.request_with_timeout(
            Method::POST,
            &format!("/api/vms/{vm_id}/browser"),
            Some(&body),
            &headers,
            true,
            budget,
        )
        .await
    }

    /// Queue the Obscura engine install on a VM (admin-only hub route; the
    /// hub pins the release coordinates — version + per-arch SHA-256 — from
    /// the fleet settings). Returns the created task immediately (202); the
    /// download runs on the worker, so no extended HTTP budget is needed.
    pub async fn install_browser_engine(
        &self,
        ctx: &CallCtx,
        vm_id: &str,
    ) -> Result<Value, HubError> {
        self.post(
            ctx,
            &format!("/api/vms/{vm_id}/browser-install"),
            &Value::Null,
        )
        .await
    }

    pub async fn trigger_update(&self, ctx: &CallCtx, vm_id: &str) -> Result<Value, HubError> {
        self.post(ctx, &format!("/api/vms/{vm_id}/update"), &Value::Null)
            .await
    }

    pub async fn list_actions(&self, ctx: &CallCtx) -> Result<Value, HubError> {
        self.get(ctx, "/api/actions").await
    }

    pub async fn get_task(&self, ctx: &CallCtx, task_id: &str) -> Result<Value, HubError> {
        self.get(ctx, &format!("/api/tasks/{task_id}")).await
    }

    pub async fn wait_task(
        &self,
        ctx: &CallCtx,
        task_id: &str,
        timeout: u64,
    ) -> Result<Value, HubError> {
        // The hub holds the request up to 300s server-side; the default 30s
        // client timeout cut the wait with a transport error and pushed agents
        // back to busy-polling. Allow the full server-side window + slack.
        let timeout = timeout.min(300);
        let path = format!("/api/tasks/{task_id}/wait?timeout={timeout}");
        let headers = ctx_headers(ctx);
        self.request_with_timeout(
            Method::GET,
            &path,
            None,
            &headers,
            true,
            Duration::from_secs(timeout + 5),
        )
        .await
    }

    pub async fn get_audit_log(
        &self,
        ctx: &CallCtx,
        vm_id: Option<&str>,
        event_type: Option<&str>,
        limit: u64,
    ) -> Result<Value, HubError> {
        let mut params = vec![format!("limit={limit}")];
        if let Some(v) = vm_id {
            params.push(format!("vm_id={v}"));
        }
        if let Some(e) = event_type {
            params.push(format!("event_type={e}"));
        }
        self.get(ctx, &format!("/api/audit?{}", params.join("&")))
            .await
    }

    async fn get(&self, ctx: &CallCtx, path: &str) -> Result<Value, HubError> {
        self.request(Method::GET, path, None, &ctx_headers(ctx), true)
            .await
    }

    async fn post(&self, ctx: &CallCtx, path: &str, body: &Value) -> Result<Value, HubError> {
        self.request(Method::POST, path, Some(body), &ctx_headers(ctx), true)
            .await
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        extra_headers: &[(String, String)],
        send_service_token: bool,
    ) -> Result<Value, HubError> {
        self.request_with_timeout(
            method,
            path,
            body,
            extra_headers,
            send_service_token,
            crate::config::HUB_TIMEOUT,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_with_timeout(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        extra_headers: &[(String, String)],
        send_service_token: bool,
        timeout: std::time::Duration,
    ) -> Result<Value, HubError> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base_url))
            .timeout(timeout);
        if send_service_token {
            req = req.header("X-MCP-Service-Token", &self.service_token);
        }
        for (k, v) in extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(b) = body {
            if !b.is_null() {
                req = req.json(b);
            }
        }
        let resp = req.send().await.map_err(|e| HubError {
            status_code: 0,
            detail: e.to_string(),
        })?;
        let status = resp.status().as_u16();
        if status >= 400 {
            let text = resp.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(str::to_string))
                .unwrap_or(text);
            return Err(HubError {
                status_code: status,
                detail,
            });
        }
        if status == 204 {
            return Ok(Value::Null);
        }
        let text = resp.text().await.unwrap_or_default();
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| HubError {
            status_code: status,
            detail: e.to_string(),
        })
    }
}

fn ctx_headers(ctx: &CallCtx) -> Vec<(String, String)> {
    let mut h = Vec::new();
    if let Some(t) = &ctx.obo_token {
        h.push(("X-MCP-On-Behalf-Of".to_string(), t.clone()));
    }
    if let Some(ip) = &ctx.client_ip {
        h.push(("X-Forwarded-For".to_string(), ip.clone()));
    }
    h
}

//! huginn-mcp — the Huginn MCP server. Rust port of mcp/app/server.py.
//!
//! Exposes the hub's fleet-management capabilities as MCP tools so an external
//! agent can drive the fleet. Every tool is a thin delegation to the hub's
//! REST API — no business logic is duplicated, and the server never talks to
//! workers directly.
//!
//!     huginn-mcp                          # stdio
//!     HUGINN_MCP_TRANSPORT=streamable-http huginn-mcp   # remote, per-user Bearer tokens

mod auth;
mod config;
mod hub_client;
mod protocol;
mod tools;

use auth::TokenValidator;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use hub_client::{CallCtx, HubClient};
use protocol::AppState;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let settings = Arc::new(config::Settings::from_env());
    let hub = Arc::new(HubClient::new(&settings));
    let state = Arc::new(AppState {
        hub: hub.clone(),
        validator: Arc::new(TokenValidator::new(hub)),
        trust_proxy: settings.trust_proxy,
    });

    if settings.transport == "streamable-http" {
        run_http(state, &settings).await;
    } else {
        // stdio has no per-user auth: whoever can write to this process's
        // stdin acts as the anonymous agent on the hub (full execution, no
        // attribution). Treat the host's access to the process as the trust
        // boundary — see mcp-rs/PARITY_HUB.md.
        eprintln!("huginn-mcp: stdio transport — unauthenticated local mode (no per-user attribution on the hub)");
        run_stdio(state).await;
    }
}

/// MCP over stdio: one JSON-RPC message per line, response per line.
async fn run_stdio(state: Arc<AppState>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();
    let ctx = CallCtx::default();
    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(body) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            let err = serde_json::json!(
                {"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}}
            );
            let _ = stdout.write_all(format!("{err}\n").as_bytes()).await;
            continue;
        };
        if let Some(resp) = protocol::handle_body(&state, &ctx, &body).await {
            let _ = stdout.write_all(format!("{resp}\n").as_bytes()).await;
            let _ = stdout.flush().await;
        }
    }
}

/// MCP over streamable HTTP: POST JSON-RPC, respond JSON (stateless,
/// json-response mode — parity with FastMCP stateless_http + json_response).
/// The streamable-http router (also used by the e2e tests).
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/mcp", post(mcp_post).get(mcp_get))
        .with_state(state)
}

async fn run_http(state: Arc<AppState>, settings: &config::Settings) {
    let app = router(state);
    let addr = std::net::SocketAddr::from((
        settings
            .host
            .parse()
            .unwrap_or_else(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        settings.port,
    ));
    eprintln!("huginn-mcp: listening on {addr} (streamable-http, per-user token auth)");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind HTTP listener");
    axum::serve(listener, app).await.expect("HTTP server");
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

async fn mcp_get() -> Response {
    // No server-push SSE in stateless json-response mode (parity with the
    // Python server which only accepts POST).
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "use POST for MCP messages (stateless json-response mode)",
    )
        .into_response()
}

async fn mcp_post(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Body) -> Response {
    // Client IP: behind a stamping edge proxy (trust_proxy on), the forwarded
    // headers; otherwise only the direct peer — never client-supplied headers. The direct peer is not
    // extracted here (axum 0.8: ConnectInfo is not an optional part
    // extractor); behind the bundled Caddy the stamped header is authoritative.
    let ip = if state.trust_proxy {
        auth::client_ip(
            header_value(&headers, "x-real-ip"),
            header_value(&headers, "x-forwarded-for"),
            None,
        )
    } else {
        None
    };
    let auth_header = header_value(&headers, "authorization").unwrap_or("");
    let presented = auth_header
        .strip_prefix("Bearer ")
        .unwrap_or("")
        .to_string();
    if !state.validator.valid(&presented, ip.as_deref()).await {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"error":"unauthorized"}"#))
            .unwrap();
    }

    let bytes = match axum::body::to_bytes(body, 4 << 20).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, r#"{"error":"invalid body"}"#).into_response();
        }
    };
    let Ok(json_body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (StatusCode::BAD_REQUEST, r#"{"error":"invalid json"}"#).into_response();
    };
    let ctx = CallCtx {
        obo_token: Some(presented),
        client_ip: ip,
    };
    match protocol::handle_body(&state, &ctx, &json_body).await {
        Some(resp) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(resp.to_string()))
            .unwrap(),
        // Notification(s) only → 202 Accepted with empty body.
        None => Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Body::empty())
            .unwrap(),
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn state_with_hub(hub_url: String) -> Arc<AppState> {
        let settings = config::Settings {
            hub_url,
            service_token: "svc-token".into(),
            transport: "streamable-http".into(),
            host: "127.0.0.1".into(),
            port: 0,
            trust_proxy: false,
        };
        let hub = Arc::new(HubClient::new(&settings));
        Arc::new(AppState {
            hub: hub.clone(),
            validator: Arc::new(TokenValidator::new(hub)),
            // The e2e suite exercises the behind-Caddy flow (stamped headers).
            trust_proxy: true,
        })
    }

    fn rpc(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn rejects_unauthenticated_requests() {
        let state = state_with_hub("http://127.0.0.1:1".into());
        let resp = router(state)
            .oneshot(rpc(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "no token must 401");
    }

    #[tokio::test]
    async fn serves_tools_list_for_valid_token() {
        // Mock hub validating the bearer token at /api/mcp/whoami.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/mcp/whoami"))
            .and(wiremock::matchers::header(
                "X-MCP-On-Behalf-Of",
                "user-token-1",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id": "u1", "username": "alice"})),
            )
            .mount(&server)
            .await;

        let state = state_with_hub(server.uri());
        let mut req = rpc(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        req.headers_mut()
            .insert("authorization", "Bearer user-token-1".parse().unwrap());
        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["result"]["tools"].as_array().unwrap().len(), 15);
    }

    #[tokio::test]
    async fn invalid_token_is_denied() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/mcp/whoami"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let state = state_with_hub(server.uri());
        let mut req = rpc(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        req.headers_mut()
            .insert("authorization", "Bearer bad-token".parse().unwrap());
        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tools_call_is_forwarded_with_obo_and_ip() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/mcp/whoami"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/tasks/abc"))
            .and(wiremock::matchers::header(
                "X-MCP-On-Behalf-Of",
                "user-token-1",
            ))
            .and(wiremock::matchers::header("X-Forwarded-For", "203.0.113.7"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id": "abc", "status": "succeeded"})),
            )
            .mount(&server)
            .await;

        let state = state_with_hub(server.uri());
        let mut req = rpc(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_task","arguments":{"task_id":"abc"}}}"#,
        );
        req.headers_mut()
            .insert("authorization", "Bearer user-token-1".parse().unwrap());
        req.headers_mut()
            .insert("x-real-ip", "203.0.113.7".parse().unwrap());
        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let text = json["result"]["content"][0]["text"].as_str().unwrap();
        let out: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(out["status"], "succeeded");
    }
}

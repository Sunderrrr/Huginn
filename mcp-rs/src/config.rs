//! Huginn MCP server configuration (env prefix `HUGINN_MCP_`).
//! Mirrors mcp/app/config.py.

use std::time::Duration;

pub struct Settings {
    pub hub_url: String,
    pub service_token: String,
    /// "stdio" (default) or "streamable-http".
    pub transport: String,
    pub host: String,
    pub port: u16,
    /// Trust X-Real-IP / X-Forwarded-For from the peer (fail-closed: only the
    /// direct peer is used otherwise). Set to "true"/"1" ONLY when an edge
    /// proxy stamps these headers (the bundled Caddyfile does, with
    /// header_up X-Real-IP). A directly exposed port would otherwise let any
    /// client spoof its IP and bypass the MCP tokens' IP allow-lists.
    pub trust_proxy: bool,
}

impl Settings {
    pub fn from_env() -> Self {
        Self {
            hub_url: std::env::var("HUGINN_MCP_HUB_URL")
                .unwrap_or_else(|_| "http://hub:8000".into()),
            service_token: std::env::var("HUGINN_MCP_SERVICE_TOKEN").unwrap_or_default(),
            transport: std::env::var("HUGINN_MCP_TRANSPORT").unwrap_or_else(|_| "stdio".into()),
            host: std::env::var("HUGINN_MCP_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: std::env::var("HUGINN_MCP_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(9000),
            trust_proxy: matches!(
                std::env::var("HUGINN_MCP_TRUST_PROXY").as_deref(),
                Ok("true") | Ok("1") | Ok("yes") | Ok("on")
            ),
        }
    }
}

pub const HUB_TIMEOUT: Duration = Duration::from_secs(30);
pub const WHOAMI_TIMEOUT: Duration = Duration::from_secs(10);

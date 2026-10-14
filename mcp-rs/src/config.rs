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
        }
    }
}

pub const HUB_TIMEOUT: Duration = Duration::from_secs(30);
pub const WHOAMI_TIMEOUT: Duration = Duration::from_secs(10);

//! Huginn MCP server configuration (env prefix `HUGINN_MCP_`).
//! Mirrors mcp/app/config.py.

use std::net::IpAddr;
use std::time::Duration;

/// Minimum accepted length of `HUGINN_MCP_SERVICE_TOKEN`. The token is the
/// MCP's only credential towards the hub (it is sent in `X-MCP-Service-Token`
/// on every call), so a short or unset value must never reach the hub: an
/// empty token would be accepted by a hub configured with an empty token
/// (`constant_time_equals("", "")`), which turns the MCP into an
/// unauthenticated fleet-control proxy.
pub const MIN_SERVICE_TOKEN_LEN: usize = 32;

/// Placeholders that must never be used as a real service token.
const PLACEHOLDER_MARKERS: [&str; 6] = [
    "change-me",
    "change_me",
    "changeme",
    "placeholder",
    "example",
    "your-token",
];

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
    /// Networks (CIDR or bare IP) of the reverse proxies allowed to stamp the
    /// client-IP headers. When empty, the headers are trusted from ANY peer
    /// (legacy behaviour) — that is only safe when the MCP port is reachable
    /// exclusively through the proxy. Set this to the proxy's network (e.g.
    /// `172.16.0.0/12`) to make the header trust verifiable.
    pub trusted_proxy_cidrs: Vec<String>,
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
            trusted_proxy_cidrs: std::env::var("HUGINN_MCP_TRUSTED_PROXY_CIDRS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }

    /// Startup gate: refuse to run with a missing/short service token.
    ///
    /// The MCP is a *credentialed* façade: the hub authenticates it with the
    /// service token on every call. An unset token would be sent as an empty
    /// header, which a misconfigured hub (empty `HUGINN_MCP_SERVICE_TOKEN`)
    /// accepts — the MCP would then drive the fleet as the anonymous
    /// service-token agent (full execution, no user attribution). Failing
    /// loudly at startup is the only safe behaviour.
    pub fn validate(&self) -> Result<(), String> {
        let token = self.service_token.trim();
        if token.is_empty() {
            return Err(
                "HUGINN_MCP_SERVICE_TOKEN is not set — the MCP authenticates to the hub with it \
                 (generate one with `openssl rand -hex 32`)"
                    .to_string(),
            );
        }
        if token.len() < MIN_SERVICE_TOKEN_LEN {
            return Err(format!(
                "HUGINN_MCP_SERVICE_TOKEN is too short ({} bytes, minimum {MIN_SERVICE_TOKEN_LEN}) \
                 — generate one with `openssl rand -hex 32`",
                token.len()
            ));
        }
        Ok(())
    }

    /// Non-fatal warnings about a technically valid but suspicious token.
    pub fn warnings(&self) -> Vec<String> {
        let token = self.service_token.trim().to_ascii_lowercase();
        if PLACEHOLDER_MARKERS.iter().any(|m| token.contains(m)) {
            return vec![
                "HUGINN_MCP_SERVICE_TOKEN looks like a placeholder — replace it with a generated \
                 secret (`openssl rand -hex 32`)"
                    .to_string(),
            ];
        }
        Vec::new()
    }

    /// The trusted-proxy networks, parsed. Unparseable entries are ignored
    /// (they can never match a peer, so they fail closed).
    pub fn trusted_proxy_networks(&self) -> Vec<(IpAddr, u32)> {
        self.trusted_proxy_cidrs
            .iter()
            .filter_map(|s| parse_network(s))
            .collect()
    }
}

/// Parse `"1.2.3.4"`, `"1.2.3.4/24"` or `"2001:db8::/32"` into an address and
/// a prefix length. A bare address behaves as a host route (/32, /128).
pub fn parse_network(value: &str) -> Option<(IpAddr, u32)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix.parse::<u32>().ok()?)),
        None => (value, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    match prefix {
        None => Some((ip, max)),
        Some(p) if p <= max => Some((ip, p)),
        Some(_) => None,
    }
}

pub const HUB_TIMEOUT: Duration = Duration::from_secs(30);
pub const WHOAMI_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(token: &str) -> Settings {
        Settings {
            hub_url: "http://hub:8000".into(),
            service_token: token.into(),
            transport: "streamable-http".into(),
            host: "127.0.0.1".into(),
            port: 9000,
            trust_proxy: true,
            trusted_proxy_cidrs: vec![],
        }
    }

    #[test]
    fn validate_rejects_missing_or_short_service_token() {
        assert!(settings("").validate().is_err());
        assert!(settings("   ").validate().is_err());
        assert!(settings("short").validate().is_err());
        assert!(settings(&"a".repeat(31)).validate().is_err());
        assert!(settings(&"a".repeat(32)).validate().is_ok());
    }

    #[test]
    fn validate_accepts_a_generated_token() {
        let token = "cdd677ccacfef7be3bd00cc10e92ce54f53a02d3cb8c25e53e5ff861e8d29172";
        assert!(settings(token).validate().is_ok());
        assert!(settings(token).warnings().is_empty());
    }

    #[test]
    fn warnings_flag_placeholder_tokens() {
        assert!(settings(&"a".repeat(32)).warnings().is_empty());
        let placeholder = "change-me-openssl-rand-hex-32-xxxx";
        assert!(settings(placeholder).validate().is_ok());
        assert!(!settings(placeholder).warnings().is_empty());
    }

    #[test]
    fn networks_are_parsed() {
        assert_eq!(
            parse_network("10.0.0.0/8"),
            Some(("10.0.0.0".parse().unwrap(), 8))
        );
        assert_eq!(
            parse_network("10.0.0.1"),
            Some(("10.0.0.1".parse().unwrap(), 32))
        );
        assert_eq!(
            parse_network("2001:db8::/32"),
            Some(("2001:db8::".parse().unwrap(), 32))
        );
        assert_eq!(parse_network("10.0.0.0/33"), None);
        assert_eq!(parse_network("garbage"), None);
        assert_eq!(parse_network(""), None);
    }
}

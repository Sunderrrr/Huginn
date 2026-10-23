//! Per-user MCP token authentication (streamable-http only), mirroring
//! mcp/app/server.py: the presented `Authorization: Bearer <token>` is
//! validated against the hub (`/api/mcp/whoami`) with the service token and
//! the presented token as on-behalf-of; results are cached briefly (the hub
//! re-validates on every actual tool call, so this is just a connect-time
//! gate). The client IP is resolved from the trusted proxy's stamped header
//! (`X-Real-IP`), then the proxy-appended hop of `X-Forwarded-For`, then the
//! direct peer.

use crate::hub_client::HubClient;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const CACHE_TTL: Duration = Duration::from_secs(30);
/// Cap so a flood of distinct bogus bearers can't grow the cache unbounded.
const MAX_ENTRIES: usize = 1024;

pub struct TokenValidator {
    cache: Mutex<HashMap<(String, String), (bool, Instant)>>,
    /// Insertion order for FIFO eviction — `clear()` on cap let an attacker
    /// flush every valid entry with a burst of bogus bearers.
    order: Mutex<Vec<(String, String)>>,
    client: Arc<HubClient>,
}

impl TokenValidator {
    pub fn new(client: Arc<HubClient>) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
            client,
        }
    }

    pub async fn valid(&self, presented: &str, client_ip: Option<&str>) -> bool {
        if presented.is_empty() {
            return false;
        }
        let key = (presented.to_string(), client_ip.unwrap_or("").to_string());
        {
            let cache = self.cache.lock().await;
            if let Some((ok, at)) = cache.get(&key) {
                if at.elapsed() < CACHE_TTL {
                    return *ok;
                }
            }
        }
        let ok = match self.client.whoami(presented, client_ip).await {
            Ok(_) => true,
            Err(e) if e.status_code == 0 => false, // hub unreachable → deny
            Err(_) => false,
        };
        // Negative results get a short TTL: a flood of distinct bogus bearers
        // must not evict valid entries (and each bogus hit costs a whoami
        // round-trip anyway, so the cache barely helps them).
        let ttl = if ok {
            CACHE_TTL
        } else {
            Duration::from_secs(5)
        };
        let mut cache = self.cache.lock().await;
        let mut order = self.order.lock().await;
        if cache.len() >= MAX_ENTRIES {
            while cache.len() >= MAX_ENTRIES {
                let Some(oldest) = order.first().cloned() else {
                    break;
                };
                order.remove(0);
                cache.remove(&oldest);
            }
        }
        if !cache.contains_key(&key) {
            order.push(key.clone());
        }
        cache.insert(key, (ok, Instant::now() - (CACHE_TTL - ttl)));
        ok
    }
}

/// The right-most non-empty entry of an `X-Forwarded-For` list — the hop the
/// trusted proxy appended (the bundled Caddyfile overwrites the header, and
/// the hub applies the same rule: the left-hand entries are client-controlled
/// and must never be believed).
pub fn forwarded_for_last(forwarded: &str) -> Option<&str> {
    forwarded.rsplit(',').map(str::trim).find(|s| !s.is_empty())
}

/// Parse an IP address, returning its canonical textual form. Non-IP values
/// (garbage, a hostname, an injected header payload) are rejected.
fn parse_ip(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Originating client IP from the forwarded headers, in order of trust:
/// the proxy-stamped `X-Real-IP`, then the proxy-appended hop of
/// `X-Forwarded-For`, then the direct peer. Every candidate must parse as an
/// IP address — a header carrying anything else is ignored rather than
/// relayed to the hub.
pub fn client_ip(real_ip: Option<&str>, xff: Option<&str>, peer: Option<&str>) -> Option<String> {
    if let Some(ip) = real_ip.and_then(parse_ip) {
        return Some(ip);
    }
    if let Some(last) = xff.and_then(forwarded_for_last).and_then(parse_ip) {
        return Some(last);
    }
    peer.and_then(parse_ip)
}

/// Resolve the client IP under the deployment's trust policy.
///
/// * `trust_proxy = false` → the forwarded headers are ignored entirely and
///   the direct peer is the client (it is the only address that cannot be
///   forged by the caller).
/// * `trust_proxy = true` → the headers are honoured **only** when the direct
///   peer belongs to `trusted_proxies` (the configured proxy networks). When
///   the proxy list is empty the headers are trusted from any peer — legacy
///   behaviour, only safe while the MCP port is reachable exclusively through
///   the proxy (the startup check warns about it).
///
/// When the peer is not a trusted proxy the peer address is returned, so the
/// hub sees the real (unforgeable) client and its IP allow-lists fail closed.
pub fn resolve_client_ip(
    trust_proxy: bool,
    trusted_proxies: &[(IpAddr, u32)],
    real_ip: Option<&str>,
    xff: Option<&str>,
    peer: Option<&str>,
) -> Option<String> {
    let peer_ip = peer.and_then(parse_ip);
    if !trust_proxy {
        return peer_ip;
    }
    let headers_trusted = match peer_ip.as_deref().map(|p| p.parse::<IpAddr>().ok()) {
        // No peer information (e.g. an in-process router): the configured
        // networks decide — with no networks configured the headers are
        // trusted (legacy behaviour).
        None => trusted_proxies.is_empty(),
        Some(Some(ip)) => trusted_proxies.is_empty() || ip_in_networks(&ip, trusted_proxies),
        // The peer is not an IP at all → treat it as untrusted.
        Some(None) => false,
    };
    if headers_trusted {
        client_ip(real_ip, xff, peer_ip.as_deref())
    } else {
        peer_ip
    }
}

/// True when `ip` falls inside one of the given networks.
pub fn ip_in_networks(ip: &IpAddr, networks: &[(IpAddr, u32)]) -> bool {
    networks
        .iter()
        .any(|(base, prefix)| ip_in_network(ip, base, *prefix))
}

/// True when `ip` falls inside `network` (an address + prefix length).
fn ip_in_network(ip: &IpAddr, base: &IpAddr, prefix: u32) -> bool {
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) => {
            let prefix = prefix.min(32);
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(*ip) & mask == u32::from(*base) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) => {
            let prefix = prefix.min(128);
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(*ip) & mask == u128::from(*base) & mask
        }
        _ => false,
    }
}

/// Fixed-window limiter over *failed* authentication attempts.
///
/// Without it, an unauthenticated caller can make the MCP issue one hub
/// `whoami` round-trip per bogus bearer (the cache only covers repeats),
/// which is an amplification vector against the hub and the MCP's connection
/// pool. The window is keyed by an unforgeable address (the direct peer), so
/// forging a forwarded IP cannot buy more attempts.
pub struct AuthLimiter {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
    max_failures: u32,
    window: Duration,
    max_entries: usize,
}

impl AuthLimiter {
    pub fn new(max_failures: u32) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max_failures,
            window: Duration::from_secs(60),
            max_entries: 4096,
        }
    }

    /// Whether the key is currently blocked (too many recent failures).
    /// Does not consume any quota.
    pub async fn blocked(&self, key: &str) -> bool {
        let windows = self.windows.lock().await;
        match windows.get(key) {
            Some((start, count)) => start.elapsed() < self.window && *count >= self.max_failures,
            None => false,
        }
    }

    /// Record a failed attempt for the key.
    pub async fn record_failure(&self, key: &str) {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();
        let entry = windows.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        if windows.len() > self.max_entries {
            // Evict expired windows first; a sybil flood of distinct keys
            // must not grow the map without bound.
            windows.retain(|_, (start, _)| now.duration_since(*start) < self.window);
            while windows.len() > self.max_entries {
                let Some(oldest) = windows
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                windows.remove(&oldest);
            }
        }
    }

    /// Forget the failures of a key (a successful authentication).
    pub async fn reset(&self, key: &str) {
        self.windows.lock().await.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_network;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn ip_precedence() {
        assert_eq!(
            client_ip(Some(" 1.2.3.4 "), Some("9.9.9.9"), Some("7.7.7.7")),
            Some("1.2.3.4".into())
        );
        // The proxy-appended (right-most) hop wins over the client-controlled
        // entries on its left — same rule as the hub.
        assert_eq!(
            client_ip(None, Some(" 9.9.9.9 , 8.8.8.8"), Some("7.7.7.7")),
            Some("8.8.8.8".into())
        );
        assert_eq!(
            client_ip(None, None, Some("7.7.7.7")),
            Some("7.7.7.7".into())
        );
        assert_eq!(client_ip(None, None, None), None);
    }

    #[test]
    fn non_ip_headers_are_ignored() {
        assert_eq!(
            client_ip(Some("not-an-ip"), None, Some("7.7.7.7")),
            Some("7.7.7.7".into())
        );
        assert_eq!(
            client_ip(None, Some("evil, nope"), Some("7.7.7.7")),
            Some("7.7.7.7".into())
        );
        assert_eq!(client_ip(Some(""), Some(""), Some("")), None);
    }

    #[test]
    fn forwarded_for_last_picks_the_right_most_entry() {
        assert_eq!(forwarded_for_last("1.2.3.4, 5.6.7.8"), Some("5.6.7.8"));
        assert_eq!(forwarded_for_last("1.2.3.4, 5.6.7.8, "), Some("5.6.7.8"));
        assert_eq!(forwarded_for_last(" , , 9.9.9.9"), Some("9.9.9.9"));
        assert_eq!(forwarded_for_last(" , "), None);
    }

    #[test]
    fn untrusted_peer_cannot_forge_the_client_ip() {
        let proxies = vec![parse_network("172.16.0.0/12").unwrap()];
        // A direct client (not behind the trusted proxy) forging X-Real-IP:
        // the forged value is dropped, the peer address is used instead.
        assert_eq!(
            resolve_client_ip(true, &proxies, Some("1.2.3.4"), None, Some("198.51.100.9")),
            Some("198.51.100.9".into())
        );
        // Behind the trusted proxy: the stamped header is honoured.
        assert_eq!(
            resolve_client_ip(true, &proxies, Some("1.2.3.4"), None, Some("172.18.0.5")),
            Some("1.2.3.4".into())
        );
        // Legacy: no proxy networks configured → the headers are trusted.
        assert_eq!(
            resolve_client_ip(true, &[], Some("1.2.3.4"), None, Some("198.51.100.9")),
            Some("1.2.3.4".into())
        );
        // Without proxy trust the headers are never used.
        assert_eq!(
            resolve_client_ip(false, &proxies, Some("1.2.3.4"), None, Some("172.18.0.5")),
            Some("172.18.0.5".into())
        );
    }

    #[test]
    fn network_matching() {
        let nets = vec![
            parse_network("10.0.0.0/8").unwrap(),
            parse_network("2001:db8::/32").unwrap(),
        ];
        assert!(ip_in_networks(&"10.1.2.3".parse().unwrap(), &nets));
        assert!(!ip_in_networks(&"11.0.0.1".parse().unwrap(), &nets));
        assert!(ip_in_networks(&"2001:db8::1".parse().unwrap(), &nets));
        assert!(!ip_in_networks(&"2001:db9::1".parse().unwrap(), &nets));
    }

    #[tokio::test]
    async fn limiter_blocks_after_too_many_failures() {
        let limiter = AuthLimiter::new(3);
        assert!(!limiter.blocked("1.2.3.4").await);
        for _ in 0..3 {
            limiter.record_failure("1.2.3.4").await;
        }
        assert!(limiter.blocked("1.2.3.4").await);
        assert!(
            !limiter.blocked("5.6.7.8").await,
            "other keys are independent"
        );
        limiter.reset("1.2.3.4").await;
        assert!(!limiter.blocked("1.2.3.4").await);
    }

    #[tokio::test]
    async fn validator_caches_and_caps() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/mcp/whoami"))
            .and(header("X-MCP-On-Behalf-Of", "tok-ok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/mcp/whoami"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let settings = crate::config::Settings {
            hub_url: server.uri(),
            service_token: "svc".into(),
            transport: "stdio".into(),
            host: "127.0.0.1".into(),
            port: 0,
            trust_proxy: false,
            trusted_proxy_cidrs: vec![],
        };
        let validator = TokenValidator::new(Arc::new(HubClient::new(&settings)));

        // valid token
        assert!(validator.valid("tok-ok", Some("1.2.3.4")).await);
        // second call hits the cache: only 1 hub call total for this key
        assert!(validator.valid("tok-ok", Some("1.2.3.4")).await);
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs.iter()
                .filter(|r| r
                    .headers
                    .get("X-MCP-On-Behalf-Of")
                    .map(|v| v == "tok-ok")
                    .unwrap_or(false))
                .count(),
            1,
            "second check must be served from cache"
        );

        // invalid token → deny
        assert!(!validator.valid("tok-bad", Some("1.2.3.4")).await);
        // empty → deny without hub call
        assert!(!validator.valid("", None).await);
    }
}

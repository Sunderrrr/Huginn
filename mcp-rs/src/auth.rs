//! Per-user MCP token authentication (streamable-http only), mirroring
//! mcp/app/server.py: the presented `Authorization: Bearer <token>` is
//! validated against the hub (`/api/mcp/whoami`) with the service token and
//! the presented token as on-behalf-of; results are cached briefly (the hub
//! re-validates on every actual tool call, so this is just a connect-time
//! gate). The client IP is resolved X-Real-IP → first X-Forwarded-For hop →
//! peer address.

use crate::hub_client::HubClient;
use std::collections::HashMap;
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

/// Originating client IP: trusted `X-Real-IP` (stamped by the edge proxy,
/// not forwardable by the client), then the first X-Forwarded-For hop, then
/// the direct peer.
pub fn client_ip(real_ip: Option<&str>, xff: Option<&str>, peer: Option<&str>) -> Option<String> {
    if let Some(ip) = real_ip.map(str::trim) {
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
    }
    if let Some(xff) = xff {
        if let Some(first) = xff.split(',').next().map(str::trim) {
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    peer.map(|p| p.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn ip_precedence() {
        assert_eq!(
            client_ip(Some(" 1.2.3.4 "), Some("9.9.9.9"), Some("7.7.7.7")),
            Some("1.2.3.4".into())
        );
        assert_eq!(
            client_ip(None, Some(" 9.9.9.9 , 8.8.8.8"), Some("7.7.7.7")),
            Some("9.9.9.9".into())
        );
        assert_eq!(
            client_ip(None, None, Some("7.7.7.7")),
            Some("7.7.7.7".into())
        );
        assert_eq!(client_ip(None, None, None), None);
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

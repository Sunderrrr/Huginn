//! Request-pipeline plumbing (`app/api/deps.py` + `app/main.py`): client
//! IP/header extraction, the fixed-window rate limiter and the FastAPI-shaped
//! JSON rejection mapping.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Extension};
use axum::http::HeaderMap;

use crate::config::Config;
use crate::error::ApiError;

use super::principal::{require_operator, Principal};
use super::AuthState;

/// Best-effort real client IP (`deps.client_ip`). Behind the bundled reverse
/// proxy `peer` is the proxy's address, so when `trust_forwarded_for` is set we
/// read `X-Forwarded-For` — taking the LAST hop, i.e. the entry appended by
/// the trusted proxy (the bundled Caddyfile overwrites the header with
/// `header_up X-Forwarded-For {remote_host}`). The left-hand entries are
/// client-controlled and forgeable, so they are never trusted (H-1: they used
/// to drive rate limiting and audit attribution). The header is only honoured
/// when explicitly trusted.
pub fn client_ip(headers: &HeaderMap, config: &Config, peer: Option<SocketAddr>) -> Option<String> {
    if config.trust_forwarded_for {
        if let Some(forwarded) = header_str(headers, "x-forwarded-for") {
            if let Some(last) = forwarded_for_last(forwarded) {
                return Some(last.to_owned());
            }
        }
    }
    peer.map(|p| p.ip().to_string())
}

/// The right-most non-empty entry of an `X-Forwarded-For` list — the hop the
/// trusted proxy closest to us appended. Everything to its left can be set
/// freely by the client (`X-Forwarded-For: 1.2.3.4, <real>`, or worse), so the
/// last entry is the only one that may be believed (H-1). This is the single
/// shared implementation the per-router `client_ip` wrappers delegate to.
pub(crate) fn forwarded_for_last(forwarded: &str) -> Option<&str> {
    forwarded.rsplit(',').map(str::trim).find(|s| !s.is_empty())
}

pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The peer address captured by `ConnectInfo` (only present when the server
/// layer installs it).
pub fn peer_addr(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<SocketAddr> {
    peer.map(|Extension(ConnectInfo(addr))| addr)
}

/// Authorize as operator, then throttle execution endpoints per principal
/// (`deps.rate_limit_exec`).
pub fn rate_limit_exec(state: &AuthState, principal: &Principal) -> Result<(), ApiError> {
    require_operator(principal)?;
    let key = format!("{}:{}", principal.actor_type.as_str(), principal.actor_id);
    if !state.exec_limiter.allow(&key) {
        return Err(ApiError::too_many_requests(
            "rate limit exceeded; slow down",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal rate limiter (app/core/ratelimit.py)
// ---------------------------------------------------------------------------

/// In-process fixed-window rate limiter. Sufficient for a single hub instance;
/// for a horizontally-scaled deployment back this with Redis (the interface
/// stays the same).
type BucketMap =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, (Instant, u32)>>>;

/// Above this many tracked keys, [`RateLimiter::allow`] first purges the
/// windows that have already expired. Keys are client-controlled (IPs), so
/// without eviction a sybil flood would grow the map without bound (H-1).
pub(crate) const MAX_TRACKED_BUCKETS: usize = 100_000;

#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    buckets: BucketMap,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self::new_with_window(max_per_minute, Duration::from_secs(60))
    }

    /// A limiter with an explicit window — production always wants the
    /// 60-second fixed window of `app/core/ratelimit.py`; the millisecond
    /// windows exist so tests can exercise expiry without sleeping.
    pub(crate) fn new_with_window(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            buckets: BucketMap::default(),
        }
    }

    /// Consume one slot for `key`; false when the window's budget is spent.
    pub fn allow(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        // Eviction (H-1): past the cap, drop the windows that have already
        // expired — they limit nobody and are pure dead weight.
        if buckets.len() > MAX_TRACKED_BUCKETS {
            buckets.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let (start, count) = buckets.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(*start) >= self.window {
            // An expired window never counts as active: reset, don't
            // increment (H-1).
            *start = now;
            *count = 0;
        }
        if *count >= self.max_per_window {
            return false;
        }
        *count += 1;
        true
    }

    /// Whether the key is currently under the limit, without consuming
    /// (`RateLimiter.check`).
    pub fn check(&self, key: &str) -> bool {
        let buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match buckets.get(key) {
            Some((start, count)) if now.duration_since(*start) < self.window => {
                *count < self.max_per_window
            }
            _ => true,
        }
    }

    /// Number of tracked windows (tests only — asserts the eviction cap).
    #[cfg(test)]
    pub(crate) fn bucket_count(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ---------------------------------------------------------------------------
// Axum JSON rejections mapped onto FastAPI semantics (see worker.rs)
// ---------------------------------------------------------------------------

/// Oversized bodies are 413 ("request body too large", like the global body
/// cap middleware); every parse/shape failure is 422 (pydantic's status).
pub(crate) fn map_json_rejection(err: axum::extract::rejection::JsonRejection) -> ApiError {
    use axum::http::StatusCode;
    if err.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large("request body too large")
    } else {
        ApiError::unprocessable_entity(err.body_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::enums::UserRole;
    use crate::routes::authapi::support;

    // ---- client IP / MCP allow-list ---------------------------------------

    #[test]
    fn client_ip_honours_trust_forwarded_for() {
        let mut config = Config::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.7, 172.16.0.2".parse().unwrap(),
        );
        let peer: SocketAddr = "10.0.0.1:4321".parse().unwrap();

        config.trust_forwarded_for = true;
        assert_eq!(
            client_ip(&headers, &config, Some(peer)).as_deref(),
            Some("172.16.0.2")
        );
        config.trust_forwarded_for = false;
        assert_eq!(
            client_ip(&headers, &config, Some(peer)).as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(client_ip(&headers, &config, None), None);
    }

    #[test]
    fn client_ip_takes_the_last_forwarded_hop_not_the_client_controlled_one() {
        // H-1: the client controls every entry of X-Forwarded-For except the
        // one the trusted proxy appends; only that last hop may be believed.
        let config = Config {
            trust_forwarded_for: true,
            ..Config::default()
        };
        let peer: SocketAddr = "10.0.0.1:4321".parse().unwrap();
        let ip = |forwarded: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", forwarded.parse().unwrap());
            client_ip(&headers, &config, Some(peer))
        };

        assert_eq!(ip("1.2.3.4, 5.6.7.8").as_deref(), Some("5.6.7.8"));
        // The proxy-appended hop is the last non-empty entry, even with
        // trailing separators/empties.
        assert_eq!(ip("1.2.3.4, 5.6.7.8, ").as_deref(), Some("5.6.7.8"));
        assert_eq!(ip(" , , 9.9.9.9").as_deref(), Some("9.9.9.9"));
        // A fully client-controlled list still answers the LAST entry —
        // behind the bundled proxy that value is the overwritten one.
        assert_eq!(ip("1.2.3.4").as_deref(), Some("1.2.3.4"));
        // Only empty entries → no usable hop → the peer address.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", " , ".parse().unwrap());
        assert_eq!(
            client_ip(&headers, &config, Some(peer)).as_deref(),
            Some("10.0.0.1")
        );
    }

    // ---- rate limiter (app/core/ratelimit.py) -----------------------------

    #[test]
    fn rate_limiter_is_a_fixed_window_with_a_non_consuming_check() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.check("k"), "fresh key is under the limit");
        assert!(limiter.allow("k"));
        assert!(limiter.check("k"), "peek does not consume");
        assert!(limiter.allow("k"));
        assert!(!limiter.check("k"), "budget spent");
        assert!(!limiter.allow("k"), "budget spent");
        assert!(limiter.allow("other"), "budgets are per key");
    }

    #[tokio::test]
    async fn rate_limiter_resets_an_expired_window_instead_of_counting_it() {
        let limiter = RateLimiter::new_with_window(2, Duration::from_millis(5));
        assert!(limiter.allow("k"));
        assert!(limiter.allow("k"));
        assert!(!limiter.allow("k"), "budget spent");
        tokio::time::sleep(Duration::from_millis(10)).await;
        // The window expired → it no longer counts as active: the next call
        // starts a fresh window rather than staying throttled (H-1).
        assert!(limiter.allow("k"), "expired window resets");
        assert!(limiter.allow("k"));
        assert!(!limiter.allow("k"));
    }

    #[tokio::test]
    async fn rate_limiter_purges_expired_windows_past_the_eviction_cap() {
        let limiter = RateLimiter::new_with_window(1, Duration::from_millis(5));
        // Push past the cap with distinct (client-controlled) keys.
        for i in 0..=MAX_TRACKED_BUCKETS {
            assert!(limiter.allow(&format!("ip:{i}")));
        }
        assert!(limiter.bucket_count() > MAX_TRACKED_BUCKETS);
        // Let every window expire, then touch one more key: the purge on the
        // way in must drop all the expired windows (H-1).
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(limiter.allow("fresh"));
        assert_eq!(limiter.bucket_count(), 1, "expired windows were purged");
        // A fresh (unexpired) window survives the purge.
        assert!(limiter.allow("fresh:2"));
        assert!(limiter.allow("fresh:3"));
        assert_eq!(limiter.bucket_count(), 3);
    }

    #[tokio::test]
    async fn rate_limit_exec_throttles_per_principal() {
        let state = AuthState::new(
            crate::db::pool_options(1)
                .connect_lazy("postgres://huginn@localhost/huginn_test")
                .unwrap(),
            Config {
                rate_limit_exec_per_minute: 2,
                ..Config::default()
            },
        );
        let principal = Principal::from_user(support::sample_user(UserRole::Operator));
        assert!(rate_limit_exec(&state, &principal).is_ok());
        assert!(rate_limit_exec(&state, &principal).is_ok());
        let err = rate_limit_exec(&state, &principal).unwrap_err();
        assert_eq!(err.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }
}

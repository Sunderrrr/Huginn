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
/// take the first hop in `X-Forwarded-For` (the original client). The header is
/// only honoured when explicitly trusted, since clients could spoof it.
pub fn client_ip(headers: &HeaderMap, config: &Config, peer: Option<SocketAddr>) -> Option<String> {
    if config.trust_forwarded_for {
        if let Some(forwarded) = header_str(headers, "x-forwarded-for") {
            if let Some(first) = forwarded.split(',').map(str::trim).find(|s| !s.is_empty()) {
                return Some(first.to_owned());
            }
        }
    }
    peer.map(|p| p.ip().to_string())
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

#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    buckets: BucketMap,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_window: max_per_minute,
            window: Duration::from_secs(60),
            buckets: BucketMap::default(),
        }
    }

    /// Consume one slot for `key`; false when the window's budget is spent.
    pub fn allow(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let (start, count) = buckets.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(*start) >= self.window {
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
            Some("203.0.113.7")
        );
        config.trust_forwarded_for = false;
        assert_eq!(
            client_ip(&headers, &config, Some(peer)).as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(client_ip(&headers, &config, None), None);
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

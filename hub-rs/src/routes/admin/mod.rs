//! Administration CRUD API — port of the hub's admin routes
//! (`hub/app/api/routes/{settings,mcp,tags,schedules,custom_actions,enrollment}.py`).
//!
//! | route                                    | Python handler            |
//! |------------------------------------------|---------------------------|
//! | `GET/PUT /api/settings`                  | `settings.py`             |
//! | `GET/POST /api/mcp/tokens`               | `mcp.py`                  |
//! | `PATCH/DELETE /api/mcp/tokens/{id}`      | `mcp.py`                  |
//! | `GET /api/mcp/whoami`                    | `mcp.py:whoami`           |
//! | `GET/POST /api/tags`, `PUT/DELETE …/{id}`| `tags.py`                 |
//! | `GET/POST /api/schedules`, `PUT/DELETE …/{id}` | `schedules.py`    |
//! | `GET/POST /api/actions`, `PATCH/DELETE …/{id}` | `custom_actions.py` |
//! | `GET/POST /api/enrollment-tokens`, `DELETE …/{id}` | `enrollment.py` |
//!
//! The handlers mirror the FastAPI surface exactly: the same status codes and
//! `{"detail": ...}` error shapes, the same request validation (pydantic field
//! bounds, cross-field checks), the same response models (secrets are never
//! listed — a plaintext token is returned exactly once, at creation), and the
//! same audit events through the tamper-evident audit chain.
//!
//! Two behaviors are worth calling out because they are easy to lose in a port:
//!
//! * **Authentication comes before body validation** — FastAPI solves
//!   dependencies (`get_principal` / `require_admin` / …) before it validates
//!   the request body, so an unauthenticated caller sees 401 even when the body
//!   is malformed. Only the global body-size cap (`app/main.py` middleware) runs
//!   earlier.
//! * **`GET /api/settings` is truncated for non-admins**: only the fleet fields
//!   (`target_worker_version`, `target_release_repo`, `allowed_release_domains`,
//!   `auto_update_enabled`, `updated_at`) are visible; SSO/LDAP/notification
//!   config (and every secret) stays admin-only.
//!
//! Data access goes through [`AdminStore`]; [`PgStore`] is the sqlx-backed
//! implementation used in production and `testing::MockStore` the in-memory one
//! used by the tests.
use std::net::SocketAddr;

use axum::extract::{rejection::JsonRejection, ConnectInfo, DefaultBodyLimit, Extension};
use axum::http::{HeaderMap, StatusCode};
use axum::{Json, Router};
use uuid::Uuid;

use crate::config::Config;
use crate::models::audit::AuditNew;

use self::schemas::{Caller, Principal};

pub mod backups;
pub mod custom_actions;
pub mod enrollment;
pub mod mcp_tokens;
pub mod schedules;
pub mod settings;
pub mod tags;

// ---------------------------------------------------------------------------
// Submodules — plumbing split by function
// ---------------------------------------------------------------------------

mod schemas;
mod store;

#[cfg(test)]
pub(crate) mod testing;

pub use schemas::RouteError;
pub use store::AdminState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// The `/api/settings` + `/api/mcp` + `/api/tags` + `/api/schedules` +
/// `/api/actions` + `/api/enrollment-tokens` router (prefixes included, so it
/// can be merged as-is).
pub fn router(state: AdminState) -> Router {
    // Same hard global request-body cap as `app/main.py`'s middleware.
    let global_cap = state.global_body_cap();
    Router::new()
        .merge(settings::routes())
        .merge(backups::routes())
        .merge(mcp_tokens::routes())
        .merge(tags::routes())
        .merge(schedules::routes())
        .merge(custom_actions::routes())
        .merge(enrollment::routes())
        .layer(DefaultBodyLimit::max(global_cap))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Request pipeline helpers (app/api/deps.py + app/main.py)
// ---------------------------------------------------------------------------

/// Header lookup, case-insensitive (HeaderMap already is).
pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Peer address from axum's `ConnectInfo` extension (absent in unit tests).
pub fn peer_addr(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<SocketAddr> {
    peer.map(|Extension(ConnectInfo(addr))| addr)
}

/// Python `repr()` of a string — the `!r` formatting used in the hub's error
/// messages (e.g. `f"unknown action: {name!r}"`).
pub fn py_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Best-effort real client IP (`deps.client_ip`): the LAST hop of
/// `X-Forwarded-For` when `trust_forwarded_for` is explicitly set (the entry
/// the trusted proxy appended — see the bundled Caddyfile's `header_up`),
/// otherwise the peer address (H-1: the client-controlled entries to the
/// left are never believed). Delegates to the single shared implementation
/// in [`crate::routes::authapi::client_ip`].
pub fn client_ip(headers: &HeaderMap, config: &Config, peer: Option<SocketAddr>) -> Option<String> {
    crate::routes::authapi::client_ip(headers, config, peer)
}

/// `app/main.py`'s global body cap, checked before authentication exactly like
/// the middleware (Content-Length first, then the actual body size).
pub fn enforce_body_size(headers: &HeaderMap, cap: usize) -> Result<(), RouteError> {
    if let Some(cl) = header_str(headers, "content-length") {
        if let Ok(len) = cl.trim().parse::<usize>() {
            if len > cap {
                return Err(RouteError::payload_too_large("request body too large"));
            }
        }
    }
    Ok(())
}

/// Axum JSON rejections mapped onto FastAPI semantics: oversized bodies are 413
/// ("request body too large"), every parse/shape failure is 422 (pydantic's
/// status).
pub fn json_body<T: serde::de::DeserializeOwned>(
    body: Result<Json<T>, JsonRejection>,
) -> Result<T, RouteError> {
    match body {
        Ok(Json(value)) => Ok(value),
        Err(err) if err.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(RouteError::payload_too_large("request body too large"))
        }
        Err(err) => Err(RouteError::unprocessable_entity(err.body_text())),
    }
}

/// Authenticate the caller as a user (JWT bearer) or the MCP agent (service
/// token) — `deps.get_principal`.
pub async fn authenticate(
    state: &AdminState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Result<Caller, RouteError> {
    let source_ip = client_ip(headers, &state.config, peer);
    let principal = principal_of(state, headers, source_ip.as_deref()).await?;
    Ok(Caller {
        principal,
        source_ip,
    })
}

async fn principal_of(
    state: &AdminState,
    headers: &HeaderMap,
    client_ip: Option<&str>,
) -> Result<Principal, RouteError> {
    // MCP façade: timing-safe service-token check, then optional on-behalf-of.
    if let Some(service_token) = header_str(headers, "x-mcp-service-token") {
        if !crate::security::constant_time_equals(service_token, &state.config.mcp_service_token) {
            return Err(RouteError::unauthorized("invalid service token"));
        }
        if let Some(presented) = header_str(headers, "x-mcp-on-behalf-of").filter(|s| !s.is_empty())
        {
            let user = mcp_tokens::resolve(state, presented, client_ip).await?;
            let Some(user) = user else {
                return Err(RouteError::unauthorized("invalid MCP token"));
            };
            return Ok(Principal::agent(Some(&user)));
        }
        return Ok(Principal::agent(None));
    }

    let Some(authorization) = header_str(headers, "authorization") else {
        return Err(RouteError::unauthorized_bearer("authentication required"));
    };
    let mut parts = authorization.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let Some(token) = parts.next().map(str::trim).filter(|t| !t.is_empty()) else {
        return Err(RouteError::unauthorized_bearer("authentication required"));
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(RouteError::unauthorized_bearer("authentication required"));
    }

    let payload = crate::security::decode_access_token(&state.security.jwt_secret, token)
        .map_err(|_| RouteError::unauthorized("invalid token"))?;
    let Some(sub) = payload.get("sub").and_then(|v| v.as_str()) else {
        return Err(RouteError::unauthorized("invalid token"));
    };
    let Ok(user_id) = Uuid::parse_str(sub) else {
        return Err(RouteError::unauthorized("invalid token"));
    };
    // Intermediate MFA challenge/setup tokens are not valid for the business
    // API: they may only be presented to `/api/auth/mfa`.
    if let Some(scope) = payload.get("scope").and_then(|v| v.as_str()) {
        if crate::security::MFA_SCOPES.contains(&scope) {
            return Err(RouteError::unauthorized("token not valid for API access"));
        }
    }
    let user = state
        .store
        .get_user(user_id)
        .await
        .map_err(RouteError::from)?;
    let Some(user) = user.filter(|u| u.is_active) else {
        return Err(RouteError::unauthorized("user not found or inactive"));
    };
    // The session epoch must still match: a logout, a password change or
    // an MFA reset bumps it and kills the tokens issued before (F-08).
    if !crate::security::session_is_current(&payload, user.session_epoch) {
        return Err(RouteError::unauthorized("session revoked"));
    }
    Ok(Principal::from_user(&user))
}

/// `audit.record(...)` — append one tamper-evident audit entry.
pub async fn audit_record(
    state: &AdminState,
    caller: &Caller,
    event_type: &str,
    detail: serde_json::Value,
) -> Result<(), RouteError> {
    let mut entry = AuditNew::new(
        caller.principal.actor_type,
        caller.principal.actor_id.clone(),
        event_type,
    );
    entry.detail = detail;
    entry.source_ip = caller.source_ip.clone();
    state.store.record_audit(entry).await.map_err(Into::into)
}

/// Parse a path id the way FastAPI parses `uuid.UUID` path params.
pub fn path_uuid(raw: &str, what: &str) -> Result<Uuid, RouteError> {
    raw.parse::<Uuid>()
        .map_err(|_| RouteError::unprocessable_entity(format!("{what} must be a valid UUID")))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::testing::*;
    use super::*;

    #[tokio::test]
    async fn unauthenticated_requests_get_401_before_anything_else() {
        let store = Arc::new(MockStore::default());
        let app = router(test_state(store));
        let response = tower::ServiceExt::oneshot(
            app,
            json_request("GET", "/api/settings", serde_json::Value::Null),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"detail": "authentication required"})
        );
    }

    #[tokio::test]
    async fn invalid_service_token_is_rejected() {
        let store = Arc::new(MockStore::default());
        let app = router(test_state(store));
        let request = json_request_with(
            "GET",
            "/api/mcp/whoami",
            serde_json::Value::Null,
            &[("x-mcp-service-token", "wrong".to_owned())],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"detail": "invalid service token"})
        );
    }
}

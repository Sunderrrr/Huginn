//! `/api/mcp/tokens` + `/api/mcp/whoami` — port of `hub/app/api/routes/mcp.py`.
//!
//! Every user manages their own named MCP tokens; the plaintext secret is
//! returned **once**, at creation, and only its HMAC is stored
//! (`security::hash_secret`). The listing never exposes secrets. `whoami` is
//! the endpoint the MCP server calls to validate an `X-MCP-Service-Token` +
//! `X-MCP-On-Behalf-Of` pair: the presented token is resolved to its active
//! owner (IP allow-list enforced, `last_used_at` bumped), exactly like
//! `deps.get_principal` + `services/mcp_tokens.resolve`.

use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use super::{
    audit_record, authenticate, enforce_body_size, json_body, path_uuid, peer_addr, AdminState,
    RouteError,
};
use crate::models::mcp_token::{McpToken, McpTokenNew};
use crate::models::user::User;
use crate::models::UserRole;

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/mcp.py)
// ---------------------------------------------------------------------------

/// `McpTokenCreate`.
#[derive(Debug, Clone, Deserialize)]
pub struct McpTokenCreate {
    pub name: String,
    #[serde(default)]
    pub allowed_ip: Option<String>,
}

/// `McpTokenUpdate` — `None`/blank clears the restriction (usable from
/// anywhere).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpTokenUpdate {
    #[serde(default)]
    pub allowed_ip: Option<String>,
}

/// `McpTokenOut` — no secret, ever.
#[derive(Debug, Clone, Serialize)]
pub struct McpTokenOut {
    pub id: Uuid,
    pub name: String,
    pub allowed_ip: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub last_used_at: Option<chrono::DateTime<Utc>>,
}

impl From<&McpToken> for McpTokenOut {
    fn from(token: &McpToken) -> Self {
        Self {
            id: token.id,
            name: token.name.clone(),
            allowed_ip: token.allowed_ip.clone(),
            created_at: token.created_at,
            last_used_at: token.last_used_at,
        }
    }
}

/// `McpTokenCreated` — the plaintext token, shown once.
#[derive(Debug, Clone, Serialize)]
pub struct McpTokenCreated {
    pub id: Uuid,
    pub name: String,
    pub allowed_ip: Option<String>,
    pub token: String,
}

/// `WhoAmI`.
#[derive(Debug, Clone, Serialize)]
pub struct WhoAmI {
    pub username: String,
    pub role: UserRole,
}

// ---------------------------------------------------------------------------
// IP allow-list policy (app/services/mcp_tokens.py)
// ---------------------------------------------------------------------------

/// Parse an IP or CIDR the way `ipaddress.ip_network(value, strict=False)`
/// does: a bare IP becomes a /32 (or /128), host bits are masked away.
fn parse_network(value: &str) -> Result<(std::net::IpAddr, u32), ()> {
    let mut parts = value.split('/');
    let addr_s = parts.next().unwrap_or_default();
    let prefix_s = parts.next();
    if parts.next().is_some() || addr_s.is_empty() {
        return Err(());
    }
    let addr: std::net::IpAddr = addr_s.parse().map_err(|_| ())?;
    let max_prefix = if addr.is_ipv4() { 32u32 } else { 128u32 };
    let prefix = match prefix_s {
        None => max_prefix,
        Some(p) => {
            if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
                return Err(());
            }
            let value: u32 = p.parse().map_err(|_| ())?;
            if value > max_prefix {
                return Err(());
            }
            value
        }
    };
    Ok((addr, prefix))
}

fn mask_addr(addr: std::net::IpAddr, prefix: u32) -> std::net::IpAddr {
    match addr {
        std::net::IpAddr::V4(v4) => {
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & mask))
        }
        std::net::IpAddr::V6(v6) => {
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// `mcp_tokens.normalize_allowed_ip` — validate/normalize an IP or CIDR
/// allow-list value (`None`/blank for "any"). Errors carry the exact pydantic
/// message of `schemas/mcp.py`.
pub fn normalize_allowed_ip(value: Option<&str>) -> Result<Option<String>, RouteError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let (addr, prefix) = parse_network(value).map_err(|_| {
        RouteError::unprocessable_entity(
            "must be a valid IP address or CIDR (e.g. 203.0.113.7 or 10.0.0.0/24)",
        )
    })?;
    Ok(Some(format!("{}/{}", mask_addr(addr, prefix), prefix)))
}

/// `mcp_tokens.ip_allowed` — is `client_ip` permitted by the token's `allowed`
/// rule? No rule (`None`) → always allowed. A rule with no/invalid client IP →
/// denied.
pub fn ip_allowed(client_ip: Option<&str>, allowed: Option<&str>) -> bool {
    let Some(allowed) = allowed else {
        return true;
    };
    let Some(client_ip) = client_ip else {
        return false;
    };
    let (Ok(ip), Ok((net, prefix))) = (
        client_ip.parse::<std::net::IpAddr>(),
        parse_network(allowed),
    ) else {
        return false;
    };
    mask_addr(ip, prefix) == net
}

/// `mcp_tokens.resolve` — map a presented MCP token to its active owner, or
/// `None`. Enforces the token's optional IP allow-list against `client_ip` and
/// bumps `last_used_at`.
pub async fn resolve(
    state: &AdminState,
    presented: &str,
    client_ip: Option<&str>,
) -> Result<Option<User>, RouteError> {
    if presented.is_empty() {
        return Ok(None);
    }
    let token_hash = state.security.hash_secret(presented);
    let Some(token) = state.store.active_mcp_token_by_hash(&token_hash).await? else {
        return Ok(None);
    };
    if !ip_allowed(client_ip, token.allowed_ip.as_deref()) {
        tracing::warn!(
            "MCP token {} rejected: client ip {:?} not in allow-list {:?}",
            token.id,
            client_ip,
            token.allowed_ip
        );
        return Ok(None);
    }
    let Some(user) = state.store.get_user(token.user_id).await? else {
        return Ok(None);
    };
    if !user.is_active {
        return Ok(None);
    }
    state.store.touch_mcp_token(token.id, Utc::now()).await?;
    Ok(Some(user))
}

/// Validate the `allowed_ip` field of a create/update payload.
fn checked_allowed_ip(value: &Option<String>) -> Result<Option<String>, RouteError> {
    normalize_allowed_ip(value.as_deref())
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// The `/api/mcp` router (prefix included).
pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/mcp/tokens", get(list_tokens))
        .route("/api/mcp/tokens", post(create_token))
        .route("/api/mcp/tokens/{token_id}", patch(update_token))
        .route("/api/mcp/tokens/{token_id}", delete(revoke_token))
        .route("/api/mcp/whoami", get(whoami))
}

/// `GET /api/mcp/tokens` — the caller's active tokens (no secrets).
async fn list_tokens(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    let user = caller.require_user()?;
    let tokens = state.store.list_mcp_tokens(user.id).await?;
    Ok(Json(
        tokens.iter().map(McpTokenOut::from).collect::<Vec<_>>(),
    ))
}

/// `POST /api/mcp/tokens` — mint a token (201, plaintext shown once).
async fn create_token(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<McpTokenCreate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    let user = caller.require_user()?;
    let body = json_body(body)?;
    if body.name.is_empty() {
        return Err(RouteError::unprocessable_entity(
            "name must be at least 1 character",
        ));
    }
    if body.name.chars().count() > 255 {
        return Err(RouteError::unprocessable_entity(
            "name must be at most 255 characters",
        ));
    }
    let allowed_ip = checked_allowed_ip(&body.allowed_ip)?;

    let plaintext = crate::security::generate_secret();
    let token = state
        .store
        .create_mcp_token(McpTokenNew {
            user_id: user.id,
            token_hash: state.security.hash_secret(&plaintext),
            // `mcp_tokens_service.create` falls back to "token" for an empty
            // name; the schema (min_length=1) makes that unreachable.
            name: body.name.clone(),
            allowed_ip: allowed_ip.clone(),
        })
        .await?;
    audit_record(
        &state,
        &caller,
        "mcp_token_created",
        serde_json::json!({"name": token.name, "allowed_ip": token.allowed_ip}),
    )
    .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(McpTokenCreated {
            id: token.id,
            name: token.name,
            allowed_ip,
            token: plaintext,
        }),
    ))
}

/// `PATCH /api/mcp/tokens/{token_id}` — update the IP allow-list.
async fn update_token(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(token_id): Path<String>,
    body: Result<Json<McpTokenUpdate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    let user = caller.require_user()?;
    let token_id = path_uuid(&token_id, "token id")?;
    let body = json_body(body)?;
    let allowed_ip = checked_allowed_ip(&body.allowed_ip)?;

    let token = state
        .store
        .set_mcp_allowed_ip(token_id, user.id, allowed_ip)
        .await?;
    let Some(token) = token else {
        return Err(RouteError::not_found("token not found"));
    };
    audit_record(
        &state,
        &caller,
        "mcp_token_updated",
        serde_json::json!({"name": token.name, "allowed_ip": token.allowed_ip}),
    )
    .await?;
    Ok(Json(McpTokenOut::from(&token)))
}

/// `DELETE /api/mcp/tokens/{token_id}` — revoke a token the caller owns (204).
async fn revoke_token(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(token_id): Path<String>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    let user = caller.require_user()?;
    let token_id = path_uuid(&token_id, "token id")?;

    if !state.store.revoke_mcp_token(token_id, user.id).await? {
        return Err(RouteError::not_found("token not found"));
    }
    audit_record(
        &state,
        &caller,
        "mcp_token_revoked",
        serde_json::json!({"token_id": token_id.to_string()}),
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `GET /api/mcp/whoami` — resolve the caller (used by the MCP server to
/// validate an on-behalf-of token).
async fn whoami(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    let who = match &caller.principal.user {
        Some(user) => WhoAmI {
            username: user.username.clone(),
            role: user.role,
        },
        None => WhoAmI {
            username: caller.principal.actor_id.clone(),
            role: caller.principal.role,
        },
    };
    Ok(Json(who))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use serde_json::json;

    use super::super::router;
    use super::super::testing::*;
    use super::super::AdminStore;
    use super::*;
    use crate::models::UserRole;

    fn setup() -> (Arc<MockStore>, AdminState, User) {
        let store = Arc::new(MockStore::default());
        let state = test_state(store.clone());
        let user = seed_user(&store, make_user("alice", UserRole::Operator));
        (store, state, user)
    }

    #[test]
    fn normalize_allowed_ip_matches_ipaddress() {
        // A bare IP becomes a /32 (or /128) network.
        assert_eq!(
            normalize_allowed_ip(Some("203.0.113.7")).unwrap(),
            Some("203.0.113.7/32".to_owned())
        );
        assert_eq!(
            normalize_allowed_ip(Some("2001:db8::1")).unwrap(),
            Some("2001:db8::1/128".to_owned())
        );
        // A CIDR keeps its prefix; host bits are masked away (strict=False).
        assert_eq!(
            normalize_allowed_ip(Some("10.0.0.0/24")).unwrap(),
            Some("10.0.0.0/24".to_owned())
        );
        assert_eq!(
            normalize_allowed_ip(Some("10.0.0.1/24")).unwrap(),
            Some("10.0.0.0/24".to_owned())
        );
        // None / blank means "anywhere".
        assert_eq!(normalize_allowed_ip(None).unwrap(), None);
        assert_eq!(normalize_allowed_ip(Some("")).unwrap(), None);
        assert_eq!(normalize_allowed_ip(Some("   ")).unwrap(), None);
        // Invalid values carry the pydantic message.
        for bad in ["10.0.0.0/33", "abc", "10.0.0.0/24/8", "1.2.3.4.5", "/24"] {
            assert_eq!(
                normalize_allowed_ip(Some(bad)).unwrap_err().status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "value={bad}"
            );
        }
    }

    #[test]
    fn ip_allowed_matches_python() {
        assert!(ip_allowed(None, None));
        assert!(ip_allowed(Some("203.0.113.7"), None));
        // With a rule, a missing/invalid client IP is denied.
        assert!(!ip_allowed(None, Some("203.0.113.7/32")));
        assert!(!ip_allowed(Some("not-an-ip"), Some("203.0.113.7/32")));
        // Membership inside the network.
        assert!(ip_allowed(Some("10.0.0.7"), Some("10.0.0.0/24")));
        assert!(!ip_allowed(Some("10.0.1.7"), Some("10.0.0.0/24")));
        assert!(ip_allowed(Some("2001:db8::5"), Some("2001:db8::/64")));
        assert!(!ip_allowed(Some("2001:db9::5"), Some("2001:db8::/64")));
    }

    #[tokio::test]
    async fn token_lifecycle_create_list_patch_delete() {
        let (store, state, user) = setup();
        let auth = ("authorization", format!("Bearer {}", bearer(&state, &user)));

        // Create → 201 with the plaintext token exactly once.
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/mcp/tokens",
            json!({"name": "ci", "allowed_ip": "203.0.113.7"}),
            std::slice::from_ref(&auth),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        assert_eq!(created["name"], json!("ci"));
        assert_eq!(created["allowed_ip"], json!("203.0.113.7/32"));
        let plaintext = created["token"].as_str().unwrap().to_owned();
        assert!(!plaintext.is_empty());
        let token_id = created["id"].as_str().unwrap().to_owned();

        // List → no secret ever leaves this endpoint.
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/mcp/tokens",
            serde_json::Value::Null,
            std::slice::from_ref(&auth),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = body_json(response).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        let row = &listed[0];
        assert_eq!(row["id"], json!(token_id));
        assert!(row.get("token").is_none(), "plaintext must not be listed");
        assert!(row.get("token_hash").is_none(), "hash must not be listed");

        // Patch the allow-list.
        let app = router(state.clone());
        let request = json_request_with(
            "PATCH",
            &format!("/api/mcp/tokens/{token_id}"),
            json!({"allowed_ip": "10.0.0.0/24"}),
            std::slice::from_ref(&auth),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await["allowed_ip"],
            json!("10.0.0.0/24")
        );

        // Patch again with a blank value → the restriction is cleared.
        let app = router(state.clone());
        let request = json_request_with(
            "PATCH",
            &format!("/api/mcp/tokens/{token_id}"),
            json!({"allowed_ip": null}),
            std::slice::from_ref(&auth),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["allowed_ip"], json!(null));

        // Delete → 204, then 404 on the second attempt.
        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/mcp/tokens/{token_id}"),
            serde_json::Value::Null,
            std::slice::from_ref(&auth),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/mcp/tokens/{token_id}"),
            serde_json::Value::Null,
            std::slice::from_ref(&auth),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "token not found"})
        );

        // The audit trail recorded every step.
        let db = store.db.lock().unwrap();
        let events: Vec<&str> = db.audit.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(
            events,
            vec![
                "mcp_token_created",
                "mcp_token_updated",
                "mcp_token_updated",
                "mcp_token_revoked"
            ]
        );
    }

    #[tokio::test]
    async fn create_rejects_an_invalid_allowed_ip() {
        let (_store, state, user) = setup();
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/mcp/tokens",
            json!({"name": "ci", "allowed_ip": "not-an-ip"}),
            &[("authorization", format!("Bearer {}", bearer(&state, &user)))],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn whoami_contract() {
        let (store, state, user) = setup();

        // No credentials at all → 401 "authentication required".
        let app = router(state.clone());
        let request = json_request("GET", "/api/mcp/whoami", serde_json::Value::Null);
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "authentication required"})
        );

        // Wrong service token → 401 "invalid service token".
        let app = router(state.clone());
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
            json!({"detail": "invalid service token"})
        );

        // Service token alone → the anonymous agent ("hermes", read-only).
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/mcp/whoami",
            serde_json::Value::Null,
            &[(
                "x-mcp-service-token",
                state.config.mcp_service_token.clone(),
            )],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            json!({"username": "hermes", "role": "readonly"})
        );

        // On-behalf-of with an unknown MCP token → 401 "invalid MCP token".
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/mcp/whoami",
            serde_json::Value::Null,
            &[
                (
                    "x-mcp-service-token",
                    state.config.mcp_service_token.clone(),
                ),
                ("x-mcp-on-behalf-of", "unknown-token".to_owned()),
            ],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "invalid MCP token"})
        );

        // On-behalf-of with a valid token → the owning user.
        let (_token, plaintext) = seed_mcp_token(&state, &store, user.id, "cli", None).await;
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/mcp/whoami",
            serde_json::Value::Null,
            &[
                (
                    "x-mcp-service-token",
                    state.config.mcp_service_token.clone(),
                ),
                ("x-mcp-on-behalf-of", plaintext),
            ],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            json!({"username": "alice", "role": "operator"})
        );
    }

    #[tokio::test]
    async fn whoami_enforces_the_token_ip_allow_list() {
        let (store, state, user) = setup();
        let (_token, plaintext) =
            seed_mcp_token(&state, &store, user.id, "cli", Some("203.0.113.7/32")).await;

        // The request carries no client IP → denied.
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/mcp/whoami",
            serde_json::Value::Null,
            &[
                (
                    "x-mcp-service-token",
                    state.config.mcp_service_token.clone(),
                ),
                ("x-mcp-on-behalf-of", plaintext.clone()),
            ],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "invalid MCP token"})
        );

        // With a trusted X-Forwarded-For inside the allow-list → resolved.
        let mut config = test_config();
        config.trust_forwarded_for = true;
        let state = AdminState {
            config: config.clone(),
            security: state.security.clone(),
            store: state.store.clone(),
        };
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/mcp/whoami",
            serde_json::Value::Null,
            &[
                (
                    "x-mcp-service-token",
                    state.config.mcp_service_token.clone(),
                ),
                ("x-mcp-on-behalf-of", plaintext.clone()),
                ("x-forwarded-for", "203.0.113.7".to_owned()),
            ],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["username"], json!("alice"));
    }

    #[tokio::test]
    async fn revoked_tokens_stop_resolving() {
        let (store, state, user) = setup();
        let (token, plaintext) = seed_mcp_token(&state, &store, user.id, "cli", None).await;
        store.revoke_mcp_token(token.id, user.id).await.unwrap();

        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/mcp/whoami",
            serde_json::Value::Null,
            &[
                (
                    "x-mcp-service-token",
                    state.config.mcp_service_token.clone(),
                ),
                ("x-mcp-on-behalf-of", plaintext),
            ],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mcp_token_crud_requires_a_user_session() {
        let (_store, state, _user) = setup();
        // The anonymous service-token agent has no user behind it.
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/mcp/tokens",
            serde_json::Value::Null,
            &[(
                "x-mcp-service-token",
                state.config.mcp_service_token.clone(),
            )],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "a user session is required"})
        );
    }
}

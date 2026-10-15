//! The authenticated caller (`app/core/principal.py` + `app/api/deps.py`):
//! the [`Principal`] type and its RBAC checks, bearer/challenge/MCP token
//! resolution, and the request-authentication extractors.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::enums::{ActorType, UserRole};
use crate::models::user::User;
use crate::security::jwt::MFA_SCOPES;
use crate::security::SecurityConfig;

use super::middleware::{client_ip, header_str};
use super::service::db_err;
use super::AuthState;

/// The authenticated principal acting on a request (a user or an agent).
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub role: UserRole,
    pub user: Option<User>,
}

impl Principal {
    /// A real user is behind this principal — either a direct human session or
    /// an MCP agent acting on behalf of a user (a per-user MCP token).
    fn has_identity(&self) -> bool {
        self.actor_type == ActorType::User || self.user.is_some()
    }

    /// True for an admin user, including via an on-behalf-of MCP token. The
    /// anonymous service-token agent (no carried user) is NOT admin.
    pub fn is_admin(&self) -> bool {
        self.has_identity() && self.role == UserRole::Admin
    }

    /// True for admin/operator users (incl. via an on-behalf-of MCP token).
    pub fn is_operator(&self) -> bool {
        self.has_identity() && matches!(self.role, UserRole::Admin | UserRole::Operator)
    }

    /// Operator capability: run actions/commands, trigger updates, read audit.
    /// Granted to operators/admins (human or on-behalf-of) and to the anonymous
    /// service-token agent — but NOT to read-only users, even through MCP (an
    /// MCP token never grants more than its owner's real role).
    pub fn can_execute(&self) -> bool {
        if self.actor_type == ActorType::Agent && self.user.is_none() {
            return true; // anonymous service-token agent
        }
        self.is_operator()
    }

    pub fn from_user(user: User) -> Self {
        Self {
            actor_type: ActorType::User,
            actor_id: user.id.to_string(),
            role: user.role,
            user: Some(user),
        }
    }

    /// The MCP façade. With a user (per-user MCP token) it acts AS that user —
    /// actor_type stays `agent` so the audit shows "mcp", actor_id is the user's
    /// id, and authorization uses the user's real role. Without a user
    /// (service-token-only calls) it is `hermes`, a read-only agent role that
    /// `can_execute` still grants operator capability to.
    pub fn agent(user: Option<User>) -> Self {
        match user {
            Some(user) => Self {
                actor_type: ActorType::Agent,
                actor_id: user.id.to_string(),
                role: user.role,
                user: Some(user),
            },
            None => Self {
                actor_type: ActorType::Agent,
                actor_id: "hermes".to_owned(),
                role: UserRole::Readonly,
                user: None,
            },
        }
    }
}

/// The bearer credential of an `Authorization: Bearer <token>` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = header_str(headers, "authorization")?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// Authenticate the caller as a user (JWT) or the MCP agent (service token),
/// mirroring `deps.get_principal`.
pub async fn get_principal(
    state: &AuthState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Result<Principal, ApiError> {
    // MCP façade: timing-safe service-token check, then optional on-behalf-of user.
    if let Some(service_token) = header_str(headers, "x-mcp-service-token") {
        if !crate::security::constant_time_equals(service_token, &state.config.mcp_service_token) {
            return Err(ApiError::unauthorized("invalid service token"));
        }
        let obo = header_str(headers, "x-mcp-on-behalf-of");
        return match obo {
            Some(obo) => {
                let ip = client_ip(headers, &state.config, peer);
                let user = resolve_mcp_token(state, obo, ip.as_deref()).await?;
                match user {
                    Some(user) => Ok(Principal::agent(Some(user))),
                    None => Err(ApiError::unauthorized("invalid MCP token")),
                }
            }
            None => Ok(Principal::agent(None)),
        };
    }

    let Some(token) = bearer_token(headers) else {
        return Err(ApiError::unauthorized("authentication required"));
    };
    let (user_id, payload) = decode_principal_token(&state.security, token)?;
    // Intermediate MFA challenge/setup tokens are NOT valid for the business API:
    // they may only be presented to the dedicated /api/auth/mfa endpoints.
    if scope_of(&payload).is_some_and(|s| MFA_SCOPES.contains(&s)) {
        return Err(ApiError::unauthorized("token not valid for API access"));
    }
    load_active_user(state, user_id)
        .await
        .map(Principal::from_user)
}

/// Decode an access token for a business-API caller: returns the `sub` user id
/// and the full payload (so callers can inspect `scope`), or 401 "invalid token".
pub(crate) fn decode_principal_token(
    security: &SecurityConfig,
    token: &str,
) -> Result<(Uuid, serde_json::Value), ApiError> {
    let payload = decode_access(security, token)?;
    let user_id = sub_uuid(&payload)?;
    Ok((user_id, payload))
}

/// Decode an access token, mapping every token failure onto FastAPI's 401
/// "invalid token".
fn decode_access(security: &SecurityConfig, token: &str) -> Result<serde_json::Value, ApiError> {
    security
        .jwt()
        .decode_access_token(token)
        .map_err(|_| ApiError::unauthorized("invalid token"))
}

/// Decode an MFA challenge token requiring the exact scope; every failure maps
/// onto FastAPI's 401 "invalid challenge token".
fn decode_challenge(
    security: &SecurityConfig,
    token: &str,
    expected_scope: &str,
) -> Result<serde_json::Value, ApiError> {
    security
        .jwt()
        .decode_mfa_challenge_token(token, expected_scope)
        .map_err(|_| ApiError::unauthorized("invalid challenge token"))
}

/// The `sub` claim as a user id (401 "invalid token" when missing/malformed).
fn sub_uuid(payload: &serde_json::Value) -> Result<Uuid, ApiError> {
    payload
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::unauthorized("invalid token"))
}

fn scope_of(payload: &serde_json::Value) -> Option<&str> {
    payload.get("scope").and_then(serde_json::Value::as_str)
}

async fn load_active_user(state: &AuthState, user_id: Uuid) -> Result<User, ApiError> {
    let user = crate::models::user::get_by_id(&state.pool, user_id)
        .await
        .map_err(db_err)?;
    match user {
        Some(user) if user.is_active => Ok(user),
        _ => Err(ApiError::unauthorized("user not found or inactive")),
    }
}

/// Human admin only (excludes the automation agent) — `deps.require_admin`.
pub fn require_admin(principal: &Principal) -> Result<(), ApiError> {
    if !principal.is_admin() {
        return Err(ApiError::forbidden("admin role required"));
    }
    Ok(())
}

/// Admin, operator, or agent; read-only users are rejected — `deps.require_operator`.
pub fn require_operator(principal: &Principal) -> Result<(), ApiError> {
    if !principal.can_execute() {
        return Err(ApiError::forbidden("operator privileges required"));
    }
    Ok(())
}

/// Resolve the user behind an MFA challenge token (scope-checked) —
/// `mfa._challenge_user`.
pub(crate) async fn challenge_user(
    state: &AuthState,
    headers: &HeaderMap,
    expected_scope: &str,
) -> Result<User, ApiError> {
    let Some(token) = bearer_token(headers) else {
        return Err(ApiError::unauthorized("challenge token required"));
    };
    let payload = decode_challenge(&state.security, token, expected_scope)?;
    let user_id =
        sub_uuid(&payload).map_err(|_| ApiError::unauthorized("invalid challenge token"))?;
    let user = crate::models::user::get_by_id(&state.pool, user_id)
        .await
        .map_err(db_err)?;
    match user {
        Some(user) if user.is_active => Ok(user),
        _ => Err(ApiError::unauthorized("user not found or inactive")),
    }
}

/// Authenticate an enrollment caller — `mfa.enrolling_actor`. Accepts a normal
/// access token (logged-in user managing their own factors) and, only when
/// `allow_setup`, an `mfa_setup` challenge token (admin completing forced
/// first-time setup). The `mfa` verify scope is never accepted. Returns
/// `(user, is_setup)`.
pub(crate) async fn enrolling_actor(
    state: &AuthState,
    headers: &HeaderMap,
    allow_setup: bool,
) -> Result<(User, bool), ApiError> {
    let Some(token) = bearer_token(headers) else {
        return Err(ApiError::unauthorized("authentication required"));
    };
    let (user_id, payload) = decode_principal_token(&state.security, token)?;
    let scope = scope_of(&payload);
    if scope == Some(crate::security::jwt::MFA_SCOPE) {
        return Err(ApiError::unauthorized("token not valid for enrollment"));
    }
    let is_setup = scope == Some(crate::security::jwt::MFA_SETUP_SCOPE);
    if is_setup && !allow_setup {
        return Err(ApiError::unauthorized("setup token not valid here"));
    }
    load_active_user(state, user_id)
        .await
        .map(|u| (u, is_setup))
}

// ---------------------------------------------------------------------------
// MCP token resolution (app/services/mcp_tokens.py)
// ---------------------------------------------------------------------------

/// Map a presented MCP token to its active owner, or `None`. Deterministic
/// keyed HMAC means a single indexed lookup; enforces the token's optional IP
/// allow-list against `client_ip`; bumps `last_used_at`.
async fn resolve_mcp_token(
    state: &AuthState,
    presented: &str,
    client_ip: Option<&str>,
) -> Result<Option<User>, ApiError> {
    if presented.is_empty() {
        return Ok(None);
    }
    let token_hash = state.security.hash_secret(presented);
    let token = crate::models::mcp_token::get_active_by_token_hash(&state.pool, &token_hash)
        .await
        .map_err(db_err)?;
    let Some(token) = token else {
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
    let user = crate::models::user::get_by_id(&state.pool, token.user_id)
        .await
        .map_err(db_err)?;
    let Some(user) = user.filter(|u| u.is_active) else {
        return Ok(None);
    };
    crate::models::mcp_token::touch_last_used(&state.pool, token.id, chrono::Utc::now())
        .await
        .map_err(db_err)?;
    Ok(Some(user))
}

/// True if `client_ip` is permitted by the token's `allowed` rule. No rule
/// (`None`) → always allowed. A rule with no/invalid client IP → denied
/// (`mcp_tokens.ip_allowed`).
fn ip_allowed(client_ip: Option<&str>, allowed: Option<&str>) -> bool {
    let Some(allowed) = allowed else {
        return true;
    };
    let Some(client_ip) = client_ip else {
        return false;
    };
    match (client_ip.parse::<IpAddr>(), parse_network(allowed)) {
        (Ok(ip), Some((network, prefix))) => ip_in_network(ip, network, prefix),
        _ => false,
    }
}

/// Parse "1.2.3.4[/32]" / "::1[/128]" into the base address and prefix length.
/// A malformed or out-of-range rule (Python raises `ValueError`) yields `None`.
fn parse_network(value: &str) -> Option<(IpAddr, u32)> {
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix.parse::<u32>().ok()?)),
        None => (value, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    match prefix {
        None => Some((ip, max)),
        Some(prefix) if prefix <= max => Some((ip, prefix)),
        Some(_) => None,
    }
}

fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u32) -> bool {
    match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let (a, b) = (u32::from(a), u32::from(b));
            prefix == 0 || (a ^ b) >> (32 - prefix) == 0
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (a, b) = (u128::from(a), u128::from(b));
            prefix == 0 || (a ^ b) >> (128 - prefix) == 0
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::authapi::support;
    use crate::security::jwt::MFA_SCOPE;
    use serde_json::json;

    // ---- Principal / RBAC (mirrors core/principal.py) ----------------------

    #[test]
    fn principal_rbac_matrix() {
        let admin = Principal::from_user(support::sample_user(UserRole::Admin));
        assert!(admin.is_admin());
        assert!(admin.is_operator());
        assert!(admin.can_execute());

        let operator = Principal::from_user(support::sample_user(UserRole::Operator));
        assert!(!operator.is_admin());
        assert!(operator.is_operator());
        assert!(operator.can_execute());

        let readonly = Principal::from_user(support::sample_user(UserRole::Readonly));
        assert!(!readonly.is_admin());
        assert!(!readonly.is_operator());
        assert!(!readonly.can_execute());

        // Anonymous service-token agent: operator capability, never admin.
        let agent = Principal::agent(None);
        assert!(!agent.is_admin());
        assert!(!agent.is_operator());
        assert!(agent.can_execute());

        // On-behalf-of agent: never exceeds the owner's real role.
        let obo_readonly = Principal::agent(Some(support::sample_user(UserRole::Readonly)));
        assert!(!obo_readonly.is_admin());
        assert!(!obo_readonly.can_execute());
        let obo_admin = Principal::agent(Some(support::sample_user(UserRole::Admin)));
        assert!(obo_admin.is_admin(), "admin via on-behalf-of MCP token");
    }

    #[test]
    fn require_admin_rejects_operator_with_403() {
        let operator = Principal::from_user(support::sample_user(UserRole::Operator));
        let err = require_admin(&operator).unwrap_err();
        assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(err.detail(), "admin role required");

        let admin = Principal::from_user(support::sample_user(UserRole::Admin));
        assert!(require_admin(&admin).is_ok());
    }

    #[test]
    fn require_operator_grants_agents_and_rejects_readonly() {
        let readonly = Principal::from_user(support::sample_user(UserRole::Readonly));
        let err = require_operator(&readonly).unwrap_err();
        assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(err.detail(), "operator privileges required");

        assert!(require_operator(&Principal::agent(None)).is_ok());
        assert!(require_operator(&Principal::from_user(support::sample_user(
            UserRole::Operator
        )))
        .is_ok());
    }

    // ---- token handling ---------------------------------------------------

    #[tokio::test]
    async fn mfa_scoped_tokens_are_rejected_for_the_api() {
        let state = support::test_state();
        let sub = Uuid::new_v4().to_string();
        let challenge = state
            .security
            .jwt()
            .create_mfa_challenge_token(&sub, MFA_SCOPE, 5)
            .unwrap();
        // The token itself decodes fine — `get_principal` rejects its scope.
        let (_, payload) = decode_principal_token(&state.security, &challenge).unwrap();
        assert!(MFA_SCOPES.contains(&scope_of(&payload).unwrap()));
    }

    #[tokio::test]
    async fn expired_tokens_map_to_401_invalid_token() {
        let state = support::test_state();
        let sub = Uuid::new_v4().to_string();
        let expired = state
            .security
            .jwt()
            .create_access_token_at(&sub, "admin", -5, 1_700_000_000)
            .unwrap();
        let err = decode_principal_token(&state.security, &expired).unwrap_err();
        assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.detail(), "invalid token");
    }

    #[tokio::test]
    async fn challenge_tokens_map_to_invalid_challenge_token() {
        let state = support::test_state();
        let sub = Uuid::new_v4().to_string();
        let challenge = state
            .security
            .jwt()
            .create_mfa_challenge_token(&sub, crate::security::jwt::MFA_SETUP_SCOPE, 5)
            .unwrap();
        let err = decode_challenge(&state.security, &challenge, MFA_SCOPE).unwrap_err();
        assert_eq!(err.detail(), "invalid challenge token");
        assert!(decode_challenge(&state.security, "garbage", MFA_SCOPE).is_err());
    }

    #[test]
    fn missing_or_malformed_sub_is_invalid_token() {
        assert_eq!(
            sub_uuid(&json!({"sub": 42})).unwrap_err().detail(),
            "invalid token"
        );
        assert_eq!(
            sub_uuid(&json!({"sub": "not-a-uuid"}))
                .unwrap_err()
                .detail(),
            "invalid token"
        );
    }

    #[test]
    fn mcp_ip_allow_list_matches_ip_and_cidr() {
        // No rule → always allowed.
        assert!(ip_allowed(Some("1.2.3.4"), None));
        assert!(ip_allowed(None, None));
        // Rule with no/invalid client IP → denied.
        assert!(!ip_allowed(None, Some("10.0.0.0/8")));
        assert!(!ip_allowed(Some("not-an-ip"), Some("10.0.0.0/8")));
        // Bare IP rule behaves as /32 (Python normalizes, matching is identical).
        assert!(ip_allowed(Some("192.0.2.5"), Some("192.0.2.5")));
        assert!(!ip_allowed(Some("192.0.2.6"), Some("192.0.2.5")));
        // CIDR rules.
        assert!(ip_allowed(Some("10.1.2.3"), Some("10.0.0.0/8")));
        assert!(!ip_allowed(Some("11.0.0.1"), Some("10.0.0.0/8")));
        assert!(ip_allowed(Some("2001:db8::1"), Some("2001:db8::/32")));
        assert!(!ip_allowed(Some("2001:db9::1"), Some("2001:db8::/32")));
        assert!(!ip_allowed(Some("1.2.3.4"), Some("garbage")));
    }
}

//! The authenticated caller (`app/api/deps.py` + `app/core/principal.py`):
//! [`Principal`] and its RBAC checks, bearer/MCP token resolution, the
//! request-enforcement helpers and the execution throttle.

use axum::http::HeaderMap;
use chrono::Utc;
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::error::ApiError;
use crate::models::mcp_token;
use crate::models::user::{self, User};
use crate::models::{ActorType, UserRole};
use crate::security::constant_time_equals;
use crate::security::jwt::{decode_access_token, MFA_SCOPES};

use super::{db_err, unauthorized_bearer, FleetState, RouteError};

// ---------------------------------------------------------------------------
// Principal + RBAC (app/api/deps.py, app/core/principal.py)
// ---------------------------------------------------------------------------

/// The authenticated principal acting on a request (a user or an agent).
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub role: UserRole,
    pub user: Option<User>,
}

impl Principal {
    pub fn from_user(user: User) -> Self {
        Self {
            actor_type: ActorType::User,
            actor_id: user.id.to_string(),
            role: user.role,
            user: Some(user),
        }
    }

    /// The MCP façade. With a user (per-user MCP token) it acts AS that user:
    /// `actor_type` stays `agent` so the audit shows "mcp", `actor_id` is the
    /// user's id, and authorization uses the user's real role. Without a user
    /// (service-token-only calls) it is an operator capability, not an admin.
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

    /// A real user is behind this principal — a direct human session or an MCP
    /// agent acting on behalf of a user.
    pub fn has_identity(&self) -> bool {
        self.actor_type == ActorType::User || self.user.is_some()
    }

    /// Admin user, including via an on-behalf-of MCP token. The anonymous
    /// service-token agent is NOT admin (control-plane operations require a
    /// real admin identity).
    pub fn is_admin(&self) -> bool {
        self.has_identity() && self.role == UserRole::Admin
    }

    /// Admin/operator users (including via an on-behalf-of MCP token).
    pub fn is_operator(&self) -> bool {
        self.has_identity() && matches!(self.role, UserRole::Admin | UserRole::Operator)
    }

    /// Operator capability: run actions/commands, trigger updates, read audit.
    /// Granted to operators/admins (human or on-behalf-of MCP) and to the
    /// anonymous service-token agent — never to read-only users, even via MCP.
    pub fn can_execute(&self) -> bool {
        if self.actor_type == ActorType::Agent && self.user.is_none() {
            return true;
        }
        self.is_operator()
    }
}

/// Best-effort real client IP (`deps.client_ip`): behind the bundled reverse
/// proxy the peer address is the proxy's, so the LAST hop of a trusted
/// `X-Forwarded-For` is used — the entry the proxy appended (the bundled
/// Caddyfile overwrites the header), never the client-controlled entries to
/// its left (H-1). The header is only honoured when explicitly trusted, since
/// clients could otherwise spoof it. Delegates to the single shared
/// implementation in [`crate::routes::authapi::client_ip`].
pub fn client_ip(
    headers: &HeaderMap,
    config: &Config,
    peer: Option<std::net::SocketAddr>,
) -> Option<String> {
    crate::routes::authapi::client_ip(headers, config, peer)
}

/// The peer address as axum's `ConnectInfo` layer provides it (absent when no
/// such layer is applied).
pub type Peer = Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>;

/// Unwrap the [`Peer`] extractor argument.
pub fn peer_addr(peer: Peer) -> Option<std::net::SocketAddr> {
    peer.map(|axum::extract::Extension(axum::extract::ConnectInfo(addr))| addr)
}

/// `deps.enforce_body_size` — reject oversized request bodies early.
pub fn enforce_body_size(headers: &HeaderMap, max_body_bytes: usize) -> Result<(), RouteError> {
    if let Some(len) = header_str(headers, "content-length") {
        if let Ok(len) = len.trim().parse::<usize>() {
            if len > max_body_bytes {
                return Err(ApiError::payload_too_large("request body too large").into());
            }
        }
    }
    Ok(())
}

pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// `Bearer <token>` from the Authorization header (scheme is case-insensitive).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = header_str(headers, "authorization")?;
    let (scheme, param) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") && !param.trim().is_empty() {
        Some(param.trim())
    } else {
        None
    }
}

/// `deps.get_principal` — authenticate as a user (JWT) or the MCP agent
/// (service token, optionally on behalf of a user).
pub async fn authenticate(
    state: &FleetState,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> Result<Principal, RouteError> {
    // MCP façade: timing-safe service-token check, then optional on-behalf-of.
    if let Some(presented) = header_str(headers, "x-mcp-service-token") {
        // Fail closed on an empty credential: `constant_time_equals("", "")`
        // is true, so an unset service token would otherwise authenticate an
        // empty header as the (fleet-wide) automation agent.
        let configured = state.config.mcp_service_token.as_str();
        if configured.is_empty() || presented.is_empty() {
            return Err(ApiError::unauthorized("invalid service token").into());
        }
        if !constant_time_equals(presented, configured) {
            return Err(ApiError::unauthorized("invalid service token").into());
        }
        if let Some(obo) = header_str(headers, "x-mcp-on-behalf-of") {
            let user = resolve_mcp_token(state, obo, ip).await?;
            return match user {
                Some(user) => Ok(Principal::agent(Some(user))),
                None => Err(ApiError::unauthorized("invalid MCP token").into()),
            };
        }
        return Ok(Principal::agent(None));
    }

    let Some(token) = bearer_token(headers) else {
        return Err(unauthorized_bearer("authentication required"));
    };
    let payload = decode_access_token(&state.config.jwt_secret, token)
        .map_err(|_| ApiError::unauthorized("invalid token"))?;
    let user_id = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<Uuid>().ok())
        .ok_or_else(|| ApiError::unauthorized("invalid token"))?;

    // Intermediate MFA challenge/setup tokens are NOT valid for the business
    // API: they may only be presented to the dedicated /api/auth/mfa endpoints.
    if let Some(scope) = payload.get("scope").and_then(|v| v.as_str()) {
        if MFA_SCOPES.contains(&scope) {
            return Err(ApiError::unauthorized("token not valid for API access").into());
        }
    }

    let user = user::get_by_id(&state.pool, user_id)
        .await
        .map_err(db_err)?;
    match user {
        Some(user) if user.is_active => Ok(Principal::from_user(user)),
        _ => Err(ApiError::unauthorized("user not found or inactive").into()),
    }
}

/// `deps.require_admin` — human admin only (excludes the automation agent).
pub async fn require_admin(
    state: &FleetState,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> Result<Principal, RouteError> {
    let principal = authenticate(state, headers, ip).await?;
    if !principal.is_admin() {
        return Err(ApiError::forbidden("admin role required").into());
    }
    Ok(principal)
}

/// `deps.require_operator` — admin, operator, or agent; read-only users are
/// rejected.
pub async fn require_operator(
    state: &FleetState,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> Result<Principal, RouteError> {
    let principal = authenticate(state, headers, ip).await?;
    if !principal.can_execute() {
        return Err(ApiError::forbidden("operator privileges required").into());
    }
    Ok(principal)
}

/// `deps.rate_limit_exec` — authorize as operator, then throttle the execution
/// endpoints per principal.
pub async fn rate_limit_exec(
    state: &FleetState,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> Result<Principal, RouteError> {
    let principal = require_operator(state, headers, ip).await?;
    throttle_exec(state, &principal)?;
    Ok(principal)
}

/// `rate_limit_exec`'s throttle: one fixed window per `{actor_type}:{actor_id}`.
pub fn throttle_exec(state: &FleetState, principal: &Principal) -> Result<(), RouteError> {
    let key = format!("{}:{}", principal.actor_type.as_str(), principal.actor_id);
    if state.exec_limiter.allow(&key) {
        Ok(())
    } else {
        Err(ApiError::too_many_requests("rate limit exceeded; slow down").into())
    }
}

/// `deps.principal_can_access_vm` — admins and the anonymous service-token
/// agent always can; everyone else needs an entry in `user_vm_access`.
pub async fn principal_can_access_vm(
    pool: &sqlx::PgPool,
    principal: &Principal,
    vm_id: Uuid,
) -> Result<bool, DbError> {
    if principal.is_admin()
        || (principal.actor_type == ActorType::Agent && principal.user.is_none())
    {
        return Ok(true);
    }
    let Some(user) = &principal.user else {
        return Ok(false);
    };
    let ids = user::user_ids_for_vm(pool, vm_id).await?;
    Ok(ids.contains(&user.id))
}

/// `deps.accessible_vm_ids` — VM ids the principal may see, or `None` when
/// unrestricted (admin / anonymous agent).
pub async fn accessible_vm_ids(
    pool: &sqlx::PgPool,
    principal: &Principal,
) -> Result<Option<Vec<Uuid>>, DbError> {
    if principal.is_admin()
        || (principal.actor_type == ActorType::Agent && principal.user.is_none())
    {
        return Ok(None);
    }
    let Some(user) = &principal.user else {
        return Ok(Some(Vec::new()));
    };
    Ok(Some(user::vm_ids_for_user(pool, user.id).await?))
}

/// `services/mcp_tokens.resolve` — map a presented MCP token to its active
/// owner: deterministic keyed HMAC lookup, optional IP allow-list, `last_used_at`
/// bump.
async fn resolve_mcp_token(
    state: &FleetState,
    presented: &str,
    client_ip: Option<&str>,
) -> Result<Option<User>, RouteError> {
    if presented.is_empty() {
        return Ok(None);
    }
    let token_hash = state.security.hash_secret(presented);
    let token = mcp_token::get_active_by_token_hash(&state.pool, &token_hash)
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
    let user = user::get_by_id(&state.pool, token.user_id)
        .await
        .map_err(db_err)?;
    let Some(user) = user else {
        return Ok(None);
    };
    if !user.is_active {
        return Ok(None);
    }
    mcp_token::touch_last_used(&state.pool, token.id, Utc::now())
        .await
        .map_err(db_err)?;
    Ok(Some(user))
}

/// `mcp_tokens.ip_allowed` — no rule → always allowed; a rule with no/invalid
/// client IP → denied.
pub fn ip_allowed(client_ip: Option<&str>, allowed: Option<&str>) -> bool {
    let Some(allowed) = allowed else {
        return true;
    };
    let Some(client_ip) = client_ip else {
        return false;
    };
    ip_in_network(client_ip, allowed)
}

/// True when `ip` falls inside `network` (an address or CIDR range).
fn ip_in_network(ip: &str, network: &str) -> bool {
    let Ok(ip) = ip.trim().parse::<std::net::IpAddr>() else {
        return false;
    };
    let network = network.trim();
    let (base, prefix) = match network.split_once('/') {
        Some((base, prefix)) => {
            let Ok(prefix) = prefix.parse::<u32>() else {
                return false;
            };
            (base, prefix)
        }
        None => (network, u32::MAX),
    };
    let Ok(base) = base.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (ip, base) {
        (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(base)) => {
            let prefix = prefix.min(32);
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(base) & mask
        }
        (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(base)) => {
            let prefix = prefix.min(128);
            let (ip, base) = (u128::from(ip), u128::from(base));
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            ip & mask == base & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn ip_allow_list_matches_python_ipaddress() {
        assert!(ip_allowed(Some("10.0.0.5"), None), "no rule → allowed");
        assert!(
            !ip_allowed(None, Some("10.0.0.0/8")),
            "rule, no ip → denied"
        );
        assert!(ip_allowed(Some("10.0.0.5"), Some("10.0.0.0/8")));
        assert!(!ip_allowed(Some("11.0.0.5"), Some("10.0.0.0/8")));
        assert!(ip_allowed(Some("192.168.1.9"), Some("192.168.1.9")), "/32");
        assert!(!ip_allowed(Some("192.168.1.10"), Some("192.168.1.9")));
        assert!(
            ip_allowed(Some("2001:db8::1"), Some("2001:db8::/32")),
            "IPv6"
        );
        assert!(!ip_allowed(Some("2001:db9::1"), Some("2001:db8::/32")));
        assert!(!ip_allowed(Some("nope"), Some("10.0.0.0/8")), "invalid ip");
        assert!(
            !ip_allowed(Some("10.0.0.1"), Some("garbage")),
            "invalid rule"
        );
    }

    #[test]
    fn principal_capability_matches_python() {
        let mut user = sample_user(UserRole::Operator);

        let operator = Principal::from_user(user.clone());
        assert!(operator.is_operator());
        assert!(!operator.is_admin());
        assert!(operator.can_execute());

        user.role = UserRole::Readonly;
        let readonly = Principal::from_user(user.clone());
        assert!(!readonly.can_execute(), "read-only users never execute");

        user.role = UserRole::Admin;
        let admin = Principal::from_user(user);
        assert!(admin.is_admin());

        let agent = Principal::agent(None);
        assert!(!agent.is_admin(), "anonymous agent is never admin");
        assert!(!agent.is_operator());
        assert!(agent.can_execute(), "but it may execute");
        assert_eq!(agent.actor_id, "hermes");

        let agent_obo = Principal::agent(Some(sample_user(UserRole::Readonly)));
        assert!(
            !agent_obo.can_execute(),
            "MCP never exceeds the owner's role"
        );
        assert_eq!(agent_obo.actor_type, ActorType::Agent);
    }

    #[tokio::test]
    async fn execution_rate_limit_is_per_principal() {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let state = FleetState::new(
            pool,
            Config {
                rate_limit_exec_per_minute: 2,
                ..Config::default()
            },
        );
        let principal = Principal::from_user(sample_user(UserRole::Operator));
        assert!(throttle_exec(&state, &principal).is_ok());
        assert!(throttle_exec(&state, &principal).is_ok());
        let error = throttle_exec(&state, &principal).unwrap_err();
        assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.detail(), "rate limit exceeded; slow down");

        // Each principal gets its own window.
        assert!(throttle_exec(&state, &Principal::agent(None)).is_ok());
    }

    /// An unset (empty) service token must never authenticate a request: the
    /// MCP façade would otherwise hand the fleet-wide operator capability to
    /// anybody sending an empty `x-mcp-service-token` header.
    #[tokio::test]
    async fn an_empty_service_token_never_authenticates() {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let state = FleetState::new(
            pool,
            Config {
                mcp_service_token: String::new(),
                ..Config::default()
            },
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-mcp-service-token", "".parse().unwrap());
        let error = authenticate(&state, &headers, None).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(error.detail(), "invalid service token");

        // A wrong token is refused as well.
        let mut headers = HeaderMap::new();
        headers.insert("x-mcp-service-token", "nope".parse().unwrap());
        let error = authenticate(&state, &headers, None).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    }

    /// An empty presented service token is refused even when the configured
    /// one is set (an empty header must never reach the comparison).
    #[tokio::test]
    async fn an_empty_presented_service_token_is_refused() {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let state = FleetState::new(
            pool,
            Config {
                mcp_service_token: "s3rvice-token".into(),
                ..Config::default()
            },
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-mcp-service-token", "".parse().unwrap());
        let error = authenticate(&state, &headers, None).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(error.detail(), "invalid service token");
    }
}

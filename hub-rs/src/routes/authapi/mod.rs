//! Authentication, MFA and user management — the `/api/auth` + `/api/users`
//! surface, ported from `hub/app/api/routes/{auth,mfa,users}.py` with the
//! request-authentication dependencies of `hub/app/api/deps.py`.
//!
//! | route                                              | Python handler            |
//! |----------------------------------------------------|---------------------------|
//! | `GET  /api/auth/config`                            | `auth_config`             |
//! | `POST /api/auth/login`                             | `login`                   |
//! | `GET/PUT /api/auth/me`                             | `me` / `update_me`        |
//! | `POST /api/auth/logout`                            | `logout`                  |
//! | `POST /api/auth/mfa/verify`                        | `verify_mfa`              |
//! | `POST /api/auth/mfa/totp/enroll/begin`             | `totp_enroll_begin`       |
//! | `POST /api/auth/mfa/totp/enroll/finish`            | `totp_enroll_finish`      |
//! | `POST /api/auth/mfa/totp/disable`                  | `totp_disable`            |
//! | `POST /api/auth/mfa/totp/backup-codes/regenerate`  | `regenerate_backup_codes` |
//! | `POST /api/auth/mfa/webauthn/register/begin`       | `webauthn_register_begin` (501, phase 2) |
//! | `POST /api/auth/mfa/webauthn/register/finish`      | `webauthn_register_finish` (501, phase 2) |
//! | `POST /api/auth/mfa/webauthn/login/begin`          | `webauthn_login_begin` (501, phase 2) |
//! | `POST /api/auth/mfa/webauthn/login/finish`         | `webauthn_login_finish` (501, phase 2) |
//! | `GET  /api/auth/mfa/webauthn/credentials`          | `list_passkeys`           |
//! | `PUT  /api/auth/mfa/webauthn/credentials/{cred_id}` | `rename_passkey`         |
//! | `DELETE /api/auth/mfa/webauthn/credentials/{cred_id}` | `delete_passkey`       |
//! | `GET/POST /api/users`                              | `list_users` / `create_user` |
//! | `GET/PUT/DELETE /api/users/{user_id}`              | `get_user` / `update_user` / `deactivate_user` |
//! | `PUT  /api/users/{user_id}/password`               | `change_password`         |
//! | `POST /api/users/{user_id}/mfa/reset`              | `reset_user_mfa`          |
//! | `PUT  /api/users/{user_id}/vms`                    | `set_user_vms`            |
//!
//! Two-step login works like the Python hub: `POST /api/auth/login` validates
//! the password and, when a second factor is required, returns a short-lived
//! *challenge token* (scope `mfa`) instead of an access token. Admins without
//! any factor get an `mfa_setup` token. [`get_principal`] REJECTS these scoped
//! tokens for the business API, so they are only ever usable on the MFA routes.
//!
//! Not yet ported (see `PARITY_HUB.md`): OIDC (`/api/auth/oidc/*`, needs an
//! HTTP client + JWKS verification), the LDAP login fallback (needs an LDAP
//! client) and the WebAuthn ceremony crypto (needs `webauthn-rs`); the WebAuthn
//! *credential management* endpoints are fully ported — only the four ceremony
//! endpoints answer 501.

pub mod auth;
pub mod mfa;
pub mod users;

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension};
use axum::http::HeaderMap;
use axum::Router;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::error::ApiError;
use crate::models::audit::{append_chained, AuditNew};
use crate::models::enums::{ActorType, UserRole};
use crate::models::user::User;
use crate::security::jwt::MFA_SCOPES;
use crate::security::SecurityConfig;

// ---------------------------------------------------------------------------
// Wire schemas shared by the auth and users routes (app/schemas/{auth,user}.py)
// ---------------------------------------------------------------------------

/// `UserOut` — identical in `app/schemas/auth.py` and `app/schemas/user.py`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserOut {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    #[serde(default)]
    pub vm_ids: Vec<Uuid>,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub passkey_count: i64,
}

/// `TokenResponse` (`token_type` defaults to `"bearer"` in the Python schema).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

impl TokenResponse {
    pub fn new(access_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            token_type: "bearer".to_owned(),
            expires_in,
        }
    }
}

// ---------------------------------------------------------------------------
// Principal (app/core/principal.py)
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

// ---------------------------------------------------------------------------
// State + router
// ---------------------------------------------------------------------------

/// Everything the auth/users routes need. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AuthState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub security: SecurityConfig,
    /// Per-IP brute-force guard on login (5 attempts/minute — `auth._login_limiter`).
    pub login_limiter: RateLimiter,
    /// Per-IP/per-user guard on MFA verification (10/minute — `mfa._verify_limiter`).
    pub verify_limiter: RateLimiter,
    /// Per-IP guard on the WebAuthn endpoints (20/minute — `mfa._webauthn_limiter`).
    pub webauthn_limiter: RateLimiter,
    /// Per-principal guard on execution endpoints (`deps._exec_limiter`).
    pub exec_limiter: RateLimiter,
}

impl AuthState {
    pub fn new(pool: sqlx::PgPool, config: Config) -> Self {
        let security = SecurityConfig::new(
            &config.mfa_encryption_key,
            &config.jwt_secret,
            &config.secret_hash_key,
        );
        Self {
            login_limiter: RateLimiter::new(5),
            verify_limiter: RateLimiter::new(10),
            webauthn_limiter: RateLimiter::new(20),
            exec_limiter: RateLimiter::new(config.rate_limit_exec_per_minute),
            pool,
            config,
            security,
        }
    }
}

/// The `/api/auth` + `/api/users` router (prefixes included, merge as-is).
pub fn router(state: AuthState) -> Router {
    let body_cap = state.config.max_body_bytes;
    auth::router()
        .merge(mfa::router())
        .merge(users::router())
        .layer(DefaultBodyLimit::max(body_cap))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Request authentication (app/api/deps.py)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Service helpers (app/services/{users,mfa}.py)
// ---------------------------------------------------------------------------

pub(crate) fn db_err(err: DbError) -> ApiError {
    ApiError::internal(err.to_string())
}

/// Verify credentials. Always spends Argon2 work (even for unknown users or
/// accounts without a local password) to limit user enumeration —
/// `users_service.authenticate`. A successful password bumps `last_login_at`
/// and transparently re-hashes with current parameters.
pub(crate) async fn authenticate(
    state: &AuthState,
    username: &str,
    password: &str,
) -> Result<Option<User>, ApiError> {
    let user = crate::models::user::get_by_username(&state.pool, username)
        .await
        .map_err(db_err)?;
    let hash = user.as_ref().and_then(|u| u.password_hash.as_deref());
    if !crate::security::verify_password(password, hash) {
        return Ok(None);
    }
    let Some(user) = user.filter(|u| u.is_active) else {
        return Ok(None);
    };
    crate::models::user::touch_last_login(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    if let Some(hash) = user.password_hash.as_deref() {
        if crate::security::needs_rehash(hash) {
            let new_hash = crate::security::hash_password(password)
                .map_err(|e| ApiError::internal(e.to_string()))?;
            crate::models::user::update_password(&state.pool, user.id, Some(&new_hash))
                .await
                .map_err(db_err)?;
        }
    }
    Ok(Some(user))
}

/// Issue a fresh access token (`users_service.issue_token`).
pub(crate) fn issue_token(state: &AuthState, user: &User) -> Result<String, ApiError> {
    state
        .security
        .jwt()
        .create_access_token(
            &user.id.to_string(),
            user.role.as_str(),
            state.config.access_token_ttl_minutes,
        )
        .map_err(|e| ApiError::internal(e.to_string()))
}

/// `expires_in` of a fresh access token (`access_token_ttl_minutes * 60`).
pub(crate) fn token_expires_in(state: &AuthState) -> i64 {
    state.config.access_token_ttl_minutes * 60
}

pub(crate) fn token_response(state: &AuthState, user: &User) -> Result<TokenResponse, ApiError> {
    Ok(TokenResponse::new(
        issue_token(state, user)?,
        token_expires_in(state),
    ))
}

/// `UserOut` with `vm_ids` and the live passkey count (`auth.me`, `get_user`,
/// `list_users`, `reset_user_mfa`).
pub(crate) async fn user_out(state: &AuthState, user: &User) -> Result<UserOut, ApiError> {
    let vm_ids = crate::models::user::vm_ids_for_user(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    let passkey_count = crate::models::webauthn::count_credentials(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    Ok(UserOut {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        role: user.role,
        is_active: user.is_active,
        vm_ids,
        totp_enabled: user.totp_enabled,
        passkey_count,
    })
}

/// `UserOut` with `vm_ids` only. Faithful to the Python `users.py` responses
/// for create/update/vms, which `model_copy(update={"vm_ids": ...})` and thus
/// leave `passkey_count` at its `0` schema default (see PARITY_HUB.md).
pub(crate) async fn user_out_vms_only(state: &AuthState, user: &User) -> Result<UserOut, ApiError> {
    let vm_ids = crate::models::user::vm_ids_for_user(&state.pool, user.id)
        .await
        .map_err(db_err)?;
    Ok(UserOut {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        role: user.role,
        is_active: user.is_active,
        vm_ids,
        totp_enabled: user.totp_enabled,
        passkey_count: 0,
    })
}

/// Set the profile email exactly as `auth.update_me` does (`user.email =
/// body.email or None`), including clearing it to `NULL`. The
/// `models::user::update` patch keeps NULL out (`COALESCE`), hence the direct
/// statement.
pub(crate) async fn set_user_email(
    state: &AuthState,
    user_id: Uuid,
    email: Option<String>,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET email = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(&email)
        .bind(chrono::Utc::now())
        .execute(&state.pool)
        .await
        .map_err(|e| db_err(DbError::from(e)))?;
    Ok(())
}

/// Store a *pending* TOTP secret (enrollment begun, not yet confirmed) —
/// `mfa.totp_enroll_begin` sets `user.totp_secret_enc` without enabling TOTP.
pub(crate) async fn set_pending_totp_secret(
    state: &AuthState,
    user_id: Uuid,
    secret_enc: &str,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET totp_secret_enc = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(secret_enc)
        .bind(chrono::Utc::now())
        .execute(&state.pool)
        .await
        .map_err(|e| db_err(DbError::from(e)))?;
    Ok(())
}

/// Append one chained audit entry (`app.core.audit.record`): the row hash is
/// computed while holding the chain's advisory lock.
pub(crate) async fn record_audit(
    state: &AuthState,
    mut new: AuditNew,
    source_ip: Option<String>,
) -> Result<(), ApiError> {
    new.source_ip = source_ip;
    append_chained(&state.pool, new, |entry, head| {
        let row_hash = crate::security::compute_row_hash(head, &entry.hash_fields());
        (head.to_owned(), row_hash)
    })
    .await
    .map_err(db_err)?;
    Ok(())
}

/// The TOTP secret at rest, Fernet-encrypted (`totp_service.encrypt_secret`).
pub(crate) fn encrypt_totp_secret(state: &AuthState, secret: &str) -> Result<String, ApiError> {
    state
        .security
        .fernet()
        .encrypt(secret)
        .map_err(|e| ApiError::internal(e.to_string()))
}

/// Decrypt the stored TOTP secret (`totp_service.decrypt_secret`). The caller
/// maps failure onto its own auth error (key rotated/corrupt must not 500).
pub(crate) fn decrypt_totp_secret(state: &AuthState, enc: &str) -> Result<String, ()> {
    state.security.fernet().decrypt(enc).map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Backup codes (app/services/mfa.py)
// ---------------------------------------------------------------------------

/// How many single-use recovery codes an enrollment generates.
pub(crate) const BACKUP_CODE_COUNT: usize = 10;

/// 10 single-use codes, formatted `xxxxx-xxxxx` from 10 hex chars
/// (`mfa.generate_backup_codes`).
pub(crate) fn generate_backup_codes() -> Vec<String> {
    use rand::RngCore;
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0u8; 5];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            format_backup_code(&crate::security::hex_encode(&bytes))
        })
        .collect()
}

/// `mfa._format_code`: 10 hex chars grouped as `xxxxx-xxxxx` for readability.
fn format_backup_code(raw_hex: &str) -> String {
    format!("{}-{}", &raw_hex[..5], &raw_hex[5..])
}

/// Hash a presented backup code the way `consume_backup_code` looks it up
/// (whitespace-stripped first).
pub(crate) fn backup_code_hash(state: &AuthState, code: &str) -> String {
    state.security.hash_secret(code.trim())
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod support {
    use super::*;

    /// A minimal `User` row for unit tests.
    pub(crate) fn sample_user(role: UserRole) -> User {
        User {
            id: Uuid::new_v4(),
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            password_hash: Some(crate::security::hash_password("correct horse battery").unwrap()),
            oidc_subject: None,
            ldap_dn: None,
            role,
            is_active: true,
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            totp_secret_enc: None,
            totp_enabled: false,
            totp_confirmed_at: None,
            totp_last_step: None,
        }
    }

    /// A state wired to a lazy pool: only paths that never touch the database
    /// can be exercised through it (any query fails fast).
    pub(crate) fn test_state() -> AuthState {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        AuthState::new(pool, Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    // ---- backup codes -----------------------------------------------------

    #[test]
    fn backup_codes_are_ten_grouped_hex_codes() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        for code in &codes {
            assert_eq!(code.len(), 11, "xxxxx-xxxxx");
            let (a, b) = code.split_once('-').unwrap();
            assert_eq!(a.len(), 5);
            assert_eq!(b.len(), 5);
            assert!(code
                .chars()
                .filter(|c| *c != '-')
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), BACKUP_CODE_COUNT, "codes are unique");
    }

    #[tokio::test]
    async fn backup_code_hashing_strips_whitespace_like_python() {
        let state = support::test_state();
        // `secrets.token_hex(5)` → 10 hex chars, formatted `xxxxx-xxxxx`.
        let formatted = format_backup_code(&crate::security::hex_encode(b"hello"));
        assert_eq!(formatted, "68656-c6c6f");
        assert_eq!(
            backup_code_hash(&state, &formatted),
            backup_code_hash(&state, &format!("  {formatted}\t")),
            "lookup hashes the whitespace-stripped code"
        );
    }

    // ---- UserOut shape ----------------------------------------------------

    #[test]
    fn user_out_serializes_like_the_pydantic_schema() {
        let out = UserOut {
            id: Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
            username: "alice".into(),
            email: None,
            role: UserRole::Admin,
            is_active: true,
            vm_ids: vec![Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap()],
            totp_enabled: true,
            passkey_count: 2,
        };
        assert_eq!(
            serde_json::to_value(&out).unwrap(),
            json!({
                "id": "00000000-0000-4000-8000-000000000001",
                "username": "alice",
                "email": null,
                "role": "admin",
                "is_active": true,
                "vm_ids": ["00000000-0000-4000-8000-000000000002"],
                "totp_enabled": true,
                "passkey_count": 2,
            })
        );
    }

    #[test]
    fn token_response_carries_the_bearer_type() {
        let resp = TokenResponse::new("tok".into(), 3600);
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            json!({"access_token": "tok", "token_type": "bearer", "expires_in": 3600})
        );
    }
}

#[cfg(test)]
mod live_tests {
    //! End-to-end exercise of the auth/MFA/users routes against a live
    //! PostgreSQL (skipped unless `HUGINN_TEST_DATABASE_URL` is set — `cargo
    //! test` stays green without a database, like `db.rs`/`models::live_tests`).

    use super::*;
    use crate::models::user::UserNew;
    use axum::body::Body;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    async fn fresh_state() -> Option<(AuthState, tokio::sync::MutexGuard<'static, ()>)> {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return None;
        };
        let guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = crate::db::connect(&url, 4).await.expect("connect");
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(&pool)
            .await
            .expect("drop schema");
        sqlx::query("CREATE SCHEMA public")
            .execute(&pool)
            .await
            .expect("create schema");
        crate::db::run_migrations(&pool).await.expect("migrations");
        Some((AuthState::new(pool, Config::default()), guard))
    }

    async fn make_user(state: &AuthState, username: &str, password: &str, role: UserRole) -> Uuid {
        let password_hash = crate::security::hash_password(password).unwrap();
        crate::models::user::create(
            &state.pool,
            UserNew {
                username: username.into(),
                password_hash: Some(password_hash),
                role,
                is_active: true,
                ..UserNew::default()
            },
        )
        .await
        .unwrap()
        .id
    }

    fn request(
        method: &str,
        uri: &str,
        body: serde_json::Value,
        token: Option<&str>,
    ) -> axum::http::Request<Body> {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if !body.is_null() {
            builder = builder.header("content-type", "application/json");
        }
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder
            .body(Body::from(if body.is_null() {
                String::new()
            } else {
                body.to_string()
            }))
            .unwrap()
    }

    async fn send(
        state: &AuthState,
        request: axum::http::Request<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let response = crate::routes::authapi::router(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(json!(null));
        (status, body)
    }

    #[tokio::test]
    async fn login_mfa_enrollment_and_verification_flows() {
        let Some((state, _guard)) = fresh_state().await else {
            return;
        };
        make_user(&state, "admin", "correct horse battery", UserRole::Admin).await;

        // Wrong password and unknown users both answer the same 401.
        for body in [
            json!({"username": "admin", "password": "wrong"}),
            json!({"username": "ghost", "password": "correct horse battery"}),
        ] {
            let (status, resp) = send(&state, request("POST", "/api/auth/login", body, None)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(resp, json!({"detail": "invalid credentials"}));
        }

        // Admin without a factor + require_admin_mfa → mfa_setup challenge.
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            resp,
            json!({
                "mfa_required": false,
                "mfa_setup_required": true,
                "challenge_token": resp["challenge_token"],
                "methods": ["totp", "webauthn"],
            })
        );
        let setup_token = resp["challenge_token"].as_str().unwrap().to_owned();
        state
            .security
            .jwt()
            .decode_mfa_challenge_token(&setup_token, crate::security::jwt::MFA_SETUP_SCOPE)
            .expect("setup token carries the mfa_setup scope");

        // The setup token is not an API token.
        let (status, resp) = send(
            &state,
            request("GET", "/api/auth/me", json!(null), Some(&setup_token)),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp, json!({"detail": "token not valid for API access"}));

        // TOTP enrollment, driven by the setup token.
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/totp/enroll/begin",
                json!({}),
                Some(&setup_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let secret = resp["secret"].as_str().unwrap().to_owned();
        assert_eq!(
            resp["otpauth_uri"],
            json!(format!(
                "otpauth://totp/Huginn:admin?secret={secret}&issuer=Huginn"
            ))
        );

        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let code = crate::security::totp_code_at(&secret, now).unwrap();

        // A wrong code refuses and keeps the pending enrollment.
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/totp/enroll/finish",
                json!({"code": "abcdef"}),
                Some(&setup_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp, json!({"detail": "invalid code"}));

        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/totp/enroll/finish",
                json!({"code": code}),
                Some(&setup_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let backup_codes = resp["backup_codes"].as_array().unwrap().clone();
        assert_eq!(
            backup_codes.len(),
            crate::routes::authapi::BACKUP_CODE_COUNT
        );
        assert!(
            resp["access_token"].is_string(),
            "the setup flow logs the admin in"
        );

        // Second factor is now required at login.
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["mfa_required"], json!(true));
        assert_eq!(resp["mfa_setup_required"], json!(false));
        assert_eq!(resp["methods"], json!(["totp", "backup"]));
        let challenge = resp["challenge_token"].as_str().unwrap().to_owned();

        // A bad code fails, the right one exchanges the challenge for a token.
        let (status, _) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"code": "abcdef"}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"code": code}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["token_type"], json!("bearer"));
        assert_eq!(resp["expires_in"], json!(3600));
        let access_token = resp["access_token"].as_str().unwrap().to_owned();

        // The access token works on the business API.
        let (status, resp) = send(
            &state,
            request("GET", "/api/auth/me", json!(null), Some(&access_token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["username"], json!("admin"));
        assert_eq!(resp["role"], json!("admin"));
        assert_eq!(resp["totp_enabled"], json!(true));
        assert_eq!(resp["passkey_count"], json!(0));

        // Replay: the claimed time-step cannot be spent twice.
        let (_, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        let challenge = resp["challenge_token"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"code": code}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp, json!({"detail": "invalid code"}));

        // Backup codes are single-use too.
        let code0 = backup_codes[0].as_str().unwrap().to_owned();
        let (_, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        let challenge = resp["challenge_token"].as_str().unwrap().to_owned();
        let (status, _) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"backup_code": code0}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/login",
                json!({"username": "admin", "password": "correct horse battery"}),
                None,
            ),
        )
        .await;
        let challenge = resp["challenge_token"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/auth/mfa/verify",
                json!({"backup_code": code0}),
                Some(&challenge),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp, json!({"detail": "invalid code"}));
    }

    #[tokio::test]
    async fn users_crud_password_and_rbac_flows() {
        let Some((mut state, _guard)) = fresh_state().await else {
            return;
        };
        // No forced setup here: the admin logs straight in.
        state.config.require_admin_mfa = false;
        make_user(&state, "admin", "correct horse battery", UserRole::Admin).await;

        let login = |username: &str, password: &str| {
            request(
                "POST",
                "/api/auth/login",
                json!({"username": username, "password": password}),
                None,
            )
        };
        let (_, resp) = send(&state, login("admin", "correct horse battery")).await;
        let admin_token = resp["access_token"].as_str().unwrap().to_owned();

        // RBAC: an operator may not list users.
        make_user(&state, "olive", "olive-olive-olive", UserRole::Operator).await;
        let (_, resp) = send(&state, login("olive", "olive-olive-olive")).await;
        let olive_token = resp["access_token"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request("GET", "/api/users", json!(null), Some(&olive_token)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(resp, json!({"detail": "admin role required"}));

        // Create (201) and duplicate (409) and validation (422).
        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/users",
                json!({"username": "eve", "password": "eve-eve-eve-eve", "role": "operator"}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(resp["username"], json!("eve"));
        assert_eq!(resp["role"], json!("operator"));
        assert_eq!(resp["passkey_count"], json!(0));
        let eve_id = resp["id"].as_str().unwrap().to_owned();
        assert_eq!(resp["vm_ids"], json!([]));

        let (status, resp) = send(
            &state,
            request(
                "POST",
                "/api/users",
                json!({"username": "eve", "password": "eve-eve-eve-eve"}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(resp, json!({"detail": "username already exists"}));

        let (status, _) = send(
            &state,
            request(
                "POST",
                "/api/users",
                json!({"username": "short", "password": "short"}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Role update (with audit detail) and VM access.
        let vm = crate::models::vm::create(
            &state.pool,
            crate::models::vm::VmNew::new("vm-1", crate::models::enums::WorkerArch::Amd64),
        )
        .await
        .unwrap();
        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/vms"),
                json!({"vm_ids": [vm.id.to_string()]}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["vm_ids"], json!([vm.id.to_string()]));

        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}"),
                json!({"role": "readonly"}),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["role"], json!("readonly"));
        let audit =
            crate::models::audit::list_filtered(&state.pool, None, Some("user_updated"), 10)
                .await
                .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(
            audit[0].detail["role"],
            json!({"old": "operator", "new": "readonly"})
        );

        // Self password change: old password required and checked.
        let (status, _) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/password"),
                json!({"new_password": "new-new-new-new"}),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "unauthenticated");

        let (_, resp) = send(&state, login("eve", "eve-eve-eve-eve")).await;
        let eve_token = resp["access_token"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/password"),
                json!({"new_password": "new-new-new-new"}),
                Some(&eve_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            resp,
            json!({"detail": "old_password required for self-change"})
        );

        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/password"),
                json!({"old_password": "nope", "new_password": "new-new-new-new"}),
                Some(&eve_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp, json!({"detail": "incorrect old password"}));

        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{eve_id}/password"),
                json!({"old_password": "eve-eve-eve-eve", "new_password": "new-new-new-new"}),
                Some(&eve_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp, json!({"status": "ok"}));
        let (status, _) = send(&state, login("eve", "new-new-new-new")).await;
        assert_eq!(status, StatusCode::OK);

        // A non-admin may not reset someone else's password.
        let (_, resp) = send(
            &state,
            request("GET", "/api/auth/me", json!(null), Some(&admin_token)),
        )
        .await;
        let admin_id = resp["id"].as_str().unwrap().to_owned();
        let (status, resp) = send(
            &state,
            request(
                "PUT",
                &format!("/api/users/{admin_id}/password"),
                json!({"new_password": "new-new-new-new"}),
                Some(&eve_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            resp,
            json!({"detail": "admin role required to reset other passwords"})
        );

        // Deactivation: self-delete refused, others disabled.
        let (status, resp) = send(
            &state,
            request(
                "DELETE",
                &format!("/api/users/{admin_id}"),
                json!(null),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp, json!({"detail": "cannot deactivate yourself"}));

        let (status, _) = send(
            &state,
            request(
                "DELETE",
                &format!("/api/users/{eve_id}"),
                json!(null),
                Some(&admin_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, resp) = send(&state, login("eve", "new-new-new-new")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp, json!({"detail": "invalid credentials"}));
    }
}

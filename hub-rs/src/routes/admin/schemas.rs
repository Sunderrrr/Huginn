//! Shared request/response shapes of the admin routes: who is calling
//! ([`Principal`] / [`Caller`]) and what errors look like on the wire
//! ([`RouteError`]).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::db::DbError;
use crate::error::ApiError;
use crate::models::user::User;
use crate::models::{ActorType, UserRole};

// ---------------------------------------------------------------------------
// Errors: `ApiError` plus the few response headers FastAPI adds
// ---------------------------------------------------------------------------

/// Route error: [`ApiError`] plus optional response headers (e.g. the
/// `WWW-Authenticate: Bearer` FastAPI sends on a missing/invalid bearer
/// scheme — `ApiError` itself only renders the `{"detail": ...}` body).
#[derive(Debug, Clone)]
pub struct RouteError {
    api: ApiError,
    www_authenticate: bool,
}

impl RouteError {
    /// 401 with `WWW-Authenticate: Bearer` (`HTTPBearer`/`get_principal`).
    pub fn unauthorized_bearer(detail: impl Into<String>) -> Self {
        Self {
            api: ApiError::unauthorized(detail),
            www_authenticate: true,
        }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        ApiError::bad_request(detail).into()
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        ApiError::unauthorized(detail).into()
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        ApiError::forbidden(detail).into()
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        ApiError::not_found(detail).into()
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        ApiError::conflict(detail).into()
    }

    pub fn unprocessable_entity(detail: impl Into<String>) -> Self {
        ApiError::unprocessable_entity(detail).into()
    }

    pub fn payload_too_large(detail: impl Into<String>) -> Self {
        ApiError::payload_too_large(detail).into()
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        ApiError::internal(detail).into()
    }

    /// The FastAPI status code, for assertions.
    pub fn status(&self) -> StatusCode {
        self.api.status()
    }
}

impl From<ApiError> for RouteError {
    fn from(api: ApiError) -> Self {
        Self {
            api,
            www_authenticate: false,
        }
    }
}

impl From<DbError> for RouteError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::Conflict(detail) => Self::conflict(detail),
            DbError::Invalid(detail) => Self::bad_request(detail),
            DbError::NotFound => Self::not_found("not found"),
            other => Self::internal(other.to_string()),
        }
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let mut response = self.api.into_response();
        if self.www_authenticate {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                "Bearer".parse().unwrap(),
            );
        }
        response
    }
}

// ---------------------------------------------------------------------------
// The authenticated caller (app/core/principal.py + app/api/deps.py)
// ---------------------------------------------------------------------------

/// Who is performing an action: a user session, or the MCP façade acting for
/// itself / on behalf of a user (`app/core/principal.py`).
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub role: UserRole,
    pub user: Option<User>,
}

impl Principal {
    /// A real user is behind this principal — a direct human session or an MCP
    /// agent acting on behalf of a user (a per-user MCP token).
    fn has_identity(&self) -> bool {
        self.actor_type == ActorType::User || self.user.is_some()
    }

    /// True for an admin user, including via an on-behalf-of MCP token. The
    /// anonymous service-token agent is never admin.
    pub fn is_admin(&self) -> bool {
        self.has_identity() && self.role == UserRole::Admin
    }

    /// True for admin/operator users (including via an on-behalf-of MCP token).
    pub fn is_operator(&self) -> bool {
        self.has_identity() && matches!(self.role, UserRole::Admin | UserRole::Operator)
    }

    /// Operator capability: run actions/commands, read the catalog. Granted to
    /// operators/admins (human or MCP on-behalf-of) and to the anonymous
    /// service-token agent — never to read-only users, even through MCP.
    pub fn can_execute(&self) -> bool {
        if self.actor_type == ActorType::Agent && self.user.is_none() {
            return true;
        }
        self.is_operator()
    }

    /// A direct user session.
    pub fn from_user(user: &User) -> Self {
        Self {
            actor_type: ActorType::User,
            actor_id: user.id.to_string(),
            role: user.role,
            user: Some(user.clone()),
        }
    }

    /// The MCP façade. With a user (per-user MCP token) it acts AS that user;
    /// `actor_type` stays `agent` so the audit shows "mcp". Without a user it is
    /// the anonymous service-token agent ("hermes", read-only role).
    pub fn agent(user: Option<&User>) -> Self {
        match user {
            Some(user) => Self {
                actor_type: ActorType::Agent,
                actor_id: user.id.to_string(),
                role: user.role,
                user: Some(user.clone()),
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

/// The authenticated caller plus the best-effort client IP used for auditing.
#[derive(Debug, Clone)]
pub struct Caller {
    pub principal: Principal,
    pub source_ip: Option<String>,
}

impl Caller {
    /// `require_admin` — human admin (or an admin's MCP token), 403 otherwise.
    pub fn require_admin(&self) -> Result<(), RouteError> {
        if self.principal.is_admin() {
            Ok(())
        } else {
            Err(RouteError::forbidden("admin role required"))
        }
    }

    /// `require_operator` — admin/operator/agent, 403 for read-only users.
    pub fn require_operator(&self) -> Result<(), RouteError> {
        if self.principal.can_execute() {
            Ok(())
        } else {
            Err(RouteError::forbidden("operator privileges required"))
        }
    }

    /// `mcp.py:_require_user` — the user behind the request.
    pub fn require_user(&self) -> Result<&User, RouteError> {
        self.principal
            .user
            .as_ref()
            .ok_or_else(|| RouteError::forbidden("a user session is required"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::*;

    #[test]
    fn principal_capability_matches_python() {
        // Admin user: admin + operator + execute.
        let admin = make_user("admin", UserRole::Admin);
        let p = Principal::from_user(&admin);
        assert!(p.is_admin() && p.is_operator() && p.can_execute());
        assert_eq!(p.actor_type, ActorType::User);
        assert_eq!(p.actor_id, admin.id.to_string());

        // Read-only user: no admin, no operator, no execute.
        let ro = make_user("ro", UserRole::Readonly);
        let p = Principal::from_user(&ro);
        assert!(!p.is_admin() && !p.is_operator() && !p.can_execute());

        // MCP on-behalf-of an admin user keeps the user's role, but the audit
        // actor is the agent.
        let p = Principal::agent(Some(&admin));
        assert!(p.is_admin());
        assert_eq!(p.actor_type, ActorType::Agent);
        assert_eq!(p.actor_id, admin.id.to_string());

        // MCP on-behalf-of a read-only user never gains capabilities.
        let p = Principal::agent(Some(&ro));
        assert!(!p.is_admin() && !p.is_operator() && !p.can_execute());

        // Anonymous service-token agent: may execute, never admin.
        let p = Principal::agent(None);
        assert!(!p.is_admin() && !p.is_operator());
        assert!(p.can_execute());
        assert_eq!(p.actor_id, "hermes");
    }

    #[test]
    fn route_error_renders_the_fastapi_shape() {
        let response = RouteError::not_found("tag not found").into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = RouteError::unauthorized_bearer("authentication required").into_response();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer"
        );
    }
}

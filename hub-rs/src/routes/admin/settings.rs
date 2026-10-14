//! `GET/PUT /api/settings` — port of `hub/app/api/routes/settings.py`.
//!
//! The settings row is the single source of truth for fleet configuration.
//! Reads are visible to any authenticated principal, but non-admins only see
//! the fleet fields; SSO/LDAP/notification config (and every secret) is
//! admin-only. Writes are admin-only, audited (`settings_update`, secrets
//! masked as `"***"`) and validated exactly like the Python handler:
//!
//! * `allowed_release_domains` entries must pass [`validate_release_domain`]
//!   (SSRF guard — 400 on failure),
//! * `webauthn_rp_id` must be a registrable domain per
//!   [`is_registrable_domain`] (never a bare IP or `localhost`).

use axum::extract::{ConnectInfo, Extension, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::{
    audit_record, authenticate, enforce_body_size, json_body, peer_addr, py_repr, AdminState,
    RouteError,
};
use crate::models::setting::{Setting, SettingValues};

/// `SettingsOut` — the full fleet configuration. Mirrors the pydantic model
/// field for field: **no secret ever crosses this boundary** (`ldap_bind_password`
/// and `oidc_client_secret` are writable but not readable).
#[derive(Debug, Clone, Serialize)]
pub struct SettingsOut {
    pub target_worker_version: String,
    pub target_release_repo: String,
    pub allowed_release_domains: Vec<String>,
    pub auto_update_enabled: bool,
    pub updated_at: DateTime<Utc>,

    // MFA / WebAuthn
    pub require_admin_mfa: bool,
    pub allow_password_login: bool,
    pub webauthn_rp_id: String,
    pub webauthn_rp_name: String,
    pub webauthn_origin: String,

    // SSO / OIDC
    pub oidc_enabled: bool,
    pub oidc_provider_name: String,
    pub oidc_issuer: String,
    pub oidc_client_id: String,
    pub oidc_redirect_url: String,
    pub oidc_post_login_redirect: String,

    // LDAP
    pub ldap_enabled: bool,
    pub ldap_server_url: String,
    pub ldap_bind_dn: String,
    pub ldap_user_search_base: String,
    pub ldap_user_search_filter: String,
    pub ldap_start_tls: bool,
    pub ldap_use_ldaps: bool,

    // Notifications
    pub notifications_enabled: bool,
    pub discord_webhook_url: Option<String>,
    pub generic_webhook_url: Option<String>,
    pub notify_vm_offline: bool,
    pub notify_vm_recovered: bool,
    pub notify_task_failure: bool,
}

impl SettingsOut {
    pub fn from_row(row: &Setting) -> Self {
        Self {
            target_worker_version: row.target_worker_version.clone(),
            target_release_repo: row.target_release_repo.clone(),
            allowed_release_domains: row.allowed_release_domains_vec(),
            auto_update_enabled: row.auto_update_enabled,
            updated_at: row.updated_at,
            require_admin_mfa: row.require_admin_mfa,
            allow_password_login: row.allow_password_login,
            webauthn_rp_id: row.webauthn_rp_id.clone(),
            webauthn_rp_name: row.webauthn_rp_name.clone(),
            webauthn_origin: row.webauthn_origin.clone(),
            oidc_enabled: row.oidc_enabled,
            oidc_provider_name: row.oidc_provider_name.clone(),
            oidc_issuer: row.oidc_issuer.clone(),
            oidc_client_id: row.oidc_client_id.clone(),
            oidc_redirect_url: row.oidc_redirect_url.clone(),
            oidc_post_login_redirect: row.oidc_post_login_redirect.clone(),
            ldap_enabled: row.ldap_enabled,
            ldap_server_url: row.ldap_server_url.clone(),
            ldap_bind_dn: row.ldap_bind_dn.clone(),
            ldap_user_search_base: row.ldap_user_search_base.clone(),
            ldap_user_search_filter: row.ldap_user_search_filter.clone(),
            ldap_start_tls: row.ldap_start_tls,
            ldap_use_ldaps: row.ldap_use_ldaps,
            notifications_enabled: row.notifications_enabled,
            discord_webhook_url: row.discord_webhook_url.clone(),
            generic_webhook_url: row.generic_webhook_url.clone(),
            notify_vm_offline: row.notify_vm_offline,
            notify_vm_recovered: row.notify_vm_recovered,
            notify_task_failure: row.notify_task_failure,
        }
    }
}

/// The non-admin view of the settings row: only the fleet fields
/// (`settings.py:public_keys`).
#[derive(Debug, Clone, Serialize)]
pub struct SettingsPublicOut {
    pub target_worker_version: String,
    pub target_release_repo: String,
    pub allowed_release_domains: Vec<String>,
    pub auto_update_enabled: bool,
    pub updated_at: DateTime<Utc>,
}

impl From<&SettingsOut> for SettingsPublicOut {
    fn from(full: &SettingsOut) -> Self {
        Self {
            target_worker_version: full.target_worker_version.clone(),
            target_release_repo: full.target_release_repo.clone(),
            allowed_release_domains: full.allowed_release_domains.clone(),
            auto_update_enabled: full.auto_update_enabled,
            updated_at: full.updated_at,
        }
    }
}

/// `SettingsUpdate` — every field optional; `None` (absent *or* null) leaves
/// the column untouched (`model_dump(exclude_none=True)`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SettingsUpdate {
    pub target_worker_version: Option<String>,
    pub target_release_repo: Option<String>,
    pub allowed_release_domains: Option<Vec<String>>,
    pub auto_update_enabled: Option<bool>,

    // MFA / WebAuthn
    pub require_admin_mfa: Option<bool>,
    pub allow_password_login: Option<bool>,
    pub webauthn_rp_id: Option<String>,
    pub webauthn_rp_name: Option<String>,
    pub webauthn_origin: Option<String>,

    // SSO / OIDC
    pub oidc_enabled: Option<bool>,
    pub oidc_provider_name: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_url: Option<String>,
    pub oidc_post_login_redirect: Option<String>,

    // LDAP
    pub ldap_enabled: Option<bool>,
    pub ldap_server_url: Option<String>,
    pub ldap_bind_dn: Option<String>,
    pub ldap_bind_password: Option<String>,
    pub ldap_user_search_base: Option<String>,
    pub ldap_user_search_filter: Option<String>,
    pub ldap_start_tls: Option<bool>,
    pub ldap_use_ldaps: Option<bool>,

    // Notifications
    pub notifications_enabled: Option<bool>,
    pub discord_webhook_url: Option<String>,
    pub generic_webhook_url: Option<String>,
    pub notify_vm_offline: Option<bool>,
    pub notify_vm_recovered: Option<bool>,
    pub notify_task_failure: Option<bool>,
}

impl SettingsUpdate {
    /// The pydantic `Field(max_length=...)` bounds of `SettingsUpdate`.
    pub fn validate(&self) -> Result<(), RouteError> {
        for (field, value, max) in [
            (
                "target_worker_version",
                &self.target_worker_version,
                64usize,
            ),
            ("target_release_repo", &self.target_release_repo, 255),
            ("webauthn_rp_id", &self.webauthn_rp_id, 255),
            ("webauthn_rp_name", &self.webauthn_rp_name, 255),
            ("webauthn_origin", &self.webauthn_origin, 512),
            ("oidc_provider_name", &self.oidc_provider_name, 64),
            ("oidc_issuer", &self.oidc_issuer, 512),
            ("oidc_client_id", &self.oidc_client_id, 255),
            ("oidc_client_secret", &self.oidc_client_secret, 512),
            ("oidc_redirect_url", &self.oidc_redirect_url, 512),
            (
                "oidc_post_login_redirect",
                &self.oidc_post_login_redirect,
                512,
            ),
            ("ldap_server_url", &self.ldap_server_url, 512),
            ("ldap_bind_dn", &self.ldap_bind_dn, 512),
            ("ldap_bind_password", &self.ldap_bind_password, 512),
            ("ldap_user_search_base", &self.ldap_user_search_base, 512),
            (
                "ldap_user_search_filter",
                &self.ldap_user_search_filter,
                512,
            ),
            ("discord_webhook_url", &self.discord_webhook_url, 512),
            ("generic_webhook_url", &self.generic_webhook_url, 512),
        ] {
            if let Some(value) = value {
                if value.chars().count() > max {
                    return Err(RouteError::unprocessable_entity(format!(
                        "{field} must be at most {max} characters"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The audit `detail` dict: every non-null field of the request, with the
    /// secret values masked (`settings.py` never writes secrets to the log).
    pub fn audit_detail(&self) -> serde_json::Value {
        let secret_keys = ["ldap_bind_password", "oidc_client_secret"];
        let mut detail = serde_json::Map::new();
        let mut push = |key: &str, value: serde_json::Value| {
            let value = if secret_keys.contains(&key) {
                serde_json::json!("***")
            } else {
                value
            };
            detail.insert(key.to_owned(), value);
        };
        if let Some(v) = &self.target_worker_version {
            push("target_worker_version", v.clone().into());
        }
        if let Some(v) = &self.target_release_repo {
            push("target_release_repo", v.clone().into());
        }
        if let Some(v) = &self.allowed_release_domains {
            push("allowed_release_domains", v.clone().into());
        }
        if let Some(v) = self.auto_update_enabled {
            push("auto_update_enabled", v.into());
        }
        if let Some(v) = self.require_admin_mfa {
            push("require_admin_mfa", v.into());
        }
        if let Some(v) = self.allow_password_login {
            push("allow_password_login", v.into());
        }
        if let Some(v) = &self.webauthn_rp_id {
            push("webauthn_rp_id", v.clone().into());
        }
        if let Some(v) = &self.webauthn_rp_name {
            push("webauthn_rp_name", v.clone().into());
        }
        if let Some(v) = &self.webauthn_origin {
            push("webauthn_origin", v.clone().into());
        }
        if let Some(v) = self.oidc_enabled {
            push("oidc_enabled", v.into());
        }
        if let Some(v) = &self.oidc_provider_name {
            push("oidc_provider_name", v.clone().into());
        }
        if let Some(v) = &self.oidc_issuer {
            push("oidc_issuer", v.clone().into());
        }
        if let Some(v) = &self.oidc_client_id {
            push("oidc_client_id", v.clone().into());
        }
        if let Some(v) = &self.oidc_client_secret {
            push("oidc_client_secret", v.clone().into());
        }
        if let Some(v) = &self.oidc_redirect_url {
            push("oidc_redirect_url", v.clone().into());
        }
        if let Some(v) = &self.oidc_post_login_redirect {
            push("oidc_post_login_redirect", v.clone().into());
        }
        if let Some(v) = self.ldap_enabled {
            push("ldap_enabled", v.into());
        }
        if let Some(v) = &self.ldap_server_url {
            push("ldap_server_url", v.clone().into());
        }
        if let Some(v) = &self.ldap_bind_dn {
            push("ldap_bind_dn", v.clone().into());
        }
        if let Some(v) = &self.ldap_bind_password {
            push("ldap_bind_password", v.clone().into());
        }
        if let Some(v) = &self.ldap_user_search_base {
            push("ldap_user_search_base", v.clone().into());
        }
        if let Some(v) = &self.ldap_user_search_filter {
            push("ldap_user_search_filter", v.clone().into());
        }
        if let Some(v) = self.ldap_start_tls {
            push("ldap_start_tls", v.into());
        }
        if let Some(v) = self.ldap_use_ldaps {
            push("ldap_use_ldaps", v.into());
        }
        if let Some(v) = self.notifications_enabled {
            push("notifications_enabled", v.into());
        }
        if let Some(v) = &self.discord_webhook_url {
            push("discord_webhook_url", v.clone().into());
        }
        if let Some(v) = &self.generic_webhook_url {
            push("generic_webhook_url", v.clone().into());
        }
        if let Some(v) = self.notify_vm_offline {
            push("notify_vm_offline", v.into());
        }
        if let Some(v) = self.notify_vm_recovered {
            push("notify_vm_recovered", v.into());
        }
        if let Some(v) = self.notify_task_failure {
            push("notify_task_failure", v.into());
        }
        serde_json::Value::Object(detail)
    }
}

/// `SettingValues` view of a stored row (so a partial update round-trips every
/// untouched column).
pub fn values_from(row: &Setting) -> SettingValues {
    SettingValues {
        target_worker_version: row.target_worker_version.clone(),
        target_release_repo: row.target_release_repo.clone(),
        allowed_release_domains: row.allowed_release_domains.clone(),
        updated_by: row.updated_by,
        oidc_enabled: row.oidc_enabled,
        oidc_issuer: row.oidc_issuer.clone(),
        oidc_client_id: row.oidc_client_id.clone(),
        oidc_client_secret: row.oidc_client_secret.clone(),
        oidc_redirect_url: row.oidc_redirect_url.clone(),
        oidc_post_login_redirect: row.oidc_post_login_redirect.clone(),
        ldap_enabled: row.ldap_enabled,
        ldap_server_url: row.ldap_server_url.clone(),
        ldap_bind_dn: row.ldap_bind_dn.clone(),
        ldap_bind_password: row.ldap_bind_password.clone(),
        ldap_user_search_base: row.ldap_user_search_base.clone(),
        ldap_user_search_filter: row.ldap_user_search_filter.clone(),
        ldap_start_tls: row.ldap_start_tls,
        ldap_use_ldaps: row.ldap_use_ldaps,
        notifications_enabled: row.notifications_enabled,
        discord_webhook_url: row.discord_webhook_url.clone(),
        generic_webhook_url: row.generic_webhook_url.clone(),
        notify_vm_offline: row.notify_vm_offline,
        notify_vm_recovered: row.notify_vm_recovered,
        notify_task_failure: row.notify_task_failure,
        auto_update_enabled: row.auto_update_enabled,
        oidc_provider_name: row.oidc_provider_name.clone(),
        require_admin_mfa: row.require_admin_mfa,
        allow_password_login: row.allow_password_login,
        webauthn_rp_id: row.webauthn_rp_id.clone(),
        webauthn_rp_name: row.webauthn_rp_name.clone(),
        webauthn_origin: row.webauthn_origin.clone(),
    }
}

/// Row built from a full `SettingValues` payload (test store + semantics of
/// `settings_service.ensure_settings`).
pub fn setting_row(values: SettingValues, updated_at: DateTime<Utc>) -> Setting {
    Setting {
        id: crate::models::setting::SETTINGS_SINGLETON_ID,
        target_worker_version: values.target_worker_version,
        target_release_repo: values.target_release_repo,
        allowed_release_domains: values.allowed_release_domains,
        updated_by: values.updated_by,
        updated_at,
        oidc_enabled: values.oidc_enabled,
        oidc_issuer: values.oidc_issuer,
        oidc_client_id: values.oidc_client_id,
        oidc_client_secret: values.oidc_client_secret,
        oidc_redirect_url: values.oidc_redirect_url,
        oidc_post_login_redirect: values.oidc_post_login_redirect,
        ldap_enabled: values.ldap_enabled,
        ldap_server_url: values.ldap_server_url,
        ldap_bind_dn: values.ldap_bind_dn,
        ldap_bind_password: values.ldap_bind_password,
        ldap_user_search_base: values.ldap_user_search_base,
        ldap_user_search_filter: values.ldap_user_search_filter,
        ldap_start_tls: values.ldap_start_tls,
        ldap_use_ldaps: values.ldap_use_ldaps,
        notifications_enabled: values.notifications_enabled,
        discord_webhook_url: values.discord_webhook_url,
        generic_webhook_url: values.generic_webhook_url,
        notify_vm_offline: values.notify_vm_offline,
        notify_vm_recovered: values.notify_vm_recovered,
        notify_task_failure: values.notify_task_failure,
        auto_update_enabled: values.auto_update_enabled,
        oidc_provider_name: values.oidc_provider_name,
        require_admin_mfa: values.require_admin_mfa,
        allow_password_login: values.allow_password_login,
        webauthn_rp_id: values.webauthn_rp_id,
        webauthn_rp_name: values.webauthn_rp_name,
        webauthn_origin: values.webauthn_origin,
    }
}

// ---------------------------------------------------------------------------
// Validations ported from the Python hub
// ---------------------------------------------------------------------------

/// `services/webauthn.py:_is_registrable_domain` — `rp_id` must be a domain
/// (with a dot), never a bare IP or `localhost`. Binding passkeys to an IP
/// literal is invalid per spec and can't be relied on.
pub fn is_registrable_domain(rp_id: &str) -> bool {
    if rp_id.parse::<std::net::IpAddr>().is_ok() {
        return false; // bare IP
    }
    rp_id.contains('.') && rp_id != "localhost"
}

/// `services/versioning.py:validate_release_domain` — reject allow-list entries
/// that are unsafe. Private/LAN IPs are allowed for self-hosted deployments,
/// but loopback, link-local (cloud metadata) and the unspecified address are
/// always rejected, as are `localhost`/`.local`/`.internal` names.
pub fn validate_release_domain(domain: &str) -> Result<(), String> {
    let host = domain.trim().to_lowercase();
    if host.is_empty() || host.contains('/') || host.contains(':') {
        return Err(format!("invalid release domain: {}", py_repr(domain)));
    }
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return Err(format!("release domain not allowed: {}", py_repr(domain)));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let bad = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_multicast()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    // fe80::/10 (IpAddr::is_link_local is not stable yet)
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
        if bad {
            return Err(format!(
                "release domain not allowed (loopback/link-local): {}",
                py_repr(domain)
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// The `/api/settings` router (prefix included).
pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/settings", get(get_settings_endpoint))
        .route("/api/settings", put(update_settings_endpoint))
}

/// `GET /api/settings` — the fleet configuration; non-admins get only the
/// fleet fields.
async fn get_settings_endpoint(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Response, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    let row = state.store.get_settings().await?;
    let Some(row) = row else {
        return Err(RouteError::not_found("settings not initialized"));
    };
    let full = SettingsOut::from_row(&row);
    if caller.principal.is_admin() {
        Ok(Json(full).into_response())
    } else {
        Ok(Json(SettingsPublicOut::from(&full)).into_response())
    }
}

/// `PUT /api/settings` — apply the non-null fields (admin only, audited).
async fn update_settings_endpoint(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<SettingsUpdate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let body = json_body(body)?;
    body.validate()?;

    let row = state.store.get_settings().await?;
    let Some(row) = row else {
        return Err(RouteError::not_found("settings not initialized"));
    };
    let mut values = values_from(&row);

    // Guard the SSRF allowlist: no IP literals / internal hostnames.
    if let Some(domains) = &body.allowed_release_domains {
        for domain in domains {
            validate_release_domain(domain).map_err(RouteError::bad_request)?;
        }
        values.allowed_release_domains = serde_json::json!(domains);
    }
    // `webauthn_rp_id` must be a registrable domain, never an IP/localhost.
    // The Python hub raises this from `webauthn_service.rp_config` when the
    // WebAuthn flow is used (400, `str(exc)`); rejecting it at write time keeps
    // the failure identical but immediate.
    if let Some(rp_id) = &body.webauthn_rp_id {
        if !is_registrable_domain(rp_id) {
            return Err(RouteError::bad_request(
                "webauthn_rp_id must be a registrable domain, not an IP",
            ));
        }
        values.webauthn_rp_id = rp_id.clone();
    }

    if let Some(v) = &body.target_worker_version {
        values.target_worker_version = v.clone();
    }
    if let Some(v) = &body.target_release_repo {
        values.target_release_repo = v.clone();
    }
    if let Some(v) = body.auto_update_enabled {
        values.auto_update_enabled = v;
    }
    if let Some(v) = body.require_admin_mfa {
        values.require_admin_mfa = v;
    }
    if let Some(v) = body.allow_password_login {
        values.allow_password_login = v;
    }
    if let Some(v) = &body.webauthn_rp_name {
        values.webauthn_rp_name = v.clone();
    }
    if let Some(v) = &body.webauthn_origin {
        values.webauthn_origin = v.clone();
    }
    if let Some(v) = body.oidc_enabled {
        values.oidc_enabled = v;
    }
    if let Some(v) = &body.oidc_provider_name {
        values.oidc_provider_name = v.clone();
    }
    if let Some(v) = &body.oidc_issuer {
        values.oidc_issuer = v.clone();
    }
    if let Some(v) = &body.oidc_client_id {
        values.oidc_client_id = v.clone();
    }
    if let Some(v) = &body.oidc_client_secret {
        values.oidc_client_secret = Some(v.clone());
    }
    if let Some(v) = &body.oidc_redirect_url {
        values.oidc_redirect_url = v.clone();
    }
    if let Some(v) = &body.oidc_post_login_redirect {
        values.oidc_post_login_redirect = v.clone();
    }
    if let Some(v) = body.ldap_enabled {
        values.ldap_enabled = v;
    }
    if let Some(v) = &body.ldap_server_url {
        values.ldap_server_url = v.clone();
    }
    if let Some(v) = &body.ldap_bind_dn {
        values.ldap_bind_dn = v.clone();
    }
    if let Some(v) = &body.ldap_bind_password {
        values.ldap_bind_password = Some(v.clone());
    }
    if let Some(v) = &body.ldap_user_search_base {
        values.ldap_user_search_base = v.clone();
    }
    if let Some(v) = &body.ldap_user_search_filter {
        values.ldap_user_search_filter = v.clone();
    }
    if let Some(v) = body.ldap_start_tls {
        values.ldap_start_tls = v;
    }
    if let Some(v) = body.ldap_use_ldaps {
        values.ldap_use_ldaps = v;
    }
    if let Some(v) = body.notifications_enabled {
        values.notifications_enabled = v;
    }
    if let Some(v) = &body.discord_webhook_url {
        values.discord_webhook_url = Some(v.clone());
    }
    if let Some(v) = &body.generic_webhook_url {
        values.generic_webhook_url = Some(v.clone());
    }
    if let Some(v) = body.notify_vm_offline {
        values.notify_vm_offline = v;
    }
    if let Some(v) = body.notify_vm_recovered {
        values.notify_vm_recovered = v;
    }
    if let Some(v) = body.notify_task_failure {
        values.notify_task_failure = v;
    }
    // `row.updated_by = principal.user.id` when a real user is behind it.
    values.updated_by = caller.principal.user.as_ref().map(|u| u.id);
    // Never write secrets into the audit log.
    let detail = body.audit_detail();

    let updated = state.store.save_settings(values).await?;
    audit_record(&state, &caller, "settings_update", detail).await?;
    Ok(Json(SettingsOut::from_row(&updated)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use serde_json::json;

    use super::super::router;
    use super::super::testing::*;
    use super::*;
    use crate::models::user::User;
    use crate::models::{ActorType, UserRole};

    fn setup() -> (Arc<MockStore>, AdminState, User) {
        let store = Arc::new(MockStore::default());
        seed_settings(&store);
        let state = test_state(store.clone());
        let admin = seed_user(&store, make_user("admin", UserRole::Admin));
        (store, state, admin)
    }

    #[test]
    fn registrable_domain_matches_python() {
        // Bare IPs are never registrable domains.
        assert!(!is_registrable_domain("127.0.0.1"));
        assert!(!is_registrable_domain("10.0.0.1"));
        assert!(!is_registrable_domain("::1"));
        assert!(!is_registrable_domain("203.0.113.7"));
        // "localhost" without a dot is rejected too.
        assert!(!is_registrable_domain("localhost"));
        assert!(!is_registrable_domain("myhost"));
        assert!(!is_registrable_domain(""));
        // A real domain passes.
        assert!(is_registrable_domain("huginn.example.com"));
        assert!(is_registrable_domain("example.com"));
    }

    #[test]
    fn release_domain_guard_matches_python() {
        assert!(validate_release_domain("github.com").is_ok());
        assert!(validate_release_domain("objects.githubusercontent.com").is_ok());
        // Private/LAN IPs stay allowed for self-hosted deployments.
        assert!(validate_release_domain("172.16.0.2").is_ok());
        assert!(validate_release_domain("10.1.2.3").is_ok());
        // Loopback / link-local / unspecified / multicast are always rejected.
        assert_eq!(
            validate_release_domain("127.0.0.1").unwrap_err(),
            "release domain not allowed (loopback/link-local): '127.0.0.1'"
        );
        assert_eq!(
            validate_release_domain("169.254.169.254").unwrap_err(),
            "release domain not allowed (loopback/link-local): '169.254.169.254'"
        );
        assert_eq!(
            validate_release_domain("0.0.0.0").unwrap_err(),
            "release domain not allowed (loopback/link-local): '0.0.0.0'"
        );
        // Internal names and malformed entries.
        assert_eq!(
            validate_release_domain("localhost").unwrap_err(),
            "release domain not allowed: 'localhost'"
        );
        assert_eq!(
            validate_release_domain("hub.local").unwrap_err(),
            "release domain not allowed: 'hub.local'"
        );
        assert_eq!(
            validate_release_domain("hub.internal").unwrap_err(),
            "release domain not allowed: 'hub.internal'"
        );
        assert_eq!(
            validate_release_domain("evil.com/repo").unwrap_err(),
            "invalid release domain: 'evil.com/repo'"
        );
        assert_eq!(
            validate_release_domain("").unwrap_err(),
            "invalid release domain: ''"
        );
        assert_eq!(
            validate_release_domain("https://evil.com").unwrap_err(),
            "invalid release domain: 'https://evil.com'"
        );
    }

    #[tokio::test]
    async fn get_settings_hides_secrets_and_fleet_fields_only_for_non_admins() {
        let (store, state, admin) = setup();
        let app = router(state.clone());

        // Admin: the full shape…
        let request = json_request_with(
            "GET",
            "/api/settings",
            serde_json::Value::Null,
            &[(
                "authorization",
                format!("Bearer {}", bearer(&state, &admin)),
            )],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["target_worker_version"], json!(""));
        assert_eq!(body["oidc_provider_name"], json!("SSO"));
        assert_eq!(body["webauthn_rp_name"], json!("Huginn"));
        assert_eq!(body["notify_vm_offline"], json!(true));
        // …and never the secrets, even for admins.
        assert!(body.get("ldap_bind_password").is_none());
        assert!(body.get("oidc_client_secret").is_none());

        // Non-admin: only the fleet fields.
        let ro = seed_user(&store, make_user("ro", UserRole::Readonly));
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/settings",
            serde_json::Value::Null,
            &[("authorization", format!("Bearer {}", bearer(&state, &ro)))],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        // Exactly the five `public_keys` of the Python handler (key order is
        // not semantically meaningful — the parity harness sorts keys).
        let mut keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "allowed_release_domains",
                "auto_update_enabled",
                "target_release_repo",
                "target_worker_version",
                "updated_at",
            ]
        );
    }

    #[tokio::test]
    async fn put_settings_validates_webauthn_rp_id() {
        let (_store, state, admin) = setup();
        for rp_id in ["127.0.0.1", "192.168.1.10", "::1", "localhost", "myhost"] {
            let app = router(state.clone());
            let request = json_request_with(
                "PUT",
                "/api/settings",
                json!({"webauthn_rp_id": rp_id}),
                &[(
                    "authorization",
                    format!("Bearer {}", bearer(&state, &admin)),
                )],
            );
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "rp_id={rp_id}");
            assert_eq!(
                body_json(response).await,
                json!({"detail": "webauthn_rp_id must be a registrable domain, not an IP"})
            );
        }

        // A registrable domain is accepted and persisted.
        let app = router(state.clone());
        let request = json_request_with(
            "PUT",
            "/api/settings",
            json!({"webauthn_rp_id": "huginn.example.com", "webauthn_rp_name": "Fleet"}),
            &[(
                "authorization",
                format!("Bearer {}", bearer(&state, &admin)),
            )],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["webauthn_rp_id"], json!("huginn.example.com"));
        assert_eq!(body["webauthn_rp_name"], json!("Fleet"));
    }

    #[tokio::test]
    async fn put_settings_rejects_unsafe_release_domains() {
        let (_store, state, admin) = setup();
        let app = router(state.clone());
        let request = json_request_with(
            "PUT",
            "/api/settings",
            json!({"allowed_release_domains": ["github.com", "localhost"]}),
            &[(
                "authorization",
                format!("Bearer {}", bearer(&state, &admin)),
            )],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "release domain not allowed: 'localhost'"})
        );
    }

    #[tokio::test]
    async fn put_settings_masks_secrets_in_the_audit_log() {
        let (store, state, admin) = setup();
        let app = router(state.clone());
        let request = json_request_with(
            "PUT",
            "/api/settings",
            json!({"ldap_bind_password": "s3cret", "oidc_client_secret": "s3cret", "ldap_enabled": true}),
            &[(
                "authorization",
                format!("Bearer {}", bearer(&state, &admin)),
            )],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let db = store.db.lock().unwrap();
        let entry = db.audit.last().unwrap();
        assert_eq!(entry.event_type, "settings_update");
        assert_eq!(entry.actor_type, ActorType::User);
        assert_eq!(entry.actor_id, admin.id.to_string());
        assert_eq!(entry.detail["ldap_bind_password"], json!("***"));
        assert_eq!(entry.detail["oidc_client_secret"], json!("***"));
        assert_eq!(entry.detail["ldap_enabled"], json!(true));
    }

    #[tokio::test]
    async fn put_settings_is_admin_only() {
        let (store, state, admin) = setup();
        let ro = seed_user(&store, make_user("ro", UserRole::Readonly));
        let app = router(state.clone());
        let request = json_request_with(
            "PUT",
            "/api/settings",
            json!({"target_worker_version": "v9"}),
            &[("authorization", format!("Bearer {}", bearer(&state, &ro)))],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "admin role required"})
        );

        // Nothing was written.
        assert_eq!(store.db.lock().unwrap().audit.len(), 0);
        let _ = admin;
    }
}

//! Settings wire shapes (`app/schemas/setting.py`) and the row <-> schema
//! mapping, including the update validation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::RouteError;
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

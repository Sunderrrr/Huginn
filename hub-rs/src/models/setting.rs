//! `settings` — the single-row fleet configuration table
//! (`app/models/setting.py`, `app/services/settings_service.py`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

/// Column default of `backup_s3_retention_days` (`migrations/0002`).
fn default_backup_retention_days() -> i32 {
    30
}

/// The settings row is a singleton (parity with `SETTINGS_SINGLETON_ID`).
pub const SETTINGS_SINGLETON_ID: i32 = 1;

const COLUMNS: &str = "id, target_worker_version, target_release_repo, allowed_release_domains, \
                      updated_by, updated_at, oidc_enabled, oidc_issuer, oidc_client_id, \
                      oidc_client_secret, oidc_redirect_url, oidc_post_login_redirect, \
                      ldap_enabled, ldap_server_url, ldap_bind_dn, ldap_bind_password, \
                      ldap_user_search_base, ldap_user_search_filter, ldap_start_tls, \
                      ldap_use_ldaps, notifications_enabled, discord_webhook_url, \
                      generic_webhook_url, notify_vm_offline, notify_vm_recovered, \
                      notify_task_failure, auto_update_enabled, oidc_provider_name, \
                      require_admin_mfa, allow_password_login, webauthn_rp_id, \
                      webauthn_rp_name, webauthn_origin, backup_s3_enabled, \
                      backup_s3_endpoint, backup_s3_region, backup_s3_bucket, \
                      backup_s3_prefix, backup_s3_access_key, backup_s3_secret_key, \
                      backup_s3_retention_days";

/// Fleet-wide configuration (one row).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Setting {
    pub id: i32,
    pub target_worker_version: String,
    pub target_release_repo: String,
    /// JSON list of allowed release download domains (SSRF allow-list).
    pub allowed_release_domains: serde_json::Value,
    pub updated_by: Option<Uuid>,
    pub updated_at: DateTime<Utc>,
    pub oidc_enabled: bool,
    pub oidc_issuer: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_url: String,
    pub oidc_post_login_redirect: String,
    pub ldap_enabled: bool,
    pub ldap_server_url: String,
    pub ldap_bind_dn: String,
    pub ldap_bind_password: Option<String>,
    pub ldap_user_search_base: String,
    pub ldap_user_search_filter: String,
    pub ldap_start_tls: bool,
    pub ldap_use_ldaps: bool,
    pub notifications_enabled: bool,
    pub discord_webhook_url: Option<String>,
    pub generic_webhook_url: Option<String>,
    pub notify_vm_offline: bool,
    pub notify_vm_recovered: bool,
    pub notify_task_failure: bool,
    pub auto_update_enabled: bool,
    pub oidc_provider_name: String,
    pub require_admin_mfa: bool,
    pub allow_password_login: bool,
    pub webauthn_rp_id: String,
    pub webauthn_rp_name: String,
    pub webauthn_origin: String,
    /// Automatic database backups to S3-compatible storage (`migrations/0002`).
    /// `serde(default)`: fixtures/rows captured before 0002 keep decoding.
    #[serde(default)]
    pub backup_s3_enabled: bool,
    /// S3-compatible endpoint URL (`https://…`); empty = AWS S3.
    #[serde(default)]
    pub backup_s3_endpoint: String,
    #[serde(default)]
    pub backup_s3_region: String,
    #[serde(default)]
    pub backup_s3_bucket: String,
    /// Object-key prefix the backups live under.
    #[serde(default)]
    pub backup_s3_prefix: String,
    #[serde(default)]
    pub backup_s3_access_key: String,
    /// **Write-only** — never serialized back by any API (like
    /// `ldap_bind_password`).
    #[serde(default)]
    pub backup_s3_secret_key: Option<String>,
    /// Delete backup objects older than this many days (0 = keep forever).
    #[serde(default = "default_backup_retention_days")]
    pub backup_s3_retention_days: i32,
}

impl Setting {
    pub fn allowed_release_domains_vec(&self) -> Vec<String> {
        self.allowed_release_domains
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// True when a secret key is stored (the value itself is never returned).
    pub fn backup_s3_secret_configured(&self) -> bool {
        self.backup_s3_secret_key.is_some()
    }
}

/// Full upsert payload (everything except `id`/`updated_at`).
#[derive(Debug, Clone)]
pub struct SettingValues {
    pub target_worker_version: String,
    pub target_release_repo: String,
    pub allowed_release_domains: serde_json::Value,
    pub updated_by: Option<Uuid>,
    pub oidc_enabled: bool,
    pub oidc_issuer: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_url: String,
    pub oidc_post_login_redirect: String,
    pub ldap_enabled: bool,
    pub ldap_server_url: String,
    pub ldap_bind_dn: String,
    pub ldap_bind_password: Option<String>,
    pub ldap_user_search_base: String,
    pub ldap_user_search_filter: String,
    pub ldap_start_tls: bool,
    pub ldap_use_ldaps: bool,
    pub notifications_enabled: bool,
    pub discord_webhook_url: Option<String>,
    pub generic_webhook_url: Option<String>,
    pub notify_vm_offline: bool,
    pub notify_vm_recovered: bool,
    pub notify_task_failure: bool,
    pub auto_update_enabled: bool,
    pub oidc_provider_name: String,
    pub require_admin_mfa: bool,
    pub allow_password_login: bool,
    pub webauthn_rp_id: String,
    pub webauthn_rp_name: String,
    pub webauthn_origin: String,
    pub backup_s3_enabled: bool,
    pub backup_s3_endpoint: String,
    pub backup_s3_region: String,
    pub backup_s3_bucket: String,
    pub backup_s3_prefix: String,
    pub backup_s3_access_key: String,
    pub backup_s3_secret_key: Option<String>,
    pub backup_s3_retention_days: i32,
}

/// Defaults mirror the SQLAlchemy column defaults.
impl Default for SettingValues {
    fn default() -> Self {
        Self {
            target_worker_version: String::new(),
            target_release_repo: String::new(),
            allowed_release_domains: serde_json::Value::Array(Vec::new()),
            updated_by: None,
            oidc_enabled: false,
            oidc_issuer: String::new(),
            oidc_client_id: String::new(),
            oidc_client_secret: None,
            oidc_redirect_url: String::new(),
            oidc_post_login_redirect: String::new(),
            ldap_enabled: false,
            ldap_server_url: String::new(),
            ldap_bind_dn: String::new(),
            ldap_bind_password: None,
            ldap_user_search_base: String::new(),
            ldap_user_search_filter: String::new(),
            ldap_start_tls: false,
            ldap_use_ldaps: false,
            notifications_enabled: false,
            discord_webhook_url: None,
            generic_webhook_url: None,
            notify_vm_offline: true,
            notify_vm_recovered: false,
            notify_task_failure: false,
            auto_update_enabled: false,
            oidc_provider_name: "SSO".into(),
            require_admin_mfa: true,
            allow_password_login: false,
            webauthn_rp_id: String::new(),
            webauthn_rp_name: "Huginn".into(),
            webauthn_origin: String::new(),
            backup_s3_enabled: false,
            backup_s3_endpoint: String::new(),
            backup_s3_region: String::new(),
            backup_s3_bucket: String::new(),
            backup_s3_prefix: String::new(),
            backup_s3_access_key: String::new(),
            backup_s3_secret_key: None,
            backup_s3_retention_days: 30,
        }
    }
}

pub async fn get_settings_row(pool: &PgPool) -> Result<Option<Setting>, DbError> {
    let row =
        sqlx::query_as::<_, Setting>(&format!("SELECT {COLUMNS} FROM settings WHERE id = $1"))
            .bind(SETTINGS_SINGLETON_ID)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Insert or replace the singleton settings row.
pub async fn upsert(pool: &PgPool, values: SettingValues) -> Result<Setting, DbError> {
    let now = Utc::now();
    let row = sqlx::query_as::<_, Setting>(&format!(
        "INSERT INTO settings (id, target_worker_version, target_release_repo, \
         allowed_release_domains, updated_by, updated_at, oidc_enabled, oidc_issuer, \
         oidc_client_id, oidc_client_secret, oidc_redirect_url, oidc_post_login_redirect, \
         ldap_enabled, ldap_server_url, ldap_bind_dn, ldap_bind_password, ldap_user_search_base, \
         ldap_user_search_filter, ldap_start_tls, ldap_use_ldaps, notifications_enabled, \
         discord_webhook_url, generic_webhook_url, notify_vm_offline, notify_vm_recovered, \
         notify_task_failure, auto_update_enabled, oidc_provider_name, require_admin_mfa, \
         allow_password_login, webauthn_rp_id, webauthn_rp_name, webauthn_origin, \
         backup_s3_enabled, backup_s3_endpoint, backup_s3_region, backup_s3_bucket, \
         backup_s3_prefix, backup_s3_access_key, backup_s3_secret_key, backup_s3_retention_days) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
         $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, \
         $35, $36, $37, $38, $39, $40, $41) \
         ON CONFLICT (id) DO UPDATE SET \
         target_worker_version = EXCLUDED.target_worker_version, \
         target_release_repo = EXCLUDED.target_release_repo, \
         allowed_release_domains = EXCLUDED.allowed_release_domains, \
         updated_by = EXCLUDED.updated_by, \
         updated_at = EXCLUDED.updated_at, \
         oidc_enabled = EXCLUDED.oidc_enabled, \
         oidc_issuer = EXCLUDED.oidc_issuer, \
         oidc_client_id = EXCLUDED.oidc_client_id, \
         oidc_client_secret = EXCLUDED.oidc_client_secret, \
         oidc_redirect_url = EXCLUDED.oidc_redirect_url, \
         oidc_post_login_redirect = EXCLUDED.oidc_post_login_redirect, \
         ldap_enabled = EXCLUDED.ldap_enabled, \
         ldap_server_url = EXCLUDED.ldap_server_url, \
         ldap_bind_dn = EXCLUDED.ldap_bind_dn, \
         ldap_bind_password = EXCLUDED.ldap_bind_password, \
         ldap_user_search_base = EXCLUDED.ldap_user_search_base, \
         ldap_user_search_filter = EXCLUDED.ldap_user_search_filter, \
         ldap_start_tls = EXCLUDED.ldap_start_tls, \
         ldap_use_ldaps = EXCLUDED.ldap_use_ldaps, \
         notifications_enabled = EXCLUDED.notifications_enabled, \
         discord_webhook_url = EXCLUDED.discord_webhook_url, \
         generic_webhook_url = EXCLUDED.generic_webhook_url, \
         notify_vm_offline = EXCLUDED.notify_vm_offline, \
         notify_vm_recovered = EXCLUDED.notify_vm_recovered, \
         notify_task_failure = EXCLUDED.notify_task_failure, \
         auto_update_enabled = EXCLUDED.auto_update_enabled, \
         oidc_provider_name = EXCLUDED.oidc_provider_name, \
         require_admin_mfa = EXCLUDED.require_admin_mfa, \
         allow_password_login = EXCLUDED.allow_password_login, \
         webauthn_rp_id = EXCLUDED.webauthn_rp_id, \
         webauthn_rp_name = EXCLUDED.webauthn_rp_name, \
         webauthn_origin = EXCLUDED.webauthn_origin, \
         backup_s3_enabled = EXCLUDED.backup_s3_enabled, \
         backup_s3_endpoint = EXCLUDED.backup_s3_endpoint, \
         backup_s3_region = EXCLUDED.backup_s3_region, \
         backup_s3_bucket = EXCLUDED.backup_s3_bucket, \
         backup_s3_prefix = EXCLUDED.backup_s3_prefix, \
         backup_s3_access_key = EXCLUDED.backup_s3_access_key, \
         backup_s3_secret_key = EXCLUDED.backup_s3_secret_key, \
         backup_s3_retention_days = EXCLUDED.backup_s3_retention_days \
         RETURNING {COLUMNS}"
    ))
    .bind(SETTINGS_SINGLETON_ID)
    .bind(&values.target_worker_version)
    .bind(&values.target_release_repo)
    .bind(&values.allowed_release_domains)
    .bind(values.updated_by)
    .bind(now)
    .bind(values.oidc_enabled)
    .bind(&values.oidc_issuer)
    .bind(&values.oidc_client_id)
    .bind(&values.oidc_client_secret)
    .bind(&values.oidc_redirect_url)
    .bind(&values.oidc_post_login_redirect)
    .bind(values.ldap_enabled)
    .bind(&values.ldap_server_url)
    .bind(&values.ldap_bind_dn)
    .bind(&values.ldap_bind_password)
    .bind(&values.ldap_user_search_base)
    .bind(&values.ldap_user_search_filter)
    .bind(values.ldap_start_tls)
    .bind(values.ldap_use_ldaps)
    .bind(values.notifications_enabled)
    .bind(&values.discord_webhook_url)
    .bind(&values.generic_webhook_url)
    .bind(values.notify_vm_offline)
    .bind(values.notify_vm_recovered)
    .bind(values.notify_task_failure)
    .bind(values.auto_update_enabled)
    .bind(&values.oidc_provider_name)
    .bind(values.require_admin_mfa)
    .bind(values.allow_password_login)
    .bind(&values.webauthn_rp_id)
    .bind(&values.webauthn_rp_name)
    .bind(&values.webauthn_origin)
    .bind(values.backup_s3_enabled)
    .bind(&values.backup_s3_endpoint)
    .bind(&values.backup_s3_region)
    .bind(&values.backup_s3_bucket)
    .bind(&values.backup_s3_prefix)
    .bind(&values.backup_s3_access_key)
    .bind(&values.backup_s3_secret_key)
    .bind(values.backup_s3_retention_days)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_sqlalchemy_column_defaults() {
        let d = SettingValues::default();
        assert_eq!(d.oidc_provider_name, "SSO");
        assert_eq!(d.webauthn_rp_name, "Huginn");
        assert!(d.require_admin_mfa);
        assert!(d.notify_vm_offline);
        assert!(!d.notify_vm_recovered);
        assert!(!d.allow_password_login);
        assert!(!d.auto_update_enabled);
        // Backup columns (migrations/0002): disabled by default, 30-day
        // retention, no secret.
        assert!(!d.backup_s3_enabled);
        assert_eq!(d.backup_s3_retention_days, 30);
        assert!(d.backup_s3_secret_key.is_none());
    }

    #[test]
    fn allowed_release_domains_reads_json_list() {
        let s = Setting {
            id: 1,
            target_worker_version: "v1.0.0".into(),
            target_release_repo: "example/huginn".into(),
            allowed_release_domains: serde_json::json!([
                "github.com",
                "objects.githubusercontent.com"
            ]),
            updated_by: None,
            updated_at: Utc::now(),
            oidc_enabled: false,
            oidc_issuer: String::new(),
            oidc_client_id: String::new(),
            oidc_client_secret: None,
            oidc_redirect_url: String::new(),
            oidc_post_login_redirect: String::new(),
            ldap_enabled: false,
            ldap_server_url: String::new(),
            ldap_bind_dn: String::new(),
            ldap_bind_password: None,
            ldap_user_search_base: String::new(),
            ldap_user_search_filter: String::new(),
            ldap_start_tls: false,
            ldap_use_ldaps: false,
            notifications_enabled: false,
            discord_webhook_url: None,
            generic_webhook_url: None,
            notify_vm_offline: true,
            notify_vm_recovered: false,
            notify_task_failure: false,
            auto_update_enabled: false,
            oidc_provider_name: "SSO".into(),
            require_admin_mfa: true,
            allow_password_login: false,
            webauthn_rp_id: String::new(),
            webauthn_rp_name: "Huginn".into(),
            webauthn_origin: String::new(),
            backup_s3_enabled: false,
            backup_s3_endpoint: String::new(),
            backup_s3_region: String::new(),
            backup_s3_bucket: String::new(),
            backup_s3_prefix: String::new(),
            backup_s3_access_key: String::new(),
            backup_s3_secret_key: None,
            backup_s3_retention_days: 30,
        };
        assert_eq!(
            s.allowed_release_domains_vec(),
            vec![
                "github.com".to_string(),
                "objects.githubusercontent.com".to_string()
            ]
        );
    }
}

//! Hub configuration, loaded from environment (prefix `HUGINN_`).
//! Mirrors hub/app/config.py, including `validate_for_prod` fail-closed rules.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    // Core
    pub env: String, // "dev" | "prod"
    pub log_level: String,

    // Database
    pub database_url: String,
    pub db_pool_size: u32,
    pub db_max_overflow: u32,

    // Security
    pub jwt_secret: String,
    pub jwt_algorithm: String,
    pub access_token_ttl_minutes: i64,
    pub secret_hash_key: String,
    pub mcp_service_token: String,
    /// Dedicated key for reversible encryption of TOTP secrets at rest. MUST
    /// be distinct from jwt_secret/secret_hash_key (a Fernet key is derived).
    pub mfa_encryption_key: String,
    pub mfa_challenge_ttl_minutes: i64,
    pub require_admin_mfa: bool,
    /// When OIDC is enabled, password login is disabled unless true (unsafe
    /// opt-in). With OIDC off, password login is always available.
    pub allow_password_login: bool,

    // WebAuthn / passkeys (empty rp_id => passkeys off)
    pub webauthn_rp_id: String,
    pub webauthn_rp_name: String,
    pub webauthn_origin: String,
    pub webauthn_user_verification: String,

    // TLS policy for hub<->worker
    pub require_tls: bool,
    pub trust_forwarded_for: bool,

    // CORS: comma-separated origins. Empty disables CORS.
    pub cors_origins_csv: String,

    // Bootstrap admin
    pub bootstrap_admin_username: String,
    pub bootstrap_admin_password: Option<String>,

    // OIDC / Authentik
    pub oidc_enabled: bool,
    pub oidc_provider_name: String,
    pub oidc_issuer: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_redirect_url: String,
    pub oidc_post_login_redirect: String,

    // Execution limits
    pub max_body_bytes: usize,
    pub max_output_bytes: usize,
    pub default_task_timeout_seconds: u64,
    pub task_dead_letter_retries: i32,
    pub rate_limit_exec_per_minute: u32,
    pub heartbeat_offline_seconds: u64,

    // Worker update / release source
    pub target_worker_version: String,
    pub target_release_repo: String,
    pub allowed_release_domains_csv: String,
}

impl Default for Config {
    fn default() -> Self {
        // Defaults mirror app/config.py exactly.
        Self {
            env: "dev".into(),
            log_level: "INFO".into(),
            database_url: "postgresql+asyncpg://huginn:huginn@localhost:5432/huginn".into(),
            db_pool_size: 20,
            db_max_overflow: 30,
            jwt_secret: "change-me-please-generate-a-real-secret".into(),
            jwt_algorithm: "HS256".into(),
            access_token_ttl_minutes: 60,
            secret_hash_key: "change-me-another-32-byte-secret".into(),
            mcp_service_token: "change-me-mcp-service-token".into(),
            mfa_encryption_key: "change-me-mfa-encryption-key-32b".into(),
            mfa_challenge_ttl_minutes: 5,
            require_admin_mfa: true,
            allow_password_login: false,
            webauthn_rp_id: String::new(),
            webauthn_rp_name: "Huginn".into(),
            webauthn_origin: String::new(),
            webauthn_user_verification: "preferred".into(),
            require_tls: true,
            trust_forwarded_for: true,
            cors_origins_csv: String::new(),
            bootstrap_admin_username: "admin".into(),
            bootstrap_admin_password: None,
            oidc_enabled: false,
            oidc_provider_name: "SSO".into(),
            oidc_issuer: String::new(),
            oidc_client_id: String::new(),
            oidc_client_secret: String::new(),
            oidc_redirect_url: "http://localhost:8000/api/auth/oidc/callback".into(),
            oidc_post_login_redirect: String::new(),
            max_body_bytes: 65_536,
            max_output_bytes: 1_048_576,
            default_task_timeout_seconds: 60,
            task_dead_letter_retries: 3,
            rate_limit_exec_per_minute: 30,
            heartbeat_offline_seconds: 120,
            target_worker_version: "v1.0.0".into(),
            target_release_repo: "Sunderrrr/Huginn".into(),
            allowed_release_domains_csv: "github.com,objects.githubusercontent.com".into(),
        }
    }
}

impl Config {
    /// Load from the process environment (`HUGINN_*`), starting from defaults.
    /// Boolean and numeric parsing mirrors pydantic's coercion loosely but
    /// strictly enough for deployment env files.
    pub fn from_env() -> Self {
        let mut c = Config::default();
        let envs: HashMap<String, String> = std::env::vars()
            .filter(|(k, _)| k.starts_with("HUGINN_"))
            .collect();
        let get = |name: &str| envs.get(name).cloned();

        if let Some(v) = get("HUGINN_ENV") {
            c.env = v;
        }
        if let Some(v) = get("HUGINN_LOG_LEVEL") {
            c.log_level = v;
        }
        if let Some(v) = get("HUGINN_DATABASE_URL") {
            c.database_url = v;
        }
        if let Some(v) = get("HUGINN_DB_POOL_SIZE") {
            c.db_pool_size = v.parse().unwrap_or(c.db_pool_size);
        }
        if let Some(v) = get("HUGINN_DB_MAX_OVERFLOW") {
            c.db_max_overflow = v.parse().unwrap_or(c.db_max_overflow);
        }
        if let Some(v) = get("HUGINN_JWT_SECRET") {
            c.jwt_secret = v;
        }
        if let Some(v) = get("HUGINN_JWT_ALGORITHM") {
            c.jwt_algorithm = v;
        }
        if let Some(v) = get("HUGINN_ACCESS_TOKEN_TTL_MINUTES") {
            c.access_token_ttl_minutes = v.parse().unwrap_or(c.access_token_ttl_minutes);
        }
        if let Some(v) = get("HUGINN_SECRET_HASH_KEY") {
            c.secret_hash_key = v;
        }
        if let Some(v) = get("HUGINN_MCP_SERVICE_TOKEN") {
            c.mcp_service_token = v;
        }
        if let Some(v) = get("HUGINN_MFA_ENCRYPTION_KEY") {
            c.mfa_encryption_key = v;
        }
        if let Some(v) = get("HUGINN_MFA_CHALLENGE_TTL_MINUTES") {
            c.mfa_challenge_ttl_minutes = v.parse().unwrap_or(c.mfa_challenge_ttl_minutes);
        }
        if let Some(v) = get("HUGINN_REQUIRE_ADMIN_MFA") {
            c.require_admin_mfa = parse_bool(&v, c.require_admin_mfa);
        }
        if let Some(v) = get("HUGINN_ALLOW_PASSWORD_LOGIN") {
            c.allow_password_login = parse_bool(&v, c.allow_password_login);
        }
        if let Some(v) = get("HUGINN_WEBAUTHN_RP_ID") {
            c.webauthn_rp_id = v;
        }
        if let Some(v) = get("HUGINN_WEBAUTHN_RP_NAME") {
            c.webauthn_rp_name = v;
        }
        if let Some(v) = get("HUGINN_WEBAUTHN_ORIGIN") {
            c.webauthn_origin = v;
        }
        if let Some(v) = get("HUGINN_WEBAUTHN_USER_VERIFICATION") {
            c.webauthn_user_verification = v;
        }
        if let Some(v) = get("HUGINN_REQUIRE_TLS") {
            c.require_tls = parse_bool(&v, c.require_tls);
        }
        if let Some(v) = get("HUGINN_TRUST_FORWARDED_FOR") {
            c.trust_forwarded_for = parse_bool(&v, c.trust_forwarded_for);
        }
        if let Some(v) = get("HUGINN_CORS_ORIGINS") {
            c.cors_origins_csv = v;
        }
        if let Some(v) = get("HUGINN_BOOTSTRAP_ADMIN_USERNAME") {
            c.bootstrap_admin_username = v;
        }
        if let Some(v) = get("HUGINN_BOOTSTRAP_ADMIN_PASSWORD") {
            c.bootstrap_admin_password = Some(v);
        }
        if let Some(v) = get("HUGINN_OIDC_ENABLED") {
            c.oidc_enabled = parse_bool(&v, c.oidc_enabled);
        }
        if let Some(v) = get("HUGINN_OIDC_PROVIDER_NAME") {
            c.oidc_provider_name = v;
        }
        if let Some(v) = get("HUGINN_OIDC_ISSUER") {
            c.oidc_issuer = v;
        }
        if let Some(v) = get("HUGINN_OIDC_CLIENT_ID") {
            c.oidc_client_id = v;
        }
        if let Some(v) = get("HUGINN_OIDC_CLIENT_SECRET") {
            c.oidc_client_secret = v;
        }
        if let Some(v) = get("HUGINN_OIDC_REDIRECT_URL") {
            c.oidc_redirect_url = v;
        }
        if let Some(v) = get("HUGINN_OIDC_POST_LOGIN_REDIRECT") {
            c.oidc_post_login_redirect = v;
        }
        if let Some(v) = get("HUGINN_MAX_BODY_BYTES") {
            c.max_body_bytes = v.parse().unwrap_or(c.max_body_bytes);
        }
        if let Some(v) = get("HUGINN_MAX_OUTPUT_BYTES") {
            c.max_output_bytes = v.parse().unwrap_or(c.max_output_bytes);
        }
        if let Some(v) = get("HUGINN_DEFAULT_TASK_TIMEOUT_SECONDS") {
            c.default_task_timeout_seconds = v.parse().unwrap_or(c.default_task_timeout_seconds);
        }
        if let Some(v) = get("HUGINN_TASK_DEAD_LETTER_RETRIES") {
            c.task_dead_letter_retries = v.parse().unwrap_or(c.task_dead_letter_retries);
        }
        if let Some(v) = get("HUGINN_RATE_LIMIT_EXEC_PER_MINUTE") {
            c.rate_limit_exec_per_minute = v.parse().unwrap_or(c.rate_limit_exec_per_minute);
        }
        if let Some(v) = get("HUGINN_HEARTBEAT_OFFLINE_SECONDS") {
            c.heartbeat_offline_seconds = v.parse().unwrap_or(c.heartbeat_offline_seconds);
        }
        if let Some(v) = get("HUGINN_TARGET_WORKER_VERSION") {
            c.target_worker_version = v;
        }
        if let Some(v) = get("HUGINN_TARGET_RELEASE_REPO") {
            c.target_release_repo = v;
        }
        if let Some(v) = get("HUGINN_ALLOWED_RELEASE_DOMAINS") {
            c.allowed_release_domains_csv = v;
        }
        c
    }

    pub fn is_prod(&self) -> bool {
        self.env == "prod"
    }

    pub fn allowed_release_domains(&self) -> Vec<String> {
        csv(&self.allowed_release_domains_csv)
    }

    pub fn cors_origins(&self) -> Vec<String> {
        csv(&self.cors_origins_csv)
    }

    /// Password login is on unless OIDC is active and it isn't re-enabled.
    pub fn password_login_enabled(&self) -> bool {
        (!self.oidc_enabled) || self.allow_password_login
    }

    /// Fail closed if deployed to prod with placeholder/weak secrets.
    /// Mirrors Settings.validate_for_prod (raises RuntimeError in Python).
    pub fn validate_for_prod(&self) -> Result<(), String> {
        if !self.is_prod() {
            return Ok(());
        }
        let checks = [
            ("HUGINN_JWT_SECRET", &self.jwt_secret),
            ("HUGINN_SECRET_HASH_KEY", &self.secret_hash_key),
            ("HUGINN_MCP_SERVICE_TOKEN", &self.mcp_service_token),
            ("HUGINN_MFA_ENCRYPTION_KEY", &self.mfa_encryption_key),
        ];
        let weak: Vec<&str> = checks
            .iter()
            .filter(|(_, v)| v.starts_with("change-me") || v.len() < 32)
            .map(|(name, _)| *name)
            .collect();
        if !weak.is_empty() {
            let mut names: Vec<&str> = weak.clone();
            names.sort_unstable();
            return Err(format!(
                "refusing to start in prod with placeholder/weak secrets: {} (generate with: openssl rand -hex 32)",
                names.join(", ")
            ));
        }
        Ok(())
    }
}

fn parse_bool(raw: &str, fallback: bool) -> bool {
    match raw.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => fallback,
    }
}

fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_for_prod_rejects_placeholders_and_short_secrets() {
        let mut c = Config {
            env: "prod".into(),
            ..Default::default()
        };
        let err = c.validate_for_prod().unwrap_err();
        assert!(err.contains("HUGINN_JWT_SECRET"));
        assert!(err.contains("change-me") || err.contains("openssl"));

        c.jwt_secret = "x".repeat(32);
        c.secret_hash_key = "y".repeat(32);
        c.mcp_service_token = "z".repeat(32);
        c.mfa_encryption_key = "k".repeat(32);
        assert!(c.validate_for_prod().is_ok());
    }

    #[test]
    fn validate_for_prod_is_noop_in_dev() {
        assert!(Config::default().validate_for_prod().is_ok());
    }

    #[test]
    fn csv_parsing_matches_python() {
        assert_eq!(csv(" a, b ,,c "), vec!["a", "b", "c"]);
        assert!(csv("").is_empty());
    }

    #[test]
    fn password_login_enabled_rules() {
        let mut c = Config::default();
        // OIDC off → password always on
        assert!(c.password_login_enabled());
        c.oidc_enabled = true;
        assert!(!c.password_login_enabled());
        c.allow_password_login = true;
        assert!(c.password_login_enabled());
    }
}

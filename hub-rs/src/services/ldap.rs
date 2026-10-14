//! LDAP / LDAPS authentication fallback (port of `hub/app/core/ldap.py`).
//!
//! Config lives in the DB `settings` row (admin-editable), not in environment
//! variables. The flow is the standard bind-search-bind:
//!
//! 1. Bind with a service account (`ldap_bind_dn` / `ldap_bind_password`).
//! 2. Search for the user by `ldap_user_search_filter` (`{username}` substituted
//!    and RFC 4515-escaped to prevent LDAP injection).
//! 3. Re-bind as the found DN with the supplied password to verify it.
//!
//! Both LDAPS (`ldaps://`) and StartTLS (`ldap://` + StartTLS) are supported.
//! The wire protocol itself is exercised against a real directory in
//! deployment; the injection-prevention, filter construction, enablement
//! gating, fallback ordering and user-reconciliation decisions are unit-tested
//! here (see `tests` and the note at the bottom of this file).

use std::time::Duration;

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry, SearchResult};

use crate::db::DbError;
use crate::models::enums::UserRole;
use crate::models::setting::Setting;
use crate::models::user::{self, User, UserNew};

/// Mirrors `_CONNECT_TIMEOUT` in `ldap.py`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Configuration (DB settings row)
// ---------------------------------------------------------------------------

/// The LDAP settings, read from the DB `Setting` row (`LDAPClient(settings_row)`).
#[derive(Clone)]
pub struct LdapConfig {
    pub enabled: bool,
    pub server_url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_search_base: String,
    pub user_search_filter: String,
    pub start_tls: bool,
    pub use_ldaps: bool,
}

impl std::fmt::Debug for LdapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapConfig")
            .field("enabled", &self.enabled)
            .field("server_url", &self.server_url)
            .field("bind_dn", &self.bind_dn)
            .field("bind_password", &"[redacted]")
            .field("user_search_base", &self.user_search_base)
            .field("user_search_filter", &self.user_search_filter)
            .field("start_tls", &self.start_tls)
            .field("use_ldaps", &self.use_ldaps)
            .finish()
    }
}

impl LdapConfig {
    pub fn from_setting(s: &Setting) -> Self {
        Self {
            enabled: s.ldap_enabled,
            server_url: s.ldap_server_url.clone(),
            bind_dn: s.ldap_bind_dn.clone(),
            bind_password: s.ldap_bind_password.clone().unwrap_or_default(),
            user_search_base: s.ldap_user_search_base.clone(),
            user_search_filter: s.ldap_user_search_filter.clone(),
            start_tls: s.ldap_start_tls,
            use_ldaps: s.ldap_use_ldaps,
        }
    }

    /// `LDAPClient.enabled`: `ldap_enabled and ldap_server_url and
    /// ldap_user_search_base`.
    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.server_url.is_empty() && !self.user_search_base.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// The directory identity proved by a successful user bind (`LDAPClaims`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapClaims {
    pub dn: String,
    pub username: String,
    pub email: Option<String>,
}

// ---------------------------------------------------------------------------
// Injection-safe filter construction (pure, tested)
// ---------------------------------------------------------------------------

/// RFC 4515 LDAP filter escaping (`ldap3.utils.conv.escape_filter_chars`).
/// Escapes the injection-sensitive set — `\ * ( )` and NUL — plus any byte
/// outside printable ASCII, as `\XX` hex. This neutralises filter injection.
pub fn escape_filter_chars(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0x00 => out.push_str("\\00"),
            0x20..=0x7e => out.push(byte as char),
            other => out.push_str(&format!("\\{other:02x}")),
        }
    }
    out
}

/// Substitute the escaped username into the search filter template
/// (`ldap_user_search_filter.replace("{username}", safe_username)`).
pub fn build_search_filter(template: &str, username: &str) -> String {
    template.replace("{username}", &escape_filter_chars(username))
}

/// Whether the login should fall back to LDAP: only when local auth did not
/// match AND LDAP is enabled (`login`'s ordering).
pub(crate) fn ldap_fallback_needed(local_matched: bool, ldap_enabled: bool) -> bool {
    !local_matched && ldap_enabled
}

// ---------------------------------------------------------------------------
// Client (bind-search-bind)
// ---------------------------------------------------------------------------

/// Synchronous LDAP client (`LDAPClient`). `authenticate` is blocking (ldap3 is
/// blocking) — call it from `tokio::task::spawn_blocking` in async contexts,
/// exactly like the Python `run_in_threadpool(client.authenticate, ...)`.
pub struct LdapClient {
    config: LdapConfig,
}

impl LdapClient {
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.is_enabled()
    }

    /// Return claims if the username/password bind succeeds, else `None`.
    pub fn authenticate(&self, username: &str, password: &str) -> Option<LdapClaims> {
        if !self.is_enabled() || password.is_empty() {
            return None;
        }
        match self.try_authenticate(username, password) {
            Ok(claims) => claims,
            Err(err) => {
                tracing::warn!("LDAP authentication error: {err}");
                None
            }
        }
    }

    fn try_authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<LdapClaims>, ldap3::LdapError> {
        let c = &self.config;
        let filter = build_search_filter(&c.user_search_filter, username);

        // 1. Bind as the service account.
        let mut conn = self.connect()?;
        if conn
            .simple_bind(&c.bind_dn, &c.bind_password)
            .map(|r| r.success())?
            .is_err()
        {
            tracing::warn!("LDAP service bind failed");
            let _ = conn.unbind();
            return Ok(None);
        }

        // 2. Search for the user.
        let SearchResult(entries, _res) = conn.search(
            &c.user_search_base,
            Scope::Subtree,
            &filter,
            ["mail", "cn", "uid"],
        )?;
        let _ = conn.unbind();
        let entries: Vec<SearchEntry> = entries.into_iter().map(SearchEntry::construct).collect();
        let Some(entry) = entries.into_iter().next() else {
            return Ok(None);
        };
        let user_dn = entry.dn.clone();
        let email = entry
            .attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mail"))
            .and_then(|(_, v)| v.first())
            .cloned();

        // 3. Re-bind as the user to verify the password.
        let mut user_conn = self.connect()?;
        if user_conn
            .simple_bind(&user_dn, password)
            .map(|r| r.success())?
            .is_err()
        {
            let _ = user_conn.unbind();
            return Ok(None);
        }
        let _ = user_conn.unbind();

        Ok(Some(LdapClaims {
            dn: user_dn,
            username: username.to_owned(),
            email,
        }))
    }

    /// Open a connection honouring LDAPS / StartTLS (`_build_server`).
    fn connect(&self) -> Result<LdapConn, ldap3::LdapError> {
        let c = &self.config;
        let mut settings = LdapConnSettings::new().set_conn_timeout(CONNECT_TIMEOUT);
        if c.start_tls && !c.use_ldaps {
            settings = settings.set_starttls(true);
        }
        let url = if c.use_ldaps {
            to_ldaps(&c.server_url)
        } else {
            c.server_url.clone()
        };
        LdapConn::with_settings(settings, &url)
    }
}

/// Rewrite `ldap://` → `ldaps://` (idempotent for already-`ldaps://` URLs).
fn to_ldaps(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("ldap://") {
        format!("ldaps://{rest}")
    } else {
        url.to_owned()
    }
}

// ---------------------------------------------------------------------------
// User reconciliation (`users_service.upsert_ldap_user`)
// ---------------------------------------------------------------------------

/// Find or create a user from LDAP attributes (`upsert_ldap_user`): match on
/// `ldap_dn`, else an existing local user with the same `username` adopts the
/// DN, else create a read-only password-less account. Always bumps
/// `last_login_at`.
pub async fn upsert_ldap_user(
    pool: &sqlx::PgPool,
    dn: &str,
    username: &str,
    email: Option<&str>,
) -> Result<User, DbError> {
    use super::oidc::{decide_reconcile, Reconcile};
    let by_dn = user::get_by_ldap_dn(pool, dn).await?;
    let by_username = if by_dn.is_none() {
        user::get_by_username(pool, username).await?
    } else {
        None
    };
    let user = match decide_reconcile(by_dn.as_ref(), by_username.as_ref()) {
        Reconcile::Reuse => by_dn.expect("reuse implies a dn match"),
        Reconcile::Link => {
            let existing = by_username.expect("link implies a username match");
            user::set_ldap_dn(pool, existing.id, dn)
                .await?
                .unwrap_or(existing)
        }
        Reconcile::Create => {
            user::create(
                pool,
                UserNew {
                    username: username.to_owned(),
                    email: email.map(str::to_owned),
                    password_hash: None,
                    ldap_dn: Some(dn.to_owned()),
                    role: UserRole::Readonly,
                    is_active: true,
                    ..UserNew::default()
                },
            )
            .await?
        }
    };
    user::touch_last_login(pool, user.id).await?;
    Ok(user)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The real bind-search-bind wire protocol is not integration-tested here (an
// LDAP mock is heavy); these cover the security- and decision-critical pure
// logic. `upsert_ldap_user`'s mapping is covered by `decide_reconcile` below and
// by the DB-gated live tests in `routes::authapi`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::oidc::{decide_reconcile, Reconcile};

    #[test]
    fn escape_filter_chars_neutralises_injection() {
        // The injection-sensitive characters are escaped.
        assert_eq!(escape_filter_chars("a*b"), r"a\2ab");
        assert_eq!(escape_filter_chars("a(b)c"), r"a\28b\29c");
        assert_eq!(escape_filter_chars(r"a\b"), r"a\5cb");
        assert_eq!(escape_filter_chars("a\0b"), r"a\00b");
        // A malicious filter wildcard/DN breakout attempt is inert.
        assert_eq!(escape_filter_chars("*)(uid=*"), r"\2a\29\28uid=\2a");
        // Printable ASCII passes through; high/control bytes are hex-escaped.
        assert_eq!(escape_filter_chars("alice"), "alice");
        assert_eq!(escape_filter_chars("a\nb"), r"a\0ab");
    }

    #[test]
    fn build_search_filter_substitutes_the_escaped_username() {
        let template = "(uid={username})";
        assert_eq!(build_search_filter(template, "alice"), "(uid=alice)");
        assert_eq!(
            build_search_filter(template, "a*)(uid=admin"),
            r"(uid=a\2a\29\28uid=admin)"
        );
    }

    #[test]
    fn enabled_requires_flag_server_and_base() {
        let mut c = LdapConfig {
            enabled: true,
            server_url: "ldap://d".into(),
            user_search_base: "ou=users,dc=x".into(),
            ..empty()
        };
        assert!(c.is_enabled());
        c.enabled = false;
        assert!(!c.is_enabled());
        c.enabled = true;
        c.server_url = String::new();
        assert!(!c.is_enabled());
        c.server_url = "ldap://d".into();
        c.user_search_base = String::new();
        assert!(!c.is_enabled());
    }

    #[test]
    fn fallback_only_after_local_failure_and_when_enabled() {
        assert!(ldap_fallback_needed(false, true), "local miss + enabled");
        assert!(!ldap_fallback_needed(true, true), "local hit wins");
        assert!(!ldap_fallback_needed(false, false), "disabled → no LDAP");
    }

    #[test]
    fn ldaps_url_rewrite() {
        assert_eq!(to_ldaps("ldap://d:389"), "ldaps://d:389");
        assert_eq!(to_ldaps("ldaps://d:636"), "ldaps://d:636");
    }

    #[test]
    fn reconcile_mapping_for_ldap_matches_username_then_create() {
        let found = sample();
        assert_eq!(
            decide_reconcile(Some(&found), Some(&found)),
            Reconcile::Reuse,
            "dn match reuses the account"
        );
        assert_eq!(
            decide_reconcile(None, Some(&found)),
            Reconcile::Link,
            "username match adopts the DN"
        );
        assert_eq!(decide_reconcile(None, None), Reconcile::Create);
    }

    #[test]
    fn bind_password_never_appears_in_debug() {
        let c = LdapConfig {
            bind_password: "super-secret-bind".into(),
            ..empty()
        };
        assert!(!format!("{c:?}").contains("super-secret-bind"));
    }

    fn empty() -> LdapConfig {
        LdapConfig {
            enabled: false,
            server_url: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            user_search_base: String::new(),
            user_search_filter: String::new(),
            start_tls: false,
            use_ldaps: false,
        }
    }

    fn sample() -> User {
        User {
            id: uuid::Uuid::new_v4(),
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            password_hash: None,
            oidc_subject: None,
            ldap_dn: None,
            role: UserRole::Readonly,
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
}

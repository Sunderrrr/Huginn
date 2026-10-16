//! Minimal S3-compatible object-storage client (AWS S3, MinIO, R2, B2 …).
//!
//! Requests are signed with [`super::sigv4`] and sent with `reqwest` — no AWS
//! SDK. Only four operations are needed by the backup pipeline: PUT an object,
//! HEAD an object, LIST the backups (ListObjectsV2, paginated) and DELETE one
//! (retention).
//!
//! Two safety rules live here:
//!
//! * **HTTPS only** — an `http://` endpoint is rejected unless its host is
//!   loopback (`127.0.0.1` / `::1` / `localhost`), which is what the tests and
//!   a local MinIO on the same box use. Everything else would put the SigV4
//!   credentials and the dump on the clear-text wire.
//! * **The secret never leaks** — [`S3Config`]'s `Debug` masks it and every
//!   error string is scrubbed with [`S3Config::sanitize`] before it can reach
//!   a log line or an API response.

use std::fmt;

use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::sigv4;
use super::BackupError;
use crate::models::setting::Setting;

/// One backup object in the bucket (name relative to the configured prefix).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupObject {
    /// Object key relative to [`S3Config::prefix`] (e.g.
    /// `huginn-db-20260101T031500Z.sql.gz`).
    pub name: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
}

/// Result of `HEAD` on one object.
#[derive(Debug, Clone, Copy)]
pub struct ObjectHead {
    pub size: u64,
}

/// S3 endpoint + credentials, mirrored from the `backup_s3_*` settings.
#[derive(Clone)]
pub struct S3Config {
    /// Normalized custom endpoint (`https://host[:port]`), empty = AWS S3.
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Object-key prefix without leading/trailing slash ("" = bucket root).
    pub prefix: String,
    pub access_key: String,
    pub secret_key: String,
}

/// `Debug` that never prints the secret key.
impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("access_key", &self.access_key)
            .field("secret_key", &"***")
            .finish()
    }
}

impl S3Config {
    /// True when the settings row carries a full backup configuration.
    pub fn is_configured(row: &Setting) -> bool {
        !row.backup_s3_bucket.trim().is_empty()
            && !row.backup_s3_access_key.trim().is_empty()
            && row
                .backup_s3_secret_key
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty())
    }

    /// Build (and validate) the configuration from the settings row.
    pub fn from_settings(row: &Setting) -> Result<Self, BackupError> {
        let cfg = Self {
            endpoint: row
                .backup_s3_endpoint
                .trim()
                .trim_end_matches('/')
                .to_owned(),
            region: if row.backup_s3_region.trim().is_empty() {
                "us-east-1".to_owned()
            } else {
                row.backup_s3_region.trim().to_owned()
            },
            bucket: row.backup_s3_bucket.trim().to_owned(),
            prefix: row.backup_s3_prefix.trim().trim_matches('/').to_owned(),
            access_key: row.backup_s3_access_key.trim().to_owned(),
            secret_key: row
                .backup_s3_secret_key
                .clone()
                .unwrap_or_default()
                .trim()
                .to_owned(),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Configuration checks. Messages never contain the secret key.
    pub fn validate(&self) -> Result<(), BackupError> {
        if self.bucket.is_empty() && self.access_key.is_empty() && self.secret_key.is_empty() {
            return Err(BackupError::NotConfigured);
        }
        if self.bucket.is_empty() {
            return Err(BackupError::Config("backup_s3_bucket is required".into()));
        }
        if self.bucket.contains(['/', ' ']) {
            return Err(BackupError::Config(
                "backup_s3_bucket must not contain '/' or spaces".into(),
            ));
        }
        if self.access_key.is_empty() {
            return Err(BackupError::Config(
                "backup_s3_access_key is required".into(),
            ));
        }
        if self.secret_key.is_empty() {
            return Err(BackupError::NotConfigured);
        }
        if !self.endpoint.is_empty() {
            self.validate_endpoint()?;
        }
        Ok(())
    }

    /// Endpoint rule: `https://host[:port]` anywhere, `http://host[:port]` only
    /// on loopback (local MinIO / the test fake). No path, query, fragment or
    /// userinfo — the endpoint is just a scheme + authority.
    fn validate_endpoint(&self) -> Result<(), BackupError> {
        let (scheme, rest) = self.endpoint.split_once("://").ok_or_else(|| {
            BackupError::Config("backup_s3_endpoint must be an http(s):// URL".into())
        })?;
        if !matches!(scheme, "https" | "http") {
            return Err(BackupError::Config(
                "backup_s3_endpoint must be an http(s):// URL".into(),
            ));
        }
        if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
            return Err(BackupError::Config(
                "backup_s3_endpoint must be a bare scheme://host[:port] URL".into(),
            ));
        }
        if scheme == "http" && !crate::services::is_loopback_host(host_of(rest)) {
            return Err(BackupError::Config(
                "insecure backup_s3_endpoint rejected: http:// is only allowed for \
                 loopback hosts (use https://)"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Scrub the secret key out of a message before it is logged or returned.
    pub fn sanitize(&self, message: &str) -> String {
        if self.secret_key.is_empty() {
            return message.to_owned();
        }
        message.replace(self.secret_key.as_str(), "***")
    }

    /// Full object key of a backup file (prefix + name).
    pub fn object_key(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{}/{}", self.prefix, name)
        }
    }

    /// `scheme://authority` of the storage endpoint.
    fn base_url(&self) -> String {
        if self.endpoint.is_empty() {
            // AWS: virtual-hosted style, bucket in the host.
            format!("https://{}.s3.{}.amazonaws.com", self.bucket, self.region)
        } else {
            self.endpoint.clone()
        }
    }

    /// Host header value (== the URL authority).
    fn authority(&self) -> String {
        if self.endpoint.is_empty() {
            format!("{}.s3.{}.amazonaws.com", self.bucket, self.region)
        } else {
            self.endpoint
                .split_once("://")
                .map(|(_, rest)| rest.to_owned())
                .unwrap_or_else(|| self.endpoint.clone())
        }
    }

    /// Decoded request path for an object key (or the bucket root when `None`).
    /// The bucket lives in the host on AWS and in the path on custom endpoints.
    fn path_for(&self, key: Option<&str>) -> String {
        match (self.endpoint.is_empty(), key) {
            (true, None) => "/".to_owned(),
            (true, Some(key)) => format!("/{key}"),
            (false, None) => format!("/{}", self.bucket),
            (false, Some(key)) => format!("/{}/{}", self.bucket, key),
        }
    }
}

fn host_of(authority: &str) -> &str {
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// Signed HTTP client for one S3 configuration.
pub struct S3Client {
    cfg: S3Config,
    http: reqwest::Client,
}

impl S3Client {
    pub fn new(cfg: S3Config) -> Result<Self, BackupError> {
        cfg.validate()?;
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            // No redirect following (M-3): the request carries the SigV4
            // `Authorization` header, which is bound to the signed host — a 3xx
            // would re-send it, credentials included, to whatever host the
            // response points at (same policy as the webhook client,
            // services/notifications/webhook.rs).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| BackupError::Transport(cfg.sanitize(&e.to_string())))?;
        Ok(Self { cfg, http })
    }

    pub fn config(&self) -> &S3Config {
        &self.cfg
    }

    /// Sign and send one request.
    async fn send(
        &self,
        method: Method,
        key: Option<&str>,
        query: &[(String, String)],
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, BackupError> {
        let path = self.cfg.path_for(key);
        let payload_sha256 = sigv4::sha256_hex(body.as_deref().unwrap_or_default());
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let host = self.cfg.authority();

        let params = sigv4::SignParams {
            method: method.as_str(),
            host: &host,
            path: &path,
            query,
            headers: vec![
                ("host".to_owned(), host.clone()),
                ("x-amz-content-sha256".to_owned(), payload_sha256.clone()),
                ("x-amz-date".to_owned(), amz_date.clone()),
            ],
            payload_sha256_hex: &payload_sha256,
            access_key: &self.cfg.access_key,
            secret_key: &self.cfg.secret_key,
            region: &self.cfg.region,
            service: "s3",
            amz_date: &amz_date,
        };
        let authorization = sigv4::authorization(&params);

        // The wire path is the *encoded* path — the same encoding the
        // canonical request used.
        let encoded_path = sigv4::uri_encode(&path, true);
        let mut url = format!("{}{}", self.cfg.base_url(), encoded_path);
        if !query.is_empty() {
            let mut pairs: Vec<String> = query
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}={}",
                        sigv4::uri_encode(k, false),
                        sigv4::uri_encode(v, false)
                    )
                })
                .collect();
            pairs.sort();
            url.push('?');
            url.push_str(&pairs.join("&"));
        }

        let mut request = self
            .http
            .request(method, &url)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_sha256)
            .header("authorization", &authorization);
        if let Some(body) = body {
            request = request.body(body);
        }
        request
            .send()
            .await
            .map_err(|e| BackupError::Transport(self.cfg.sanitize(&e.to_string())))
    }

    /// Non-2xx → [`BackupError::Http`] with the S3 error code when the body
    /// carries one (sanitized, truncated).
    async fn check(
        &self,
        response: reqwest::Response,
        accept: &[u16],
    ) -> Result<reqwest::Response, BackupError> {
        let status = response.status().as_u16();
        if accept.contains(&status) {
            return Ok(response);
        }
        let body = response.text().await.unwrap_or_default();
        let code = xml_tag_value(&body, "Code")
            .filter(|c| c.len() <= 64)
            .unwrap_or_else(|| format!("HTTP {status}"));
        Err(BackupError::Http {
            status,
            code: self.cfg.sanitize(&code),
        })
    }

    /// `PUT /{key}` — upload one object.
    pub async fn put_object(&self, key: &str, body: Vec<u8>) -> Result<(), BackupError> {
        let response = self.send(Method::PUT, Some(key), &[], Some(body)).await?;
        self.check(response, &[200, 201]).await?;
        Ok(())
    }

    /// `HEAD /{key}` — `None` when the object does not exist.
    pub async fn head_object(&self, key: &str) -> Result<Option<ObjectHead>, BackupError> {
        let response = self.send(Method::HEAD, Some(key), &[], None).await?;
        let status = response.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        let response = self.check(response, &[200]).await?;
        let size = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Ok(Some(ObjectHead { size }))
    }

    /// `GET /?list-type=2&prefix=…` — every backup object under the prefix
    /// (paginated; foreign objects and non-`.sql.gz` keys are skipped).
    pub async fn list_objects(&self) -> Result<Vec<BackupObject>, BackupError> {
        let prefix = if self.cfg.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.cfg.prefix)
        };
        let mut objects = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..20 {
            let mut query = vec![
                ("list-type".to_owned(), "2".to_owned()),
                ("max-keys".to_owned(), "1000".to_owned()),
                ("prefix".to_owned(), prefix.clone()),
            ];
            if let Some(token) = &token {
                query.push(("continuation-token".to_owned(), token.clone()));
            }
            let response = self.send(Method::GET, None, &query, None).await?;
            let response = self.check(response, &[200]).await?;
            let body = response
                .text()
                .await
                .map_err(|e| BackupError::Transport(self.cfg.sanitize(&e.to_string())))?;
            let (page, next) = parse_list_page(&body);
            for (key, size, last_modified) in page {
                let Some(name) = key.strip_prefix(prefix.as_str()) else {
                    continue;
                };
                if name.is_empty() || name.contains('/') || !name.ends_with(".sql.gz") {
                    continue;
                }
                objects.push(BackupObject {
                    name: name.to_owned(),
                    size,
                    last_modified,
                });
            }
            match next {
                Some(next) => token = Some(next),
                None => break,
            }
        }
        Ok(objects)
    }

    /// `DELETE /{key}`.
    pub async fn delete_object(&self, key: &str) -> Result<(), BackupError> {
        let response = self.send(Method::DELETE, Some(key), &[], None).await?;
        self.check(response, &[200, 204]).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ListObjectsV2 response parsing (just enough XML for one flat result page)
// ---------------------------------------------------------------------------

/// One `<Contents>` entry: key, size, last-modified.
type ListEntry = (String, u64, DateTime<Utc>);

/// `(objects, next_continuation_token)` out of a `ListBucketResult` document.
fn parse_list_page(xml: &str) -> (Vec<ListEntry>, Option<String>) {
    let mut objects = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Contents>") {
        let Some(end) = rest[start..].find("</Contents>") else {
            break;
        };
        let block = &rest[start + "<Contents>".len()..start + end];
        rest = &rest[start + end..];
        let (Some(key), Some(size), Some(modified)) = (
            xml_tag_value(block, "Key"),
            xml_tag_value(block, "Size").and_then(|s| s.parse::<u64>().ok()),
            xml_tag_value(block, "LastModified"),
        ) else {
            continue;
        };
        let Ok(last_modified) = DateTime::parse_from_rfc3339(&modified) else {
            continue;
        };
        objects.push((key, size, last_modified.with_timezone(&Utc)));
    }
    let truncated = xml_tag_value(xml, "IsTruncated").is_some_and(|v| v == "true");
    let next = truncated
        .then(|| xml_tag_value(xml, "NextContinuationToken"))
        .flatten();
    (objects, next)
}

/// Text of `<tag>…</tag>` (first occurrence), with the five XML entities
/// decoded.
fn xml_tag_value(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    let raw = &xml[start..end];
    Some(decode_entities(raw))
}

fn decode_entities(raw: &str) -> String {
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
impl crate::models::setting::SettingValues {
    /// Test helper: a settings *row* out of the defaults (mirrors
    /// `setting_row`, which lives in the routes layer).
    fn into_row(self) -> crate::models::setting::Setting {
        let now = Utc::now();
        crate::models::setting::Setting {
            id: 1,
            target_worker_version: self.target_worker_version,
            target_release_repo: self.target_release_repo,
            allowed_release_domains: self.allowed_release_domains,
            updated_by: self.updated_by,
            updated_at: now,
            oidc_enabled: self.oidc_enabled,
            oidc_issuer: self.oidc_issuer,
            oidc_client_id: self.oidc_client_id,
            oidc_client_secret: self.oidc_client_secret,
            oidc_redirect_url: self.oidc_redirect_url,
            oidc_post_login_redirect: self.oidc_post_login_redirect,
            ldap_enabled: self.ldap_enabled,
            ldap_server_url: self.ldap_server_url,
            ldap_bind_dn: self.ldap_bind_dn,
            ldap_bind_password: self.ldap_bind_password,
            ldap_user_search_base: self.ldap_user_search_base,
            ldap_user_search_filter: self.ldap_user_search_filter,
            ldap_start_tls: self.ldap_start_tls,
            ldap_use_ldaps: self.ldap_use_ldaps,
            notifications_enabled: self.notifications_enabled,
            discord_webhook_url: self.discord_webhook_url,
            generic_webhook_url: self.generic_webhook_url,
            notify_vm_offline: self.notify_vm_offline,
            notify_vm_recovered: self.notify_vm_recovered,
            notify_task_failure: self.notify_task_failure,
            auto_update_enabled: self.auto_update_enabled,
            oidc_provider_name: self.oidc_provider_name,
            require_admin_mfa: self.require_admin_mfa,
            allow_password_login: self.allow_password_login,
            webauthn_rp_id: self.webauthn_rp_id,
            webauthn_rp_name: self.webauthn_rp_name,
            webauthn_origin: self.webauthn_origin,
            backup_s3_enabled: self.backup_s3_enabled,
            backup_s3_endpoint: self.backup_s3_endpoint,
            backup_s3_region: self.backup_s3_region,
            backup_s3_bucket: self.backup_s3_bucket,
            backup_s3_prefix: self.backup_s3_prefix,
            backup_s3_access_key: self.backup_s3_access_key,
            backup_s3_secret_key: self.backup_s3_secret_key,
            backup_s3_retention_days: self.backup_s3_retention_days,
            enrollment_base_url: String::new(),
            browser_engine_version: String::new(),
            browser_engine_sha256_amd64: String::new(),
            browser_engine_sha256_arm64: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_for(endpoint: &str) -> S3Config {
        S3Config {
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "backups".to_owned(),
            prefix: "db".to_owned(),
            access_key: "AKIDEXAMPLE".to_owned(),
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        }
    }

    #[test]
    fn settings_mapping_and_validation() {
        let mut row = crate::models::setting::SettingValues::default().into_row();
        // Not configured at all: the empty secret reports "not configured".
        assert!(!S3Config::is_configured(&row));
        assert!(matches!(
            S3Config::from_settings(&row),
            Err(BackupError::NotConfigured)
        ));

        row.backup_s3_bucket = "backups".into();
        row.backup_s3_access_key = "AKIDEXAMPLE".into();
        row.backup_s3_secret_key = Some("s3cret".into());
        row.backup_s3_endpoint = "https://minio.example.com/".into();
        row.backup_s3_region = String::new();
        row.backup_s3_prefix = "/db/backups/".into();
        assert!(S3Config::is_configured(&row));
        let cfg = S3Config::from_settings(&row).unwrap();
        // Trailing slash trimmed, empty region defaults, prefix normalized.
        assert_eq!(cfg.endpoint, "https://minio.example.com");
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.prefix, "db/backups");
        assert_eq!(cfg.object_key("x.sql.gz"), "db/backups/x.sql.gz");
    }

    #[test]
    fn https_is_required_except_on_loopback() {
        // Non-loopback http endpoints are refused outright.
        for endpoint in [
            "http://minio.example.com",
            "http://192.0.2.10:9000",
            "http://[::1.evil]:9000",
            "minio.example.com",
            "https://host/with/path",
            "https://user@host",
        ] {
            let mut cfg = config_for(endpoint);
            cfg.endpoint = endpoint.to_owned();
            assert!(
                cfg.validate().is_err(),
                "endpoint {endpoint} should be rejected"
            );
        }
        // Loopback http is fine (tests + local MinIO)…
        for endpoint in [
            "http://127.0.0.1:9000",
            "http://localhost:9000",
            "http://[::1]:9000",
        ] {
            let cfg = config_for(endpoint);
            cfg.validate().unwrap_or_else(|e| panic!("{endpoint}: {e}"));
        }
        // …and https everywhere.
        config_for("https://minio.example.com").validate().unwrap();
    }

    #[test]
    fn debug_and_errors_never_leak_the_secret() {
        let cfg = config_for("https://minio.example.com");
        let secret = cfg.secret_key.clone();
        assert!(!format!("{cfg:?}").contains(&secret));
        assert!(!cfg
            .sanitize("boom wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY end")
            .contains(&secret));
    }

    #[test]
    fn list_page_parsing_handles_entities_and_tokens() {
        let xml = r#"<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>backups</Name>
  <Prefix>db/</Prefix>
  <IsTruncated>true</IsTruncated>
  <NextContinuation-token>x</NextContinuation-token>
  <NextContinuationToken>tok+en=</NextContinuationToken>
  <Contents>
    <Key>db/a&amp;b.sql.gz</Key>
    <LastModified>2026-01-02T03:04:05.000Z</LastModified>
    <Size>123</Size>
  </Contents>
  <Contents>
    <Key>db/old.sql.gz</Key>
    <LastModified>2025-12-31T23:59:59Z</LastModified>
    <Size>9</Size>
  </Contents>
</ListBucketResult>"#;
        let (objects, next) = parse_list_page(xml);
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].0, "db/a&b.sql.gz");
        assert_eq!(objects[0].1, 123);
        assert_eq!(
            objects[0].2,
            DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(objects[1].0, "db/old.sql.gz");
        assert_eq!(next.as_deref(), Some("tok+en="));

        // Not truncated → no token.
        let (objects, next) = parse_list_page(
            "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
        );
        assert!(objects.is_empty());
        assert!(next.is_none());
    }

    /// M-3: a 3xx from the storage endpoint must surface as a typed error,
    /// never be followed — the request carries the SigV4 `Authorization`
    /// header, which would be replayed at whatever host the redirect points to.
    #[tokio::test]
    async fn redirect_responses_are_not_followed() {
        let server = MockServer::start().await;
        let endpoint = format!("http://{}", server.address());
        let client = S3Client::new(config_for(&endpoint)).unwrap();

        Mock::given(method("HEAD"))
            .and(path("/backups/db/x.sql.gz"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", "/attacker-hoooks"))
            .expect(1)
            .mount(&server)
            .await;

        let err = client.head_object("db/x.sql.gz").await.unwrap_err();
        assert!(
            matches!(err, BackupError::Http { status: 302, .. }),
            "typed 3xx error, got {err:?}"
        );
        // Exactly one request: the redirect was not followed (following it
        // would have re-sent the signed Authorization header).
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
    }

    /// PUT / HEAD / LIST / DELETE against a fake S3 (wiremock), including the
    /// signed request shape and the prefix-relative naming.
    #[tokio::test]
    async fn client_round_trips_against_a_fake_s3() {
        let server = MockServer::start().await;
        let endpoint = format!("http://{}", server.address());
        let client = S3Client::new(config_for(&endpoint)).unwrap();

        // PUT: assert the signed request shape.
        Mock::given(method("PUT"))
            .and(path("/backups/db/huginn-db-20260101T031500Z.sql.gz"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        client
            .put_object("db/huginn-db-20260101T031500Z.sql.gz", b"dump".to_vec())
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let put = requests.iter().find(|r| r.method == "PUT").unwrap();
        let headers: Vec<String> = put
            .headers
            .iter()
            .map(|(name, _)| name.as_str().to_lowercase())
            .collect();
        for expected in [
            "authorization",
            "x-amz-date",
            "x-amz-content-sha256",
            "host",
        ] {
            assert!(headers.contains(&expected.to_owned()), "missing {expected}");
        }
        let auth = put
            .headers
            .iter()
            .find(|(name, _)| name.as_str().eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.to_str().ok())
            .unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        // The payload hash header matches the body actually sent.
        let sha = put
            .headers
            .iter()
            .find(|(name, _)| name.as_str().eq_ignore_ascii_case("x-amz-content-sha256"))
            .and_then(|(_, v)| v.to_str().ok())
            .unwrap();
        assert_eq!(sha, sigv4::sha256_hex(b"dump"));

        // HEAD: present → size, missing → None (wiremock picks the first
        // matching mock in mounting order, so the specific one goes first).
        Mock::given(method("HEAD"))
            .and(path("/backups/db/present.sql.gz"))
            .respond_with(ResponseTemplate::new(200).insert_header("content-length", "42"))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let head = client.head_object("db/present.sql.gz").await.unwrap();
        assert_eq!(head.map(|h| h.size), Some(42));
        assert!(client
            .head_object("db/absent.sql.gz")
            .await
            .unwrap()
            .is_none());

        // LIST: prefix-relative names, foreign objects filtered out.
        let xml = r#"<ListBucketResult>
          <IsTruncated>false</IsTruncated>
          <Contents><Key>db/huginn-db-20260101T031500Z.sql.gz</Key><LastModified>2026-01-01T03:15:00Z</LastModified><Size>4</Size></Contents>
          <Contents><Key>db/notes.txt</Key><LastModified>2026-01-01T03:15:00Z</LastModified><Size>1</Size></Contents>
          <Contents><Key>other/x.sql.gz</Key><LastModified>2026-01-01T03:15:00Z</LastModified><Size>1</Size></Contents>
        </ListBucketResult>"#;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(xml, "application/xml"))
            .mount(&server)
            .await;
        let objects = client.list_objects().await.unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].name, "huginn-db-20260101T031500Z.sql.gz");
        assert_eq!(objects[0].size, 4);

        // DELETE
        Mock::given(method("DELETE"))
            .and(path("/backups/db/gone.sql.gz"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        client.delete_object("db/gone.sql.gz").await.unwrap();
    }

    #[tokio::test]
    async fn list_follows_continuation_tokens() {
        let server = MockServer::start().await;
        let endpoint = format!("http://{}", server.address());
        let client = S3Client::new(config_for(&endpoint)).unwrap();

        let page1 = r#"<ListBucketResult><IsTruncated>true</IsTruncated>
          <NextContinuationToken>page2</NextContinuationToken>
          <Contents><Key>db/one.sql.gz</Key><LastModified>2026-01-01T00:00:00Z</LastModified><Size>1</Size></Contents>
        </ListBucketResult>"#;
        let page2 = r#"<ListBucketResult><IsTruncated>false</IsTruncated>
          <Contents><Key>db/two.sql.gz</Key><LastModified>2026-01-02T00:00:00Z</LastModified><Size>2</Size></Contents>
        </ListBucketResult>"#;
        // First match wins: the continuation mock must be mounted before the
        // catch-all page.
        Mock::given(method("GET"))
            .and(wiremock::matchers::query_param(
                "continuation-token",
                "page2",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_raw(page2, "application/xml"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(page1, "application/xml"))
            .mount(&server)
            .await;

        let objects = client.list_objects().await.unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].name, "one.sql.gz");
        assert_eq!(objects[1].name, "two.sql.gz");
    }

    #[tokio::test]
    async fn storage_errors_are_typed_and_secret_free() {
        let server = MockServer::start().await;
        let endpoint = format!("http://{}", server.address());
        let client = S3Client::new(config_for(&endpoint)).unwrap();

        let xml = "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>";
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(403).set_body_raw(xml, "application/xml"))
            .mount(&server)
            .await;
        let err = client
            .put_object("db/x.sql.gz", b"dump".to_vec())
            .await
            .unwrap_err();
        match &err {
            BackupError::Http { status, code } => {
                assert_eq!(*status, 403);
                assert_eq!(code, "AccessDenied");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // The error text must never carry the secret key.
        let rendered = err.to_string();
        assert!(!rendered.contains("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"));
        assert!(rendered.contains("AccessDenied"));
    }

    #[tokio::test]
    async fn transport_errors_are_sanitized() {
        // Nothing listens here: the connection error must not echo the secret.
        let cfg = config_for("http://127.0.0.1:1");
        let client = S3Client::new(cfg.clone()).unwrap();
        let err = client.list_objects().await.unwrap_err();
        let rendered = err.to_string();
        assert!(!rendered.contains(&cfg.secret_key), "{rendered}");
    }
}

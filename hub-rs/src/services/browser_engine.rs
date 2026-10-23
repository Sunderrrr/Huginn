//! Browser engine (Obscura) auto-update: fetches the latest release from
//! GitHub, verifies both arch tarballs by SHA-256, and re-pins the fleet
//! settings so `browser_install` tasks pick up the new version. Runs on
//! demand (admin/MCP) and daily from the sweeper when enabled.
//!
//! # Outbound request policy (SSRF / resource exhaustion)
//!
//! The release metadata and the archives are fetched from GitHub, but the hub
//! is the one making the request, from inside the fleet's network — so the
//! downloader is hardened like the worker's own updater:
//!
//! - **every redirect hop is re-validated** against the host allowlist (the
//!   client never follows a redirect blindly: a 302 to `169.254.169.254` or
//!   to an internal service is refused, not fetched);
//! - the scheme must be `https` — on the first URL *and* on every hop;
//! - the asset URL from the release payload is validated before the request
//!   (the redirect policy only sees the hops *after* the first one);
//! - **both responses are size-capped** and the archives are hashed while
//!   they stream, so a huge (or hostile) body can neither exhaust the hub's
//!   memory nor be buffered whole.

use std::collections::BTreeMap;

use chrono::Utc;
use serde::Deserialize;
use sqlx::PgPool;

use crate::db::DbError;
use crate::models::setting::{Setting, SettingValues};

/// GitHub repository that ships the Obscura releases.
const OBSCURA_REPO: &str = "h4ckf0r0day/obscura";
/// User-Agent for the GitHub API (required; unauthenticated = 60 req/h).
const USER_AGENT: &str = "huginn-hub/obscura-updater";

/// Hosts the release metadata and the assets may be served from. A leading
/// dot matches every subdomain (`.githubusercontent.com` covers
/// `objects.githubusercontent.com` and `release-assets.githubusercontent.com`,
/// where GitHub serves the release archives).
const ALLOWED_HOSTS: &[&str] = &["api.github.com", "github.com", ".githubusercontent.com"];

/// Cap for the release metadata (a few KB in practice).
const MAX_METADATA_BYTES: usize = 1024 * 1024;

/// Cap for one engine archive (~70 MiB in practice).
const MAX_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;

/// Per-request timeout (metadata or archive).
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    assets: Vec<GhAsset>,
}

/// The release metadata plus the per-arch digest of each archive.
#[derive(Debug)]
struct ReleaseInfo {
    version: String,
    digests: BTreeMap<String, String>,
}

/// The outbound policy applied to every engine request: which hosts may be
/// talked to and whether the scheme must be `https`.
#[derive(Debug, Clone)]
struct ReleasePolicy {
    allowed_hosts: Vec<String>,
    require_https: bool,
}

impl ReleasePolicy {
    /// The production policy: GitHub only, `https` only.
    fn production() -> Self {
        Self {
            allowed_hosts: ALLOWED_HOSTS.iter().map(|h| (*h).to_owned()).collect(),
            require_https: true,
        }
    }

    /// Host allow-list check. An entry starting with a dot matches every
    /// subdomain (`".githubusercontent.com"`).
    fn allows_host(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        self.allowed_hosts.iter().any(|entry| {
            let entry = entry.trim().to_ascii_lowercase();
            match entry.strip_prefix('.') {
                Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
                None => host == entry,
            }
        })
    }

    /// Scheme + host check for a URL the hub is about to request.
    fn allows_url(&self, url: &str) -> Result<(), String> {
        let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid release URL: {e}"))?;
        if self.require_https && parsed.scheme() != "https" {
            return Err(format!("release URL must be https: {url}"));
        }
        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        if !self.allows_host(&host) {
            return Err(format!("release host {host:?} not in allowlist"));
        }
        Ok(())
    }

    /// Scheme + host check for a redirect hop.
    fn allows_redirect(&self, url: &reqwest::Url) -> bool {
        let scheme_ok = !self.require_https || url.scheme() == "https";
        scheme_ok && self.allows_host(url.host_str().unwrap_or_default())
    }
}

/// Fetch the latest Obscura release and re-pin the fleet settings if it is
/// newer than the currently pinned version. Returns a human-readable status
/// string ("up to date: v0.2.4", "updated to v0.2.5", or an error).
pub async fn check_for_update(pool: &PgPool) -> Result<String, DbError> {
    let policy = ReleasePolicy::production();
    let client = validating_client(&policy)
        .map_err(|e| DbError::Invalid(format!("browser engine client: {e}")))?;
    let api_url = format!("https://api.github.com/repos/{OBSCURA_REPO}/releases/latest");
    let info = fetch_release(&client, &api_url, &policy)
        .await
        .map_err(DbError::Invalid)?;

    // 3. Re-pin only when the version actually changed.
    let row = crate::models::setting::get_settings_row(pool)
        .await?
        .ok_or_else(|| DbError::NotFound)?;
    let now = Utc::now();
    if row.browser_engine_version == info.version {
        // Already pinned — just record the check.
        let mut values = crate::models::setting::values_from(&row);
        values.browser_engine_last_check_at = Some(now);
        values.browser_engine_last_check_result = format!("up to date: {}", info.version);
        crate::models::setting::upsert(pool, values).await?;
        return Ok(format!("up to date: {}", info.version));
    }
    let mut values = crate::models::setting::values_from(&row);
    values.browser_engine_version = info.version.clone();
    values.browser_engine_sha256_amd64 = info.digests.get("amd64").cloned().unwrap_or_default();
    values.browser_engine_sha256_arm64 = info.digests.get("arm64").cloned().unwrap_or_default();
    values.browser_engine_last_check_at = Some(now);
    values.browser_engine_last_check_result = format!("updated to {}", info.version);
    crate::models::setting::upsert(pool, values).await?;
    Ok(format!("updated to {}", info.version))
}

/// The HTTP client used for every engine download.
///
/// The redirect policy validates **each hop** (the URL that is about to be
/// followed) against the allowlist and refuses anything that is not `https`,
/// so a hostile or hijacked release URL cannot steer the hub at an internal
/// address.
fn validating_client(policy: &ReleasePolicy) -> Result<reqwest::Client, reqwest::Error> {
    let policy = policy.clone();
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            let url = attempt.url();
            if policy.allows_redirect(url) {
                attempt.follow()
            } else {
                let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
                attempt.error(std::io::Error::other(format!(
                    "redirect to a non-allowlisted host refused: {host}"
                )))
            }
        }))
        .build()
}

/// Format a reqwest error together with its source chain: the redirect
/// policy's refusal ("non-allowlisted host") is wrapped by reqwest and would
/// otherwise be lost.
fn describe(err: &reqwest::Error) -> String {
    let mut out = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(inner) = source {
        out.push_str(": ");
        out.push_str(&inner.to_string());
        source = inner.source();
    }
    out
}

/// Fetch the release metadata and digest both arch archives.
async fn fetch_release(
    client: &reqwest::Client,
    api_url: &str,
    policy: &ReleasePolicy,
) -> Result<ReleaseInfo, String> {
    // 1. Latest release metadata (size-capped).
    let resp = client
        .get(api_url)
        .send()
        .await
        .map_err(|e| format!("github releases: {}", describe(&e)))?;
    if !resp.status().is_success() {
        return Err(format!("github releases: HTTP {}", resp.status()));
    }
    let body = read_capped(resp, MAX_METADATA_BYTES, "github releases").await?;
    let release: GhRelease =
        serde_json::from_slice(&body).map_err(|e| format!("github releases json: {e}"))?;

    let version = release.tag_name.clone();
    if !crate::models::task::engine_version_allowed(&version) {
        return Err(format!(
            "github returned an invalid version tag: {version:?}"
        ));
    }

    // 2. Resolve both arch assets and digest them (streamed, size-capped).
    let mut digests = BTreeMap::new();
    for (asset_arch, key) in [("x86_64", "amd64"), ("aarch64", "arm64")] {
        let asset_name = format!("obscura-{asset_arch}-linux.tar.gz");
        let asset = release
            .assets
            .iter()
            .find(|a| a.name == asset_name)
            .ok_or_else(|| format!("release {version} has no {asset_name} asset"))?;
        // The asset URL comes from the release payload: validate it BEFORE the
        // request (the redirect policy only sees the hops after the first).
        policy.allows_url(&asset.browser_download_url)?;
        let digest = digest_url(client, &asset.browser_download_url).await?;
        digests.insert(key.to_owned(), digest);
    }

    Ok(ReleaseInfo { version, digests })
}

/// Stream one archive into a SHA-256 digest. The body is never buffered
/// whole: the hasher consumes it chunk by chunk and the transfer is aborted
/// as soon as it exceeds the cap.
async fn digest_url(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("download {url}: {}", describe(&e)))?;
    if !resp.status().is_success() {
        return Err(format!("download {url}: HTTP {}", resp.status()));
    }
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut total: usize = 0;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("read {url}: {}", describe(&e)))?
    {
        total = total.saturating_add(chunk.len());
        if total > MAX_ARCHIVE_BYTES {
            return Err(format!(
                "download {url}: archive exceeds the {MAX_ARCHIVE_BYTES} byte cap"
            ));
        }
        hasher.update(&chunk);
    }
    Ok(crate::security::hex_encode(&hasher.finalize()))
}

/// Read a response body, refusing anything above `cap`.
async fn read_capped(
    mut resp: reqwest::Response,
    cap: usize,
    what: &str,
) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("read {what}: {}", describe(&e)))?
    {
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(format!("{what} exceeds the {cap} byte cap"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Parse "HH:MM" into (hour, minute) in UTC. Returns None on malformed input.
pub fn parse_check_time(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.split(':');
    let h: u32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    if h < 24 && m < 60 && parts.next().is_none() {
        Some((h, m))
    } else {
        None
    }
}

/// Whether the daily check should run now: auto-update on, past the check
/// time today, and the last check was before today's check instant.
pub fn should_check_now(
    auto_update: bool,
    check_time: &str,
    last_check: Option<chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
) -> bool {
    if !auto_update {
        return false;
    }
    let Some((h, m)) = parse_check_time(check_time) else {
        return false;
    };
    let today_check = now.date_naive().and_hms_opt(h, m, 0).map(|dt| dt.and_utc());
    let Some(today_check) = today_check else {
        return false;
    };
    if now < today_check {
        return false; // before today's check time
    }
    match last_check {
        Some(lc) => lc < today_check,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The test policy: the fake server is plain http on localhost.
    fn test_policy() -> ReleasePolicy {
        ReleasePolicy {
            allowed_hosts: vec!["127.0.0.1".to_string()],
            require_https: false,
        }
    }

    #[test]
    fn parse_check_time_accepts_valid() {
        assert_eq!(parse_check_time("03:00"), Some((3, 0)));
        assert_eq!(parse_check_time("23:59"), Some((23, 59)));
        assert_eq!(parse_check_time("00:00"), Some((0, 0)));
    }

    #[test]
    fn parse_check_time_rejects_garbage() {
        for bad in ["", "3", "3:00:00", "24:00", "03:60", "ab:cd", "3:5:0"] {
            assert!(parse_check_time(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn should_check_respects_auto_update_flag() {
        let now = chrono::Utc::now();
        assert!(!should_check_now(false, "03:00", None, now));
    }

    #[test]
    fn should_check_runs_once_per_day() {
        use chrono::{TimeZone, Utc};
        // 04:00 UTC today, check time 03:00.
        let now = Utc.with_ymd_and_hms(2026, 10, 23, 4, 0, 0).unwrap();
        let today_check = Utc.with_ymd_and_hms(2026, 10, 23, 3, 0, 0).unwrap();
        // Never checked → run.
        assert!(should_check_now(true, "03:00", None, now));
        // Checked after today's check time → don't run again.
        assert!(!should_check_now(true, "03:00", Some(today_check), now));
        // Checked yesterday → run.
        let yesterday = Utc.with_ymd_and_hms(2026, 10, 22, 3, 0, 0).unwrap();
        assert!(should_check_now(true, "03:00", Some(yesterday), now));
        // Before today's check time → don't run.
        let early = Utc.with_ymd_and_hms(2026, 10, 23, 2, 30, 0).unwrap();
        assert!(!should_check_now(true, "03:00", None, early));
    }

    // ---- outbound request policy ------------------------------------------

    #[test]
    fn host_allowlist_matches_github_hosts_only() {
        let policy = ReleasePolicy::production();
        assert!(policy.allows_host("api.github.com"));
        assert!(policy.allows_host("github.com"));
        assert!(policy.allows_host("objects.githubusercontent.com"));
        assert!(policy.allows_host("release-assets.githubusercontent.com"));
        assert!(!policy.allows_host("evil.example.com"));
        assert!(!policy.allows_host("169.254.169.254"));
        assert!(!policy.allows_host("127.0.0.1"));
        assert!(
            !policy.allows_host("github.com.evil.example.com"),
            "a suffix look-alike must not match"
        );
    }

    #[test]
    fn release_urls_must_be_https_and_allowlisted() {
        let policy = ReleasePolicy::production();
        assert!(policy.allows_url("https://github.com/a/b").is_ok());
        assert!(policy.allows_url("http://github.com/a/b").is_err());
        assert!(policy.allows_url("https://evil.example.com/a").is_err());
        assert!(policy.allows_url("file:///etc/passwd").is_err());
        assert!(policy.allows_url("not a url").is_err());
    }

    /// The release metadata + both archives are fetched from allow-listed
    /// hosts, and the per-arch digests are computed from the bytes received.
    #[tokio::test]
    async fn fetch_release_digests_both_archives() {
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/release.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v0.2.4",
                "assets": [
                    {"name": "obscura-x86_64-linux.tar.gz",
                     "browser_download_url": format!("{base}/obscura-x86_64-linux.tar.gz")},
                    {"name": "obscura-aarch64-linux.tar.gz",
                     "browser_download_url": format!("{base}/obscura-aarch64-linux.tar.gz")}
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/obscura-x86_64-linux.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_string("amd64-archive"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/obscura-aarch64-linux.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_string("arm64-archive"))
            .mount(&server)
            .await;

        let policy = test_policy();
        let client = validating_client(&policy).expect("client");
        let info = fetch_release(&client, &format!("{base}/release.json"), &policy)
            .await
            .expect("fetch");
        assert_eq!(info.version, "v0.2.4");
        assert_eq!(
            info.digests.get("amd64").unwrap(),
            &sha256_hex("amd64-archive")
        );
        assert_eq!(
            info.digests.get("arm64").unwrap(),
            &sha256_hex("arm64-archive")
        );
    }

    /// A redirect to a host outside the allowlist must be refused — the hub
    /// never fetches an address the release payload points at.
    #[tokio::test]
    async fn redirect_to_a_non_allowlisted_host_is_refused() {
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/release.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v0.2.4",
                "assets": [
                    {"name": "obscura-x86_64-linux.tar.gz",
                     "browser_download_url": format!("{base}/obscura-x86_64-linux.tar.gz")},
                    {"name": "obscura-aarch64-linux.tar.gz",
                     "browser_download_url": format!("{base}/obscura-aarch64-linux.tar.gz")}
                ]
            })))
            .mount(&server)
            .await;
        // The archive answers with a redirect to an internal address.
        Mock::given(method("GET"))
            .and(path("/obscura-x86_64-linux.tar.gz"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
            )
            .mount(&server)
            .await;

        let policy = test_policy();
        let client = validating_client(&policy).expect("client");
        let err = fetch_release(&client, &format!("{base}/release.json"), &policy)
            .await
            .expect_err("the redirect must be refused");
        assert!(
            err.contains("not in allowlist") || err.contains("non-allowlisted"),
            "unexpected error: {err}"
        );
    }

    /// An oversized body is refused instead of being buffered (the cap keeps
    /// a hostile release from exhausting the hub's memory).
    #[tokio::test]
    async fn an_oversized_metadata_body_is_refused() {
        let server = MockServer::start().await;
        let base = server.uri();
        let big = "x".repeat(MAX_METADATA_BYTES + 1);
        Mock::given(method("GET"))
            .and(path("/release.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(big))
            .mount(&server)
            .await;

        let policy = test_policy();
        let client = validating_client(&policy).expect("client");
        let err = fetch_release(&client, &format!("{base}/release.json"), &policy)
            .await
            .expect_err("the oversized body must be refused");
        assert!(err.contains("cap"), "unexpected error: {err}");
    }

    /// A release payload pointing at a host outside the allowlist is refused
    /// before the request is made.
    #[tokio::test]
    async fn a_payload_pointing_at_a_foreign_host_is_refused() {
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/release.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v0.2.4",
                "assets": [
                    {"name": "obscura-x86_64-linux.tar.gz",
                     "browser_download_url": "http://169.254.169.254/latest/meta-data/"},
                    {"name": "obscura-aarch64-linux.tar.gz",
                     "browser_download_url": format!("{base}/obscura-aarch64-linux.tar.gz")}
                ]
            })))
            .mount(&server)
            .await;

        let policy = test_policy();
        let client = validating_client(&policy).expect("client");
        let err = fetch_release(&client, &format!("{base}/release.json"), &policy)
            .await
            .expect_err("the foreign asset URL must be refused");
        assert!(err.contains("not in allowlist"), "unexpected error: {err}");
    }

    /// Why the validating client exists: reqwest's DEFAULT redirect policy
    /// follows a 302 to any host, so the pre-fix downloader would have
    /// fetched whatever the release payload pointed at. The validating client
    /// refuses the hop instead.
    #[tokio::test]
    async fn the_default_client_would_have_followed_the_redirect() {
        // The "internal" host the redirect points at (same machine, a
        // different host name so the allow-list can tell them apart).
        let internal = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/internal"))
            .respond_with(ResponseTemplate::new(200).set_body_string("internal-secret"))
            .mount(&internal)
            .await;
        let internal_url = format!("http://localhost:{}/internal", internal.address().port());

        let edge = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", &internal_url))
            .mount(&edge)
            .await;
        let edge_url = format!("{}/redirect", edge.uri());

        // 1. The default policy follows the hop and reaches the internal
        //    host — this is the behaviour the fix removes.
        let default_client = reqwest::Client::builder().build().unwrap();
        let body = default_client
            .get(&edge_url)
            .send()
            .await
            .expect("the default policy follows the redirect")
            .text()
            .await
            .expect("body");
        assert_eq!(body, "internal-secret");
        assert!(
            !internal.received_requests().await.unwrap().is_empty(),
            "the default policy really fetched the internal host"
        );

        // 2. The validating client refuses the hop: the internal host is
        //    never contacted.
        let policy = test_policy();
        let client = validating_client(&policy).expect("client");
        assert!(
            client.get(&edge_url).send().await.is_err(),
            "the validating client must refuse the hop"
        );
        // (the internal server only ever saw the default client's request)
    }

    fn sha256_hex(data: &str) -> String {
        use sha2::Digest;
        crate::security::hex_encode(&sha2::Sha256::digest(data.as_bytes()))
    }
}

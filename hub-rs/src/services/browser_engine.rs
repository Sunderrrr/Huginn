//! Browser engine (Obscura) auto-update: fetches the latest release from
//! GitHub, verifies both arch tarballs by SHA-256, and re-pins the fleet
//! settings so `browser_install` tasks pick up the new version. Runs on
//! demand (admin/MCP) and daily from the sweeper when enabled.

use chrono::Utc;
use serde::Deserialize;
use sqlx::PgPool;

use crate::db::DbError;
use crate::models::setting::{Setting, SettingValues};

/// GitHub repository that ships the Obscura releases.
const OBSCURA_REPO: &str = "h4ckf0r0day/obscura";
/// User-Agent for the GitHub API (required; unauthenticated = 60 req/h).
const USER_AGENT: &str = "huginn-hub/obscura-updater";

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

/// Fetch the latest Obscura release and re-pin the fleet settings if it is
/// newer than the currently pinned version. Returns a human-readable status
/// string ("up to date: v0.2.4", "updated to v0.2.5", or an error).
pub async fn check_for_update(pool: &PgPool) -> Result<String, DbError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| DbError::Sqlx(sqlx::Error::Protocol(e.to_string())))?;

    // 1. Latest release metadata.
    let url = format!("https://api.github.com/repos/{OBSCURA_REPO}/releases/latest");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| DbError::Invalid(format!("github releases: {e}")))?;
    if !resp.status().is_success() {
        return Err(DbError::Invalid(format!(
            "github releases: HTTP {}",
            resp.status()
        )));
    }
    let release: GhRelease = resp
        .json()
        .await
        .map_err(|e| DbError::Invalid(format!("github releases json: {e}")))?;

    let version = release.tag_name.clone();
    if !crate::models::task::engine_version_allowed(&version) {
        return Err(DbError::Invalid(format!(
            "github returned an invalid version tag: {version:?}"
        )));
    }

    // 2. Resolve both arch assets + download + SHA-256.
    let mut shas = std::collections::BTreeMap::new();
    for (asset_arch, key) in [("x86_64", "amd64"), ("aarch64", "arm64")] {
        let asset_name = format!("obscura-{asset_arch}-linux.tar.gz");
        let asset = release
            .assets
            .iter()
            .find(|a| a.name == asset_name)
            .ok_or_else(|| {
                DbError::Invalid(format!("release {version} has no {asset_name} asset"))
            })?;
        let bytes = client
            .get(&asset.browser_download_url)
            .send()
            .await
            .map_err(|e| DbError::Invalid(format!("download {asset_name}: {e}")))?
            .bytes()
            .await
            .map_err(|e| DbError::Invalid(format!("read {asset_name}: {e}")))?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&bytes);
        shas.insert(key.to_owned(), crate::security::hex_encode(&digest));
    }

    // 3. Re-pin only when the version actually changed.
    let row = crate::models::setting::get_settings_row(pool)
        .await?
        .ok_or_else(|| DbError::NotFound)?;
    let now = Utc::now();
    if row.browser_engine_version == version {
        // Already pinned — just record the check.
        let mut values = crate::models::setting::values_from(&row);
        values.browser_engine_last_check_at = Some(now);
        values.browser_engine_last_check_result = format!("up to date: {version}");
        crate::models::setting::upsert(pool, values).await?;
        return Ok(format!("up to date: {version}"));
    }
    let mut values = crate::models::setting::values_from(&row);
    values.browser_engine_version = version.clone();
    values.browser_engine_sha256_amd64 = shas.remove("amd64").unwrap_or_default();
    values.browser_engine_sha256_arm64 = shas.remove("arm64").unwrap_or_default();
    values.browser_engine_last_check_at = Some(now);
    values.browser_engine_last_check_result = format!("updated to {version}");
    crate::models::setting::upsert(pool, values).await?;
    Ok(format!("updated to {version}"))
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
    let today_check = now
        .date_naive()
        .and_hms_opt(h, m, 0)
        .map(|dt| dt.and_utc());
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
}

//! Release URL construction with the worker-side SSRF allowlist
//! (moved out of `routes/worker.rs` — the service layer owns versioning).

use crate::models::enums::WorkerArch;

/// Operating systems supported by the published worker artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerOs {
    Linux,
    Windows,
}

impl WorkerOs {
    /// Read the reported OS, treating older enrollments without OS metadata as Linux.
    pub fn from_vm(vm: &crate::models::vm::VM) -> Self {
        match vm.os_info.get("os").and_then(serde_json::Value::as_str) {
            Some("windows") => Self::Windows,
            _ => Self::Linux,
        }
    }

    fn asset_name(self, arch: WorkerArch) -> String {
        match self {
            Self::Linux => format!("huginn-worker-linux-{}", arch.as_str()),
            Self::Windows => format!("huginn-worker-windows-{}.exe", arch.as_str()),
        }
    }
}

/// SSRF-validated release URL object for update tasks — port of
/// `versioning.build_release_urls` (GitHub `owner/repo` mode or self-hosted
/// base-URL mode). This is the `urls` value `models::task::UpdateTaskNew`
/// expects; it should move to a shared `services::versioning` module when that
/// lands (INTEGRATION_NOTES.md).
pub fn build_release_urls(
    repo: &str,
    version: &str,
    arch: WorkerArch,
    os: WorkerOs,
    allowed_domains: &[String],
) -> Result<serde_json::Value, String> {
    let asset = os.asset_name(arch);
    if !valid_version(version) {
        return Err(format!("invalid version: {version:?}"));
    }
    let urls = if let Some(base) = repo
        .strip_prefix("https://")
        .or(repo.strip_prefix("http://"))
    {
        // Self-hosted mode: repo is a base URL.
        let scheme = if repo.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        let base = format!("{scheme}://{base}");
        let base = base.trim_end_matches('/');
        serde_json::json!({
            "binary_url": format!("{base}/{asset}"),
            "checksums_url": format!("{base}/checksums.txt"),
            "asset_name": asset,
            "version": version,
        })
    } else {
        // GitHub releases mode: repo is owner/repo.
        if !valid_repo(repo) {
            return Err(format!("invalid repo: {repo:?}"));
        }
        let base = format!("https://github.com/{repo}/releases/download/{version}");
        serde_json::json!({
            "binary_url": format!("{base}/{asset}"),
            "checksums_url": format!("{base}/checksums.txt"),
            "asset_name": asset,
            "version": version,
        })
    };
    validate_url_host(urls["binary_url"].as_str().unwrap(), allowed_domains)?;
    validate_url_host(urls["checksums_url"].as_str().unwrap(), allowed_domains)?;
    Ok(urls)
}

/// A tag like "v1.2.3" — same character class as `versioning._VERSION_RE`.
pub fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-'))
}
/// "owner/repo" — no path traversal, no userinfo, no metacharacters.
pub fn valid_repo(repo: &str) -> bool {
    let parts: Vec<&str> = repo.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        })
}
/// Every release URL host must be on the allowlist (defense in depth; the
/// worker enforces the same list on its side).
pub fn validate_url_host(url: &str, allowed_domains: &[String]) -> Result<(), String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(format!("release URL must be http or https: {url:?}"));
    };
    if scheme != "https" && scheme != "http" {
        return Err(format!("release URL must be http or https: {url:?}"));
    }
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    if !allowed_domains
        .iter()
        .any(|d| d.trim().to_ascii_lowercase() == host)
    {
        return Err(format!("release host {host:?} not in allowlist"));
    }
    Ok(())
}

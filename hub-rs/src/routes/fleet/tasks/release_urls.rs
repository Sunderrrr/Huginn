//! Release-URL construction and SSRF gating
//! (`app/services/versioning.py`, fleet-side).

use super::super::py_repr;

// ---------------------------------------------------------------------------
// Release URLs (app/services/versioning.py)
// ---------------------------------------------------------------------------

/// `versioning.SSRFError` — a release URL host is not in the allowlist.
pub fn build_release_urls(
    repo: &str,
    version: &str,
    arch: crate::models::enums::WorkerArch,
    allowed_domains: &[String],
) -> Result<serde_json::Value, String> {
    let asset = format!("huginn-worker-linux-{}", arch.as_str());
    if !valid_version(version) {
        return Err(format!("invalid version: {}", py_repr(version)));
    }
    let urls = if let Some(base) = repo
        .strip_prefix("https://")
        .or(repo.strip_prefix("http://"))
    {
        // Self-hosted mode: repo is a base URL.
        let base = format!(
            "{}://{}",
            &repo[..repo.len() - base.len() - 3],
            base.trim_end_matches('/')
        );
        serde_json::json!({
            "binary_url": format!("{base}/{asset}"),
            "checksums_url": format!("{base}/checksums.txt"),
            "asset_name": asset,
            "version": version,
        })
    } else {
        // GitHub releases mode: repo is owner/repo.
        if !valid_repo(repo) {
            return Err(format!("invalid repo: {}", py_repr(repo)));
        }
        let base = format!("https://github.com/{repo}/releases/download/{version}");
        serde_json::json!({
            "binary_url": format!("{base}/{asset}"),
            "checksums_url": format!("{base}/checksums.txt"),
            "asset_name": asset,
            "version": version,
        })
    };
    for key in ["binary_url", "checksums_url"] {
        validate_url_host(urls[key].as_str().unwrap(), allowed_domains)?;
    }
    Ok(urls)
}

/// `"owner/repo"` — no path traversal, no userinfo, no metacharacters
/// (`versioning._REPO_RE`).
fn valid_repo(repo: &str) -> bool {
    let parts: Vec<&str> = repo.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        })
}

/// A tag like `v1.2.3` (`versioning._VERSION_RE`).
fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-'))
}

/// `versioning.validate_url_host` — every release URL host must be on the
/// allowlist (defense in depth; the worker enforces the same list).
pub fn validate_url_host(url: &str, allowed_domains: &[String]) -> Result<(), String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(format!(
            "release URL must be http or https: {}",
            py_repr(url)
        ));
    };
    if scheme != "https" && scheme != "http" {
        return Err(format!(
            "release URL must be http or https: {}",
            py_repr(url)
        ));
    }
    let host = rest.split('/').next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or("");
    let host = if let Some(inner) = host.strip_prefix('[') {
        inner.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    let host = host.to_ascii_lowercase();
    if !allowed_domains
        .iter()
        .any(|d| d.trim().to_ascii_lowercase() == host)
    {
        return Err(format!("release host {} not in allowlist", py_repr(&host)));
    }
    Ok(())
}

/// `versioning.validate_release_domain` — reject allowlist entries that are
/// unsafe (loopback, link-local, `.local`/`.internal`, ...). Used by the
/// settings routes when the allow-list is edited.
pub fn validate_release_domain(domain: &str) -> Result<(), String> {
    let host = domain.trim().to_ascii_lowercase();
    if host.is_empty() || host.contains('/') || host.contains(':') {
        return Err(format!("invalid release domain: {}", py_repr(domain)));
    }
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return Err(format!("release domain not allowed: {}", py_repr(domain)));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let (loopback, link_local, unspecified, multicast) = match ip {
            std::net::IpAddr::V4(ip) => (
                ip.is_loopback(),
                ip.is_link_local(),
                ip.is_unspecified(),
                ip.is_multicast(),
            ),
            std::net::IpAddr::V6(ip) => (
                ip.is_loopback(),
                ip.is_unicast_link_local(),
                ip.is_unspecified(),
                ip.is_multicast(),
            ),
        };
        if loopback || link_local || unspecified || multicast {
            return Err(format!(
                "release domain not allowed (loopback/link-local): {}",
                py_repr(domain)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::models::enums::WorkerArch;

    #[test]
    fn release_urls_match_python_shapes() {
        let domains = vec![
            "github.com".to_string(),
            "objects.githubusercontent.com".to_string(),
        ];
        let urls =
            build_release_urls("example/huginn", "v1.2.3", WorkerArch::Amd64, &domains).unwrap();
        assert_eq!(
            urls,
            json!({
                "binary_url": "https://github.com/example/huginn/releases/download/v1.2.3/huginn-worker-linux-amd64",
                "checksums_url": "https://github.com/example/huginn/releases/download/v1.2.3/checksums.txt",
                "asset_name": "huginn-worker-linux-amd64",
                "version": "v1.2.3",
            })
        );

        let self_hosted = build_release_urls(
            "https://hub.example.com/dist",
            "v1.2.3",
            WorkerArch::Arm64,
            &["hub.example.com".into()],
        )
        .unwrap();
        assert_eq!(
            self_hosted["binary_url"],
            "https://hub.example.com/dist/huginn-worker-linux-arm64"
        );
        assert_eq!(self_hosted["version"], "v1.2.3");
    }

    #[test]
    fn release_urls_are_ssrf_gated() {
        let domains = vec!["github.com".to_string()];
        assert_eq!(
            build_release_urls("example/huginn", "v1;rm -rf", WorkerArch::Amd64, &domains)
                .unwrap_err(),
            "invalid version: 'v1;rm -rf'"
        );
        assert_eq!(
            build_release_urls("../etc/passwd", "v1", WorkerArch::Amd64, &domains).unwrap_err(),
            "invalid repo: '../etc/passwd'"
        );
        assert_eq!(
            build_release_urls(
                "https://evil.example.com/dist",
                "v1",
                WorkerArch::Amd64,
                &domains
            )
            .unwrap_err(),
            "release host 'evil.example.com' not in allowlist"
        );
        assert!(
            build_release_urls("example/huginn", "v1", WorkerArch::Amd64, &[]).is_err(),
            "an empty allowlist rejects everything"
        );
    }

    #[test]
    fn release_domain_validation_rejects_metadata_endpoints() {
        assert!(validate_release_domain("github.com").is_ok());
        assert!(
            validate_release_domain("172.16.0.2").is_ok(),
            "LAN is allowed"
        );
        assert!(validate_release_domain("localhost").is_err());
        assert!(validate_release_domain("metadata.google.internal").is_err());
        assert!(validate_release_domain("127.0.0.1").is_err());
        assert!(validate_release_domain("169.254.169.254").is_err());
        assert!(validate_release_domain("0.0.0.0").is_err());
        assert!(validate_release_domain("hub/foo").is_err());
    }
}

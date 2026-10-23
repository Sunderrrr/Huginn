//! `browser_install` task handler: download the hub-pinned Obscura release
//! and install it under the Huginn-managed root. Linux only (the parent
//! module is `#[cfg(target_os = "linux")]`).
//!
//! The hub is the pinning authority: the task payload carries the release
//! `version` and the per-arch `sha256` map from the fleet settings (admin
//! configured). The worker re-validates both, checks the VM's C library
//! (Obscura's binaries target glibc ≥ 2.35 — a clear error on musl/Alpine or
//! older glibc), downloads only from GitHub release hosts through the
//! updater's SSRF-validated client, verifies the SHA-256, extracts strictly
//! (only the `obscura` and `obscura-worker` members, no links, no traversal),
//! writes the Apache-2.0 license and third-party notice beside the binary,
//! smoke-tests `obscura --version`, and only then renames the staging
//! directory into place. Any failure leaves nothing behind.

use std::io::{Cursor, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::Digest;
use tar::{Archive, EntryType};
use tokio::process::Command;

use super::{truncate_chars, OBSCURA_INSTALL_ROOT};
use crate::hubclient::{Task, TaskResult};

/// GitHub-owned hosts the engine download may touch (the worker update
/// allowlist plus the release CDN GitHub now redirects through).
const OBSCURA_RELEASE_HOSTS: [&str; 3] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

/// Download cap: the release tarball is ~70 MB; 256 MB is generous.
const DOWNLOAD_CAP: usize = 256 * 1024 * 1024;
/// Minimum glibc version Obscura's release binaries require (Ubuntu 22.04).
const MIN_GLIBC: (u64, u64) = (2, 35);
/// `obscura --version` smoke-test timeout.
const SMOKE_TIMEOUT: Duration = Duration::from_secs(20);
/// Timeout for the libc-detection helpers (`getconf`, `ldd`).
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// The Apache-2.0 license text, redistributed with the installed engine
/// (the license's own requirement; the repo root LICENSE is that text).
const APACHE_2_0: &str = include_str!("../../../LICENSE");

/// Run the `browser_install` task end to end.
pub async fn run_browser_install_task(task: &Task, state_dir: &str) -> TaskResult {
    let mut log = Vec::new();
    match install_engine(&task.payload, state_dir, &mut log).await {
        Ok(()) => TaskResult {
            status: "succeeded".into(),
            exit_code: Some(0),
            stdout: log.join("\n"),
            stderr: String::new(),
            error: String::new(),
        },
        Err(e) => TaskResult {
            status: "failed".into(),
            exit_code: None,
            stdout: log.join("\n"),
            stderr: String::new(),
            error: e,
        },
    }
}

/// One install log line.
fn line(log: &mut Vec<String>, text: String) {
    if log.len() < 64 {
        log.push(text);
    }
}

/// The whole install pipeline; `log` collects the operator-facing lines.
async fn install_engine(
    payload: &serde_json::Map<String, Value>,
    state_dir: &str,
    log: &mut Vec<String>,
) -> Result<(), String> {
    // ---- hub-pinned coordinates (re-validated here) ----------------------
    let version = payload
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    version_gate(version)?;
    let (arch, asset_arch) = arch_key()?;
    let sha_map = payload
        .get("sha256")
        .and_then(Value::as_object)
        .ok_or_else(|| "browser_install payload has no sha256 map".to_owned())?;
    let pinned = sha_map
        .get(arch)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("browser_install: no pinned sha256 for {arch}"))?;
    sha256_gate(pinned)?;

    // ---- C library gate ----------------------------------------------------
    let libc = detect_libc().await?;
    line(log, format!("libc: {libc}"));

    // ---- allowlisted download ---------------------------------------------
    let asset = format!("obscura-{asset_arch}-linux.tar.gz");
    let url = format!("https://github.com/h4ckf0r0day/obscura/releases/download/{version}/{asset}");
    let allowed: Vec<String> = OBSCURA_RELEASE_HOSTS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let bytes = crate::update::download_bytes(&url, &allowed, DOWNLOAD_CAP)
        .await
        .map_err(|e| format!("download {asset}: {e}"))?;
    line(log, format!("downloaded {asset} ({} bytes)", bytes.len()));

    // ---- SHA-256 against the hub-pinned value ------------------------------
    let digest = sha2::Sha256::digest(&bytes);
    let actual = hex::encode(digest);
    // Constant-time comparison (the same primitive the updater uses): a
    // timing side channel on a hash comparison is a leak, not a defence.
    if !crate::update::constant_time_eq(
        actual.to_ascii_lowercase().as_bytes(),
        pinned.to_ascii_lowercase().as_bytes(),
    ) {
        return Err(format!(
            "sha256 mismatch for {asset}: hub pinned {}, download hashed {actual}; \
             refusing to install",
            truncate_chars(pinned, 16)
        ));
    }
    line(log, "sha256 verified".to_owned());

    // ---- staging + strict extraction ----------------------------------------
    let root = install_root(state_dir)?;
    let staging = root.join(format!(".staging-{version}"));
    let dest = root.join(version);
    let _ = std::fs::remove_dir_all(&staging); // a leftover from an aborted run
    std::fs::create_dir_all(&staging).map_err(|e| staging_err(&staging, e))?;
    let result = assemble(&bytes, &staging, version, log).await;
    if let Err(e) = result {
        // A failed install leaves nothing behind — the discovery walk must
        // never find a half-written engine.
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

    // ---- rename into place (atomic-ish) -------------------------------------
    if dest.exists() {
        std::fs::remove_dir_all(&dest)
            .map_err(|e| format!("remove old {}: {e}", dest.display()))?;
    }
    std::fs::rename(&staging, &dest).map_err(|e| {
        let _ = std::fs::remove_dir_all(&staging);
        format!("publish {}: {e}", dest.display())
    })?;
    line(log, format!("installed to {}", dest.display()));
    Ok(())
}

/// Extract, license, and smoke-test into `staging` — everything that must be
/// rolled back on failure.
async fn assemble(
    bytes: &[u8],
    staging: &Path,
    version: &str,
    log: &mut Vec<String>,
) -> Result<(), String> {
    let installed = extract_strict(bytes, staging)?;
    line(log, format!("extracted {}", installed.join(", ")));

    // The license travels with the binary (Apache-2.0 redistribution terms).
    std::fs::write(staging.join("LICENSE"), APACHE_2_0)
        .map_err(|e| format!("write LICENSE: {e}"))?;
    std::fs::write(
        staging.join("THIRD_PARTY_NOTICES.txt"),
        format!(
            "This directory contains Obscura {version} \
             (https://github.com/h4ckf0r0day/obscura), \
             licensed under the Apache License 2.0 (see LICENSE in this \
             directory), installed by the Huginn worker for browser \
             automation.\n"
        ),
    )
    .map_err(|e| format!("write THIRD_PARTY_NOTICES.txt: {e}"))?;

    // Smoke test: the binary must answer --version on this system.
    let bin = staging.join("obscura");
    let version_out = smoke_test(&bin).await?;
    line(log, format!("obscura --version: {}", version_out.trim()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation gates (pure functions — unit tested)
// ---------------------------------------------------------------------------

/// `version` becomes a directory name under the install root, so it must be
/// path-safe: `v` + 1..=32 chars of `[A-Za-z0-9._-]`, no `..`, no leading
/// dot. The hub applies the same rule before queueing the task.
pub(crate) fn version_gate(version: &str) -> Result<(), String> {
    let invalid = || {
        format!(
            "invalid engine version {version:?}: expected v-prefixed semver-like tag (e.g. v0.2.4)"
        )
    };
    if !version.starts_with('v') || version.len() > 33 || version.len() < 3 {
        return Err(invalid());
    }
    let rest = &version[1..];
    if rest.starts_with('.') || rest.contains("..") {
        return Err(invalid());
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(invalid());
    }
    Ok(())
}

/// A pinned SHA-256 is 64 hex characters.
pub(crate) fn sha256_gate(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "invalid pinned sha256 {:?}: expected 64 hex characters",
            truncate_chars(value, 16)
        ))
    }
}

/// The worker's architecture as (hub settings key, release asset arch).
pub(crate) fn arch_key() -> Result<(&'static str, &'static str), String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(("amd64", "x86_64")),
        "aarch64" => Ok(("arm64", "aarch64")),
        other => Err(format!(
            "browser engine: unsupported architecture {other} (expected x86_64 or aarch64)"
        )),
    }
}

// ---------------------------------------------------------------------------
// C library gate
// ---------------------------------------------------------------------------

/// Parse a `glibc X.Y` version out of tool output (case-insensitive).
pub(crate) fn parse_libc_version(text: &str) -> Option<(u64, u64)> {
    let lower = text.to_lowercase();
    let idx = lower.find("glibc")?;
    let rest = &text[idx + "glibc".len()..];
    let rest = rest.trim_start();
    let mut parts = rest.split('.');
    let major = parts.next()?.trim_matches(|c: char| !c.is_ascii_digit());
    let minor_raw = parts.next().unwrap_or("");
    let minor = minor_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    if major.is_empty() || minor.is_empty() {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Determine the C library and enforce glibc ≥ [`MIN_GLIBC`]. Musl systems
/// (Alpine) get a clear refusal — Obscura's binaries are glibc-built.
async fn detect_libc() -> Result<String, String> {
    let too_old = |found: String| {
        format!(
            "{found} is too old: the browser engine binaries require glibc \
             >= {}.{} (Ubuntu 22.04+); musl/Alpine is not supported",
            MIN_GLIBC.0, MIN_GLIBC.1
        )
    };
    // glibc systems answer "glibc 2.35".
    if let Ok((stdout, _)) = run_capture("getconf", &["GNU_LIBC_VERSION"]).await {
        if let Some(version) = parse_libc_version(&stdout) {
            if version < MIN_GLIBC {
                return Err(too_old(format!("glibc {}.{}", version.0, version.1)));
            }
            return Ok(format!("glibc {}.{}", version.0, version.1));
        }
    }
    // Fall back to ldd --version; musl identifies itself there.
    let (stdout, stderr) = run_capture("ldd", &["--version"]).await.unwrap_or_default();
    let combined = format!("{stdout}{stderr}");
    if combined.to_lowercase().contains("musl") {
        return Err(
            "musl libc detected (Alpine?): the browser engine binaries require \
             glibc >= 2.35 and musl systems are not supported"
                .to_owned(),
        );
    }
    if let Some(version) = parse_libc_version(&combined) {
        if version < MIN_GLIBC {
            return Err(too_old(format!("glibc {}.{}", version.0, version.1)));
        }
        return Ok(format!("glibc {}.{}", version.0, version.1));
    }
    Err(
        "could not determine the C library version; the browser engine \
         binaries require glibc >= 2.35 (not musl/Alpine)"
            .to_owned(),
    )
}

/// Run a helper and capture (stdout, stderr) — pure argv, never a shell.
/// The helper is bounded by [`HELPER_TIMEOUT`]: a hung `getconf`/`ldd` must
/// not block the worker forever.
async fn run_capture(program: &str, args: &[&str]) -> Result<(String, String), String> {
    let out = tokio::time::timeout(
        HELPER_TIMEOUT,
        Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    )
    .await
    .map_err(|_| format!("{program} timed out after {}s", HELPER_TIMEOUT.as_secs()))?
    .map_err(|e| format!("run {program}: {e}"))?;
    Ok((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Extraction + install layout
// ---------------------------------------------------------------------------

/// Extract the two engine binaries from the (already verified) tarball into
/// `dest`, chmod 0755. STRICT: only regular files named `obscura` or
/// `obscura-worker` at the archive root are unpacked; directory entries are
/// skipped, every other member type (symlink, hardlink, fifo…) and any path
/// with more than one component is refused. The tarball is fully in memory
/// (≤ [`DOWNLOAD_CAP`]) so a hostile member cannot stream forever.
///
/// The member is written by US, not by the tar crate: the destination is
/// opened `O_NOFOLLOW` (a pre-placed symlink is refused, never written
/// through) with mode 0700 and only made 0755 once the content is complete.
/// The uncompressed size of a member is capped ([`MAX_ENGINE_BYTES`]) so a
/// decompression bomb cannot fill the disk.
pub(crate) fn extract_strict(bytes: &[u8], dest: &Path) -> Result<Vec<String>, String> {
    extract_strict_with_limit(bytes, dest, MAX_ENGINE_BYTES)
}

/// Per-binary cap on the uncompressed size of an extracted member. The
/// release binaries are ~75 MB (the aarch64 asset unpacks to ~78 MB); the
/// cap is generous but finite, so a decompression bomb cannot fill the disk.
pub(crate) const MAX_ENGINE_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) fn extract_strict_with_limit(
    bytes: &[u8],
    dest: &Path,
    max_bytes: u64,
) -> Result<Vec<String>, String> {
    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(gz);
    let mut installed = Vec::new();
    for entry in archive
        .entries()
        .map_err(|e| format!("read tarball: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("read tar member: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("read tar member name: {e}"))?
            .to_path_buf();
        // Normalize "./obscura" → "obscura", skip the harmless "./" root
        // marker GNU tar writes, and demand exactly one normal component —
        // no nested paths, no traversal, no absolute paths.
        let components: Vec<_> = path
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect();
        let name = match components.as_slice() {
            [] => continue, // "./" — the archive-root marker, nothing to extract
            [std::path::Component::Normal(name)] => name.to_string_lossy().to_string(),
            _ => return Err(format!("refusing tar member with path {path:?}")),
        };
        match entry.header().entry_type() {
            EntryType::Directory => continue, // harmless (e.g. "./")
            EntryType::Regular => {}
            other => {
                return Err(format!(
                    "refusing tar member {name:?} of type {other:?} (only regular files)"
                ))
            }
        }
        if name != "obscura" && name != "obscura-worker" {
            continue; // future extra assets are ignored, never executed
        }
        // The declared size is checked BEFORE anything is written: a
        // decompression bomb (a member that expands to gigabytes) is refused
        // here, not after it filled the disk.
        let declared = entry.header().size().unwrap_or(0);
        if declared > max_bytes {
            return Err(format!(
                "refusing tar member {name:?}: declared size {declared} bytes exceeds the {max_bytes} byte cap"
            ));
        }
        let out_path = dest.join(&name);
        write_member(&mut entry, &out_path, max_bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod {name}: {e}"))?;
        }
        installed.push(name);
    }
    if !installed.iter().any(|n| n == "obscura") {
        return Err("tarball has no obscura binary".to_owned());
    }
    installed.sort();
    Ok(installed)
}

/// Write one tar member to `out_path` ourselves: the destination is opened
/// `O_NOFOLLOW` (a pre-placed symlink is refused, never written through)
/// with mode 0700 — never group/other-writable, not even for the microsecond
/// the content is being written. At most `max_bytes` are copied: a member
/// that lies about its size (or a zip-bomb style stream) is cut off and
/// refused.
fn write_member<R: std::io::Read>(
    entry: &mut R,
    out_path: &Path,
    max_bytes: u64,
) -> Result<(), String> {
    use std::io::Read as _;

    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW)
        .open(out_path)
        .map_err(|e| format!("open {}: {e}", out_path.display()))?;
    let written = {
        let mut limited = (&mut *entry).take(max_bytes.saturating_add(1));
        std::io::copy(&mut limited, &mut out)
            .map_err(|e| format!("extract {}: {e}", out_path.display()))?
    };
    if written > max_bytes {
        let _ = std::fs::remove_file(out_path);
        return Err(format!(
            "refusing tar member {}: more than {max_bytes} bytes",
            out_path.display()
        ));
    }
    out.flush()
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;
    // Flush to disk before the staging directory is published: a power loss
    // must not leave a half-written engine behind a "successful" install.
    out.sync_all()
        .map_err(|e| format!("sync {}: {e}", out_path.display()))?;
    Ok(())
}

/// The install root for the engine: `$HUGINN_OBSCURA_DIR` when set, else the
/// managed [`OBSCURA_INSTALL_ROOT`], falling back to `<state_dir>/obscura`
/// for non-root workers. Created if missing.
pub(crate) fn install_root(state_dir: &str) -> Result<PathBuf, String> {
    if let Ok(root) = std::env::var("HUGINN_OBSCURA_DIR") {
        if !root.is_empty() {
            let root = PathBuf::from(root);
            std::fs::create_dir_all(&root).map_err(|e| staging_err(&root, e))?;
            return Ok(root);
        }
    }
    let primary = PathBuf::from(OBSCURA_INSTALL_ROOT);
    if std::fs::create_dir_all(&primary).is_ok() {
        return Ok(primary);
    }
    if !state_dir.is_empty() {
        let local = Path::new(state_dir).join("obscura");
        if std::fs::create_dir_all(&local).is_ok() {
            return Ok(local);
        }
    }
    Err(format!(
        "cannot create {} for the browser engine (set HUGINN_OBSCURA_DIR to override)",
        primary.display()
    ))
}

fn staging_err(path: &Path, e: std::io::Error) -> String {
    format!("create {}: {e}", path.display())
}

/// Smoke test: `obscura --version` must exit 0 within [`SMOKE_TIMEOUT`].
/// Pure argv — never a shell.
async fn smoke_test(bin: &Path) -> Result<String, String> {
    let out = tokio::time::timeout(
        SMOKE_TIMEOUT,
        Command::new(bin)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    )
    .await
    .map_err(|_| {
        format!(
            "obscura --version timed out after {}s",
            SMOKE_TIMEOUT.as_secs()
        )
    })?
    .map_err(|e| format!("run {}: {e}", bin.display()))?;
    if !out.status.success() {
        return Err(format!(
            "obscura --version exited with {} — the binary is not usable on this system",
            out.status.code().unwrap_or(-1)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if text.trim().is_empty() {
        return Err("obscura --version printed nothing".to_owned());
    }
    Ok(truncate_chars(text.trim(), 256))
}

/// Remove every engine install root (best effort) — the `uninstall` task's
/// browser part. Returns the removed roots for the uninstall report.
pub fn uninstall_cleanup(state_dir: &str) -> Vec<String> {
    let mut removed = Vec::new();
    for root in super::install_roots(state_dir) {
        if std::fs::remove_dir_all(&root).is_ok() {
            removed.push(root.display().to_string());
        }
    }
    removed
}

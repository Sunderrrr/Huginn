// Worker build version, default paths, and on-disk state (hub URL + per-worker
// credentials). The state file is written atomically via tmp+rename: 0600 on
// Unix, default (restrictive) ACLs on Windows.
//
// Rust port of worker/internal/config, ported to Windows.
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Version is set at build time via the HUGINN_WORKER_VERSION env var. It is
/// reported to the hub on every heartbeat.
pub const VERSION: &str = match option_env!("HUGINN_WORKER_VERSION") {
    Some(v) => v,
    None => "dev",
};

/// Default filesystem locations. Overridable via flags / env for tests.
#[cfg(unix)]
pub const DEFAULT_STATE_DIR: &str = "/etc/huginn";
#[cfg(windows)]
pub const DEFAULT_STATE_DIR: &str = "C:\\ProgramData\\Huginn";
pub const DEFAULT_STATE_FILE: &str = "worker.json";
#[cfg(unix)]
pub const DEFAULT_BINARY_PATH: &str = "/usr/local/bin/huginn-worker";
#[cfg(windows)]
pub const DEFAULT_BINARY_PATH: &str = "C:\\Program Files\\Huginn\\huginn-worker.exe";

/// Worker-side SSRF allowlist for update downloads (defense in depth; the hub
/// also validates).
pub const DEFAULT_ALLOWED_RELEASE_DOMAINS: [&str; 2] =
    ["github.com", "objects.githubusercontent.com"];

/// State is the persisted worker configuration and identity.
///
/// JSON field order and `omitempty` semantics mirror the Go struct exactly:
/// `hub_url`, `worker_id` and `worker_secret` are always present; the other
/// fields are omitted when unset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub hub_url: String,
    #[serde(default)]
    pub worker_id: String,
    #[serde(default)]
    pub worker_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_release_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub binary_path: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_insecure_transport: bool,
    /// Path to a PEM-encoded CA certificate the hub's TLS certificate was
    /// signed with (self-signed/internal CAs, e.g. the Caddy root served at
    /// /caddy-root.crt). None = use the bundled Mozilla root store, which
    /// covers publicly trusted hubs (the FQDN behind Cloudflare) but not an
    /// IP/localhost hub. Set by install.sh from HUB_CA_CERT / HUB_URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_path: Option<String>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

impl State {
    /// AllowedDomains returns the configured allowlist or the built-in default.
    pub fn allowed_domains(&self) -> Vec<String> {
        match &self.allowed_release_domains {
            Some(domains) if !domains.is_empty() => domains.clone(),
            _ => DEFAULT_ALLOWED_RELEASE_DOMAINS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// BinaryLocation returns the configured binary path or the default.
    pub fn binary_location(&self) -> String {
        if self.binary_path.is_empty() {
            DEFAULT_BINARY_PATH.to_string()
        } else {
            self.binary_path.clone()
        }
    }

    /// StateDir returns the directory containing the state file. Like the Go
    /// implementation, this is the built-in constant (the --state-dir flag only
    /// affects where enroll persists the file).
    #[allow(dead_code)] // parity with Go State.StateDir
    pub fn state_dir(&self) -> &'static str {
        DEFAULT_STATE_DIR
    }
}

/// StatePath returns the state file path for a given directory.
pub fn state_path(dir: &str) -> PathBuf {
    let dir = if dir.is_empty() {
        DEFAULT_STATE_DIR
    } else {
        dir
    };
    PathBuf::from(dir).join(DEFAULT_STATE_FILE)
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// Refusal to persist a state file without a worker identity.
    Identity,
    Parse {
        path: String,
        source: serde_json::Error,
    },
    /// The state directory could not be locked down (Windows ACL).
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))] // built by the Windows code
    Acl(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Json(e) => write!(f, "{e}"),
            Error::Identity => write!(f, "refusing to save state without worker identity"),
            Error::Parse { path, source } => write!(f, "parse state {path}: {source}"),
            Error::Acl(detail) => write!(f, "state directory ACL: {detail}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Json(e) | Error::Parse { source: e, .. } => Some(e),
            Error::Identity | Error::Acl(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Load reads worker state from path.
pub fn load(path: &Path) -> Result<State, Error> {
    let data = std::fs::read(path)?;
    serde_json::from_slice(&data).map_err(|source| Error::Parse {
        path: path.display().to_string(),
        source,
    })
}

/// Creates the state directory (recursively) and makes sure it is locked
/// down. On Unix it is tightened to 0700; on Windows inheritance from
/// ProgramData is stripped and access is limited to SYSTEM and
/// Administrators — the state file holds the worker secret, and the default
/// ACLs would let every local user read it.
///
/// The lock-down is applied **every time**, not only when the directory is
/// created: the directory may already exist with the inherited, wide-open
/// ProgramData ACL (the installer creates it before the first enrollment), and
/// the secret would then be written into a directory anyone can read. On
/// Windows a failure is fatal (the error propagates) and the effective ACL
/// is verified afterwards.
pub fn ensure_state_dir(dir: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    #[cfg(windows)]
    restrict_dir_acl(dir)?;
    Ok(())
}

/// The icacls grants applied to the state directory: SYSTEM and the
/// Administrators group, the latter by **SID** (`*S-1-5-32-544`) and never by
/// its English name — on a localized Windows ("Administrateurs") the name does
/// not resolve, so icacls warns instead of applying the right.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))] // used by the Windows build and the tests
pub(crate) const STATE_DIR_ACL_GRANTS: &[&str] = &[
    "/inheritance:r",
    "/grant:r",
    "SYSTEM:(OI)(CI)F",
    "/grant:r",
    "*S-1-5-32-544:(OI)(CI)F",
];

/// The principals that must NOT be able to read the state directory. The
/// directory holds the worker secret.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))] // used by the Windows build and the tests
pub(crate) const FORBIDDEN_ACL_PRINCIPALS: &[&str] = &[
    "BUILTIN\\Users",
    "BUILTIN\\Authenticated Users",
    "NT AUTHORITY\\Everyone",
    "Everyone",
    "Users",
    "Authenticated Users",
];

/// Locks the state dir down to SYSTEM and Administrators via icacls (ships
/// with every supported Windows; fixed argv, no shell involved), then
/// **verifies** the result: the state directory holds the worker secret, so a
/// silent failure here would leave it readable by every local account.
#[cfg(windows)]
fn restrict_dir_acl(dir: &Path) -> Result<(), Error> {
    let output = std::process::Command::new("icacls")
        .arg(dir)
        .args(STATE_DIR_ACL_GRANTS)
        .output()
        .map_err(|e| Error::Acl(format!("icacls could not be run: {e}")))?;
    if !output.status.success() {
        return Err(Error::Acl(format!(
            "icacls refused to lock down {}: {}",
            dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    verify_dir_acl(dir)
}

/// Reads back the ACL and refuses to continue if a forbidden principal can
/// still read the directory.
#[cfg(windows)]
fn verify_dir_acl(dir: &Path) -> Result<(), Error> {
    let output = std::process::Command::new("icacls")
        .arg(dir)
        .output()
        .map_err(|e| Error::Acl(format!("icacls could not be run: {e}")))?;
    let listing = String::from_utf8_lossy(&output.stdout).to_string();
    // icacls prints one ACE per line, each starting with the principal.
    for line in listing.lines() {
        let ace = line.trim();
        if ace.is_empty() || ace.starts_with("Successfully processed") {
            continue;
        }
        let principal = ace.split_whitespace().next().unwrap_or("");
        for forbidden in FORBIDDEN_ACL_PRINCIPALS {
            if principal.eq_ignore_ascii_case(forbidden) {
                return Err(Error::Acl(format!(
                    "{} is still readable by {} — the worker secret would be exposed",
                    dir.display(),
                    principal
                )));
            }
        }
    }
    Ok(())
}

/// Creates the secret-bearing temp file with restrictive permissions before
/// the atomic rename: 0600 from creation on Unix (mirroring
/// os.WriteFile(tmp, data, 0o600)), default inherited ACLs on Windows.
///
/// On Unix the file is opened `O_NOFOLLOW`: a pre-placed symlink at the temp
/// path is refused instead of being written through — the state file
/// carries the worker secret, and following a symlink would write it
/// wherever the link points.
fn create_secret_file(path: &Path) -> Result<std::fs::File, Error> {
    #[cfg(unix)]
    {
        Ok(std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?)
    }
    #[cfg(windows)]
    {
        Ok(std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?)
    }
}

/// Save writes worker state atomically (tmp + rename) with 0600 permissions.
/// Credentials must never be world-readable, and a state file without a worker
/// identity is refused.
pub fn save(path: &Path, state: &State) -> Result<(), Error> {
    if state.worker_id.is_empty() || state.worker_secret.is_empty() {
        return Err(Error::Identity);
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !dir.exists() {
        ensure_state_dir(dir)?;
    }
    let data = serde_json::to_vec_pretty(state).map_err(Error::Json)?;
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    {
        let mut f = create_secret_file(&tmp)?;
        f.write_all(&data)?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Unique scratch directory per test invocation (Go's t.TempDir()).
    pub fn temp_dir(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "huginn-worker-test-{}-{label}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_load_roundtrip() {
        let dir = testutil::temp_dir("roundtrip");
        let path = state_path(dir.to_str().unwrap());
        let input = State {
            hub_url: "https://hub.example.com".into(),
            worker_id: "w1".into(),
            worker_secret: "s3cr3t".into(),
            ..Default::default()
        };
        save(&path, &input).expect("Save");
        let out = load(&path).expect("Load");
        assert_eq!(out.worker_id, "w1");
        assert_eq!(out.worker_secret, "s3cr3t");
        assert_eq!(out.hub_url, input.hub_url);
    }

    #[cfg(unix)]
    #[test]
    fn test_save_sets_0600_permissions() {
        let dir = testutil::temp_dir("perms");
        let path = state_path(dir.to_str().unwrap());
        save(
            &path,
            &State {
                hub_url: "h".into(),
                worker_id: "w".into(),
                worker_secret: "s".into(),
                ..Default::default()
            },
        )
        .expect("Save");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "permissions = {:o}, want 600 (secrets must not be world-readable)",
            mode & 0o777
        );
    }

    /// The state file holds the worker secret: the temp file it is written
    /// through must never be a pre-placed symlink (which would divert the
    /// secret to an arbitrary path).
    #[cfg(unix)]
    #[test]
    fn test_save_refuses_to_write_through_a_symlink() {
        let dir = testutil::temp_dir("symlink");
        let path = state_path(dir.to_str().unwrap());
        let outside = dir.join("outside");
        std::fs::write(&outside, b"untouched").expect("write outside");
        // Pre-place a symlink where the temp file would go.
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        std::os::unix::fs::symlink(&outside, &tmp).expect("symlink");

        let err = save(
            &path,
            &State {
                hub_url: "https://hub.example.com".into(),
                worker_id: "w1".into(),
                worker_secret: "s3cr3t".into(),
                ..Default::default()
            },
        )
        .expect_err("a symlinked temp file must be refused");
        assert!(matches!(err, Error::Io(_)), "{err:?}");
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"untouched",
            "the symlink target must not be written through"
        );
    }

    #[test]
    fn test_save_refuses_empty_identity() {
        let dir = testutil::temp_dir("no-identity");
        let path = state_path(dir.to_str().unwrap());
        let err = save(
            &path,
            &State {
                hub_url: "h".into(),
                ..Default::default()
            },
        );
        assert!(err.is_err(), "expected refusal to save without identity");
    }

    #[test]
    fn test_saved_json_uses_omitempty_shape() {
        let state = State {
            hub_url: "https://h".into(),
            worker_id: "w".into(),
            worker_secret: "s".into(),
            ..Default::default()
        };
        let value = serde_json::to_value(&state).expect("marshal");
        assert_eq!(
            value,
            serde_json::json!({"hub_url": "https://h", "worker_id": "w", "worker_secret": "s"}),
            "unset optional fields must be omitted"
        );
    }

    #[test]
    fn test_allowed_domains_default() {
        let s = State::default();
        assert!(
            !s.allowed_domains().is_empty(),
            "expected default allowlist"
        );
        let s = State {
            allowed_release_domains: Some(vec!["only.example.com".into()]),
            ..Default::default()
        };
        let got = s.allowed_domains();
        assert_eq!(got.len(), 1, "override not respected");
        assert_eq!(got[0], "only.example.com");
    }

    #[test]
    fn test_binary_location_default() {
        let s = State::default();
        assert_eq!(s.binary_location(), DEFAULT_BINARY_PATH);
        let s = State {
            binary_path: "/srv/huginn".into(),
            ..Default::default()
        };
        assert_eq!(s.binary_location(), "/srv/huginn", "override not respected");
    }

    #[test]
    fn test_state_path_joins_state_file() {
        assert_eq!(
            state_path("/etc/huginn"),
            PathBuf::from("/etc/huginn").join("worker.json")
        );
        // An empty dir falls back to the platform default.
        assert_eq!(
            state_path(""),
            PathBuf::from(DEFAULT_STATE_DIR).join("worker.json")
        );
    }

    // Per-OS default paths (the Windows arm runs only on the Windows CI).
    #[cfg(unix)]
    #[test]
    fn test_default_paths_unix() {
        assert_eq!(DEFAULT_STATE_DIR, "/etc/huginn");
        assert_eq!(DEFAULT_BINARY_PATH, "/usr/local/bin/huginn-worker");
    }

    #[cfg(windows)]
    #[test]
    fn test_default_paths_windows() {
        assert_eq!(DEFAULT_STATE_DIR, "C:\\ProgramData\\Huginn");
        // The self-update target must carry the .exe extension.
        assert!(DEFAULT_BINARY_PATH.ends_with(".exe"));
        assert_eq!(
            DEFAULT_BINARY_PATH,
            "C:\\Program Files\\Huginn\\huginn-worker.exe"
        );
    }

    /// The Administrators group is granted by SID: a localized Windows has
    /// no "Administrators" name to resolve, and icacls would only warn.
    #[test]
    fn the_acl_grants_use_the_administrators_sid() {
        let grants = STATE_DIR_ACL_GRANTS.join(" ");
        assert!(
            grants.contains("*S-1-5-32-544"),
            "the Administrators SID is missing: {grants}"
        );
        assert!(
            !grants.contains("Administrators"),
            "the English group name must not be used: {grants}"
        );
        assert!(grants.contains("SYSTEM"), "SYSTEM must keep its grant");
    }
}

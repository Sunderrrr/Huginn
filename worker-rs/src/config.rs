// Worker build version, default paths, and on-disk state (hub URL + per-worker
// credentials). The state file is written 0600, atomically via tmp+rename.
//
// Rust port of worker/internal/config.
use std::fmt;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
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
pub const DEFAULT_STATE_DIR: &str = "/etc/huginn";
pub const DEFAULT_STATE_FILE: &str = "worker.json";
pub const DEFAULT_BINARY_PATH: &str = "/usr/local/bin/huginn-worker";

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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Json(e) => write!(f, "{e}"),
            Error::Identity => write!(f, "refusing to save state without worker identity"),
            Error::Parse { path, source } => write!(f, "parse state {path}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Json(e) | Error::Parse { source: e, .. } => Some(e),
            Error::Identity => None,
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
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let data = serde_json::to_vec_pretty(state).map_err(Error::Json)?;
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    {
        // 0600 from creation, mirroring os.WriteFile(tmp, data, 0o600).
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
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
            binary_path: "/opt/huginn".into(),
            ..Default::default()
        };
        assert_eq!(s.binary_location(), "/opt/huginn", "override not respected");
    }
}

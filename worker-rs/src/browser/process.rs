//! The `obscura serve` child process: spawn, readiness, and guaranteed
//! teardown. Linux only (the parent module is `#[cfg(target_os = "linux")]`).

use std::fmt;
use std::io::Read;
use std::time::Duration;

use std::process::Stdio;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Child;
use tokio::process::Command;

use super::ensure_obscura_installed;

/// How long `spawn_obscura` waits for the port to accept connections.
const PORT_READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Grace between SIGTERM and SIGKILL when killing the process group.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// Poll interval for the port-readiness loop.
const READY_POLL: Duration = Duration::from_millis(100);

/// Default per-worker memory cap (MB) passed to Obscura
/// (`--worker-max-rss`). The flag only takes effect with `--workers > 1`,
/// so the spawn always passes `--workers 2`.
pub(crate) const DEFAULT_MAX_RSS_MB: u64 = 512;

/// Random CDP bearer token: 32 bytes from `/dev/urandom`, hex-encoded (64
/// chars). Obscura requires ≥ 32 bytes. Never logged, never in Debug.
pub(crate) fn random_cdp_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    let mut file = std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(hex::encode(bytes))
}

/// Parse `HUGINN_BROWSER_MAX_RSS_MB` into a clamped per-worker memory cap.
/// Unset or unparsable → [`DEFAULT_MAX_RSS_MB`]; out-of-range values are
/// clamped into 64..=8192 MB (a cap below Obscura's own footprint would kill
/// the worker on startup, an unbounded one would defeat the flag).
pub(crate) fn parse_max_rss_mb(raw: Option<&str>) -> u64 {
    let Some(raw) = raw else {
        return DEFAULT_MAX_RSS_MB;
    };
    match raw.trim().parse::<u64>() {
        Ok(mb) => mb.clamp(64, 8192),
        Err(_) => DEFAULT_MAX_RSS_MB,
    }
}

/// Spawn options. `allow_private_network` lifts Obscura's SSRF guard so it
/// may navigate to loopback/private addresses — set only when the operator
/// explicitly opts in via `HUGINN_BROWSER_ALLOW_PRIVATE_NETWORK=1` (dev, and
/// the E2E test, whose fixture page is served on 127.0.0.1). Production
/// leaves it unset, so Obscura's SSRF protection stays fully on.
#[derive(Debug, Clone)]
pub struct ObscuraSpawn {
    pub allow_private_network: bool,
    /// Per-worker memory cap (MB) passed as `--worker-max-rss`.
    pub max_rss_mb: u64,
}

impl Default for ObscuraSpawn {
    fn default() -> Self {
        Self {
            allow_private_network: std::env::var("HUGINN_BROWSER_ALLOW_PRIVATE_NETWORK")
                .ok()
                .is_some_and(|v| v == "1"),
            max_rss_mb: parse_max_rss_mb(
                std::env::var("HUGINN_BROWSER_MAX_RSS_MB").ok().as_deref(),
            ),
        }
    }
}

/// A running `obscura serve` child: its own process group, an ephemeral
/// loopback port, and the bearer token Obscura demands on the WebSocket
/// handshake.
///
/// The token deliberately has NO accessor besides the private borrow the CDP
/// client takes, and `Debug` redacts it.
pub struct ObscuraProcess {
    pub(crate) child: Child,
    pub(crate) port: u16,
    pub(crate) token: String,
}

impl fmt::Debug for ObscuraProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token must never reach a log line via a Debug dump.
        f.debug_struct("ObscuraProcess")
            .field("port", &self.port)
            .field("pid", &self.child.id())
            .finish()
    }
}

impl Drop for ObscuraProcess {
    fn drop(&mut self) {
        // Panic safety: Drop cannot await, so reap synchronously. The whole
        // group gets SIGKILL; kill_on_drop covers the direct child too.
        if let Some(pid) = self.child.id() {
            // Negative pid addresses the process group (process_group(0)).
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
}

impl ObscuraProcess {
    /// The browser-level CDP WebSocket endpoint (loopback only).
    pub(crate) fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/devtools/browser", self.port)
    }

    /// The bearer token for the CDP handshake (never logged; never returned
    /// in an error).
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// Graceful shutdown: SIGTERM the whole process group, wait up to
    /// [`KILL_GRACE`], then SIGKILL the group. Consumes `self` so the task
    /// handler cannot forget it; the `Drop` impl is the backstop.
    pub async fn kill(mut self) {
        if let Some(pid) = self.child.id() {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
        }
        let deadline = tokio::time::Instant::now() + KILL_GRACE;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return, // reaped by the kill signal
                Ok(None) => {}
                Err(_) => break,
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(READY_POLL).await;
        }
        if let Some(pid) = self.child.id() {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        let _ = self.child.wait().await;
    }
}

/// Pick a free ephemeral port by binding to 127.0.0.1:0 and closing the
/// listener. If Obscura loses the race for it, it exits during the readiness
/// wait and the spawn fails loudly — never silently reuses a stranger's port.
async fn ephemeral_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| format!("pick ephemeral port: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("read ephemeral port: {e}"))?
        .port();
    Ok(port)
}

/// Whether the installed engine's `serve` supports `--worker-max-rss`.
/// The pinned v0.2.4 release predates the flag (it exists on Obscura's main
/// but shipped in no release yet); passing an unknown flag makes clap exit
/// with status 2, so the flag is probed from `serve --help` and the result
/// cached per binary path — a future pinned release gets the memory cap
/// applied automatically, with no worker change.
async fn supports_worker_max_rss(bin: &std::path::Path) -> bool {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, bool>>,
    > = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(known) = cache.lock().unwrap().get(bin) {
        return *known;
    }
    let supported = Command::new(bin)
        .args(["serve", "--help"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map(|out| {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            out.status.success() && text.contains("--worker-max-rss")
        })
        .unwrap_or(false);
    cache.lock().unwrap().insert(bin.to_path_buf(), supported);
    supported
}

/// Spawn `obscura serve --port <ephemeral> --workers 2 --max-connections 4`
/// (plus `--worker-max-rss <MB>` when the installed engine supports the flag)
/// with a random CDP bearer token, its own process group, and
/// `kill_on_drop`. `state_dir` widens the install search (see
/// [`ensure_obscura_installed`]). Waits until the port accepts connections
/// (or the child dies / the readiness window elapses).
///
/// Resource bounds: `--workers 2` bounds the parallel V8 worker processes
/// (and is the prerequisite for the recycle flags), `--max-connections 4`
/// bounds the live CDP connection threads (the worker opens exactly one),
/// and `--worker-max-rss` caps each worker's memory — but the pinned
/// v0.2.4 release predates that flag, so it is passed only when the
/// installed binary's `serve --help` advertises it (probed once per binary
/// path; a future pinned release picks the cap up automatically). The
/// whole-task timeout stays enforced by the worker — `obscura serve` has no
/// global timeout flag of its own.
pub async fn spawn_obscura(opts: ObscuraSpawn, state_dir: &str) -> Result<ObscuraProcess, String> {
    let bin = ensure_obscura_installed(state_dir)?;
    let port = ephemeral_port().await?;
    let token = random_cdp_token()?;

    // Pure argv — never a shell. The only interpolated values are the port
    // and the caps we just picked; the token rides in the environment, not
    // argv (it would be visible in /proc/<pid>/cmdline otherwise).
    let mut cmd = Command::new(&bin);
    cmd.args([
        "serve",
        "--port",
        &port.to_string(),
        "--workers",
        "2",
        "--max-connections",
        "4",
    ]);
    if supports_worker_max_rss(&bin).await {
        cmd.arg("--worker-max-rss").arg(opts.max_rss_mb.to_string());
    }
    cmd.env("OBSCURA_CDP_TOKEN", &token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    if opts.allow_private_network {
        cmd.env("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    let mut proc = ObscuraProcess { child, port, token };

    // Wait for the port to accept TCP connections.
    let deadline = tokio::time::Instant::now() + PORT_READY_TIMEOUT;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(proc);
        }
        match proc.child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "obscura exited during startup (status {status}); \
                     is the binary compatible with this system?"
                ))
            }
            Ok(None) => {}
            Err(e) => return Err(format!("obscura process error: {e}")),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "obscura did not become ready within {}s",
                PORT_READY_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

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
/// Timeout for the `serve --help` capability probe — a hanging engine must
/// not block the worker.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Set once the child has been REAPED. A reaped child's pid can be
    /// reused by an unrelated process, and the process-group id with it —
    /// so the group kill must never run after that point.
    pub(crate) reaped: bool,
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
        //
        // The group kill is skipped once the child has been reaped: a freed
        // pid may already belong to an unrelated process, and killing ITS
        // process group would take down a stranger's processes (the classic
        // pid-reuse race). While the child is unreaped it is a zombie and
        // its pid — and therefore the group id — is still reserved, so the
        // kill is safe.
        if self.reaped {
            return;
        }
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
    ///
    /// The child's exit is detected WITHOUT reaping it (`waitid` +
    /// `WNOWAIT`): a reaped pid can be handed to another process, and the
    /// process-group id with it — the final group kill would then hit an
    /// unrelated process group. The child is reaped only after the group
    /// has been killed.
    pub async fn kill(mut self) {
        let pid = self.child.id();
        if let Some(pid) = pid {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
        }
        let deadline = tokio::time::Instant::now() + KILL_GRACE;
        loop {
            match pid {
                Some(pid) if exited_without_reaping(pid) => break, // the child is gone
                Some(_) => {}
                None => break,
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(READY_POLL).await;
        }
        if let Some(pid) = pid {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        let _ = self.child.wait().await;
        self.reaped = true;
    }
}

/// Whether `pid` has exited, WITHOUT reaping it: the pid (and therefore the
/// process-group id) stays reserved while the child is a zombie, so a group
/// kill aimed at it cannot land on an unrelated process.
///
/// The check is thread-agnostic: `waitid()` only sees the children of the
/// CALLING thread (the engine is spawned and killed from different tokio
/// tasks), so the exit is read from `/proc/<pid>/stat` instead — a child
/// that exited but was not reaped is a zombie, and its state says so.
fn exited_without_reaping(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let state = stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .unwrap_or_default();
            // Z = zombie (exited, not reaped), X = dead.
            matches!(state, "Z" | "X" | "x")
        }
        // No /proc entry: the child is gone (reaped) — treat it as exited.
        Err(_) => exited_without_reaping_waitid(pid),
    }
}

/// Fallback for systems without /proc: `waitid` + `WNOWAIT` reports the
/// exit without reaping the child.
fn exited_without_reaping_waitid(pid: u32) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    if rc == 0 {
        return true;
    }
    // ECHILD: the child was already reaped (nothing of ours is left to
    // kill) — treat it as exited.
    let err = std::io::Error::last_os_error();
    err.raw_os_error() == Some(libc::ECHILD)
}

// --- CDP port ownership ----------------------------------------------------
//
// The CDP port is picked by binding an ephemeral socket and closing it, so
// there is a window in which a local attacker can take (or share, with
// SO_REUSEPORT) the port. The worker would then drive a stranger's CDP
// server and report its answers as the task result. These helpers answer
// "who listens on this loopback port?" straight from /proc.

/// The process groups of every process listening on `127.0.0.1:port`.
///
/// Returns None when the answer cannot be determined (no /proc, no
/// permission) — the caller then skips the check rather than failing a
/// healthy browser task.
pub(crate) fn cdp_port_owners(port: u16) -> Option<Vec<u32>> {
    let inodes = listening_socket_inodes(port)?;
    let mut owners = Vec::new();
    for inode in inodes {
        let Some(pid) = pid_of_socket_inode(inode) else {
            continue;
        };
        if let Some(pgid) = process_group_of(pid) {
            owners.push(pgid);
        }
    }
    Some(owners)
}

/// The inodes of every LISTEN socket bound to 127.0.0.1:port (from
/// /proc/net/tcp).
pub(crate) fn listening_socket_inodes(port: u16) -> Option<Vec<u64>> {
    let table = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let wanted = format!("0100007F:{port:04X}");
    let mut inodes = Vec::new();
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        // f[1] = local address, f[3] = state (0A = LISTEN), f[9] = inode.
        if f[1] != wanted || f[3] != "0A" {
            continue;
        }
        if let Ok(inode) = f[9].parse::<u64>() {
            inodes.push(inode);
        }
    }
    Some(inodes)
}

/// The pid holding a socket with that inode (scan /proc/<pid>/fd).
pub(crate) fn pid_of_socket_inode(inode: u64) -> Option<u32> {
    let wanted = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                if link.to_string_lossy() == wanted {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// The process group of a pid (from /proc/<pid>/stat). The `comm` field may
/// contain spaces and parentheses, so the fields are taken after the LAST
/// ')': state, ppid, pgrp, …
pub(crate) fn process_group_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next()?;
    let _ppid = fields.next()?;
    fields.next()?.parse().ok()
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
    let supported = tokio::time::timeout(
        PROBE_TIMEOUT,
        Command::new(bin)
            .args(["serve", "--help"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .ok()
    .and_then(|out| out.ok())
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
    let mut proc = ObscuraProcess {
        child,
        port,
        token,
        reaped: false,
    };

    // Wait for the port to accept TCP connections.
    let deadline = tokio::time::Instant::now() + PORT_READY_TIMEOUT;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            // The CDP port was picked by binding an ephemeral socket and
            // closing it: a LOCAL attacker can win that race and hold the
            // port (or share it with SO_REUSEPORT), and the worker would
            // then talk to a stranger's server and report attacker-chosen
            // page content. The listening socket(s) must belong to our own
            // process group — the child was spawned as a group leader, so
            // its descendants inherit the group.
            if let Some(owners) = cdp_port_owners(port) {
                let ours = proc.child.id().unwrap_or(0);
                if let Some(foreign) = owners.iter().find(|pgid| **pgid != ours) {
                    return Err(format!(
                        "the CDP port {port} is held by a foreign process (pgid {foreign}) — \
                         refusing to talk to it"
                    ));
                }
            }
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

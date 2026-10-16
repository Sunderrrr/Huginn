//! Browser automation: management of the Obscura headless-browser process
//! plus a minimal CDP (Chrome DevTools Protocol) client, and the `browser`
//! task handler. Linux only — this module is compiled `#[cfg(target_os =
//! "linux")]` (see main.rs); every other OS answers "browser not supported
//! on this OS" in the dispatcher.
//!
//! # Architecture
//!
//! ```text
//! run_browser_task
//!   ├─ ensure Obscura is installed (<root>/<version>/obscura)
//!   ├─ spawn `obscura serve --port <ephemeral>`   (pure argv, own process
//!   │   group, kill_on_drop, 127.0.0.1 only, random bearer token)
//!   ├─ CDP WebSocket → ws://127.0.0.1:<port>/devtools/browser
//!   ├─ Target.createTarget → attachToTarget → Page.enable
//!   ├─ steps: navigate/click/type/eval/screenshot/get_text/get_html/wait_for
//!   ├─ Target.closeTarget
//!   └─ kill the whole process group (SIGTERM → 5s → SIGKILL)
//! ```
//!
//! # Security invariants
//!
//! - Obscura is spawned with pure argv — never a shell. The URL/port are the
//!   only interpolation points and are worker-generated.
//! - The CDP bearer token is random (32 bytes from `/dev/urandom`, 64 hex
//!   chars) and NEVER appears in a log line, error message, or Debug output
//!   (`ObscuraProcess` implements Debug by hand, redacting it).
//! - The listening port is ephemeral and bound to 127.0.0.1 only; no port
//!   above 1024 is ever exposed on another interface.
//! - The process (and its whole group) is killed on completion, on step
//!   failure, on global timeout, and on drop — a panic mid-task still reaps
//!   it (`kill_on_drop` plus a synchronous group kill in `Drop`).
//! - Step payloads are re-validated here even though the hub already checked
//!   them: URL scheme/length, script size, selector size, typed-text size,
//!   step count and global timeout. A hostile hub must not be able to
//!   smuggle a step field past the worker.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::process::Stdio;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Child;
use tokio::process::Command;
use tokio_tungstenite::connect_async_tls_with_config;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::hubclient::{Task, TaskResult};

// ---------------------------------------------------------------------------
// Limits (mirrored by the hub's create path; enforced again here)
// ---------------------------------------------------------------------------

/// Maximum number of steps per task.
pub const MAX_STEPS: usize = 50;
/// Maximum size of one `eval` script.
pub const MAX_STEP_JS: usize = 64 * 1024;
/// Maximum length of one CSS selector.
pub const MAX_SELECTOR: usize = 512;
/// Maximum size of the text a `type` step may insert.
pub const MAX_TYPE_TEXT: usize = 10 * 1024;
/// Maximum length of a `navigate` URL (and http(s) only).
pub const MAX_URL_CHARS: usize = 2048;
/// Hard cap on the whole-task timeout.
pub const MAX_TIMEOUT_SECONDS: u64 = 300;
/// Default whole-task timeout when the payload omits one.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 120;
/// A screenshot's base64 payload must stay under this, else the step fails.
pub const MAX_SCREENSHOT_B64: usize = 900 * 1024;
/// Default JPEG quality for screenshots.
pub const DEFAULT_JPEG_QUALITY: u8 = 80;
/// Default (and maximum) `wait_for` step timeout in milliseconds.
pub const MAX_WAIT_FOR_MS: u64 = 60_000;

/// Default Obscura install root: `<root>/<version>/obscura`. Overridable via
/// the `HUGINN_OBSCURA_DIR` environment variable (tests/dev).
pub const OBSCURA_INSTALL_ROOT: &str = "/opt/huginn/obscura";

/// How long `spawn_obscura` waits for the port to accept connections.
const PORT_READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Grace between SIGTERM and SIGKILL when killing the process group.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// Per-CDP-command timeouts.
const CMD_TIMEOUT: Duration = Duration::from_secs(30);
const NAVIGATE_TIMEOUT: Duration = Duration::from_secs(60);
const EVAL_TIMEOUT: Duration = Duration::from_secs(45);
const SCREENSHOT_TIMEOUT: Duration = Duration::from_secs(60);
/// Extra wait for the load event after `Page.navigate` answered.
const LOAD_EVENT_GRACE: Duration = Duration::from_secs(10);
/// Poll interval for `wait_for_selector` and the port-readiness loop.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Per-step stdout contribution cap (a `get_html` can be huge).
const MAX_STEP_OUTPUT: usize = 128 * 1024;
/// Whole-task stdout cap (matches `exec::DEFAULT_MAX_OUTPUT_BYTES`).
const MAX_STDOUT: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Obscura install discovery
// ---------------------------------------------------------------------------

/// Parse a version directory name (`v0.2.4` / `0.2.4`) into comparable
/// numeric parts. Non-version directories are skipped by the caller.
fn parse_version(name: &str) -> Option<Vec<u64>> {
    let trimmed = name.trim_start_matches('v');
    let mut parts = Vec::new();
    for part in trimmed.split('.') {
        parts.push(part.parse::<u64>().ok()?);
    }
    Some(parts)
}

/// The newest `<root>/<version>/obscura` binary under one install root.
fn newest_binary(root: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    let mut best: Option<(Vec<u64>, PathBuf)> = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(version) = parse_version(name) else {
            continue;
        };
        let bin = entry.path().join("obscura");
        if !bin.is_file() {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(best_version, _)| version > *best_version)
        {
            best = Some((version, bin));
        }
    }
    best.map(|(_, bin)| bin)
}

/// Install roots to search, in order: `$HUGINN_OBSCURA_DIR` when set, else
/// [`OBSCURA_INSTALL_ROOT`] and `<state_dir>/obscura` (a state-local install
/// for dev setups).
fn install_roots(state_dir: &str) -> Vec<PathBuf> {
    if let Ok(root) = std::env::var("HUGINN_OBSCURA_DIR") {
        if !root.is_empty() {
            return vec![PathBuf::from(root)];
        }
    }
    let mut roots = vec![PathBuf::from(OBSCURA_INSTALL_ROOT)];
    if !state_dir.is_empty() {
        let local = Path::new(state_dir).join("obscura");
        if !roots.contains(&local) {
            roots.push(local);
        }
    }
    roots
}

/// Resolve the Obscura binary to run — the `ensure_obscura_installed` gate:
/// search [`install_roots`] for the newest `<root>/<version>/obscura`. The
/// error names every root searched so an operator sees exactly what is
/// missing. `state_dir` widens the search (a state-local install for dev
/// setups); production installs live under [`OBSCURA_INSTALL_ROOT`].
pub fn ensure_obscura_installed(state_dir: &str) -> Result<PathBuf, String> {
    let roots = install_roots(state_dir);
    for root in &roots {
        if let Some(bin) = newest_binary(root) {
            return Ok(bin);
        }
    }
    let searched: Vec<String> = roots.iter().map(|r| r.display().to_string()).collect();
    Err(format!(
        "obscura is not installed (searched for <root>/<version>/obscura in: {}); \
         install it under {}/<version>/ or set HUGINN_OBSCURA_DIR",
        searched.join(", "),
        OBSCURA_INSTALL_ROOT
    ))
}

// ---------------------------------------------------------------------------
// Obscura process management
// ---------------------------------------------------------------------------

/// Random CDP bearer token: 32 bytes from `/dev/urandom`, hex-encoded (64
/// chars). Obscura requires ≥ 32 bytes. Never logged, never in Debug.
fn random_cdp_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    let mut file = std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(hex::encode(bytes))
}

/// Spawn options. `allow_private_network` lifts Obscura's SSRF guard so it
/// may navigate to loopback/private addresses — set only when the operator
/// explicitly opts in via `HUGINN_BROWSER_ALLOW_PRIVATE_NETWORK=1` (dev, and
/// the E2E test, whose fixture page is served on 127.0.0.1). Production
/// leaves it unset, so Obscura's SSRF protection stays fully on.
#[derive(Debug, Clone)]
pub struct ObscuraSpawn {
    pub allow_private_network: bool,
}

impl Default for ObscuraSpawn {
    fn default() -> Self {
        Self {
            allow_private_network: std::env::var("HUGINN_BROWSER_ALLOW_PRIVATE_NETWORK")
                .ok()
                .is_some_and(|v| v == "1"),
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
    child: Child,
    port: u16,
    token: String,
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
    fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/devtools/browser", self.port)
    }

    /// The bearer token for the CDP handshake (never logged; never returned
    /// in an error).
    fn token(&self) -> &str {
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
            tokio::time::sleep(POLL_INTERVAL).await;
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

/// Spawn `obscura serve --port <ephemeral>` with a random CDP bearer token,
/// its own process group, and `kill_on_drop`. `state_dir` widens the install
/// search (see [`ensure_obscura_installed`]). Waits until the port accepts
/// connections (or the child dies / the readiness window elapses).
pub async fn spawn_obscura(opts: ObscuraSpawn, state_dir: &str) -> Result<ObscuraProcess, String> {
    let bin = ensure_obscura_installed(state_dir)?;
    let port = ephemeral_port().await?;
    let token = random_cdp_token()?;

    // Pure argv — never a shell. The only interpolated value is the port we
    // just picked; the token rides in the environment, not argv (it would be
    // visible in /proc/<pid>/cmdline otherwise).
    let mut cmd = Command::new(&bin);
    cmd.args(["serve", "--port", &port.to_string()])
        .env("OBSCURA_CDP_TOKEN", &token)
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
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ---------------------------------------------------------------------------
// CDP client
// ---------------------------------------------------------------------------

/// One decoded CDP WebSocket frame: either a JSON-RPC response (matched by
/// id) or an event. Pure function over the wire bytes — unit-testable without
/// a browser.
#[derive(Debug, Clone, PartialEq)]
pub enum CdpFrame {
    Response {
        id: u64,
        result: Option<Value>,
        error: Option<String>,
    },
    Event {
        method: String,
    },
    /// Not JSON, or neither an id-carrying response nor a method-carrying
    /// event.
    Malformed,
}

/// Classify one raw CDP WebSocket text frame.
pub fn classify_cdp_frame(text: &str) -> CdpFrame {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return CdpFrame::Malformed;
    };
    if let Some(id) = value.get("id").and_then(Value::as_u64) {
        let result = value.get("result").cloned();
        let error = value
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        return CdpFrame::Response { id, result, error };
    }
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        return CdpFrame::Event {
            method: method.to_owned(),
        };
    }
    CdpFrame::Malformed
}

/// Minimal CDP client: one WebSocket, JSON-RPC with auto ids, one attached
/// target. No SDK — the whole protocol surface used here is ~8 methods.
pub struct CdpClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    target_id: String,
    session_id: String,
    /// Set when a `Page.loadEventFired` event was seen since the last
    /// navigation started.
    load_fired: bool,
}

impl CdpClient {
    /// Open the browser-level WebSocket, authenticating with the bearer
    /// token. The token travels in a request header and never enters an
    /// error string (tungstenite errors quote the URL, never the headers).
    pub async fn connect(url: &str, token: &str) -> Result<Self, String> {
        let mut request = url
            .into_client_request()
            .map_err(|e| format!("cdp url: {e}"))?;
        let bearer = format!("Bearer {token}");
        request
            .headers_mut()
            .insert("authorization", bearer.parse().map_err(|_| "cdp header")?);
        let (ws, _response) = connect_async_tls_with_config(request, None, true, None)
            .await
            .map_err(|e| format!("cdp connect failed: {e}"))?;
        Ok(Self {
            ws,
            next_id: 0,
            target_id: String::new(),
            session_id: String::new(),
            load_fired: false,
        })
    }

    /// Read one frame with a deadline.
    async fn read_frame(&mut self, deadline: tokio::time::Instant) -> Result<Message, String> {
        let frame = tokio::time::timeout_at(deadline, self.ws.next())
            .await
            .map_err(|_| "cdp command timed out".to_owned())?;
        match frame {
            None => Err("cdp connection closed".into()),
            Some(Ok(message)) => Ok(message),
            Some(Err(e)) => Err(format!("cdp connection error: {e}")),
        }
    }

    /// Send one browser-level command (no session) and await its response.
    async fn send_browser(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.send_raw(method, params, false, timeout).await
    }

    /// Send one session-bound command and await its response. Events seen
    /// while waiting update `load_fired`; everything else is ignored.
    async fn send_session(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.send_raw(method, params, true, timeout).await
    }

    async fn send_raw(
        &mut self,
        method: &str,
        params: Value,
        with_session: bool,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if with_session && !self.session_id.is_empty() {
            message["sessionId"] = json!(self.session_id);
        }
        self.ws
            .send(Message::Text(message.to_string()))
            .await
            .map_err(|e| format!("cdp send failed: {e}"))?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.read_frame(deadline).await? {
                Message::Text(text) => match classify_cdp_frame(&text) {
                    CdpFrame::Response {
                        id: rid,
                        result,
                        error,
                    } if rid == id => {
                        return match error {
                            Some(error) => Err(format!("cdp {method} failed: {error}")),
                            None => Ok(result.unwrap_or(Value::Null)),
                        };
                    }
                    CdpFrame::Event { method: ref event } if event == "Page.loadEventFired" => {
                        self.load_fired = true;
                    }
                    _ => {}
                },
                Message::Close(_) => return Err("cdp connection closed".into()),
                // Pings are answered by tungstenite on the next read/write;
                // binary frames never occur on this connection.
                _ => {}
            }
        }
    }

    /// `Target.createTarget` + `Target.attachToTarget` + `Page.enable`: open
    /// a tab and bind this client to it. `url` is normally `about:blank`; the
    /// real page is reached with an explicit [`CdpClient::navigate`] step so
    /// the load event is observable.
    pub async fn create_target(&mut self, url: &str) -> Result<(), String> {
        let res = self
            .send_browser("Target.createTarget", json!({ "url": url }), CMD_TIMEOUT)
            .await?;
        self.target_id = res
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| "cdp createTarget: missing targetId".to_owned())?
            .to_owned();
        let res = self
            .send_browser(
                "Target.attachToTarget",
                json!({ "targetId": self.target_id, "flatten": true }),
                CMD_TIMEOUT,
            )
            .await?;
        self.session_id = res
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| "cdp attachToTarget: missing sessionId".to_owned())?
            .to_owned();
        // Page.enable makes the initial about:blank load events flow; they
        // are consumed (and flag `load_fired`) by the response wait.
        self.send_session("Page.enable", json!({}), CMD_TIMEOUT)
            .await?;
        Ok(())
    }

    /// `Page.navigate` + wait for the load event. Obscura only answers the
    /// navigate command after the navigation settles, so the response and
    /// the load event arrive back to back (either order).
    pub async fn navigate(&mut self, url: &str) -> Result<(), String> {
        self.load_fired = false;
        self.send_session("Page.navigate", json!({ "url": url }), NAVIGATE_TIMEOUT)
            .await?;
        let deadline = tokio::time::Instant::now() + LOAD_EVENT_GRACE;
        while !self.load_fired {
            match self.read_frame(deadline).await? {
                Message::Text(text) => match classify_cdp_frame(&text) {
                    CdpFrame::Event { method } if method == "Page.loadEventFired" => {
                        self.load_fired = true;
                    }
                    _ => {}
                },
                Message::Close(_) => return Err("cdp connection closed".into()),
                _ => {}
            }
        }
        Ok(())
    }

    /// `Runtime.evaluate` with `returnByValue`. A thrown exception becomes an
    /// error carrying the (truncated) exception text.
    pub async fn eval(&mut self, js: &str) -> Result<Value, String> {
        let res = self
            .send_session(
                "Runtime.evaluate",
                json!({ "expression": js, "returnByValue": true }),
                EVAL_TIMEOUT,
            )
            .await?;
        if let Some(details) = res.get("exceptionDetails") {
            return Err(format!("eval threw: {}", exception_text(details)));
        }
        Ok(res
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// `Page.captureScreenshot`. Obscura encodes JPEG natively (`format`
    /// jpeg/png + `quality`), so no PNG→JPEG conversion happens here; the
    /// base64 payload is validated (decodes, right magic, non-empty) and
    /// capped at [`MAX_SCREENSHOT_B64`].
    pub async fn screenshot(
        &mut self,
        format: ScreenshotFormat,
        quality: u8,
    ) -> Result<String, String> {
        let fmt = match format {
            ScreenshotFormat::Jpeg => "jpeg",
            ScreenshotFormat::Png => "png",
        };
        let mut params = json!({ "format": fmt });
        if format == ScreenshotFormat::Jpeg {
            params["quality"] = json!(quality);
        }
        let res = self
            .send_session("Page.captureScreenshot", params, SCREENSHOT_TIMEOUT)
            .await?;
        let data = res
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| "cdp captureScreenshot: missing data".to_owned())?
            .to_owned();
        if data.len() > MAX_SCREENSHOT_B64 {
            return Err(format!(
                "screenshot too large ({} KiB base64, cap {} KiB)",
                data.len() / 1024,
                MAX_SCREENSHOT_B64 / 1024
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&data)
            .map_err(|e| format!("screenshot decode failed: {e}"))?;
        let ok = match format {
            ScreenshotFormat::Jpeg => bytes.starts_with(&[0xFF, 0xD8]),
            ScreenshotFormat::Png => bytes.starts_with(b"\x89PNG"),
        };
        if !ok || bytes.is_empty() {
            return Err("screenshot is not a valid image".into());
        }
        Ok(data)
    }

    /// Click the first element matching `selector` (via `Runtime.evaluate`).
    pub async fn click_selector(&mut self, selector: &str) -> Result<(), String> {
        let js = format!(
            "(function(){{var el=document.querySelector({});\
             if(!el){{return 'not-found'}};el.click();return 'ok'}})()",
            js_string(selector)
        );
        selector_result(self.eval(&js).await, selector, "click")
    }

    /// Focus `selector` and insert `text` through `Input.insertText` (the
    /// text never enters a JS string — Obscura handles the escaping).
    pub async fn type_selector(&mut self, selector: &str, text: &str) -> Result<(), String> {
        let js = format!(
            "(function(){{var el=document.querySelector({});\
             if(!el){{return 'not-found'}};el.focus();return 'ok'}})()",
            js_string(selector)
        );
        selector_result(self.eval(&js).await, selector, "focus")?;
        self.send_session("Input.insertText", json!({ "text": text }), CMD_TIMEOUT)
            .await?;
        Ok(())
    }

    /// `document.body.innerText`.
    pub async fn get_text(&mut self) -> Result<String, String> {
        self.eval("document.body ? document.body.innerText : ''")
            .await
            .and_then(value_to_string)
    }

    /// `document.documentElement.outerHTML`.
    pub async fn get_html(&mut self) -> Result<String, String> {
        self.eval("document.documentElement ? document.documentElement.outerHTML : ''")
            .await
            .and_then(value_to_string)
    }

    /// Poll `document.querySelector(sel)` every 100 ms until it exists or
    /// `timeout` elapses.
    pub async fn wait_for_selector(
        &mut self,
        selector: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let js = format!("document.querySelector({}) !== null", js_string(selector));
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.eval(&js).await? == Value::Bool(true) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timeout waiting for selector {}",
                    js_string(selector)
                ));
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// `Target.closeTarget` — best effort; the process dies with the task.
    pub async fn close_target(&mut self) {
        if !self.target_id.is_empty() {
            let _ = self
                .send_browser(
                    "Target.closeTarget",
                    json!({ "targetId": self.target_id }),
                    CMD_TIMEOUT,
                )
                .await;
        }
    }
}

/// Map an eval'd `'ok' | 'not-found'` sentinel to a step result.
fn selector_result(
    value: Result<Value, String>,
    selector: &str,
    action: &str,
) -> Result<(), String> {
    match value {
        Ok(Value::String(s)) if s == "ok" => Ok(()),
        Ok(Value::String(s)) if s == "not-found" => Err(format!(
            "selector not found for {action}: {}",
            truncate_chars(selector, 120)
        )),
        Ok(_) => Err(format!("{action} failed")),
        Err(e) => Err(e),
    }
}

fn value_to_string(value: Value) -> Result<String, String> {
    match value {
        Value::String(s) => Ok(s),
        Value::Null => Ok(String::new()),
        other => Ok(other.to_string()),
    }
}

/// The exception description of a `Runtime.evaluate` failure, truncated.
fn exception_text(details: &Value) -> String {
    let text = details
        .get("exception")
        .and_then(|e| e.get("description"))
        .or_else(|| details.get("exception").and_then(|e| e.get("value")))
        .and_then(Value::as_str)
        .or_else(|| details.get("text").and_then(Value::as_str))
        .unwrap_or("unknown error");
    truncate_chars(text, 512)
}

/// Encode `s` as a JavaScript string literal. JSON string encoding is a
/// valid JS literal on every engine Obscura ships (ES2019+), and it cannot
/// be escaped out of by selector content.
fn js_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}

/// Character-count truncation (UTF-8 boundary safe), with a marker.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut cut = String::new();
    for c in text.chars().take(max) {
        cut.push(c);
    }
    cut.push_str("...");
    cut
}

// ---------------------------------------------------------------------------
// Step parsing (worker-side re-validation of the hub's payload)
// ---------------------------------------------------------------------------

/// Screenshot encoding requested by a `screenshot` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenshotFormat {
    Jpeg,
    Png,
}

/// One validated browser step.
#[derive(Debug, Clone, PartialEq)]
pub enum BrowserStep {
    Navigate {
        url: String,
    },
    Click {
        selector: String,
    },
    Type {
        selector: String,
        text: String,
    },
    Eval {
        js: String,
    },
    Screenshot {
        format: ScreenshotFormat,
        quality: u8,
    },
    GetText,
    GetHtml,
    WaitFor {
        selector: String,
        timeout_ms: u64,
    },
}

impl BrowserStep {
    /// The step's `action` label (used in output lines and error messages).
    pub fn action(&self) -> &'static str {
        match self {
            BrowserStep::Navigate { .. } => "navigate",
            BrowserStep::Click { .. } => "click",
            BrowserStep::Type { .. } => "type",
            BrowserStep::Eval { .. } => "eval",
            BrowserStep::Screenshot { .. } => "screenshot",
            BrowserStep::GetText => "get_text",
            BrowserStep::GetHtml => "get_html",
            BrowserStep::WaitFor { .. } => "wait_for",
        }
    }
}

/// http(s):// only, printable ASCII, non-empty remainder, ≤
/// [`MAX_URL_CHARS`] — the same gate the hub applies; `file://` and
/// `javascript://` die here even if a hostile hub skipped its check.
pub fn navigate_url_allowed(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else {
        return false;
    };
    if rest.is_empty() {
        return false; // scheme-only ("https://") navigates nowhere
    }
    let printable = url.chars().all(|c| ('\x21'..='\x7e').contains(&c));
    printable && url.chars().count() <= MAX_URL_CHARS
}

/// Parse and validate one step object (0-based `idx` for error messages).
fn parse_step(idx: usize, step: &Value) -> Result<BrowserStep, String> {
    let position = idx + 1;
    let obj = step
        .as_object()
        .ok_or_else(|| format!("step {position} must be a JSON object"))?;
    let action = obj
        .get("action")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| format!("step {position} has no action"))?;

    let field_str = |name: &str| obj.get(name).and_then(Value::as_str);
    let require_len = |name: &str, value: &str, max: usize| -> Result<(), String> {
        if value.is_empty() {
            Err(format!("step {position} {action} requires {name}"))
        } else if value.len() > max {
            Err(format!(
                "step {position} {action} {name} exceeds {max} bytes"
            ))
        } else {
            Ok(())
        }
    };

    match action {
        "navigate" => {
            let url = field_str("url").unwrap_or("");
            if url.is_empty() {
                return Err(format!("step {position} navigate requires url"));
            }
            if !navigate_url_allowed(url) {
                return Err(format!(
                    "step {position} navigate url must be http(s):// and at most {MAX_URL_CHARS} characters"
                ));
            }
            Ok(BrowserStep::Navigate { url: url.to_owned() })
        }
        "click" => {
            let selector = field_str("selector").unwrap_or("");
            require_len("selector", selector, MAX_SELECTOR)?;
            Ok(BrowserStep::Click {
                selector: selector.to_owned(),
            })
        }
        "type" => {
            let selector = field_str("selector").unwrap_or("");
            let text = field_str("text").unwrap_or("");
            require_len("selector", selector, MAX_SELECTOR)?;
            if text.len() > MAX_TYPE_TEXT {
                return Err(format!(
                    "step {position} type text exceeds {MAX_TYPE_TEXT} bytes"
                ));
            }
            Ok(BrowserStep::Type {
                selector: selector.to_owned(),
                text: text.to_owned(),
            })
        }
        "eval" => {
            let js = field_str("js").unwrap_or("");
            require_len("js", js, MAX_STEP_JS)?;
            Ok(BrowserStep::Eval { js: js.to_owned() })
        }
        "screenshot" => {
            let format = match field_str("format").unwrap_or("jpeg") {
                "jpeg" => ScreenshotFormat::Jpeg,
                "png" => ScreenshotFormat::Png,
                other => {
                    return Err(format!(
                        "step {position} screenshot format must be jpeg or png (got {other:?})"
                    ))
                }
            };
            let quality = obj
                .get("quality")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_JPEG_QUALITY as u64)
                .min(100) as u8;
            Ok(BrowserStep::Screenshot { format, quality })
        }
        "get_text" => Ok(BrowserStep::GetText),
        "get_html" => Ok(BrowserStep::GetHtml),
        "wait_for" => {
            let selector = field_str("selector").unwrap_or("");
            require_len("selector", selector, MAX_SELECTOR)?;
            let timeout_ms = obj
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(5_000)
                .min(MAX_WAIT_FOR_MS);
            Ok(BrowserStep::WaitFor {
                selector: selector.to_owned(),
                timeout_ms,
            })
        }
        other => Err(format!(
            "step {position} unknown action {other:?} (expected navigate, click, type, eval, screenshot, get_text, get_html or wait_for)"
        )),
    }
}

/// Parse the whole task payload: `{"steps": [...], "timeout": s}`. Validates
/// the step count (1..=MAX_STEPS) and every step (see [`parse_step`]), and
/// clamps the global timeout to 1..=[`MAX_TIMEOUT_SECONDS`] (default
/// [`DEFAULT_TIMEOUT_SECONDS`]).
pub fn parse_steps(
    payload: &serde_json::Map<String, Value>,
) -> Result<(Vec<BrowserStep>, Duration), String> {
    let steps_value = payload
        .get("steps")
        .ok_or_else(|| "browser task has no steps".to_owned())?;
    let items = steps_value
        .as_array()
        .ok_or_else(|| "steps must be a JSON array".to_owned())?;
    if items.is_empty() {
        return Err("steps must contain at least one step".into());
    }
    if items.len() > MAX_STEPS {
        return Err(format!("steps must have at most {MAX_STEPS} items"));
    }
    let steps: Vec<BrowserStep> = items
        .iter()
        .enumerate()
        .map(|(idx, step)| parse_step(idx, step))
        .collect::<Result<_, _>>()?;
    let timeout = payload
        .get("timeout")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS);
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&timeout) {
        return Err(format!(
            "timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
        ));
    }
    Ok((steps, Duration::from_secs(timeout)))
}

// ---------------------------------------------------------------------------
// The browser task handler
// ---------------------------------------------------------------------------

/// Run one `browser` task end to end. `state_dir` widens the Obscura install
/// search (a state-local `<state_dir>/obscura/<version>/obscura` is accepted
/// for dev setups). The Obscura process is killed on every path — success,
/// step failure, validation failure, and timeout; `kill_on_drop` plus the
/// `Drop` group-kill cover panics and cancellations.
pub async fn run_browser_task(task: &Task, state_dir: &str) -> TaskResult {
    let (steps, timeout) = match parse_steps(&task.payload) {
        Ok(parsed) => parsed,
        Err(e) => return failed(&e),
    };
    let obscura = match spawn_obscura(ObscuraSpawn::default(), state_dir).await {
        Ok(obscura) => obscura,
        Err(e) => return failed(&e),
    };

    let mut stdout = String::new();
    let run = execute_steps(&obscura, &steps, &mut stdout);
    let (status, exit_code, error) = match tokio::time::timeout(timeout, run).await {
        Ok(Ok(())) => ("succeeded".to_owned(), Some(0), None),
        Ok(Err(e)) => ("failed".to_owned(), None, Some(e)),
        Err(_elapsed) => (
            "timeout".to_owned(),
            None,
            Some(format!(
                "browser task exceeded its {}s timeout",
                timeout.as_secs()
            )),
        ),
    };

    // The process dies here on every path — result, error, timeout, panic
    // (Drop backstop) — never outliving the task.
    obscura.kill().await;

    TaskResult {
        status,
        exit_code,
        stdout,
        stderr: String::new(),
        error: error.unwrap_or_default(),
    }
}

/// A failed task result with a reason and no output.
fn failed(reason: &str) -> TaskResult {
    TaskResult {
        status: "failed".into(),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        error: reason.to_owned(),
    }
}

/// Drive the CDP session through the steps, appending one output line per
/// step to `stdout` (screenshots as `data:image/...;base64,...` tags).
/// Typed text is NEVER echoed — a `type` step can carry a password.
async fn execute_steps(
    obscura: &ObscuraProcess,
    steps: &[BrowserStep],
    stdout: &mut String,
) -> Result<(), String> {
    let mut client = CdpClient::connect(&obscura.ws_url(), obscura.token())
        .await
        .map_err(|e| format!("cdp connect: {e}"))?;
    let result = drive_steps(&mut client, steps, stdout).await;
    client.close_target().await;
    result
}

async fn drive_steps(
    client: &mut CdpClient,
    steps: &[BrowserStep],
    stdout: &mut String,
) -> Result<(), String> {
    client.create_target("about:blank").await?;
    for (idx, step) in steps.iter().enumerate() {
        let position = idx + 1;
        let action = step.action();
        let outcome: Result<Option<String>, String> = match step {
            BrowserStep::Navigate { url } => client.navigate(url).await.map(|_| Some(url.clone())),
            BrowserStep::Click { selector } => client
                .click_selector(selector)
                .await
                .map(|_| Some(selector.clone())),
            // The typed text is never echoed to the output.
            BrowserStep::Type { selector, text } => client
                .type_selector(selector, text)
                .await
                .map(|_| Some(selector.clone())),
            BrowserStep::Eval { js } => client.eval(js).await.map(|v| Some(v.to_string())),
            BrowserStep::Screenshot { format, quality } => client
                .screenshot(*format, *quality)
                .await
                .map(|data| Some(data_uri(*format, &data))),
            BrowserStep::GetText => client.get_text().await.map(Some),
            BrowserStep::GetHtml => client.get_html().await.map(Some),
            BrowserStep::WaitFor {
                selector,
                timeout_ms,
            } => client
                .wait_for_selector(selector, Duration::from_millis(*timeout_ms))
                .await
                .map(|_| Some(selector.clone())),
        };
        match outcome {
            Ok(detail) => {
                let line = match detail {
                    Some(text) => truncate_chars(&text, MAX_STEP_OUTPUT),
                    None => String::new(),
                };
                push_step_line(stdout, position, action, &line);
            }
            Err(e) => {
                return Err(format!("step {position} ({action}) failed: {e}"));
            }
        }
    }
    Ok(())
}

/// `data:` URI tag for an embedded screenshot.
fn data_uri(format: ScreenshotFormat, base64_data: &str) -> String {
    match format {
        ScreenshotFormat::Jpeg => format!("data:image/jpeg;base64,{base64_data}"),
        ScreenshotFormat::Png => format!("data:image/png;base64,{base64_data}"),
    }
}

/// Append one `step N (action): detail` line, keeping the total stdout under
/// [`MAX_STDOUT`] (the hub truncates too; the worker keeps the submit payload
/// bounded).
fn push_step_line(stdout: &mut String, position: usize, action: &str, detail: &str) {
    if stdout.len() >= MAX_STDOUT {
        return; // already at the cap
    }
    let line = format!("step {position} ({action}): {detail}\n");
    if stdout.len() + line.len() > MAX_STDOUT {
        stdout.push_str("[...output truncated...]\n");
        return;
    }
    stdout.push_str(&line);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Serializes env mutation/reads of `HUGINN_OBSCURA_DIR` between the unit
/// tests and the E2E test (cargo runs test fns in parallel). A tokio mutex so
/// the E2E test can hold it across awaits; sync tests use `blocking_lock`.
#[cfg(test)]
static ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    // ---- CDP frame classification (mock bytes, no browser) -----------------

    #[test]
    fn cdp_frames_classify_like_the_wire_protocol() {
        use CdpFrame::*;
        // A success response.
        assert_eq!(
            classify_cdp_frame(r#"{"id":7,"result":{"targetId":"page-1"}}"#),
            Response {
                id: 7,
                result: Some(json!({"targetId": "page-1"})),
                error: None,
            }
        );
        // An error response.
        assert_eq!(
            classify_cdp_frame(r#"{"id":8,"error":{"code":-32000,"message":"nope"}}"#),
            Response {
                id: 8,
                result: None,
                error: Some("nope".into()),
            }
        );
        // Events (with and without a session).
        assert_eq!(
            classify_cdp_frame(
                r#"{"method":"Page.loadEventFired","params":{"timestamp":1.0},"sessionId":"s"}"#
            ),
            Event {
                method: "Page.loadEventFired".into()
            }
        );
        assert_eq!(
            classify_cdp_frame(r#"{"method":"Target.targetCreated","params":{}}"#),
            Event {
                method: "Target.targetCreated".into()
            }
        );
        // Malformed frames never match an id or method.
        for bad in [
            "",
            "not json",
            r#"{"params":{}}"#,
            r#"{"foo":1}"#,
            r#"{"id":"x"}"#,
        ] {
            assert_eq!(classify_cdp_frame(bad), Malformed, "{bad:?}");
        }
    }

    #[test]
    fn cdp_response_ids_are_matched_exactly() {
        // A response for another id must not be mistaken for ours.
        match classify_cdp_frame(r#"{"id":42,"result":{}}"#) {
            CdpFrame::Response { id, .. } => assert_eq!(id, 42),
            other => panic!("expected a response, got {other:?}"),
        }
    }

    // ---- URL gate -----------------------------------------------------------

    #[test]
    fn navigate_urls_must_be_http_and_bounded() {
        for url in [
            "https://example.com",
            "http://example.com/a?b=c#d",
            "https://example.com/~user",
        ] {
            assert!(navigate_url_allowed(url), "{url} must be allowed");
        }
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,x",
            "ftp://example.com",
            "https://",
            "http://a b.com",
            "",
        ] {
            assert!(!navigate_url_allowed(url), "{url} must be refused");
        }
        let long = format!("https://example.com/{}", "a".repeat(2100));
        assert!(
            !navigate_url_allowed(&long),
            "over-long URL must be refused"
        );
    }

    // ---- step parsing --------------------------------------------------------

    #[test]
    fn steps_parse_with_defaults() {
        let (steps, timeout) =
            parse_steps(&payload(json!({ "steps": [{ "action": "get_text" }] }))).unwrap();
        assert_eq!(steps, vec![BrowserStep::GetText]);
        assert_eq!(timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECONDS));

        // screenshot defaults: jpeg, quality 80.
        let (steps, _) =
            parse_steps(&payload(json!({ "steps": [{ "action": "screenshot" }] }))).unwrap();
        assert_eq!(
            steps,
            vec![BrowserStep::Screenshot {
                format: ScreenshotFormat::Jpeg,
                quality: DEFAULT_JPEG_QUALITY,
            }]
        );
        // explicit png + quality 95.
        let (steps, _) = parse_steps(&payload(json!({
            "steps": [{ "action": "screenshot", "format": "png", "quality": 95 }]
        })))
        .unwrap();
        assert_eq!(
            steps,
            vec![BrowserStep::Screenshot {
                format: ScreenshotFormat::Png,
                quality: 95,
            }]
        );
        // wait_for default timeout 5000ms.
        let (steps, _) = parse_steps(&payload(json!({
            "steps": [{ "action": "wait_for", "selector": "#x" }]
        })))
        .unwrap();
        assert_eq!(
            steps,
            vec![BrowserStep::WaitFor {
                selector: "#x".into(),
                timeout_ms: 5_000,
            }]
        );
    }

    #[test]
    fn step_count_is_capped_at_50() {
        let steps: Vec<Value> = (0..51).map(|_| json!({ "action": "get_text" })).collect();
        let err = parse_steps(&payload(json!({ "steps": steps }))).unwrap_err();
        assert_eq!(err, "steps must have at most 50 items");
    }

    #[test]
    fn oversized_step_fields_are_refused() {
        // 10 KiB+1 of typed text.
        let big = "x".repeat(MAX_TYPE_TEXT + 1);
        let err = parse_steps(&payload(json!({
            "steps": [{ "action": "type", "selector": "#q", "text": big }]
        })))
        .unwrap_err();
        assert!(err.contains("text exceeds"), "{err}");

        // 512+1 char selector.
        let sel = "#".repeat(MAX_SELECTOR + 1);
        let err = parse_steps(&payload(json!({
            "steps": [{ "action": "click", "selector": sel }]
        })))
        .unwrap_err();
        assert!(err.contains("selector exceeds"), "{err}");

        // 64 KiB+1 script.
        let js = "1".repeat(MAX_STEP_JS + 1);
        let err = parse_steps(&payload(json!({
            "steps": [{ "action": "eval", "js": js }]
        })))
        .unwrap_err();
        assert!(err.contains("js exceeds"), "{err}");

        // 2048+1 char URL.
        let url = format!("https://e.com/{}", "a".repeat(MAX_URL_CHARS));
        let err = parse_steps(&payload(json!({
            "steps": [{ "action": "navigate", "url": url }]
        })))
        .unwrap_err();
        assert!(err.contains("http(s)://"), "{err}");

        // Unknown action.
        let err = parse_steps(&payload(json!({ "steps": [{ "action": "hover" }] }))).unwrap_err();
        assert!(err.contains("unknown action"), "{err}");
    }

    #[test]
    fn global_timeout_is_validated() {
        for timeout in [0, 301, 86_400] {
            let err = parse_steps(&payload(json!({
                "steps": [{ "action": "get_text" }],
                "timeout": timeout
            })))
            .unwrap_err();
            assert!(err.contains("between 1 and 300"), "{err}");
        }
        for timeout in [1, 120, 300] {
            let (_, t) = parse_steps(&payload(json!({
                "steps": [{ "action": "get_text" }],
                "timeout": timeout
            })))
            .unwrap();
            assert_eq!(t, Duration::from_secs(timeout));
        }
    }

    #[test]
    fn empty_or_missing_steps_are_refused() {
        let err = parse_steps(&payload(json!({}))).unwrap_err();
        assert_eq!(err, "browser task has no steps");
        let err = parse_steps(&payload(json!({ "steps": [] }))).unwrap_err();
        assert_eq!(err, "steps must contain at least one step");
        let err = parse_steps(&payload(json!({ "steps": "x" }))).unwrap_err();
        assert_eq!(err, "steps must be a JSON array");
    }

    // ---- helpers --------------------------------------------------------------

    #[test]
    fn js_string_escapes_selector_content() {
        // A selector that would break out of a naive JS string literal.
        let hostile = r#"#a");window.x="pwn"#;
        let encoded = js_string(hostile);
        assert_eq!(encoded, serde_json::to_string(hostile).unwrap());
        // Round-trips: the selector stays ONE string, escapes and all.
        assert_eq!(
            serde_json::from_str::<String>(&encoded).unwrap(),
            hostile,
            "the selector must survive a JSON-literal round trip"
        );
        // No unescaped double quote remains inside the literal — a break-out
        // would need one.
        let interior = &encoded[1..encoded.len() - 1];
        assert!(
            !interior.replace("\\\"", "").contains('"'),
            "unescaped quote in {encoded:?}"
        );
    }

    #[test]
    fn truncate_chars_is_char_safe() {
        let s = "é".repeat(600);
        let cut = truncate_chars(&s, 100);
        assert_eq!(cut.chars().count(), 103);
        assert!(cut.ends_with("..."));
        assert_eq!(truncate_chars("abc", 100), "abc");
    }

    #[test]
    fn data_uri_tags_the_right_mime() {
        assert_eq!(
            data_uri(ScreenshotFormat::Jpeg, "QUJD"),
            "data:image/jpeg;base64,QUJD"
        );
        assert_eq!(
            data_uri(ScreenshotFormat::Png, "QUJD"),
            "data:image/png;base64,QUJD"
        );
    }

    // ---- install discovery ------------------------------------------------------

    #[test]
    fn version_directories_are_picked_newest() {
        let dir = crate::config::testutil::temp_dir("obscura-versions");
        for version in [
            "v0.2.3",
            "v0.2.4",
            "v0.10.0",
            "v1.0.0-rc1",
            "not-a-version",
            "v0.2",
        ] {
            let _ = std::fs::create_dir_all(dir.join(version));
            std::fs::write(dir.join(version).join("obscura"), b"#!/bin/sh\n").unwrap();
        }
        let bin = newest_binary(&dir).expect("a binary");
        assert_eq!(bin, dir.join("v0.10.0").join("obscura"));
        // An empty root yields nothing.
        let empty = crate::config::testutil::temp_dir("obscura-empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(newest_binary(&empty).is_none());
    }

    #[test]
    fn missing_install_is_a_clear_error() {
        let dir = crate::config::testutil::temp_dir("obscura-missing");
        std::fs::create_dir_all(&dir).unwrap();
        let _guard = ENV_MUTEX.blocking_lock();
        std::env::set_var("HUGINN_OBSCURA_DIR", &dir);
        let err = ensure_obscura_installed("").unwrap_err();
        std::env::remove_var("HUGINN_OBSCURA_DIR");
        assert!(err.contains("obscura is not installed"), "{err}");
    }

    #[test]
    fn state_local_root_is_in_the_search_path() {
        let _guard = ENV_MUTEX.blocking_lock();
        std::env::remove_var("HUGINN_OBSCURA_DIR");
        let roots = install_roots("/tmp/state-x");
        assert_eq!(roots.first(), Some(&PathBuf::from(OBSCURA_INSTALL_ROOT)));
        assert!(roots.contains(&PathBuf::from("/tmp/state-x/obscura")));
        // The env override replaces the whole search path.
        std::env::set_var("HUGINN_OBSCURA_DIR", "/custom");
        assert_eq!(
            install_roots("/tmp/state-x"),
            vec![PathBuf::from("/custom")]
        );
        std::env::remove_var("HUGINN_OBSCURA_DIR");
    }

    #[test]
    fn tokens_are_64_hex_chars() {
        let token = random_cdp_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        // Two draws differ.
        assert_ne!(token, random_cdp_token().unwrap());
    }

    #[tokio::test]
    async fn token_never_reaches_debug_output() {
        let token = random_cdp_token().unwrap();
        let fake = ObscuraProcess {
            child: tokio::process::Command::new("true")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .expect("spawn true"),
            port: 12345,
            token: token.clone(),
        };
        let debug = format!("{fake:?}");
        assert!(
            !debug.contains(&token),
            "Debug must redact the token: {debug}"
        );
        assert!(debug.contains("12345"));
        // The kill path reaps the finished child.
        fake.kill().await;
    }
}

// ---------------------------------------------------------------------------
// E2E test — a real Obscura, a real CDP session, a real page
// ---------------------------------------------------------------------------

/// Gated behind `HUGINN_OBSCURA_E2E=1` and `#[ignore]` (CI never sets the
/// env var): downloads the pinned Obscura release from the allowlisted
/// GitHub hosts, installs it into a temp root, serves a local HTML fixture,
/// and drives the full task path — then proves no obscura process survives
/// the run, a failing run, or a panic.
#[cfg(all(test, target_os = "linux"))]
mod e2e {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Obscura release to test against (asset `obscura-<arch>-linux.tar.gz`).
    const OBSCURA_VERSION: &str = "v0.2.4";
    /// Download cap: the release tarball is ~70 MB; 256 MB is generous.
    const DOWNLOAD_CAP: usize = 256 * 1024 * 1024;

    fn e2e_enabled() -> bool {
        std::env::var("HUGINN_OBSCURA_E2E")
            .ok()
            .is_some_and(|v| v == "1")
    }

    /// Any live process whose argv[0] is `needle` (an absolute path).
    fn obscura_pids(needle: &str) -> Vec<u32> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return found;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if let Ok(cmdline) = std::fs::read_to_string(entry.path().join("cmdline")) {
                let argv0 = cmdline.split('\0').next().unwrap_or_default();
                if argv0 == needle {
                    found.push(pid);
                }
            }
        }
        found
    }

    /// Download + extract the Obscura release into `<root>/<version>/obscura`
    /// (the layout `ensure_obscura_installed` expects), returning the binary
    /// path. Hosts are pinned to the worker's release allowlist.
    async fn install_obscura(root: &Path) -> Result<PathBuf, String> {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            other => return Err(format!("no obscura release asset for arch {other}")),
        };
        let asset = format!("obscura-{arch}-linux.tar.gz");
        let url = format!(
            "https://github.com/h4ckf0r0day/obscura/releases/download/{OBSCURA_VERSION}/{asset}"
        );
        // The worker's release allowlist, plus the CDN host GitHub now
        // redirects release downloads through (test-local extension).
        let mut allowlist: Vec<String> = crate::config::DEFAULT_ALLOWED_RELEASE_DOMAINS
            .iter()
            .map(|s| s.to_string())
            .collect();
        allowlist.push("release-assets.githubusercontent.com".into());
        let tarball = crate::update::download_bytes(&url, &allowlist, DOWNLOAD_CAP)
            .await
            .map_err(|e| format!("download {asset}: {e}"))?;
        let tar_path = root.join(&asset);
        std::fs::write(&tar_path, &tarball).map_err(|e| e.to_string())?;
        let install_dir = root.join(OBSCURA_VERSION);
        std::fs::create_dir_all(&install_dir).map_err(|e| e.to_string())?;
        // Extract just the `obscura` member — fixed argv, no shell.
        let status = std::process::Command::new("tar")
            .arg("xzf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&install_dir)
            .arg("obscura")
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("extract {asset}: {status}"));
        }
        let bin = install_dir.join("obscura");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        Ok(bin)
    }

    /// A tiny one-shot HTTP server serving `html` (the test fixture page).
    async fn spawn_fixture_server(html: Arc<String>) -> Result<u16, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let html = Arc::clone(&html);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await; // drain the request head
                    let body = html.as_bytes();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(body).await;
                });
            }
        });
        Ok(port)
    }

    fn browser_task(steps: Value, timeout: u64) -> Task {
        Task {
            id: "e2e".into(),
            task_type: "browser".into(),
            action_name: String::new(),
            payload: json!({ "steps": steps, "timeout": timeout })
                .as_object()
                .cloned()
                .unwrap_or_default(),
        }
    }

    const FIXTURE_HTML: &str = r#"<html><head><title>huginn-e2e</title></head><body>
<h1>hello obscura</h1>
<input id="q" type="text">
<button id="b" onclick="document.title = 'clicked'">go</button>
<div id="result" style="display:none">done</div>
<script>setTimeout(function(){document.getElementById('result').style.display='block';}, 150);</script>
</body></html>"#;

    /// The full pipeline: install → fixture → navigate/click/type/eval/
    /// screenshot → no leftover processes. Also verifies the failure path
    /// (unreachable page) and the panic path (drop-time cleanup).
    #[tokio::test]
    #[ignore = "downloads Obscura from GitHub and runs a real browser (set HUGINN_OBSCURA_E2E=1)"]
    async fn e2e_browser_task_navigates_and_cleans_up() {
        if !e2e_enabled() {
            eprintln!("skipped: HUGINN_OBSCURA_E2E not set to 1");
            return;
        }
        let scratch = crate::config::testutil::temp_dir("obscura-e2e");
        let root = scratch.join("install");
        std::fs::create_dir_all(&root).unwrap();
        let bin = install_obscura(&root).await.expect("install obscura");
        let _env_guard = ENV_MUTEX.lock().await;
        std::env::set_var("HUGINN_OBSCURA_DIR", &root);
        // The fixture page is served on 127.0.0.1 — the documented escape
        // hatch for Obscura's SSRF guard (production never sets it).
        std::env::set_var("HUGINN_BROWSER_ALLOW_PRIVATE_NETWORK", "1");
        let state_dir = scratch.join("state"); // unused install root — env wins
        let state_dir = state_dir.to_str().unwrap();

        let port = spawn_fixture_server(Arc::new(FIXTURE_HTML.to_owned()))
            .await
            .expect("fixture server");
        let page_url = format!("http://127.0.0.1:{port}/");

        // ---- happy path --------------------------------------------------
        let steps = json!([
            { "action": "navigate", "url": page_url },
            { "action": "wait_for", "selector": "#result", "timeout_ms": 5000 },
            { "action": "type", "selector": "#q", "text": "huginn was here" },
            { "action": "eval", "js": "document.querySelector('#q').value" },
            { "action": "click", "selector": "#b" },
            { "action": "eval", "js": "document.title" },
            { "action": "get_text" },
            { "action": "screenshot", "format": "jpeg", "quality": 80 }
        ]);
        let result = run_browser_task(&browser_task(steps, 120), state_dir).await;
        assert_eq!(result.status, "succeeded", "error: {}", result.error);
        assert!(
            result.stdout.contains("step 4 (eval): \"huginn was here\""),
            "typed text must reach the input: {result:?}"
        );
        assert!(
            result.stdout.contains("step 6 (eval): \"clicked\""),
            "the click must have fired: {result:?}"
        );
        // The screenshot line is a decodable, non-empty JPEG.
        let line = result
            .stdout
            .lines()
            .find(|l| l.contains("data:image/jpeg;base64,"))
            .expect("a screenshot line");
        let data = line.split("base64,").nth(1).expect("base64 payload");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .expect("valid base64");
        assert!(bytes.starts_with(&[0xFF, 0xD8]), "JPEG magic");
        assert!(
            bytes.len() > 1024,
            "non-trivial image ({} bytes)",
            bytes.len()
        );
        // Typed text is echoed by the eval the task ASKED for, but the type
        // step itself never echoes it.
        let type_line = result
            .stdout
            .lines()
            .find(|l| l.contains("(type)"))
            .expect("a type step line");
        assert_eq!(
            type_line, "step 3 (type): #q",
            "type must not echo the text"
        );

        // ---- failure path: still no leftover process -----------------------
        let bad = json!([{ "action": "navigate", "url": "http://127.0.0.1:1/" }]);
        let result = run_browser_task(&browser_task(bad, 60), state_dir).await;
        assert_eq!(result.status, "failed", "error: {}", result.error);
        assert!(result.error.contains("navigate"), "{}", result.error);

        // ---- panic path: dropping a spawn mid-flight kills the process ----
        let spawned = spawn_obscura(
            ObscuraSpawn {
                allow_private_network: true,
            },
            state_dir,
        )
        .await
        .expect("spawn for panic path");
        let bin_str = bin.display().to_string();
        assert!(
            !obscura_pids(&bin_str).is_empty(),
            "obscura must be running"
        );
        let pid_seen = obscura_pids(&bin_str);
        let panicked = std::panic::AssertUnwindSafe(async move {
            // Simulate a mid-task panic: the future is dropped while the
            // process is live (cancellation/panic → Drop → group kill).
            let _held = spawned;
            panic!("mid-task failure");
        });
        use futures::FutureExt;
        let _ = panicked.catch_unwind().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            obscura_pids(&bin_str).is_empty(),
            "obscura must die with the task, even on panic (saw {pid_seen:?})"
        );

        // ---- nothing survives the whole suite -------------------------------
        assert!(
            obscura_pids(&bin_str).is_empty(),
            "no obscura process may outlive its task"
        );
        std::env::remove_var("HUGINN_OBSCURA_DIR");
        std::env::remove_var("HUGINN_BROWSER_ALLOW_PRIVATE_NETWORK");
    }
}

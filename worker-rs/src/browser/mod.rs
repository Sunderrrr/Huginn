//! Browser automation: management of the Obscura headless-browser process,
//! a minimal CDP (Chrome DevTools Protocol) client, and the `browser` /
//! `browser_install` task handlers. Linux only — this module is compiled
//! `#[cfg(target_os = "linux")]` (see main.rs); every other OS answers
//! "browser not supported on this OS" in the dispatcher.
//!
//! # Architecture
//!
//! ```text
//! run_browser_task
//!   ├─ ensure Obscura is installed (<root>/<version>/obscura)
//!   ├─ spawn `obscura serve --port <ephemeral> --workers 2
//!   │        --worker-max-rss <MB>`   (pure argv, own process group,
//!   │        kill_on_drop, 127.0.0.1 only, random bearer token)
//!   ├─ CDP WebSocket → ws://127.0.0.1:<port>/devtools/browser
//!   ├─ Target.createTarget → attachToTarget → Page.enable
//!   ├─ steps: navigate/click/type/eval/screenshot/get_text/get_html/wait_for
//!   ├─ Target.closeTarget
//!   └─ kill the whole process group (SIGTERM → 5s → SIGKILL)
//!
//! run_browser_install_task (admin-triggered, hub-pinned coordinates)
//!   ├─ payload: {"version": "v0.2.4", "sha256": {"amd64": "…", "arm64": "…"}}
//!   ├─ glibc ≥ 2.35 check (clear error on musl/Alpine or older glibc)
//!   ├─ allowlisted download from github.com Obscura releases
//!   ├─ SHA-256 verified against the hub-pinned value
//!   ├─ strict extraction (only `obscura` + `obscura-worker`, no links,
//!   │   no traversal) into a staging dir, LICENSE + notices written
//!   ├─ smoke test `obscura --version`, then atomic-ish rename into place
//!   └─ failure leaves nothing behind (staging removed)
//! ```
//!
//! # Security invariants
//!
//! - Obscura is spawned with pure argv — never a shell. The port and the
//!   memory cap are the only interpolation points and are worker-generated.
//! - The CDP bearer token is random (32 bytes from `/dev/urandom`, 64 hex
//!   chars) and NEVER appears in a log line, error message, or Debug output
//!   (`ObscuraProcess` implements Debug by hand, redacting it).
//! - The listening port is ephemeral and bound to 127.0.0.1 only; no port
//!   is ever exposed on another interface.
//! - The process (and its whole group) is killed on completion, on step
//!   failure, on global timeout, and on drop — a panic mid-task still reaps
//!   it (`kill_on_drop` plus a synchronous group kill in `Drop`).
//! - Step payloads are re-validated here even though the hub already checked
//!   them: URL scheme/length, script size, selector size, typed-text size,
//!   step count and global timeout. A hostile hub must not be able to
//!   smuggle a step field past the worker.
//! - The install path only ever downloads from GitHub release hosts
//!   (SSRF-allowlisted, redirect hops validated) with the SHA-256 pinned by
//!   the hub; a mismatch installs nothing.

mod cdp;
mod install;
mod process;
mod steps;

pub use cdp::CdpClient;
pub use install::{run_browser_install_task, uninstall_cleanup};
pub use process::{spawn_obscura, ObscuraProcess, ObscuraSpawn};
pub use steps::parse_steps;

use steps::{BrowserStep, ScreenshotFormat};

use std::path::{Path, PathBuf};

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
/// A PDF's base64 payload must stay under this (smaller than the screenshot
/// cap: the whole task stdout is itself capped at 1 MiB).
pub const MAX_PDF_B64: usize = 768 * 1024;
/// Default JPEG quality for screenshots.
pub const DEFAULT_JPEG_QUALITY: u8 = 80;
/// Default (and maximum) `wait_for` step timeout in milliseconds.
pub const MAX_WAIT_FOR_MS: u64 = 60_000;

/// Default Obscura install root: `<root>/<version>/obscura`. Overridable via
/// the `HUGINN_OBSCURA_DIR` environment variable (tests/dev).
pub const OBSCURA_INSTALL_ROOT: &str = "/opt/huginn/obscura";

/// Poll interval for `wait_for_selector` and the port-readiness loop.
pub(crate) const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
/// Per-step stdout contribution cap (a `get_html` can be huge).
pub(crate) const MAX_STEP_OUTPUT: usize = 128 * 1024;
/// Whole-task stdout cap (matches `exec::DEFAULT_MAX_OUTPUT_BYTES`).
pub(crate) const MAX_STDOUT: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Obscura install discovery
// ---------------------------------------------------------------------------

/// Parse a version directory name (`v0.2.4` / `0.2.4`) into comparable
/// numeric parts. Non-version directories are skipped by the caller.
pub(crate) fn parse_version(name: &str) -> Option<Vec<u64>> {
    let trimmed = name.trim_start_matches('v');
    let mut parts = Vec::new();
    for part in trimmed.split('.') {
        parts.push(part.parse::<u64>().ok()?);
    }
    Some(parts)
}

/// The newest `<root>/<version>/obscura` binary under one install root.
pub(crate) fn newest_binary(root: &Path) -> Option<PathBuf> {
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
/// for non-root workers and dev setups).
pub(crate) fn install_roots(state_dir: &str) -> Vec<PathBuf> {
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
/// missing. `state_dir` widens the search (a state-local install for
/// non-root workers); production installs live under
/// [`OBSCURA_INSTALL_ROOT`].
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
         trigger a browser_install task or install it under {}/<version>/",
        searched.join(", "),
        OBSCURA_INSTALL_ROOT
    ))
}

/// Character-count truncation (UTF-8 boundary safe), with a marker.
pub(crate) fn truncate_chars(text: &str, max: usize) -> String {
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
// The browser task handler
// ---------------------------------------------------------------------------

/// Run one `browser` task end to end. `state_dir` widens the Obscura install
/// search (a state-local `<state_dir>/obscura/<version>/obscura` is accepted
/// for non-root workers). The Obscura process is killed on every path —
/// success, step failure, validation failure, and timeout; `kill_on_drop`
/// plus the `Drop` group-kill cover panics and cancellations.
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
pub(crate) fn failed(reason: &str) -> TaskResult {
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
            BrowserStep::PressKey { key } => match steps::key_spec(key) {
                Some((normalized, chrome, vk)) => client
                    .press_key(&normalized, &chrome, vk)
                    .await
                    .map(|_| Some(format!("pressed {normalized}"))),
                None => Err(format!("invalid press_key {key:?}")),
            },
            BrowserStep::Hover { selector } => client
                .hover_selector(selector)
                .await
                .map(|_| Some(selector.clone())),
            BrowserStep::Scroll { selector, to } => match (selector, to) {
                (Some(sel), _) => client
                    .scroll_into_view(sel)
                    .await
                    .map(|y| Some(format!("scrolled to {sel} (scrollY {y})"))),
                (None, Some(steps::ScrollTarget::Bottom)) => client
                    .scroll_to(true)
                    .await
                    .map(|y| Some(format!("scrolled to bottom (scrollY {y})"))),
                (None, _) => client
                    .scroll_to(false)
                    .await
                    .map(|y| Some(format!("scrolled to top (scrollY {y})"))),
            },
            BrowserStep::Eval { js } => client.eval(js).await.map(|v| Some(v.to_string())),
            BrowserStep::SetViewport { width, height } => client
                .set_viewport(*width, *height)
                .await
                .map(|_| Some(format!("{width}x{height}"))),
            BrowserStep::Screenshot {
                format,
                quality,
                full_page,
            } => client
                .screenshot(*format, *quality, *full_page)
                .await
                .map(|data| Some(data_uri(*format, &data))),
            BrowserStep::Pdf { options } => {
                client.pdf(options).await.map(|data| Some(pdf_uri(&data)))
            }
            BrowserStep::GetText => client.get_text().await.map(Some),
            BrowserStep::GetHtml => client.get_html().await.map(Some),
            BrowserStep::Title => client.get_title().await.map(Some),
            BrowserStep::WaitFor {
                selector,
                timeout_ms,
            } => client
                .wait_for_selector(selector, std::time::Duration::from_millis(*timeout_ms))
                .await
                .map(|_| Some(selector.clone())),
            BrowserStep::WaitForText { text, timeout_ms } => client
                .wait_for_text(text, std::time::Duration::from_millis(*timeout_ms))
                .await
                .map(|_| Some(text.clone())),
            BrowserStep::GetCookies => client.get_cookies().await.map(Some),
            BrowserStep::SetCookies { cookies } => client
                .set_cookies(cookies)
                .await
                .map(|n| Some(format!("{n} cookie(s) set"))),
        };
        match outcome {
            Ok(detail) => {
                // Captures (screenshot/pdf data URIs) are bounded by their own
                // validated size at the CDP layer; they ride the TOTAL
                // stdout budget, not the per-step text cap — truncating a
                // base64 payload mid-string would corrupt it. Text steps
                // (get_text, get_html, eval) keep the per-step cap.
                let max_detail = if matches!(action, "screenshot" | "pdf") {
                    usize::MAX
                } else {
                    MAX_STEP_OUTPUT
                };
                let line = match detail {
                    Some(text) => truncate_chars(&text, max_detail),
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
pub(crate) fn data_uri(format: ScreenshotFormat, base64_data: &str) -> String {
    match format {
        ScreenshotFormat::Jpeg => format!("data:image/jpeg;base64,{base64_data}"),
        ScreenshotFormat::Png => format!("data:image/png;base64,{base64_data}"),
    }
}

/// `data:` URI tag for an exported PDF.
pub(crate) fn pdf_uri(base64_data: &str) -> String {
    format!("data:application/pdf;base64,{base64_data}")
}

/// Append one `step N (action): detail` line, keeping the total stdout under
/// [`MAX_STDOUT`] (the hub truncates too; the worker keeps the submit payload
/// bounded). Multi-line details (get_text, get_html) are escaped to `\n`
/// sequences so every step is exactly ONE line — the format stays
/// deterministic for the dashboard and MCP consumers.
fn push_step_line(stdout: &mut String, position: usize, action: &str, detail: &str) {
    if stdout.len() >= MAX_STDOUT {
        return; // already at the cap
    }
    let single_line = detail.replace('\r', "").replace('\n', "\\n");
    let line = format!("step {position} ({action}): {single_line}\n");
    if stdout.len() + line.len() > MAX_STDOUT {
        stdout.push_str("[...output truncated...]\n");
        return;
    }
    stdout.push_str(&line);
}

/// Serializes env mutation/reads of `HUGINN_OBSCURA_DIR` between the unit
/// tests and the E2E test (cargo runs test fns in parallel). A tokio mutex so
/// the E2E test can hold it across awaits; sync tests use `blocking_lock`.
#[cfg(test)]
pub(crate) static ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod e2e;

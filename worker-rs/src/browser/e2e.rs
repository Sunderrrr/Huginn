//! E2E test — a real Obscura, a real CDP session, a real page.
//!
//! Gated behind `HUGINN_OBSCURA_E2E=1` and `#[ignore]` (CI never sets the
//! env var): the `browser_install` handler downloads the pinned Obscura
//! release from the allowlisted GitHub hosts, verifies the SHA-256,
//! extracts strictly, smoke-tests `obscura --version`, and then the full
//! task path runs against a local HTML fixture — EVERY step action
//! (navigate, type, press_key, click, hover, scroll, eval, set_viewport,
//! screenshot jpeg/png/full-page, pdf, get_text, get_html, title,
//! wait_for, wait_for_text, get_cookies, set_cookies) plus the failure
//! paths — before proving that no obscura process survives the run, a
//! failing run, a panic, or the uninstall cleanup.

use super::install::run_browser_install_task;
use super::{uninstall_cleanup, ObscuraSpawn, ENV_MUTEX};

use crate::hubclient::Task;
use base64::Engine as _;
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Obscura release to test against (asset `obscura-<arch>-linux.tar.gz`).
const OBSCURA_VERSION: &str = "v0.2.4";
/// The pinned SHA-256 of each release asset (github.com/h4ckf0r0day/obscura
/// releases, v0.2.4) — the same values the hub's settings default to.
const PINNED_SHA256_AMD64: &str =
    "757e7b597ba5cdd53af9fc701e0a9b80f0a8d788f545d4f82ec9ad32db77f000";
const PINNED_SHA256_ARM64: &str =
    "d9ba3719c2442a227567d7664b5505b38ab68236f3f5388884eee2e27f55db28";

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

/// A `browser_install` task payload exactly as the hub queues it: the pinned
/// version plus the per-arch SHA-256 map from the fleet settings.
fn install_task(version: &str) -> Task {
    Task {
        id: "e2e-install".into(),
        task_type: "browser_install".into(),
        action_name: String::new(),
        payload: json!({
            "version": version,
            "sha256": {
                "amd64": PINNED_SHA256_AMD64,
                "arm64": PINNED_SHA256_ARM64,
            }
        })
        .as_object()
        .cloned()
        .unwrap_or_default(),
    }
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

fn browser_task(steps: serde_json::Value, timeout: u64) -> Task {
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

/// One `step N (action): detail` line of a task result, or None.
fn step_line(stdout: &str, position: usize, action: &str) -> Option<String> {
    stdout
        .lines()
        .find(|l| l.starts_with(&format!("step {position} ({action}):")))
        .map(|l| {
            l[format!("step {position} ({action}):").len()..]
                .trim_start()
                .to_string()
        })
}

const FIXTURE_HTML: &str = r#"<html><head><title>huginn-e2e</title></head><body>
<h1>hello obscura</h1>
<input id="q" type="text">
<form id="f" onsubmit="document.title='submitted';return false">
<input id="term" type="text"><button type="submit" id="go">go</button>
</form>
<div id="menu" style="display:none">menu-open</div>
<div id="hover-zone" onmouseenter="document.getElementById('menu').style.display='block'">hover me</div>
<div style="height:4000px"></div>
<div id="bottom-marker">at-the-bottom</div>
<div id="later" style="display:none">eventually-visible</div>
<button id="b" onclick="document.getElementById('result').style.display='block'">go</button>
<div id="result" style="display:none">done</div>
<script>
  document.cookie = "probe=fixture; path=/";
  setTimeout(function(){document.getElementById('later').style.display='block';}, 250);
</script>
</body></html>"#;

/// The full pipeline: install (real download, real SHA-256, real smoke test)
/// → fixture → every step action → failure paths → no leftover processes.
/// Also verifies that a mid-task panic kills the browser and that the
/// uninstall cleanup removes the engine.
#[tokio::test]
#[ignore = "downloads Obscura from GitHub and runs a real browser (set HUGINN_OBSCURA_E2E=1)"]
async fn e2e_install_drives_every_step_and_cleans_up() {
    if !e2e_enabled() {
        eprintln!("skipped: HUGINN_OBSCURA_E2E not set to 1");
        return;
    }
    let scratch = crate::config::testutil::temp_dir("obscura-e2e");
    let root = scratch.join("install");
    std::fs::create_dir_all(&root).unwrap();
    let state_dir = scratch.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let state_dir = state_dir.to_str().unwrap().to_owned();
    let _env_guard = ENV_MUTEX.lock().await;
    std::env::set_var("HUGINN_OBSCURA_DIR", &root);
    // The fixture page is served on 127.0.0.1 — the documented escape hatch
    // for Obscura's SSRF guard (production never sets it).
    std::env::set_var("HUGINN_BROWSER_ALLOW_PRIVATE_NETWORK", "1");

    // ---- install via the real task handler --------------------------
    let install = run_browser_install_task(&install_task(OBSCURA_VERSION), &state_dir).await;
    assert_eq!(
        install.status, "succeeded",
        "install error: {} | stdout: {}",
        install.error, install.stdout
    );
    assert!(
        install.stdout.contains("sha256 verified"),
        "{}",
        install.stdout
    );
    let version_dir = root.join(OBSCURA_VERSION);
    let bin = version_dir.join("obscura");
    assert!(bin.is_file(), "{} must exist", bin.display());
    assert!(version_dir.join("obscura-worker").is_file());
    assert!(
        version_dir.join("LICENSE").is_file(),
        "the license travels with the binary"
    );
    assert!(version_dir.join("THIRD_PARTY_NOTICES.txt").is_file());

    // ---- unknown release: fails cleanly, installs nothing -----------------
    let bad = run_browser_install_task(&install_task("v0.0.0-nope"), &state_dir).await;
    assert_eq!(bad.status, "failed", "stdout: {}", bad.stdout);
    assert!(bad.error.contains("download"), "{}", bad.error);
    assert!(
        !root.join("v0.0.0-nope").exists(),
        "a failed install must leave nothing behind"
    );
    assert!(!root.join(".staging-v0.0.0-nope").exists());

    let port = spawn_fixture_server(Arc::new(FIXTURE_HTML.to_owned()))
        .await
        .expect("fixture server");
    let page_url = format!("http://127.0.0.1:{port}/");

    // ---- happy path: EVERY step action, in one tab ----------------------
    let steps = json!([
        { "action": "navigate", "url": page_url },
        { "action": "wait_for", "selector": "#result", "timeout_ms": 5000 },
        { "action": "type", "selector": "#q", "text": "huginn was here" },
        { "action": "eval", "js": "document.querySelector('#q').value" },
        // press_key: type into the form, then Enter submits it.
        { "action": "type", "selector": "#term", "text": "rust" },
        { "action": "press_key", "key": "enter" },
        { "action": "title" },
        // hover: a real trusted mouse move reveals the menu.
        { "action": "hover", "selector": "#hover-zone" },
        { "action": "wait_for_text", "text": "menu-open", "timeout_ms": 5000 },
        // scroll: to the bottom of the tall page.
        { "action": "scroll", "to": "bottom" },
        { "action": "eval", "js": "window.scrollY" },
        { "action": "scroll", "selector": "#hover-zone" },
        // wait_for_text: content revealed on a timer.
        { "action": "wait_for_text", "text": "eventually-visible", "timeout_ms": 8000 },
        // cookies: read the fixture cookie, set our own, read the jar back
        // (Network.setCookie fills Obscura's request cookie jar — it is what
        // subsequent navigations carry; the page's document.cookie is a
        // separate DOM-level store).
        { "action": "get_cookies" },
        { "action": "set_cookies", "cookies": [
            { "name": "huginn", "value": "was-here", "url": page_url }
        ]},
        { "action": "get_cookies" },
        // viewport: resize the page, ask it what it sees.
        { "action": "set_viewport", "width": 800, "height": 600 },
        { "action": "eval", "js": "[window.innerWidth, window.innerHeight]" },
        // click + get_text + get_html.
        { "action": "click", "selector": "#b" },
        { "action": "eval", "js": "document.querySelector('#result').style.display" },
        { "action": "get_text" },
        { "action": "get_html" },
        // captures: jpeg, full-page png, pdf.
        { "action": "screenshot", "format": "jpeg", "quality": 80 },
        { "action": "screenshot", "format": "png", "full_page": true },
        { "action": "pdf" }
    ]);
    let result = super::run_browser_task(&browser_task(steps, 180), &state_dir).await;
    assert_eq!(
        result.status, "succeeded",
        "error: {} | stdout: {}",
        result.error, result.stdout
    );

    // Typed text reached the field (step 4).
    assert_eq!(
        step_line(&result.stdout, 4, "eval").as_deref(),
        Some("\"huginn was here\""),
        "typed text must reach the input: {result:?}"
    );
    // Enter submitted the form (step 7 title → "submitted").
    assert_eq!(
        step_line(&result.stdout, 7, "title").as_deref(),
        Some("submitted"),
        "press_key enter must submit the form: {result:?}"
    );
    // The trusted hover revealed the menu (step 9 waited for its text).
    assert!(step_line(&result.stdout, 9, "wait_for_text").is_some());
    // Scrolled to the bottom of the 4000px filler (step 11 scrollY > 3000).
    let scroll_y = step_line(&result.stdout, 11, "eval")
        .and_then(|v| v.trim().parse::<f64>().ok())
        .expect("scrollY number");
    assert!(
        scroll_y > 3000.0,
        "must have scrolled to the bottom: {scroll_y}"
    );
    assert!(step_line(&result.stdout, 12, "scroll").is_some());
    // The delayed text appeared (step 13).
    // Cookies: the fixture cookie is readable (step 14)…
    let cookies = step_line(&result.stdout, 14, "get_cookies").unwrap_or_default();
    let parsed = serde_json::from_str::<serde_json::Value>(&cookies)
        .expect("get_cookies must return a JSON array");
    assert_eq!(
        parsed[0]["name"].as_str(),
        Some("probe"),
        "get_cookies must list the fixture cookie: {cookies}"
    );
    // …and our set cookie is in the jar (step 16: Obscura's Network.setCookie
    // fills the request cookie jar, not the page's document.cookie).
    let jar = step_line(&result.stdout, 16, "get_cookies").unwrap_or_default();
    let jar = serde_json::from_str::<serde_json::Value>(&jar).expect("JSON array");
    assert!(
        jar.as_array().is_some_and(|list| {
            list.iter().any(|c| {
                c["name"].as_str() == Some("huginn") && c["value"].as_str() == Some("was-here")
            })
        }),
        "set_cookies must land in the cookie jar: {jar}"
    );
    // Viewport override applied (step 18: [800, 600]).
    assert_eq!(
        step_line(&result.stdout, 18, "eval").as_deref(),
        Some("[800,600]"),
        "set_viewport must resize the page: {result:?}"
    );
    // The click revealed #result (step 20).
    assert!(
        step_line(&result.stdout, 20, "eval")
            .map(|v| v.contains("block"))
            .unwrap_or(false),
        "the click must have fired: {result:?}"
    );
    assert!(
        step_line(&result.stdout, 21, "get_text")
            .map(|v| v.contains("at-the-bottom"))
            .unwrap_or(false),
        "get_text must include the page text: {result:?}"
    );
    assert!(
        step_line(&result.stdout, 22, "get_html")
            .map(|v| v.contains("hello obscura"))
            .unwrap_or(false),
        "get_html must include the markup: {result:?}"
    );
    // The type steps never echo the text (the selector is the only detail).
    for line in result.stdout.lines() {
        if line.contains("(type)") {
            assert!(
                !line.contains("huginn was here") && !line.contains("rust"),
                "type must not echo the text: {line}"
            );
        }
    }

    // Captures: a decodable non-empty JPEG (step 23)…
    let jpeg = result
        .stdout
        .lines()
        .find(|l| l.contains("data:image/jpeg;base64,"))
        .expect("a jpeg screenshot line");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(jpeg.split("base64,").nth(1).expect("payload"))
        .expect("valid base64");
    assert!(bytes.starts_with(&[0xFF, 0xD8]), "JPEG magic");
    assert!(
        bytes.len() > 1024,
        "non-trivial image ({} bytes)",
        bytes.len()
    );
    // …a full-page PNG (step 24)…
    let png = result
        .stdout
        .lines()
        .find(|l| l.contains("data:image/png;base64,"))
        .expect("a png screenshot line");
    let png_bytes = base64::engine::general_purpose::STANDARD
        .decode(png.split("base64,").nth(1).expect("payload"))
        .expect("valid base64");
    assert!(png_bytes.starts_with(b"\x89PNG"), "PNG magic");
    // …and a PDF (step 25).
    let pdf = result
        .stdout
        .lines()
        .find(|l| l.contains("data:application/pdf;base64,"))
        .expect("a pdf line");
    let pdf_bytes = match base64::engine::general_purpose::STANDARD
        .decode(pdf.split("base64,").nth(1).expect("payload"))
    {
        Ok(b) => b,
        Err(e) => {
            let payload = pdf.split("base64,").nth(1).unwrap_or_default();
            let bad = match &e {
                base64::DecodeError::InvalidByte(offset, _) => *offset,
                _ => 0,
            };
            let ctx = payload
                .chars()
                .skip(bad.saturating_sub(40))
                .take(80)
                .collect::<String>();
            panic!("pdf base64 decode failed at {bad}: {e} | context: {ctx:?}")
        }
    };
    assert!(pdf_bytes.starts_with(b"%PDF"), "PDF magic");
    assert!(
        pdf_bytes.len() > 500,
        "non-trivial PDF ({} bytes)",
        pdf_bytes.len()
    );

    // ---- failure paths: still no leftover process ------------------------
    // Unreachable page.
    let bad = json!([{ "action": "navigate", "url": "http://127.0.0.1:1/" }]);
    let result = super::run_browser_task(&browser_task(bad, 60), &state_dir).await;
    assert_eq!(result.status, "failed", "error: {}", result.error);
    assert!(result.error.contains("navigate"), "{}", result.error);

    // Selector that never appears: wait_for times out.
    let bad = json!([
        { "action": "navigate", "url": page_url },
        { "action": "wait_for", "selector": "#never-there", "timeout_ms": 500 }
    ]);
    let result = super::run_browser_task(&browser_task(bad, 60), &state_dir).await;
    assert_eq!(result.status, "failed", "error: {}", result.error);
    assert!(
        result.error.contains("timeout waiting for selector"),
        "{}",
        result.error
    );

    // Text that never appears: wait_for_text times out.
    let bad = json!([
        { "action": "navigate", "url": page_url },
        { "action": "wait_for_text", "text": "never-happens", "timeout_ms": 500 }
    ]);
    let result = super::run_browser_task(&browser_task(bad, 60), &state_dir).await;
    assert_eq!(result.status, "failed", "error: {}", result.error);
    assert!(
        result.error.contains("timeout waiting for text"),
        "{}",
        result.error
    );

    // Hover on a missing selector fails the step.
    let bad = json!([
        { "action": "navigate", "url": page_url },
        { "action": "hover", "selector": "#nope" }
    ]);
    let result = super::run_browser_task(&browser_task(bad, 60), &state_dir).await;
    assert_eq!(result.status, "failed", "error: {}", result.error);
    assert!(
        result.error.contains("selector not found"),
        "{}",
        result.error
    );

    // Global timeout kills a stuck task (wait_for capped under the timeout).
    let bad = json!([
        { "action": "navigate", "url": page_url },
        { "action": "wait_for", "selector": "#never-there", "timeout_ms": 30000 }
    ]);
    let result = super::run_browser_task(&browser_task(bad, 2), &state_dir).await;
    assert_eq!(result.status, "timeout", "error: {}", result.error);
    assert!(result.error.contains("timeout"), "{}", result.error);

    // ---- panic path: dropping a spawn mid-flight kills the process ----
    let spawned = super::spawn_obscura(
        ObscuraSpawn {
            allow_private_network: true,
            max_rss_mb: 512,
        },
        &state_dir,
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
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        obscura_pids(&bin_str).is_empty(),
        "obscura must die with the task, even on panic (saw {pid_seen:?})"
    );

    // ---- nothing survives the whole suite -------------------------------
    assert!(
        obscura_pids(&bin_str).is_empty(),
        "no obscura process may outlive its task"
    );

    // ---- uninstall cleanup removes the engine ----------------------------
    let removed = uninstall_cleanup(&state_dir);
    assert!(
        removed.iter().any(|r| r == &root.display().to_string()),
        "the install root must be removed (removed: {removed:?})"
    );
    assert!(!root.exists(), "{} must be gone", root.display());

    std::env::remove_var("HUGINN_OBSCURA_DIR");
    std::env::remove_var("HUGINN_BROWSER_ALLOW_PRIVATE_NETWORK");
}

//! E2E test — a real Obscura, a real CDP session, a real page.
//!
//! Gated behind `HUGINN_OBSCURA_E2E=1` and `#[ignore]` (CI never sets the
//! env var): the `browser_install` handler downloads the pinned Obscura
//! release from the allowlisted GitHub hosts, verifies the SHA-256,
//! extracts strictly, smoke-tests `obscura --version`, and then the full
//! task path runs against a local HTML fixture — before proving that no
//! obscura process survives the run, a failing run, a panic, or the
//! uninstall cleanup.

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

const FIXTURE_HTML: &str = r#"<html><head><title>huginn-e2e</title></head><body>
<h1>hello obscura</h1>
<input id="q" type="text">
<button id="b" onclick="document.title = 'clicked'">go</button>
<div id="result" style="display:none">done</div>
<script>setTimeout(function(){document.getElementById('result').style.display='block';}, 150);</script>
</body></html>"#;

/// The full pipeline: install (real download, real SHA-256, real smoke test)
/// → fixture → navigate/click/type/eval/screenshot → no leftover processes.
/// Also verifies the failure paths: an unknown release version installs
/// nothing, an unreachable page still cleans up, and a mid-task panic kills
/// the browser. Finally the uninstall cleanup removes the engine.
#[tokio::test]
#[ignore = "downloads Obscura from GitHub and runs a real browser (set HUGINN_OBSCURA_E2E=1)"]
async fn e2e_install_navigates_and_cleans_up() {
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
    // No staging leftovers.
    assert!(
        std::fs::read_dir(&root).unwrap().count() == 1,
        "only the version dir"
    );

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
    let result = super::run_browser_task(&browser_task(steps, 120), &state_dir).await;
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
    let result = super::run_browser_task(&browser_task(bad, 60), &state_dir).await;
    assert_eq!(result.status, "failed", "error: {}", result.error);
    assert!(result.error.contains("navigate"), "{}", result.error);

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

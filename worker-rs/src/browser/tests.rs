//! Unit tests for the browser module (mock bytes / synthetic tarballs — the
//! real-Obscura E2E lives in `e2e.rs`).

use super::cdp::{classify_cdp_frame, js_string, CdpFrame};
use super::install::{parse_libc_version, sha256_gate, version_gate};
use super::process::{parse_max_rss_mb, random_cdp_token};
use super::steps::{key_spec, navigate_url_allowed, BrowserStep, ScreenshotFormat, ScrollTarget};
use super::{
    data_uri, ensure_obscura_installed, install_roots, newest_binary, parse_steps, pdf_uri,
    truncate_chars, ObscuraProcess, ENV_MUTEX, MAX_SELECTOR, MAX_STEP_JS, MAX_TYPE_TEXT,
    MAX_URL_CHARS, OBSCURA_INSTALL_ROOT,
};

use serde_json::json;
use std::path::PathBuf;
use std::process::Stdio;
use tar::EntryType;

fn payload(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v.as_object().cloned().unwrap_or_default()
}

// ---- CDP frame classification (mock bytes, no browser) ---------------------

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

// ---- URL gate ---------------------------------------------------------------

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

// ---- step parsing -----------------------------------------------------------

#[test]
fn steps_parse_with_defaults() {
    let (steps, timeout) =
        parse_steps(&payload(json!({ "steps": [{ "action": "get_text" }] }))).unwrap();
    assert_eq!(steps, vec![BrowserStep::GetText]);
    assert_eq!(timeout, std::time::Duration::from_secs(120));

    // screenshot defaults: jpeg, quality 80, viewport only.
    let (steps, _) =
        parse_steps(&payload(json!({ "steps": [{ "action": "screenshot" }] }))).unwrap();
    assert_eq!(
        steps,
        vec![BrowserStep::Screenshot {
            format: ScreenshotFormat::Jpeg,
            quality: 80,
            full_page: false,
        }]
    );
    // explicit png + quality 95 + full page.
    let (steps, _) = parse_steps(&payload(json!({
        "steps": [{ "action": "screenshot", "format": "png", "quality": 95, "full_page": true }]
    })))
    .unwrap();
    assert_eq!(
        steps,
        vec![BrowserStep::Screenshot {
            format: ScreenshotFormat::Png,
            quality: 95,
            full_page: true,
        }]
    );
    // pdf defaults: portrait, background on, A4.
    let (steps, _) = parse_steps(&payload(json!({ "steps": [{ "action": "pdf" }] }))).unwrap();
    assert_eq!(
        steps,
        vec![BrowserStep::Pdf {
            options: super::steps::PdfOptions::default()
        }]
    );
    let (steps, _) = parse_steps(&payload(json!({
        "steps": [{ "action": "pdf", "landscape": true, "paper_width": 11, "paper_height": 8.5 }]
    })))
    .unwrap();
    assert_eq!(
        steps,
        vec![BrowserStep::Pdf {
            options: super::steps::PdfOptions {
                landscape: true,
                paper_width: 11.0,
                paper_height: 8.5,
                ..super::steps::PdfOptions::default()
            }
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
    let steps: Vec<serde_json::Value> = (0..51).map(|_| json!({ "action": "get_text" })).collect();
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
    let err = parse_steps(&payload(json!({ "steps": [{ "action": "teleport" }] }))).unwrap_err();
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
        assert_eq!(t, std::time::Duration::from_secs(timeout));
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

// ---- the Obscura capability steps -------------------------------------------

#[test]
fn press_key_specs_normalize_to_chrome_keys() {
    assert_eq!(
        key_spec("enter"),
        Some(("enter".into(), "Enter".into(), 13))
    );
    assert_eq!(
        key_spec("ARROWDOWN"),
        Some(("arrowdown".into(), "ArrowDown".into(), 40))
    );
    assert_eq!(
        key_spec("pageup"),
        Some(("pageup".into(), "PageUp".into(), 33))
    );
    // A single printable char: itself + its upper-case vk code.
    assert_eq!(key_spec("a"), Some(("a".into(), "a".into(), 65)));
    assert_eq!(key_spec(" "), Some((" ".into(), " ".into(), 32)));
    // Refused: multi-char names, unknown names, empty, control chars.
    for bad in ["", "ctrl", "enter-shift", "ab", "é", "\n"] {
        assert!(key_spec(bad).is_none(), "{bad:?} must be refused");
    }
}

#[test]
fn press_key_steps_validate() {
    let (steps, _) = parse_steps(&payload(json!({
        "steps": [{ "action": "press_key", "key": "enter" }]
    })))
    .unwrap();
    assert_eq!(
        steps,
        vec![BrowserStep::PressKey {
            key: "enter".into()
        }]
    );
    // Unknown keys are refused at parse time (never reach the engine).
    let err = parse_steps(&payload(json!({
        "steps": [{ "action": "press_key", "key": "ctrl+a" }]
    })))
    .unwrap_err();
    assert!(err.contains("named key"), "{err}");
    let err = parse_steps(&payload(json!({
        "steps": [{ "action": "press_key" }]
    })))
    .unwrap_err();
    assert!(err.contains("requires key"), "{err}");
}

#[test]
fn scroll_steps_require_exactly_one_target() {
    let (steps, _) = parse_steps(&payload(json!({
        "steps": [
            { "action": "scroll", "to": "bottom" },
            { "action": "scroll", "to": "top" },
            { "action": "scroll", "selector": "#footer" }
        ]
    })))
    .unwrap();
    assert_eq!(
        steps,
        vec![
            BrowserStep::Scroll {
                selector: None,
                to: Some(ScrollTarget::Bottom)
            },
            BrowserStep::Scroll {
                selector: None,
                to: Some(ScrollTarget::Top)
            },
            BrowserStep::Scroll {
                selector: Some("#footer".into()),
                to: None
            },
        ]
    );
    for bad in [
        json!({ "action": "scroll" }),               // neither
        json!({ "action": "scroll", "to": "side" }), // bad target
        json!({ "action": "scroll", "selector": "#a", "to": "bottom" }), // both
    ] {
        let err = parse_steps(&payload(json!({ "steps": [bad] }))).unwrap_err();
        assert!(err.contains("scroll"), "{err}");
    }
}

#[test]
fn wait_for_text_and_title_steps_validate() {
    let (steps, _) = parse_steps(&payload(json!({
        "steps": [
            { "action": "wait_for_text", "text": "deployed", "timeout_ms": 8000 },
            { "action": "title" }
        ]
    })))
    .unwrap();
    assert_eq!(
        steps,
        vec![
            BrowserStep::WaitForText {
                text: "deployed".into(),
                timeout_ms: 8000
            },
            BrowserStep::Title,
        ]
    );
    // Missing text / oversized text are refused.
    let err = parse_steps(&payload(json!({
        "steps": [{ "action": "wait_for_text" }]
    })))
    .unwrap_err();
    assert!(err.contains("requires text"), "{err}");
    let err = parse_steps(&payload(json!({
        "steps": [{ "action": "wait_for_text", "text": "x".repeat(513) }]
    })))
    .unwrap_err();
    assert!(err.contains("exceeds"), "{err}");
}

#[test]
fn cookie_steps_validate() {
    let (steps, _) = parse_steps(&payload(json!({
        "steps": [
            { "action": "get_cookies" },
            { "action": "set_cookies", "cookies": [
                { "name": "session", "value": "abc", "url": "https://example.com/" }
            ]}
        ]
    })))
    .unwrap();
    assert_eq!(steps[0], BrowserStep::GetCookies);
    assert_eq!(
        steps[1],
        BrowserStep::SetCookies {
            cookies: vec![super::steps::CookieSpec {
                name: "session".into(),
                value: "abc".into(),
                url: "https://example.com/".into(),
            }]
        }
    );
    // Bad URL, empty name, oversized value, too many cookies, missing array.
    for bad in [
        json!({ "action": "set_cookies", "cookies": [
            { "name": "s", "value": "v", "url": "file:///etc" }
        ]}),
        json!({ "action": "set_cookies", "cookies": [{ "name": "", "value": "v", "url": "https://x/" }] }),
        json!({ "action": "set_cookies", "cookies": [
            { "name": "s", "value": "x".repeat(4097), "url": "https://x/" }
        ]}),
        json!({ "action": "set_cookies" }),
    ] {
        let err = parse_steps(&payload(json!({ "steps": [bad] }))).unwrap_err();
        assert!(!err.is_empty());
    }
    // Over the cookie-count cap.
    let many: Vec<serde_json::Value> = (0..21)
        .map(|i| json!({ "name": format!("c{i}"), "value": "v", "url": "https://x/" }))
        .collect();
    let err = parse_steps(&payload(json!({ "steps": [
        { "action": "set_cookies", "cookies": many }
    ] })))
    .unwrap_err();
    assert!(err.contains("cookies"), "{err}");
}

#[test]
fn viewport_and_pdf_bounds_hold() {
    let (steps, _) = parse_steps(&payload(json!({
        "steps": [{ "action": "set_viewport", "width": 1280, "height": 800 }]
    })))
    .unwrap();
    assert_eq!(
        steps,
        vec![BrowserStep::SetViewport {
            width: 1280,
            height: 800
        }]
    );
    for bad in [
        json!({ "action": "set_viewport", "width": 10, "height": 800 }),
        json!({ "action": "set_viewport", "width": 1280, "height": 99999 }),
        json!({ "action": "set_viewport", "width": 1280 }),
        json!({ "action": "pdf", "paper_width": 0.5 }),
        json!({ "action": "pdf", "paper_height": 500 }),
    ] {
        let err = parse_steps(&payload(json!({ "steps": [bad] }))).unwrap_err();
        assert!(!err.is_empty(), "{bad} must be refused");
    }
}

#[test]
fn pdf_uri_tags_the_right_mime() {
    assert_eq!(pdf_uri("QUJD"), "data:application/pdf;base64,QUJD");
}

// ---- helpers -----------------------------------------------------------------

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

// ---- install discovery ---------------------------------------------------------

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
    assert!(err.contains("browser_install"), "{err}");
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

// ---- install gates --------------------------------------------------------------

#[test]
fn engine_versions_must_be_path_safe() {
    for ok in ["v0.2.4", "v1.0.0", "v0.3.0-rc1", "v10.20.30"] {
        assert!(version_gate(ok).is_ok(), "{ok} must be accepted");
    }
    for bad in [
        "0.2.4",                             // no v prefix
        "",                                  // empty
        "v",                                 // v alone
        "v0.2.4\n",                          // control char
        "v0.2.4/evil",                       // path separator
        "v..",                               // dot-dot
        "v../..",                            // traversal
        "v.0.2",                             // leading dot
        "v0.2.4;rm -rf",                     // shell metachars (should never be built anyway)
        "v0.2.4 extra",                      // space
        &format!("v{}.2.4", "0".repeat(40)), // over-long
    ] {
        assert!(version_gate(bad).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn pinned_sha256_must_be_64_hex_chars() {
    let good = "d9ba3719c2442a227567d7664b5505b38ab68236f3f5388884eee2e27f55db28";
    assert!(sha256_gate(good).is_ok());
    for bad in [
        "",
        "abc",
        &"a".repeat(63),
        &"z".repeat(64),
        &format!("{}g", "a".repeat(63)),
    ] {
        assert!(sha256_gate(bad).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn libc_versions_parse_from_tool_output() {
    assert_eq!(parse_libc_version("glibc 2.35"), Some((2, 35)));
    assert_eq!(
        parse_libc_version("ldd (Ubuntu GLIBC 2.31-0ubuntu3) 2.31"),
        Some((2, 31))
    );
    assert_eq!(
        parse_libc_version(
            "GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8) stable release version 2.39."
        ),
        Some((2, 39))
    );
    assert_eq!(
        parse_libc_version("musl libc (x86_64) Version 1.2.5"),
        None,
        "musl output has no glibc token"
    );
    assert_eq!(parse_libc_version(""), None);
}

#[test]
fn max_rss_env_is_clamped() {
    assert_eq!(parse_max_rss_mb(None), 512);
    assert_eq!(parse_max_rss_mb(Some("1024")), 1024);
    assert_eq!(parse_max_rss_mb(Some("  256 ")), 256);
    assert_eq!(parse_max_rss_mb(Some("not-a-number")), 512);
    assert_eq!(parse_max_rss_mb(Some("0")), 64, "below-range clamps up");
    assert_eq!(parse_max_rss_mb(Some("10")), 64);
    assert_eq!(
        parse_max_rss_mb(Some("999999")),
        8192,
        "above-range clamps down"
    );
}

// ---- strict extraction -----------------------------------------------------------

/// Build a synthetic gzip-compressed tarball in memory.
fn tar_gz(entries: &[(&str, EntryType, &[u8])]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (name, ty, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(*ty);
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        builder.append_data(&mut header, name, *data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

#[test]
fn strict_extraction_accepts_only_the_two_engine_binaries() {
    use std::os::unix::fs::PermissionsExt;
    let dir = crate::config::testutil::temp_dir("obscura-extract");
    let tarball = tar_gz(&[
        ("./", EntryType::Directory, b""),
        ("obscura", EntryType::Regular, b"#!/bin/sh\nfake\n"),
        ("obscura-worker", EntryType::Regular, b"#!/bin/sh\nfake\n"),
        ("README.md", EntryType::Regular, b"ignorable asset"),
    ]);
    let installed = super::install::extract_strict(&tarball, &dir).unwrap();
    assert_eq!(installed, vec!["obscura", "obscura-worker"]);
    for name in ["obscura", "obscura-worker"] {
        let mode = std::fs::metadata(dir.join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "{name} must be 0755");
    }
    assert!(!dir.join("README.md").exists(), "extra assets are skipped");
}

#[test]
fn strict_extraction_refuses_hostile_members() {
    let dir = crate::config::testutil::temp_dir("obscura-extract-bad");
    // A symlink member — refused whatever its name.
    let tarball = tar_gz(&[("link", EntryType::Symlink, b"")]);
    let err = super::install::extract_strict(&tarball, &dir).unwrap_err();
    assert!(err.contains("refusing tar member"), "{err}");

    // A nested path — refused (a traversal "../x" is the same class: more
    // than one component, and the tar crate refuses it at unpack too).
    let dir2 = crate::config::testutil::temp_dir("obscura-extract-bad2");
    let tarball = tar_gz(&[("sub/obscura", EntryType::Regular, b"x")]);
    let err = super::install::extract_strict(&tarball, &dir2).unwrap_err();
    assert!(err.contains("refusing tar member with path"), "{err}");

    // No obscura binary at all — refused.
    let dir3 = crate::config::testutil::temp_dir("obscura-extract-bad3");
    let tarball = tar_gz(&[("obscura-worker", EntryType::Regular, b"x")]);
    let err = super::install::extract_strict(&tarball, &dir3).unwrap_err();
    assert_eq!(err, "tarball has no obscura binary");
}

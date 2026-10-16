//! huginn-parity — the API parity harness (Rust port of `tools/api_parity.py`).
//!
//! Captures HTTP responses from a running hub and diffs two captures after
//! normalizing volatile fields (UUIDs, timestamps, tokens, IPs, hashes).
//!
//!     huginn-parity capture --base http://127.0.0.1:8000 \
//!         --admin-user admin --admin-pass '...' --out golden/rust
//!     huginn-parity diff golden/python golden/rust
//!
//! The goldens in `hub-rs/golden/python` were captured from the reference
//! implementation; a clean diff is the migration's release gate.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("capture") => capture(&args[2..]),
        Some("diff") => diff(&args[2..]),
        _ => {
            eprintln!(
                "usage: huginn-parity capture --base URL --admin-user U --admin-pass P --out DIR\n       huginn-parity diff A_DIR B_DIR"
            );
            2
        }
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// Normalization — volatile values become stable placeholders so diffs compare
// shape and semantics, not randomness.
// ---------------------------------------------------------------------------

fn normalize(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(normalize_str(s)),
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                // `backup_s3_*`, `enrollment_base_url`, `browser_engine_*`
                // and `browser_enabled` were added after the reference
                // goldens were captured; the parity suite predates them.
                .filter(|(k, _)| {
                    let key = k.as_str();
                    !key.starts_with("backup_s3_")
                        && !key.starts_with("browser_engine_")
                        && key != "browser_enabled"
                        && key != "enrollment_base_url"
                })
                .map(|(k, val)| (k.clone(), normalize(val)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn normalize_str(input: &str) -> String {
    use std::sync::OnceLock;
    static UUID: OnceLock<regex::Regex> = OnceLock::new();
    static PARITY: OnceLock<regex::Regex> = OnceLock::new();
    static TOKEN: OnceLock<regex::Regex> = OnceLock::new();
    static IP: OnceLock<regex::Regex> = OnceLock::new();
    static TS_ISO: OnceLock<regex::Regex> = OnceLock::new();
    static TS_SQL: OnceLock<regex::Regex> = OnceLock::new();
    static JWT: OnceLock<regex::Regex> = OnceLock::new();
    static HASH64: OnceLock<regex::Regex> = OnceLock::new();

    let uuid = UUID.get_or_init(|| {
        regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap()
    });
    let parity = PARITY.get_or_init(|| regex::Regex::new(r"parity-\d+").unwrap());
    let token = TOKEN.get_or_init(|| regex::Regex::new(r"[A-Za-z0-9_-]{40,}").unwrap());
    let ip = IP.get_or_init(|| regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
    let ts_iso = TS_ISO.get_or_init(|| {
        regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|\+00:00)").unwrap()
    });
    let ts_sql = TS_SQL.get_or_init(|| {
        regex::Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?(\+\d{2}:\d{2})?").unwrap()
    });
    let jwt = JWT.get_or_init(|| {
        regex::Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap()
    });
    let hash64 = HASH64.get_or_init(|| regex::Regex::new(r"\b[0-9a-f]{64}\b").unwrap());

    let out = uuid.replace_all(input, "<UUID>");
    let out = parity.replace_all(&out, "parity-<N>");
    let out = jwt.replace_all(&out, "<JWT>");
    let out = ts_iso.replace_all(&out, "<TS>");
    let out = ts_sql.replace_all(&out, "<TS>");
    let out = hash64.replace_all(&out, "<HASH64>");
    let out = token.replace_all(&out, "<TOKEN>");
    ip.replace_all(&out, "<IP>").into_owned()
}

// ---------------------------------------------------------------------------
// HTTP capture — mirrors the Python reference request sequence exactly.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Recorder {
    client: reqwest::blocking::Client,
    base: String,
    results: BTreeMap<String, Value>,
}

impl Recorder {
    fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> (u16, Option<Value>) {
        let url = format!("{}{}", self.base, path);
        let mut req = match method {
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            "DELETE" => self.client.delete(&url),
            _ => self.client.get(&url),
        };
        req = req.header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send();
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().unwrap_or_default();
                let parsed = serde_json::from_str(&text).ok().or_else(|| {
                    if text.trim().is_empty() {
                        Some(Value::Null)
                    } else {
                        Some(json!({"_raw": &text[..text.len().min(400)]}))
                    }
                });
                (status, parsed)
            }
            Err(e) => (0, Some(json!({"_error": e.to_string()}))),
        }
    }

    fn rec(
        &mut self,
        name: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Option<Value>) {
        self.rec_with(name, method, path, token, body, &[])
    }

    fn rec_with(
        &mut self,
        name: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> (u16, Option<Value>) {
        let (status, parsed) = self.call(method, path, token, body, extra);
        let body = parsed.clone().unwrap_or(Value::Null);
        self.results.insert(
            name.to_string(),
            json!({
                "method": normalize(&Value::String(method.into())),
                "path": normalize(&Value::String(path.into())),
                "status": status,
                "body": normalize(&body),
            }),
        );
        (status, parsed)
    }
}

fn capture(argv: &[String]) -> i32 {
    let mut base = String::new();
    let mut admin_user = String::new();
    let mut admin_pass = String::new();
    let mut out = PathBuf::from("golden/rust");
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--base" => {
                base = argv.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--admin-user" => {
                admin_user = argv.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--admin-pass" => {
                admin_pass = argv.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--out" => {
                out = PathBuf::from(argv.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
            other => {
                eprintln!("unknown flag: {other}");
                return 2;
            }
        }
    }
    if base.is_empty() || admin_user.is_empty() || admin_pass.is_empty() {
        eprintln!("--base, --admin-user and --admin-pass are required");
        return 2;
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("http client");
    let mut r = Recorder {
        client,
        base: base.trim_end_matches('/').to_string(),
        results: BTreeMap::new(),
    };

    // Unauthenticated surface (auth-gate shapes).
    r.rec("healthz", "GET", "/healthz", None, None);
    r.rec("vms_unauthenticated", "GET", "/api/vms", None, None);
    r.rec("users_unauthenticated", "GET", "/api/users", None, None);
    r.rec("audit_unauthenticated", "GET", "/api/audit", None, None);
    r.rec(
        "settings_unauthenticated",
        "GET",
        "/api/settings",
        None,
        None,
    );
    r.rec(
        "worker_next_unauthenticated",
        "GET",
        "/api/worker/tasks/next",
        None,
        None,
    );
    r.rec(
        "worker_heartbeat_unauthenticated",
        "POST",
        "/api/worker/heartbeat",
        None,
        Some(json!({})),
    );
    r.rec(
        "mcp_whoami_unauthenticated",
        "GET",
        "/api/mcp/whoami",
        None,
        None,
    );
    r.rec("auth_config", "GET", "/api/auth/config", None, None);

    // Login.
    let (status, body) = r.rec(
        "login",
        "POST",
        "/api/auth/login",
        None,
        Some(json!({"username": admin_user, "password": admin_pass})),
    );
    let token = body
        .as_ref()
        .and_then(|b| b.get("access_token"))
        .and_then(Value::as_str)
        .map(str::to_string);

    if let Some(token) = token.as_deref() {
        r.rec("me", "GET", "/api/auth/me", Some(token), None);
        r.rec("vms_list", "GET", "/api/vms", Some(token), None);
        r.rec("users_list", "GET", "/api/users", Some(token), None);
        r.rec("tags_list", "GET", "/api/tags", Some(token), None);
        r.rec("actions_list", "GET", "/api/actions", Some(token), None);
        r.rec("schedules_list", "GET", "/api/schedules", Some(token), None);
        r.rec(
            "enrollment_tokens_list",
            "GET",
            "/api/enrollment-tokens",
            Some(token),
            None,
        );
        r.rec(
            "mcp_tokens_list",
            "GET",
            "/api/mcp/tokens",
            Some(token),
            None,
        );
        r.rec("settings_get", "GET", "/api/settings", Some(token), None);
        r.rec("audit_list", "GET", "/api/audit?limit=5", Some(token), None);
        r.rec(
            "audit_verify",
            "GET",
            "/api/audit/verify",
            Some(token),
            None,
        );

        let name = format!(
            "parity-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let (st, tag) = r.rec(
            "tag_create",
            "POST",
            "/api/tags",
            Some(token),
            Some(json!({"name": name, "color": "#ff0000"})),
        );
        if st == 201 {
            if let Some(tag) = tag {
                let id = tag
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                r.rec(
                    "tag_update",
                    "PUT",
                    &format!("/api/tags/{id}"),
                    Some(token),
                    Some(json!({"name": name, "color": "#00ff00"})),
                );
                r.rec(
                    "tag_delete",
                    "DELETE",
                    &format!("/api/tags/{id}"),
                    Some(token),
                    None,
                );
            }
        }
        let (st, tok) = r.rec(
            "enrollment_token_create",
            "POST",
            "/api/enrollment-tokens",
            Some(token),
            Some(json!({"name": "parity"})),
        );
        if st == 201 {
            if let Some(tok) = tok {
                let id = tok
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let enroll_token = tok
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                // Enroll before revoking: the hub invalidates revoked tokens.
                r.rec(
                    "worker_enroll",
                    "POST",
                    "/api/worker/enroll",
                    None,
                    Some(json!({
                        "token": enroll_token, "name": "parity-vm", "hostname": "parity",
                        "arch": "amd64", "worker_version": "v1.4.3"
                    })),
                );
                r.rec(
                    "enrollment_token_delete",
                    "DELETE",
                    &format!("/api/enrollment-tokens/{id}"),
                    Some(token),
                    None,
                );
            }
        }
    } else {
        r.results.insert(
            "_note".into(),
            json!({"detail": "admin login not possible", "challenge_token_present": status == 200}),
        );
    }

    let fake = [
        ("X-Worker-Id", "00000000-0000-0000-0000-000000000000"),
        ("X-Worker-Secret", "wrong"),
    ];
    r.rec_with(
        "worker_heartbeat_noauth_shape",
        "POST",
        "/api/worker/heartbeat",
        None,
        Some(json!({"worker_version": "v1.4.3"})),
        &fake,
    );
    r.rec_with(
        "worker_tls_required",
        "GET",
        "/api/worker/tasks/next?wait=0",
        None,
        None,
        &fake,
    );

    std::fs::create_dir_all(&out).expect("create out dir");
    let file = out.join("responses.json");
    let text =
        serde_json::to_string_pretty(&Value::Object(r.results.clone().into_iter().collect()))
            .expect("serialize");
    std::fs::write(&file, text).expect("write goldens");
    println!(
        "wrote {} golden responses to {}",
        r.results.len(),
        file.display()
    );
    0
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

fn diff(argv: &[String]) -> i32 {
    let (Some(a_dir), Some(b_dir)) = (argv.first(), argv.get(1)) else {
        eprintln!("usage: huginn-parity diff A_DIR B_DIR");
        return 2;
    };
    let load = |dir: &str| -> BTreeMap<String, Value> {
        let raw = std::fs::read_to_string(PathBuf::from(dir).join("responses.json"))
            .expect("read goldens");
        let parsed: Value = serde_json::from_str(&raw).expect("parse goldens");
        // Normalize on read too: goldens stay raw, rules can be tightened
        // without re-capturing both sides.
        match normalize(&parsed) {
            Value::Object(map) => map.into_iter().collect(),
            _ => BTreeMap::new(),
        }
    };
    let (a, b) = (load(a_dir), load(b_dir));
    let mut bad = 0;
    let mut total = 0;
    let mut names: std::collections::BTreeSet<&String> = a.keys().collect();
    names.extend(b.keys());
    for name in names {
        if !a.contains_key(name) || !b.contains_key(name) {
            println!(
                "DIFF {name}: only in {}",
                if a.contains_key(name) { "A" } else { "B" }
            );
            bad += 1;
            total += 1;
            continue;
        }
        total += 1;
        let (ra, rb) = (&a[name], &b[name]);
        if ra != rb {
            bad += 1;
            println!("DIFF {name}");
            if ra.get("status") != rb.get("status") {
                println!(
                    "   status: {} != {}",
                    ra.get("status").unwrap_or(&Value::Null),
                    rb.get("status").unwrap_or(&Value::Null)
                );
            }
            if ra.get("body") != rb.get("body") {
                println!("   body A: {}", ra.get("body").unwrap_or(&Value::Null));
                println!("   body B: {}", rb.get("body").unwrap_or(&Value::Null));
            }
        }
    }
    println!("\n{}/{} responses identical", total - bad, total);
    if bad > 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_matches_the_reference_rules() {
        assert_eq!(
            normalize_str("11111111-1111-1111-1111-111111111111"),
            "<UUID>"
        );
        assert_eq!(normalize_str("parity-1791996849"), "parity-<N>");
        assert_eq!(normalize_str("10.89.0.1"), "<IP>");
        assert_eq!(normalize_str("2026-10-14T23:57:24.610044Z"), "<TS>");
        assert_eq!(normalize_str("a".repeat(43).as_str()), "<TOKEN>");
        assert_eq!(
            normalize_str("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrstuvwxyz"),
            "<JWT>"
        );
    }

    #[test]
    fn diff_passes_on_identical_goldens() {
        let dir = std::env::temp_dir().join("huginn-parity-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let content = r#"{"a": {"method": "GET", "path": "/x", "status": 200, "body": {"id": "11111111-1111-1111-1111-111111111111"}}}"#;
        std::fs::write(dir.join("responses.json"), content).unwrap();
        assert_eq!(
            diff(&[dir.display().to_string(), dir.display().to_string()]),
            0
        );
    }
}

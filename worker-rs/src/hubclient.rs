// Typed HTTP client for the hub API. It uses the per-worker credentials on
// every authenticated call and refuses plaintext transport unless explicitly
// allowed (dev only).
//
// Rust port of worker/internal/hubclient.
use std::fmt;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Timeout applied to every hub request (mirrors http.Client{Timeout: 70s}).
const HTTP_TIMEOUT: Duration = Duration::from_secs(70);

/// Build the reqwest client: bundled Mozilla roots always, plus any CA
/// certificate provided (self-signed/internal hub CAs). rustls does not
/// read the OS trust store, so a self-signed hub CA must be handed in
/// explicitly (install.sh fetches it from /caddy-root.crt and writes it to
/// a known path, then sets HUB_CA_CERT / state).
fn build_http_client(
    _allow_insecure: bool,
    ca_cert_path: Option<&str>,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder().timeout(HTTP_TIMEOUT);
    if let Some(path) = ca_cert_path {
        if let Ok(pem) = std::fs::read(path) {
            if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
                builder = builder.add_root_certificate(cert);
            }
        }
    }
    builder.build()
}
/// Response bodies are read with a hard 4 MiB cap (mirrors io.LimitReader).
const MAX_RESPONSE_BYTES: usize = 4 << 20;

/// APIError carries a non-2xx response from the hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct APIError {
    pub status_code: u16,
    pub body: String,
}

impl fmt::Display for APIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hub returned {}: {}", self.status_code, self.body)
    }
}

impl std::error::Error for APIError {}

#[derive(Debug)]
pub enum Error {
    /// Transport policy violation (plaintext hub URL without allow_insecure).
    Policy(String),
    Api(APIError),
    Http(reqwest::Error),
    Encode(String),
    Decode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Policy(msg) => write!(f, "{msg}"),
            Error::Api(err) => write!(f, "{err}"),
            // The reqwest message alone ("error sending request for url")
            // hides the cause (TLS, timeout, connection refused). The
            // source chain carries it.
            Error::Http(err) => {
                write!(f, "{err}")?;
                let mut source = std::error::Error::source(err);
                while let Some(cause) = source {
                    write!(f, ": {cause}")?;
                    source = cause.source();
                }
                Ok(())
            }
            Error::Encode(msg) => write!(f, "{msg}"),
            Error::Decode(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Http(err) => Some(err),
            _ => None,
        }
    }
}

/// Client talks to the hub.
#[derive(Debug, Clone)]
pub struct Client {
    base_url: String,
    worker_id: String,
    worker_secret: String,
    http: reqwest::Client,
    #[allow(dead_code)] // kept for parity with the Go struct
    allow_insecure: bool,
}

/// Options configures a Client.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub base_url: String,
    pub worker_id: String,
    pub worker_secret: String,
    pub allow_insecure: bool,
    /// Optional path to a PEM CA file that signed the hub's certificate
    /// (self-signed/internal CAs). None = bundled Mozilla roots only.
    pub ca_cert_path: Option<String>,
}

impl Client {
    /// New constructs a Client, validating the transport policy.
    pub fn new(opts: Options) -> Result<Self, Error> {
        let base = opts.base_url.trim_end_matches('/').to_string();
        if !opts.allow_insecure && !base.starts_with("https://") {
            return Err(Error::Policy(format!(
                "hub URL must use https (got {base:?}); set allow_insecure for dev"
            )));
        }
        let http = build_http_client(opts.allow_insecure, opts.ca_cert_path.as_deref())
            .map_err(Error::Http)?;
        Ok(Self {
            base_url: base,
            worker_id: opts.worker_id,
            worker_secret: opts.worker_secret,
            http,
            allow_insecure: opts.allow_insecure,
        })
    }

    /// Enroll registers this machine with the hub using an enrollment token.
    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse, Error> {
        let body = encode(req)?;
        let data = self
            .request(
                reqwest::Method::POST,
                "/api/worker/enroll",
                Some(body),
                false,
            )
            .await?;
        decode_or_default(&data)
    }

    /// Heartbeat reports liveness/version and returns the desired target version.
    pub async fn heartbeat(&self, req: HeartbeatRequest) -> Result<HeartbeatResponse, Error> {
        let body = encode(&req)?;
        let data = self
            .request(
                reqwest::Method::POST,
                "/api/worker/heartbeat",
                Some(body),
                true,
            )
            .await?;
        decode_or_default(&data)
    }

    /// PollNextTask long-polls for the next queued task. The hub holds the
    /// request open for up to wait_seconds (server-capped) and returns as soon
    /// as a task is available, or None if the wait elapses with an empty queue.
    pub async fn poll_next_task(&self, wait_seconds: i64) -> Result<Option<Task>, Error> {
        let path = format!("/api/worker/tasks/next?wait={wait_seconds}");
        let data = self
            .request(reqwest::Method::GET, &path, None, true)
            .await?;
        decode_or_default(&data)
    }

    /// SubmitResult posts the outcome of a task.
    pub async fn submit_result(&self, task_id: &str, res: TaskResult) -> Result<(), Error> {
        // The task id is a path segment: it is percent-encoded so a crafted
        // id can never reshape the request path (`../`, `?`, `#`).
        let path = format!(
            "/api/worker/tasks/{}/result",
            percent_encode_path_segment(task_id)
        );
        let body = encode(&res)?;
        self.request(reqwest::Method::POST, &path, Some(body), true)
            .await?;
        Ok(())
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
        auth: bool,
    ) -> Result<Vec<u8>, Error> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, url);
        if let Some(data) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(data);
        }
        if auth {
            req = req
                .header("X-Worker-Id", &self.worker_id)
                .header("X-Worker-Secret", &self.worker_secret);
        }
        let mut resp = req.send().await.map_err(Error::Http)?;

        let data = read_capped(&mut resp, MAX_RESPONSE_BYTES)
            .await
            .map_err(Error::Http)?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::Api(APIError {
                status_code: status,
                body: String::from_utf8_lossy(&data).into_owned(),
            }));
        }
        Ok(data)
    }
}

async fn read_capped(resp: &mut reqwest::Response, cap: usize) -> Result<Vec<u8>, reqwest::Error> {
    let mut buf = Vec::new();
    while buf.len() < cap {
        match resp.chunk().await? {
            Some(chunk) => {
                let space = cap - buf.len();
                if chunk.len() > space {
                    buf.extend_from_slice(&chunk[..space]);
                    break; // cap reached — stop reading, like io.LimitReader
                }
                buf.extend_from_slice(&chunk);
            }
            None => break,
        }
    }
    Ok(buf)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|e| Error::Encode(e.to_string()))
}

/// Percent-encode one URL path segment (RFC 3986 unreserved characters are
/// kept, everything else becomes `%XX`). A task id is a path segment, not a
/// path: without this, an id carrying `..`, `/`, `?` or `#` would reshape
/// the request the worker sends to the hub.
fn percent_encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Decodes a JSON body, falling back to the zero value for blank bodies (the
/// Go client only unmarshals when the trimmed body is non-empty).
fn decode_or_default<T: DeserializeOwned + Default>(data: &[u8]) -> Result<T, Error> {
    if data.iter().any(|b| !b.is_ascii_whitespace()) {
        return serde_json::from_slice(data)
            .map_err(|e| Error::Decode(format!("decode response: {e}")));
    }
    Ok(T::default())
}

// --- Wire types (mirror the hub schemas) ---

#[derive(Debug, Clone, Serialize)]
pub struct EnrollRequest {
    pub token: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip_address: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_info: Option<Value>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub worker_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_browser: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnrollResponse {
    #[serde(default)]
    pub worker_id: String,
    #[serde(default)]
    pub worker_secret: String,
    #[serde(default)]
    pub state: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HeartbeatRequest {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub worker_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip_address: String,
    /// The installed Obscura engine version (`None` when no engine is
    /// installed). The hub stores it so the dashboard can show the engine
    /// state of a node instead of leaving the operator to guess.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_engine_version: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HeartbeatResponse {
    #[serde(default)]
    #[allow(dead_code)] // reported by the hub; parity with Go's field
    pub target_worker_version: String,
    #[serde(default)]
    pub exec_mode: String,
    #[serde(default)]
    pub allowed_release_domains: Vec<String>,
}

/// A JSON `null` (or a missing value) decodes to the type's default. Go's
/// encoding/json silently accepted null into plain fields; serde rejects it —
/// command tasks carry `action_name: null` and MUST parse (regression found
/// twice by security review: without this, every free command is invisible to
/// the worker and re-queued forever).
fn null_to_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    T: Default + serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(d).map(|o| o.unwrap_or_default())
}

/// Task is a unit of work handed to the worker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Task {
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default, rename = "type", deserialize_with = "null_to_default")]
    pub task_type: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub action_name: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub payload: serde_json::Map<String, Value>,
}

/// TaskResult is submitted back to the hub. Empty optional strings are omitted
/// from the JSON payload (omitempty), while a present exit code — including 0 —
/// is always sent (Go pointer semantics).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stdout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stderr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client_for(server: &MockServer) -> Client {
        Client::new(Options {
            base_url: server.uri(),
            allow_insecure: true,
            ca_cert_path: None,
            ..Default::default()
        })
        .expect("client")
    }

    #[test]
    fn test_new_rejects_plaintext_by_default() {
        let err = Client::new(Options {
            base_url: "http://hub.local".into(),
            ca_cert_path: None,
            ..Default::default()
        });
        assert!(
            err.is_err(),
            "expected rejection of http:// without allow_insecure"
        );
    }

    #[test]
    fn test_new_allows_plaintext_when_opted_in() {
        let client = Client::new(Options {
            base_url: "http://hub.local".into(),
            allow_insecure: true,
            ca_cert_path: None,
            ..Default::default()
        });
        assert!(client.is_ok(), "unexpected error: {client:?}");
    }

    #[tokio::test]
    async fn test_heartbeat_sends_auth_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/worker/heartbeat"))
            .and(header("x-worker-id", "vm-1"))
            .and(header("x-worker-secret", "sekret"))
            .and(body_partial_json(
                serde_json::json!({"worker_version": "v0.9"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"target_worker_version": "v1.0.0", "exec_mode": "whitelist"}),
            ))
            .mount(&server)
            .await;

        let client = Client::new(Options {
            base_url: server.uri(),
            worker_id: "vm-1".into(),
            worker_secret: "sekret".into(),
            allow_insecure: true,
            ca_cert_path: None,
        })
        .expect("client");

        let resp = client
            .heartbeat(HeartbeatRequest {
                worker_version: "v0.9".into(),
                ..Default::default()
            })
            .await
            .expect("Heartbeat (mock only matches with correct auth headers)");
        assert_eq!(resp.target_worker_version, "v1.0.0");
    }

    #[tokio::test]
    async fn test_poll_next_task_null_means_no_work() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/worker/tasks/next"))
            .respond_with(ResponseTemplate::new(200).set_body_string("null"))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let task = client.poll_next_task(0).await.expect("PollNextTask");
        assert!(task.is_none(), "expected nil task, got {task:?}");
    }

    #[tokio::test]
    async fn test_poll_next_task_returns_task() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/worker/tasks/next"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {"id": "t1", "type": "action", "action_name": "status", "payload": {}}
            )))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let task = client.poll_next_task(0).await.expect("PollNextTask");
        let task = task.expect("expected a task");
        assert_eq!(task.id, "t1");
        assert_eq!(task.task_type, "action");
    }

    /// A crafted task id must never reshape the request path: it is a path
    /// SEGMENT, so `/`, `?`, `#` and `..` are percent-encoded.
    #[tokio::test]
    async fn test_submit_result_encodes_the_task_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/worker/tasks/..%2F..%2Fadmin/result"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .submit_result("../../admin", TaskResult::default())
            .await
            .expect("submit");
    }

    #[test]
    fn test_path_segment_encoding() {
        assert_eq!(
            percent_encode_path_segment("abc-123_x.y~z"),
            "abc-123_x.y~z"
        );
        assert_eq!(
            percent_encode_path_segment("../../admin"),
            "..%2F..%2Fadmin"
        );
        assert_eq!(percent_encode_path_segment("a?b#c"), "a%3Fb%23c");
        assert_eq!(percent_encode_path_segment("a b"), "a%20b");
        assert_eq!(percent_encode_path_segment("%"), "%25");
    }

    #[tokio::test]
    async fn test_non_2xx_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/worker/heartbeat"))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(serde_json::json!({"detail": "nope"})),
            )
            .mount(&server)
            .await;
        let client = client_for(&server);
        let err = client
            .heartbeat(HeartbeatRequest::default())
            .await
            .expect_err("expected APIError");
        match &err {
            Error::Api(api) => {
                assert_eq!(api.status_code, 401, "expected 401 APIError");
                assert!(api.body.contains("nope"));
            }
            other => panic!("expected 401 APIError, got {other}"),
        }
        assert_eq!(err.to_string(), "hub returned 401: {\"detail\":\"nope\"}");
    }
}

#[cfg(test)]
mod task_parity_tests {
    use super::*;

    /// The hub sends `action_name: null` for command tasks — Go's
    /// encoding/json silently accepted null into plain string fields; serde
    /// must too or every command task is invisible (claim loop, dead-letter).
    #[test]
    fn command_task_with_null_action_name_parses() {
        let json = r#"{"id":"t1","type":"command","action_name":null,"payload":{"command":"apt update","timeout":60}}"#;
        let task: Task = serde_json::from_str(json).expect("command task must parse");
        assert_eq!(task.task_type, "command");
        assert_eq!(task.action_name, "");
        assert_eq!(task.payload["command"], "apt update");
    }

    #[test]
    fn null_fields_everywhere_fall_back_to_defaults() {
        let json = r#"{"id":null,"type":null,"action_name":null,"payload":null}"#;
        let task: Task = serde_json::from_str(json).expect("all-null task must parse");
        assert_eq!(task.id, "");
        assert_eq!(task.task_type, "");
        assert!(task.payload.is_empty());
    }

    #[test]
    fn action_task_still_parses() {
        let json = r#"{"id":"t2","type":"action","action_name":"status","payload":{}}"#;
        let task: Task = serde_json::from_str(json).unwrap();
        assert_eq!(task.action_name, "status");
    }
}

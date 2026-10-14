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
            Error::Http(err) => write!(f, "{err}"),
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
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
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
        let path = format!("/api/worker/tasks/{task_id}/result");
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

/// Task is a unit of work handed to the worker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Task {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "type")]
    pub task_type: String,
    #[serde(default)]
    pub action_name: String,
    #[serde(default)]
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
            ..Default::default()
        })
        .expect("client")
    }

    #[test]
    fn test_new_rejects_plaintext_by_default() {
        let err = Client::new(Options {
            base_url: "http://hub.local".into(),
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
            ..Default::default()
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

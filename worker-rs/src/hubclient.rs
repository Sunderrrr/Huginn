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
) -> Result<reqwest::Client, Error> {
    let mut builder = reqwest::Client::builder().timeout(HTTP_TIMEOUT);
    if let Some(path) = ca_cert_path {
        // A configured CA that cannot be read or parsed is fatal. Silently
        // continuing without it turns a clear "the file is missing" into a
        // later "invalid peer certificate: UnknownIssuer".
        let pem = std::fs::read(path).map_err(|e| Error::CaCert {
            path: path.to_string(),
            detail: format!("cannot be read: {e}"),
        })?;
        // reqwest accepts any bytes here and only fails later, at the TLS
        // handshake, with a misleading "invalid peer certificate". A PEM
        // certificate block is checked first, so the operator is told which
        // file is wrong.
        if !pem
            .windows("-----BEGIN CERTIFICATE-----".len())
            .any(|w| w == b"-----BEGIN CERTIFICATE-----")
        {
            return Err(Error::CaCert {
                path: path.to_string(),
                detail: "is not a PEM certificate (no BEGIN CERTIFICATE block)".to_string(),
            });
        }
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| Error::CaCert {
            path: path.to_string(),
            detail: format!("is not a valid PEM certificate: {e}"),
        })?;
        builder = builder.add_root_certificate(cert);
    }
    builder.build().map_err(Error::Http)
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
    /// The hub's CA file is configured but could not be read or parsed.
    /// Failing here is deliberate: a client silently built without the
    /// configured root produces a confusing "invalid peer certificate:
    /// UnknownIssuer" much later, instead of naming the actual problem.
    CaCert {
        path: String,
        detail: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Policy(msg) => write!(f, "{msg}"),
            Error::Api(err) => write!(f, "{err}"),
            Error::CaCert { path, detail } => {
                write!(f, "hub CA certificate {path}: {detail}")
            }
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
    /// The hub URL this client talks to.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// New constructs a Client, validating the transport policy.
    pub fn new(opts: Options) -> Result<Self, Error> {
        let base = opts.base_url.trim_end_matches('/').to_string();
        if !opts.allow_insecure && !base.starts_with("https://") {
            return Err(Error::Policy(format!(
                "hub URL must use https (got {base:?}); set allow_insecure for dev"
            )));
        }
        let http = build_http_client(opts.allow_insecure, opts.ca_cert_path.as_deref())?;
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

/// The local address the kernel picks to reach `hub_url` — the worker's own
/// address on the network the hub is reached from. A UDP `connect` sends no
/// packet: it only makes the kernel pick the route (and therefore the source
/// address) it would use. This is the address the node really has; the one
/// the hub sees at enrollment is often a NAT/bridge address that is
/// ambiguous (podman allocates the same subnets on different hosts).
pub fn outbound_ip(hub_url: &str) -> Option<String> {
    let rest = hub_url.split_once("://").map(|(_, r)| r).unwrap_or(hub_url);
    let host = rest.split(['/', '?']).next().unwrap_or("");
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((host, 9)).ok()?; // discard port: no traffic is sent
    let addr = sock.local_addr().ok()?;
    Some(addr.ip().to_string())
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

    /// A TLS server with a self-signed certificate, to check that the
    /// client validates certificates (and that the explicit CA path works).
    async fn spawn_self_signed_tls_server() -> (String, String) {
        use std::sync::Arc;
        use tokio::net::TcpListener;
        use tokio_rustls::rustls::crypto::ring;
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor;

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert = certified.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let provider = Arc::new(ring::default_provider());
        let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol version")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server cert");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut tls = match acceptor.accept(stream).await {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    // A heartbeat answer the client can decode.
                    let body = br#"{"target_worker_version":"v1.0.0","exec_mode":"whitelist","allowed_release_domains":[]}"#;
                    let mut head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    head.extend_from_slice(body);
                    let _ = tls.write_all(&head).await;
                });
            }
        });
        let pem = certified.cert.pem();
        (format!("https://localhost:{port}"), pem)
    }

    /// The client must never accept an unknown certificate: the fix for the
    /// Windows enrollment ("invalid peer certificate: UnknownIssuer") was to
    /// trust the PLATFORM store, not to stop validating.
    #[tokio::test]
    async fn the_client_refuses_an_untrusted_certificate() {
        let (url, _pem) = spawn_self_signed_tls_server().await;
        let client = Client::new(Options {
            base_url: url,
            ..Default::default()
        })
        .expect("client");
        let err = client
            .heartbeat(HeartbeatRequest::default())
            .await
            .expect_err("an unknown certificate must be refused");
        assert!(
            format!("{err}").to_lowercase().contains("certificate")
                || format!("{err}").to_lowercase().contains("unknownissuer"),
            "unexpected error: {err}"
        );
    }

    /// The explicit CA path still works: the Linux installer hands the hub's
    /// root to the worker that way.
    #[tokio::test]
    async fn the_client_trusts_the_certificate_given_by_ca_cert_path() {
        let (url, pem) = spawn_self_signed_tls_server().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, pem.as_bytes()).expect("write ca");
        let client = Client::new(Options {
            base_url: url,
            ca_cert_path: Some(ca_path.to_string_lossy().to_string()),
            ..Default::default()
        })
        .expect("client");
        client
            .heartbeat(HeartbeatRequest::default())
            .await
            .expect("the CA given by path must be trusted");
    }

    /// A configured CA that cannot be read must fail loudly, with the path:
    /// a client silently built without the root turns into a confusing
    /// "invalid peer certificate: UnknownIssuer" much later.
    #[test]
    fn a_configured_ca_that_cannot_be_read_is_an_error() {
        let missing = std::path::Path::new("/nonexistent/hub-ca.pem");
        let err = build_http_client(false, Some(missing.to_str().unwrap()))
            .expect_err("a missing CA file must be fatal");
        let text = format!("{err}");
        assert!(text.contains("hub-ca.pem"), "unexpected error: {text}");
        assert!(text.contains("cannot be read"), "unexpected error: {text}");

        // And a file that is not a certificate is refused too.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-a-cert.pem");
        std::fs::write(&path, b"this is not a certificate").expect("write");
        let err = build_http_client(false, Some(path.to_str().unwrap()))
            .expect_err("an invalid CA file must be fatal");
        let text = format!("{err}");
        assert!(text.contains("PEM certificate"), "unexpected error: {text}");
    }

    #[test]
    fn outbound_ip_is_the_route_source_address() {
        // A UDP connect sends no packet: it only makes the kernel pick the
        // route (and the source address) it would use. Loopback keeps the
        // test hermetic (no DNS, no traffic).
        assert_eq!(
            outbound_ip("http://127.0.0.1:8000").as_deref(),
            Some("127.0.0.1")
        );
        // A path in the URL does not change the host.
        assert_eq!(
            outbound_ip("https://127.0.0.1:8443/hub").as_deref(),
            Some("127.0.0.1")
        );
        // Nothing to report without a host.
        assert!(outbound_ip("").is_none());
        assert!(outbound_ip("https://").is_none());
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

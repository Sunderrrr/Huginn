// Performs atomic, rollback-safe worker self-updates. The new binary is
// downloaded next to the current one, its SHA-256 is verified against the
// published checksums, then swapped in atomically. If the post-restart health
// check fails, the previous binary is restored. All download hosts (including
// redirect hops) are checked against an allowlist to prevent SSRF.
//
// Rust port of worker/internal/update.
use std::fmt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// checksums.txt is read with a hard 1 MiB cap.
const CHECKSUMS_MAX_BYTES: usize = 1 << 20;
/// Whole-request timeout for update downloads (mirrors http.Client{Timeout: 5m}).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Staging filename written next to the target binary before the atomic swap.
const NEW_BINARY_NAME: &str = ".huginn-worker.new";

/// Spec describes a single update, as provided by the hub (already validated
/// server-side; re-validated here).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spec {
    pub binary_url: String,
    pub checksums_url: String,
    pub asset_name: String,
    pub version: String,
    pub binary_path: String,
}

/// Injectable restart/health hooks (Go: func(ctx) error).
pub type Hook = Arc<dyn Fn() -> BoxFuture<'static, Result<(), String>> + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// SSRF-blocked download host (Go: ErrHostNotAllowed).
    HostNotAllowed(String),
    Msg(String),
}

impl Error {
    #[allow(dead_code)] // used by callers distinguishing error kinds
    pub fn is_host_not_allowed(&self) -> bool {
        matches!(self, Error::HostNotAllowed(_))
    }

    fn msg(message: impl Into<String>) -> Self {
        Error::Msg(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::HostNotAllowed(detail) => write!(f, "download host not in allowlist: {detail}"),
            Error::Msg(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for Error {}

/// Updater applies updates. Restart and health check are injectable for tests.
pub struct Updater {
    http: reqwest::Client,
    allowed_domains: Vec<String>,
    restart: Option<Hook>,
    health: Option<Hook>,
}

impl Updater {
    /// NewUpdater builds an Updater whose HTTP client validates every redirect
    /// hop against the allowlist.
    pub fn new(allowed_domains: Vec<String>, restart: Option<Hook>, health: Option<Hook>) -> Self {
        Self {
            http: validating_client(&allowed_domains),
            allowed_domains,
            restart,
            health,
        }
    }

    /// Alternate constructor mirroring Go's struct literal override of the
    /// HTTP client (used by tests).
    #[allow(dead_code)] // parity with Go's struct-literal HTTP override (tests)
    pub fn with_http(
        http: reqwest::Client,
        allowed_domains: Vec<String>,
        restart: Option<Hook>,
        health: Option<Hook>,
    ) -> Self {
        Self {
            http,
            allowed_domains,
            restart,
            health,
        }
    }

    /// Apply runs the full update with rollback on failure.
    pub async fn apply(&self, spec: Spec) -> Result<(), Error> {
        validate_url(&spec.binary_url, &self.allowed_domains)?;
        validate_url(&spec.checksums_url, &self.allowed_domains)?;

        let expected = self
            .fetch_expected_checksum(&spec.checksums_url, &spec.asset_name)
            .await
            .map_err(|e| Error::msg(format!("checksum lookup: {e}")))?;

        let binary_path = PathBuf::from(&spec.binary_path);
        let dir = binary_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let tmp = dir.join(NEW_BINARY_NAME);
        let _ = tokio::fs::remove_file(&tmp).await; // create_new is exclusive
        if let Err(e) = self.download(&spec.binary_url, &tmp).await {
            return Err(match e {
                Error::HostNotAllowed(_) => e,
                Error::Msg(m) => Error::msg(format!("download: {m}")),
            });
        }

        let result = self.swap_and_verify(&spec, &tmp, &expected).await;
        // Mirror Go's `defer os.Remove(tmp)` — a no-op once the file has been
        // renamed into place (or never existed on failure paths).
        let _ = tokio::fs::remove_file(&tmp).await;
        result
    }

    async fn swap_and_verify(&self, spec: &Spec, tmp: &Path, expected: &str) -> Result<(), Error> {
        let sum = file_sha256(tmp)
            .await
            .map_err(|e| Error::msg(e.to_string()))?;
        if !constant_time_eq(sum.as_bytes(), expected.as_bytes()) {
            return Err(Error::msg(format!(
                "checksum mismatch: got {sum} want {expected}"
            )));
        }
        // On Unix the staged file needs the executable bit; on Windows
        // executability is not a permission bit.
        #[cfg(unix)]
        tokio::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o755))
            .await
            .map_err(|e| Error::msg(e.to_string()))?;

        let binary_path = PathBuf::from(&spec.binary_path);
        // Keep a backup of the current binary for rollback — never write
        // through a pre-placed symlink at that path.
        let backup = PathBuf::from(format!("{}.bak", spec.binary_path));
        if tokio::fs::symlink_metadata(&backup)
            .await
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(Error::msg("backup path is a symlink; refusing"));
        }
        // Windows: a running image can be RENAMED but not replaced in place
        // (the swap rename would have to delete the locked target first),
        // so move the current binary out of the way — that doubles as the
        // backup. If the move fails (unexpected), fall back to a copy.
        #[cfg(windows)]
        let moved_old = tokio::fs::rename(&binary_path, &backup).await.is_ok();
        #[cfg(windows)]
        if !moved_old {
            copy_file(&binary_path, &backup)
                .await
                .map_err(|e| Error::msg(format!("backup current binary: {e}")))?;
        }
        #[cfg(unix)]
        copy_file(&binary_path, &backup)
            .await
            .map_err(|e| Error::msg(format!("backup current binary: {e}")))?;

        if let Err(e) = tokio::fs::rename(&tmp, &binary_path).await {
            // On Windows the move-away above can leave the target path
            // missing — put the old binary back before failing.
            #[cfg(windows)]
            if moved_old {
                let _ = tokio::fs::rename(&backup, &binary_path).await;
            }
            return Err(Error::msg(format!("atomic swap: {e}")));
        }

        if let Err(e) = self.restart_and_health().await {
            // Roll back to the previous binary and restart again.
            if let Err(rb) = tokio::fs::rename(&backup, &binary_path).await {
                return Err(Error::msg(format!(
                    "update failed ({e}) and rollback failed: {rb}"
                )));
            }
            if let Some(restart) = &self.restart {
                let _ = restart().await;
            }
            return Err(Error::msg(format!(
                "update health check failed, rolled back: {e}"
            )));
        }

        // On Windows with a moved-out old image, this .bak may still be the
        // running image (deleting a live exe fails) — best-effort removal,
        // it disappears after the service restarts onto the new binary.
        let _ = tokio::fs::remove_file(&backup).await;
        Ok(())
    }

    async fn restart_and_health(&self) -> Result<(), String> {
        if let Some(restart) = &self.restart {
            restart().await?;
        }
        if let Some(health) = &self.health {
            return health().await;
        }
        Ok(())
    }

    async fn fetch_expected_checksum(&self, url: &str, asset: &str) -> Result<String, Error> {
        let data = self.get_capped(url, CHECKSUMS_MAX_BYTES).await?;
        for line in String::from_utf8_lossy(&data).lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 2 {
                continue;
            }
            // sha256sum format: "<hash>  <filename>"; match on basename.
            if base_name(fields[1]) == asset {
                return Ok(fields[0].to_lowercase());
            }
        }
        Err(Error::msg(format!("no checksum entry for {asset:?}")))
    }

    /// Upper bound for a downloaded worker binary — a hostile/compromised
    /// release host could otherwise stream gigabytes and fill the disk (the
    /// checksum is only verified after the download completes).
    const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

    async fn download(&self, raw_url: &str, dest: &Path) -> Result<(), Error> {
        let mut resp = self.open(raw_url).await?;
        if let Some(len) = resp.content_length() {
            if len > Self::MAX_BINARY_BYTES {
                return Err(Error::msg("download too large (content-length)"));
            }
        }
        // create_new (O_EXCL): never write through a pre-placed symlink, and
        // never silently truncate an existing file we did not create.
        // 0600 on Unix; inherited ACLs on Windows.
        #[cfg(unix)]
        let mut out = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(dest)
            .await
            .map_err(|e| Error::msg(e.to_string()))?;
        #[cfg(windows)]
        let mut out = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(dest)
            .await
            .map_err(|e| Error::msg(e.to_string()))?;
        let mut written: u64 = 0;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    written += chunk.len() as u64;
                    if written > Self::MAX_BINARY_BYTES {
                        let _ = tokio::fs::remove_file(dest).await;
                        return Err(Error::msg("download too large"));
                    }
                    out.write_all(&chunk)
                        .await
                        .map_err(|e| Error::msg(e.to_string()))?;
                }
                Ok(None) => break,
                Err(e) => return Err(map_reqwest(e)),
            }
        }
        out.flush().await.map_err(|e| Error::msg(e.to_string()))?;
        Ok(())
    }

    async fn open(&self, raw_url: &str) -> Result<reqwest::Response, Error> {
        validate_url(raw_url, &self.allowed_domains)?;
        let resp = self.http.get(raw_url).send().await.map_err(map_reqwest)?;
        if resp.status().as_u16() != 200 {
            return Err(Error::msg(format!(
                "GET {raw_url}: status {}",
                resp.status().as_u16()
            )));
        }
        Ok(resp)
    }

    async fn get_capped(&self, raw_url: &str, cap: usize) -> Result<Vec<u8>, Error> {
        let mut resp = self.open(raw_url).await?;
        read_capped(&mut resp, cap)
            .await
            .map_err(|e| Error::msg(e.to_string()))
    }
}

/// One-off allowlisted download (used by the browser E2E test to fetch the
/// Obscura release tarball). Every redirect hop is validated against
/// `allowed`, exactly like the updater's own downloads.
#[cfg(all(test, target_os = "linux"))]
pub(crate) async fn download_bytes(
    url: &str,
    allowed: &[String],
    cap: usize,
) -> Result<Vec<u8>, Error> {
    let updater = Updater::new(allowed.to_vec(), None, None);
    let mut resp = updater.open(url).await?;
    read_capped(&mut resp, cap)
        .await
        .map_err(|e| Error::msg(e.to_string()))
}

/// ValidateURL checks scheme and host against the allowlist.
pub fn validate_url(raw: &str, allowed: &[String]) -> Result<(), Error> {
    let parsed = reqwest::Url::parse(raw).map_err(|e| Error::msg(e.to_string()))?;
    validate_host(&parsed, allowed)
}

fn validate_host(url: &reqwest::Url, allowed: &[String]) -> Result<(), Error> {
    if url.scheme() != "https" {
        return Err(Error::HostNotAllowed(format!(
            "scheme {:?} must be https",
            url.scheme()
        )));
    }
    let host = url.host_str().unwrap_or_default().to_lowercase();
    for a in allowed {
        if host == a.to_lowercase() {
            return Ok(());
        }
    }
    Err(Error::HostNotAllowed(format!("{host:?}")))
}

/// Recovers the SSRF cause from a reqwest error chain: the redirect policy
/// rejects disallowed hops with our `Error`, which reqwest wraps; surfacing it
/// keeps `errors.Is(err, ErrHostNotAllowed)` parity with Go.
fn map_reqwest(e: reqwest::Error) -> Error {
    let mut cur = std::error::Error::source(&e);
    while let Some(err) = cur {
        if let Some(inner) = err.downcast_ref::<Error>() {
            match inner {
                Error::HostNotAllowed(h) => return Error::HostNotAllowed(h.clone()),
                Error::Msg(m) => return Error::Msg(m.clone()),
            }
        }
        cur = err.source();
    }
    Error::Msg(e.to_string())
}

fn validating_client(allowed: &[String]) -> reqwest::Client {
    let allowed: Arc<[String]> = allowed.iter().cloned().collect();
    reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .redirect(reqwest::redirect::Policy::custom(
            move |attempt| match validate_host(attempt.url(), &allowed) {
                Ok(()) => attempt.follow(),
                Err(err) => attempt.error(err),
            },
        ))
        .build()
        .expect("build update HTTP client")
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

async fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

async fn copy_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut input = tokio::fs::File::open(src).await?;
    // 0755 on Unix (the backup keeps being executable); inherited ACLs on
    // Windows.
    #[cfg(unix)]
    let mut out = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o755)
        .open(dst)
        .await?;
    #[cfg(windows)]
    let mut out = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(dst)
        .await?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n]).await?;
    }
    out.flush().await?;
    Ok(())
}

/// Constant-time byte comparison (Go: subtle.ConstantTimeCompare != 1).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Mirrors Go's filepath.Base for sha256sum filename matching.
fn base_name(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let stripped = path.trim_end_matches('/');
    if stripped.is_empty() {
        return "/".to_string();
    }
    match stripped.rfind('/') {
        Some(i) => stripped[i + 1..].to_string(),
        None => stripped.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::testutil::temp_dir;
    use std::collections::HashMap;

    const ASSET_NAME: &str = "huginn-worker-linux-amd64";

    // --- minimal local HTTPS server (Go: httptest.NewTLSServer) ---

    struct TestTlsServer {
        url: String,
        handle: tokio::task::JoinHandle<()>,
    }

    impl TestTlsServer {
        fn url(&self) -> &str {
            &self.url
        }
    }

    impl Drop for TestTlsServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    fn http_ok(body: &[u8]) -> Vec<u8> {
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(body);
        resp
    }

    fn http_redirect(location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    async fn spawn_tls_server(routes: HashMap<String, Vec<u8>>) -> TestTlsServer {
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
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let acceptor = acceptor.clone();
                let routes = routes.clone();
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
                    let head = String::from_utf8_lossy(&buf);
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    if let Some(response) = routes.get(&path) {
                        let _ = tls.write_all(response).await;
                    } else {
                        let _ = tls
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    let _ = tls.shutdown().await;
                });
            }
        });
        TestTlsServer {
            url: format!("https://127.0.0.1:{port}"),
            handle,
        }
    }

    // --- test helpers (mirroring update_test.go) ---

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    async fn write_current_binary(dir: &Path) -> String {
        let path = dir.join("huginn-worker");
        tokio::fs::write(&path, b"OLD-BINARY").await.expect("write");
        path.to_string_lossy().into_owned()
    }

    fn ok_health() -> Option<Hook> {
        Some(Arc::new(|| {
            Box::pin(async { Ok(()) }) as BoxFuture<'static, Result<(), String>>
        }))
    }

    fn failing_health() -> Option<Hook> {
        Some(Arc::new(|| {
            Box::pin(async { Err("new binary is unhealthy".to_string()) })
                as BoxFuture<'static, Result<(), String>>
        }))
    }

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(DOWNLOAD_TIMEOUT)
            .build()
            .expect("client")
    }

    async fn release_server(binary: &[u8], checksum: &str) -> TestTlsServer {
        let mut routes = HashMap::new();
        routes.insert("/bin".to_string(), http_ok(binary));
        let checksums = format!("{checksum}  {ASSET_NAME}\n");
        routes.insert("/checksums.txt".to_string(), http_ok(checksums.as_bytes()));
        spawn_tls_server(routes).await
    }

    fn spec_for(server: &TestTlsServer, path: &str, version: &str) -> Spec {
        Spec {
            binary_url: format!("{}/bin", server.url()),
            checksums_url: format!("{}/checksums.txt", server.url()),
            asset_name: ASSET_NAME.to_string(),
            version: version.to_string(),
            binary_path: path.to_string(),
        }
    }

    fn chain_contains(err: &(dyn std::error::Error + 'static), needle: &str) -> bool {
        let mut current = Some(err);
        while let Some(e) = current {
            if e.to_string().contains(needle) {
                return true;
            }
            current = e.source();
        }
        false
    }

    #[tokio::test]
    async fn test_apply_success_swaps_binary() {
        let new_bin = b"NEW-BINARY-CONTENT".to_vec();
        let server = release_server(&new_bin, &sha256_hex(&new_bin)).await;

        let dir = temp_dir("update-success");
        let path = write_current_binary(&dir).await;
        let updater = Updater::with_http(
            test_http_client(),
            vec!["127.0.0.1".to_string()],
            None,
            ok_health(),
        );

        updater
            .apply(spec_for(&server, &path, "v1.2.3"))
            .await
            .expect("Apply");

        let got = tokio::fs::read(&path).await.expect("read swapped binary");
        assert_eq!(got, new_bin, "binary content should be swapped");
        assert!(
            !Path::new(&format!("{path}.bak")).exists(),
            "backup file should be removed on success"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_apply_checksum_mismatch_keeps_old_binary() {
        let new_bin = b"NEW-BINARY-CONTENT".to_vec();
        // Bad checksum on purpose.
        let server = release_server(&new_bin, &sha256_hex(b"WRONG")).await;

        let dir = temp_dir("update-checksum");
        let path = write_current_binary(&dir).await;
        let updater = Updater::with_http(
            test_http_client(),
            vec!["127.0.0.1".to_string()],
            None,
            ok_health(),
        );

        let err = updater
            .apply(spec_for(&server, &path, ""))
            .await
            .expect_err("expected checksum mismatch error");
        assert!(err.to_string().contains("checksum mismatch"), "err: {err}");

        let got = tokio::fs::read(&path).await.expect("read binary");
        assert_eq!(
            got, b"OLD-BINARY",
            "old binary should be untouched on checksum failure"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_apply_rolls_back_on_health_failure() {
        let new_bin = b"NEW-BINARY-CONTENT".to_vec();
        let server = release_server(&new_bin, &sha256_hex(&new_bin)).await;

        let dir = temp_dir("update-rollback");
        let path = write_current_binary(&dir).await;
        let updater = Updater::with_http(
            test_http_client(),
            vec!["127.0.0.1".to_string()],
            None,
            failing_health(),
        );

        let err = updater
            .apply(spec_for(&server, &path, ""))
            .await
            .expect_err("expected health-check failure error");
        assert!(err.to_string().contains("rolled back"), "err: {err}");

        let got = tokio::fs::read(&path).await.expect("read binary");
        assert_eq!(
            got, b"OLD-BINARY",
            "binary should be rolled back to old content, got {got:?}"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_apply_rejects_disallowed_host() {
        let updater = Updater::new(vec!["github.com".to_string()], None, None);
        let err = updater
            .apply(Spec {
                binary_url: "https://evil.example.com/bin".into(),
                checksums_url: "https://github.com/x/checksums.txt".into(),
                asset_name: ASSET_NAME.into(),
                version: String::new(),
                binary_path: "/tmp/whatever".into(),
            })
            .await
            .expect_err("expected ErrHostNotAllowed");
        assert!(
            err.is_host_not_allowed(),
            "expected ErrHostNotAllowed, got {err}"
        );
    }

    #[test]
    fn test_validate_url() {
        let allowed = vec!["github.com".to_string()];
        assert!(
            validate_url("https://github.com/x", &allowed).is_ok(),
            "github.com should be allowed"
        );
        assert!(
            validate_url("http://github.com/x", &allowed).is_err(),
            "http should be rejected"
        );
        assert!(
            validate_url("https://evil.com/x", &allowed).is_err(),
            "evil.com should be rejected"
        );
    }

    #[tokio::test]
    async fn test_apply_rejects_disallowed_redirect_hop() {
        // Extra parity coverage (contract: allowlist is enforced on EVERY
        // redirect hop): /redir redirects to a non-allowlisted host.
        let new_bin = b"NEW-BINARY-CONTENT".to_vec();
        let mut routes = HashMap::new();
        routes.insert("/bin".to_string(), http_ok(&new_bin));
        let checksums = format!("{}  {ASSET_NAME}\n", sha256_hex(&new_bin));
        routes.insert("/checksums.txt".to_string(), http_ok(checksums.as_bytes()));
        routes.insert(
            "/redir".to_string(),
            http_redirect("https://evil.example.com/bin"),
        );
        let server = spawn_tls_server(routes).await;

        // Client WITH the production redirect policy (like Updater::new builds),
        // but accepting the test server's self-signed certificate.
        let allowed = vec!["127.0.0.1".to_string()];
        let policy_allowed = allowed.clone();
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(DOWNLOAD_TIMEOUT)
            .redirect(reqwest::redirect::Policy::custom(
                move |attempt| match validate_host(attempt.url(), &policy_allowed) {
                    Ok(()) => attempt.follow(),
                    Err(err) => attempt.error(err),
                },
            ))
            .build()
            .expect("client");
        let updater = Updater::with_http(client, allowed, None, ok_health());

        let dir = temp_dir("update-redirect");
        let path = write_current_binary(&dir).await;
        let spec = Spec {
            binary_url: format!("{}/redir", server.url()),
            checksums_url: format!("{}/checksums.txt", server.url()),
            asset_name: ASSET_NAME.to_string(),
            version: String::new(),
            binary_path: path.clone(),
        };
        let err = updater
            .apply(spec)
            .await
            .expect_err("redirect must be blocked");
        assert!(
            chain_contains(&err, "not in allowlist"),
            "expected host-not-allowed error, got {err:?}"
        );
        let got = tokio::fs::read(&path).await.expect("read binary");
        assert_eq!(got, b"OLD-BINARY", "binary must be untouched");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn test_base_name_matches_go_filepath_base() {
        assert_eq!(
            base_name("huginn-worker-linux-amd64"),
            "huginn-worker-linux-amd64"
        );
        assert_eq!(
            base_name("releases/v1.2/huginn-worker-linux-amd64"),
            "huginn-worker-linux-amd64"
        );
        assert_eq!(base_name(""), ".");
        assert_eq!(base_name("/"), "/");
        assert_eq!(base_name("abc/"), "abc");
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}

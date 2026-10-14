// Runs commands as separated argv vectors. It NEVER interprets a shell: there
// is no `sh -c`, no string concatenation, and no metacharacter expansion. This
// is the core defense against command injection on the worker.
//
// Rust port of worker/internal/exec.
use std::io;
use std::process::Stdio;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

/// DefaultMaxOutputBytes caps captured stdout/stderr to bound memory use.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1 << 20; // 1 MiB

/// Result is the outcome of running a command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

/// Runner executes argv vectors. It is a trait so the agent can be tested with
/// a fake. The returned future is boxed to keep the trait object-safe.
pub trait Runner: Send + Sync {
    fn run(
        &self,
        argv: Vec<String>,
        timeout: Duration,
        max_output: usize,
    ) -> BoxFuture<'static, io::Result<ExecResult>>;
}

/// CommandRunner is the real, OS-backed Runner.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommandRunner;

impl Runner for CommandRunner {
    fn run(
        &self,
        argv: Vec<String>,
        timeout: Duration,
        max_output: usize,
    ) -> BoxFuture<'static, io::Result<ExecResult>> {
        Box::pin(run_command(argv, timeout, max_output))
    }
}

/// Executes argv[0] with argv[1:] as arguments — no shell is involved.
pub async fn run_command(
    argv: Vec<String>,
    timeout: Duration,
    max_output: usize,
) -> io::Result<ExecResult> {
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
    }
    let max_output = if max_output == 0 {
        DEFAULT_MAX_OUTPUT_BYTES
    } else {
        max_output
    };
    let timeout = if timeout.is_zero() {
        Duration::from_secs(60)
    } else {
        timeout
    };

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    // tokio's Command does NOT invoke a shell; argv is passed verbatim.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Never leak the child if the surrounding future is dropped (timeout or
    // shutdown) — mirrors CommandContext killing on context cancellation.
    command.kill_on_drop(true);

    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let stdout_task = tokio::spawn(capture_output(stdout, max_output));
    let stderr_task = tokio::spawn(capture_output(stderr, max_output));

    let timed_out;
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => {
            timed_out = false;
            status?
        }
        Err(_elapsed) => {
            timed_out = true;
            let _ = child.kill().await;
            child.wait().await?
        }
    };

    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();

    if timed_out {
        return Ok(ExecResult {
            stdout,
            stderr,
            exit_code: -1,
            timed_out: true,
        });
    }
    // Signal-terminated processes report -1, matching Go's (exitErr).ExitCode().
    let exit_code = status.code().unwrap_or(-1);
    Ok(ExecResult {
        stdout,
        stderr,
        exit_code,
        timed_out: false,
    })
}

/// Reads a stream until EOF, keeping at most `limit` bytes (the rest is
/// discarded but the process keeps running), mirroring the Go cappedBuffer.
async fn capture_output<R>(mut stream: R, limit: usize) -> String
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let remaining = limit.saturating_sub(buf.len());
                if remaining > 0 {
                    let take = n.min(remaining);
                    buf.extend_from_slice(&chunk[..take]);
                }
            }
        }
    }
    // Invalid UTF-8 is replaced with U+FFFD, matching what Go's JSON encoder
    // does when marshalling a raw byte string into the result payload.
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner() -> CommandRunner {
        CommandRunner
    }

    async fn run(argv: &[&str], timeout: Duration, max_output: usize) -> io::Result<ExecResult> {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        runner().run(argv, timeout, max_output).await
    }

    #[tokio::test]
    async fn test_run_captures_stdout_and_exit_zero() {
        let res = run(&["echo", "hello"], Duration::from_secs(1), 0)
            .await
            .expect("no error");
        assert_eq!(res.exit_code, 0, "exit code = {}, want 0", res.exit_code);
        assert_eq!(res.stdout.trim(), "hello", "stdout = {:?}", res.stdout);
    }

    #[tokio::test]
    async fn test_run_non_zero_exit() {
        let res = run(&["false"], Duration::from_secs(1), 0)
            .await
            .expect("no error");
        assert_ne!(res.exit_code, 0, "expected non-zero exit code");
    }

    #[tokio::test]
    async fn test_run_timeout() {
        let res = run(&["sleep", "5"], Duration::from_millis(100), 0)
            .await
            .expect("no error");
        assert!(res.timed_out, "expected TimedOut=true");
    }

    #[tokio::test]
    async fn test_run_unknown_binary_errors() {
        let res = run(
            &["definitely-not-a-real-binary-xyz"],
            Duration::from_secs(1),
            0,
        )
        .await;
        assert!(res.is_err(), "expected error for missing binary");
    }

    #[tokio::test]
    async fn test_run_empty_argv() {
        let res = runner().run(Vec::new(), Duration::from_secs(1), 0).await;
        assert!(res.is_err(), "expected error for empty argv");
    }

    #[tokio::test]
    async fn test_no_shell_interpretation() {
        // If a shell were involved, "$(touch x)" would expand. Passed as a
        // single argv element to echo, it must be emitted literally.
        let payload = "$(touch /tmp/should-not-exist); rm -rf /";
        let res = run(&["echo", payload], Duration::from_secs(1), 0)
            .await
            .expect("no error");
        assert_eq!(
            res.stdout.trim(),
            payload,
            "stdout must be the literal payload"
        );
    }

    #[tokio::test]
    async fn test_output_is_capped() {
        let res = run(
            &["sh", "-c", "yes abcdefgh | head -c 100000"],
            Duration::from_secs(5),
            1024,
        )
        .await
        .expect("no error");
        assert!(
            res.stdout.len() <= 1024,
            "stdout length = {}, want <= 1024",
            res.stdout.len()
        );
    }
}

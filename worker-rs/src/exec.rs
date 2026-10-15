// Runs commands as separated argv vectors. The runner itself NEVER interprets
// a shell: there is no string concatenation, and no metacharacter expansion.
// (The hub-gated unrestricted mode deliberately invokes a shell as an argv
// vector — `sh -c` on Linux, PowerShell on Windows — built here so the shell
// choice stays in one audited place.) This is the core defense against
// command injection on the worker.
//
// Rust port of worker/internal/exec, ported to Windows (Job Objects replace
// process groups).
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

/// The interpreter used ONLY for hub-gated unrestricted free commands: `sh`
/// on Linux; on Windows, PowerShell 7 (`pwsh`) when installed, else the
/// built-in Windows PowerShell 5.1 (`powershell`). Resolved once per process.
pub fn unrestricted_shell() -> &'static str {
    #[cfg(unix)]
    {
        "sh"
    }
    #[cfg(windows)]
    {
        detect_powershell()
    }
}

/// Builds the argv that invokes `shell` to interpret `command`. The command
/// stays a single argv element — the OS spawns the interpreter directly with
/// one argument, there is no intermediate string concatenation or quoting
/// layer to break out of.
pub fn shell_argv(shell: &str, command: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec![shell.into(), "-c".into(), command.into()]
    }
    #[cfg(windows)]
    {
        vec![
            shell.into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-ExecutionPolicy".into(),
            "Bypass".into(),
            "-Command".into(),
            command.into(),
        ]
    }
}

/// Prefers `pwsh` (PowerShell 7+) when it is on PATH, else falls back to
/// `powershell` (Windows PowerShell 5.1, ships with every supported Windows).
#[cfg(windows)]
fn detect_powershell() -> &'static str {
    use std::sync::OnceLock;
    static SHELL: OnceLock<&'static str> = OnceLock::new();
    SHELL.get_or_init(|| {
        if on_path("pwsh.exe") {
            "pwsh"
        } else {
            "powershell"
        }
    })
}

#[cfg(windows)]
fn on_path(exe: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(exe).is_file()))
        .unwrap_or(false)
}

// --- Windows: Job Objects --------------------------------------------------
//
// The Unix runner kills a timed-out child's whole process group. The Windows
// equivalent is a Job Object: assign the child to a job created with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and terminate the job at timeout — the
// child and every descendant it spawned die together, so nothing is left
// holding the stdout/stderr pipes open.
#[cfg(windows)]
mod winjob {
    use std::ffi::c_void;
    use std::io;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA};

    /// HANDLE is a raw isize in windows-sys; null is 0.
    const NULL_HANDLE: HANDLE = 0;

    pub struct Job(HANDLE);

    impl Job {
        /// Creates a job whose member processes are terminated when the last
        /// handle to it closes.
        pub fn create() -> io::Result<Self> {
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job == NULL_HANDLE {
                    return Err(io::Error::last_os_error());
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 {
                    let err = io::Error::last_os_error();
                    CloseHandle(job);
                    return Err(err);
                }
                Ok(Self(job))
            }
        }

        /// Adds a running process (by PID) to the job. Descendants the child
        /// spawns afterwards inherit its job membership.
        pub fn assign_process(&self, pid: u32) -> io::Result<()> {
            unsafe {
                let process = OpenProcess(PROCESS_SET_QUOTA, 0, pid);
                if process == NULL_HANDLE {
                    return Err(io::Error::last_os_error());
                }
                let ok = AssignProcessToJobObject(self.0, process);
                let result = if ok == 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                };
                CloseHandle(process);
                result
            }
        }

        /// Terminates every process in the job (the child and all its
        /// descendants). Best-effort — the handle drop also kills survivors.
        pub fn terminate(&self) {
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Captures a child pipe with a bounded grace: waits for EOF normally, but if
/// an orphaned descendant keeps the write end open (`sh -c "sleep 999999 &"`),
/// gives up `grace` after the child exits instead of hanging the worker.
fn spawn_bounded_capture<R>(
    stream: R,
    max_output: usize,
    exited: &tokio::sync::watch::Receiver<bool>,
    grace: Duration,
) -> tokio::task::JoinHandle<String>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut exited = exited.clone();
    tokio::spawn(async move {
        tokio::select! {
            out = capture_output(stream, max_output) => out,
            _ = async {
                let _ = exited.changed().await;
                tokio::time::sleep(grace).await;
            } => String::new(),
        }
    })
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

    // Windows: the job must exist before the spawn so the child can be
    // assigned to it right away. Its handle drops when this function
    // returns — KILL_ON_JOB_CLOSE then reaps any process still in the job,
    // so a task can never leave orphaned descendants behind.
    #[cfg(windows)]
    let job = winjob::Job::create()?;

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
    // Own process group: a killed child's descendants can otherwise keep the
    // stdout/stderr pipes open forever (e.g. `sh -c "sleep 999999 &"`), which
    // would hang the pipe capture below and freeze the whole worker.
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command.spawn()?;
    #[cfg(windows)]
    if let Some(pid) = child.id() {
        // Best-effort: if the child died instantly the assignment fails —
        // kill_on_drop and the bounded capture below still bound the run.
        if let Err(e) = job.assign_process(pid) {
            eprintln!("huginn-worker: job assignment failed: {e}");
        }
    }
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    // Bounded pipe collection: an orphaned descendant (`sh -c "sleep
    // 999999 &"`) can hold the pipe's write end open forever; waiting for
    // EOF would freeze the whole worker. Each capture gives up 5s AFTER the
    // child exits (grace for a clean flush), never mid-run.
    const PIPE_GRACE: Duration = Duration::from_secs(5);
    let (exited_tx, exited_rx) = tokio::sync::watch::channel(false);
    let stdout_task = spawn_bounded_capture(stdout, max_output, &exited_rx, PIPE_GRACE);
    let stderr_task = spawn_bounded_capture(stderr, max_output, &exited_rx, PIPE_GRACE);

    let timed_out;
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => {
            timed_out = false;
            let st = status?;
            let _ = exited_tx.send(true);
            st
        }
        Err(_elapsed) => {
            timed_out = true;
            // Kill the whole process tree: `child.kill()` alone leaves
            // grandchildren alive (they hold the pipes open → the capture
            // below would never see EOF).
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
            // Windows: terminating the job kills the child plus every
            // descendant it spawned.
            #[cfg(windows)]
            job.terminate();
            let _ = child.kill().await;
            let st = child.wait().await?;
            let _ = exited_tx.send(true);
            st
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

    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_captures_stdout_and_exit_zero() {
        let res = run(&["echo", "hello"], Duration::from_secs(1), 0)
            .await
            .expect("no error");
        assert_eq!(res.exit_code, 0, "exit code = {}, want 0", res.exit_code);
        assert_eq!(res.stdout.trim(), "hello", "stdout = {:?}", res.stdout);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_non_zero_exit() {
        let res = run(&["false"], Duration::from_secs(1), 0)
            .await
            .expect("no error");
        assert_ne!(res.exit_code, 0, "expected non-zero exit code");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_timeout() {
        let res = run(&["sleep", "5"], Duration::from_millis(100), 0)
            .await
            .expect("no error");
        assert!(res.timed_out, "expected TimedOut=true");
    }

    // Windows counterpart of the timeout test: a command that sleeps past its
    // deadline must report TimedOut (the job termination kills it).
    #[cfg(windows)]
    #[tokio::test]
    async fn test_run_timeout() {
        let argv = shell_argv(unrestricted_shell(), "Start-Sleep -Seconds 5");
        let res = runner()
            .run(argv, Duration::from_millis(300), 0)
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(windows)]
    #[test]
    fn test_shell_argv_windows_invokes_powershell_flags() {
        assert_eq!(
            shell_argv("pwsh", "Write-Output hi"),
            vec![
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Write-Output hi"
            ]
        );
        // The command is always a single argv slot, never split or quoted.
        let argv = shell_argv("powershell", "a; b | c");
        assert_eq!(argv.last().unwrap(), "a; b | c");
        assert_eq!(argv.len(), 7);
    }

    #[cfg(windows)]
    #[test]
    fn test_unrestricted_shell_is_a_known_powershell() {
        assert!(matches!(unrestricted_shell(), "pwsh" | "powershell"));
    }

    #[cfg(unix)]
    #[test]
    fn test_shell_argv_unix_invokes_sh_dash_c() {
        assert_eq!(
            shell_argv("sh", "echo hi"),
            vec!["sh", "-c", "echo hi"],
            "command must be the single -c argument"
        );
    }
}

#[cfg(all(test, unix))]
mod hang_tests {
    use super::*;

    /// H-1 regression: a background grandchild holding the pipe open must not
    /// hang the runner. With the process-group kill + bounded grace, the task
    /// returns promptly instead of waiting ~999999s for EOF.
    #[tokio::test]
    async fn background_child_holding_pipe_does_not_hang() {
        let start = std::time::Instant::now();
        let res = run_command(
            vec!["sh".into(), "-c".into(), "echo fast & sleep 300".into()],
            Duration::from_millis(300),
            1024,
        )
        .await
        .expect("run");
        assert!(res.timed_out, "expected the 300s sleep to trip the timeout");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "runner returned in {:?} — bounded, not hung",
            start.elapsed()
        );
    }

    /// Normal capture still works with the grace (output flushed before EOF).
    #[tokio::test]
    async fn capture_with_grace_still_returns_output() {
        let res = run_command(
            vec![
                "sh".into(),
                "-c".into(),
                "echo before; sleep 0.2; echo after".into(),
            ],
            Duration::from_secs(5),
            1024,
        )
        .await
        .unwrap();
        assert_eq!(res.exit_code, 0);
        assert!(res.stdout.contains("before"), "stdout: {:?}", res.stdout);
        assert!(res.stdout.contains("after"), "stdout: {:?}", res.stdout);
    }
}

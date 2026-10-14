//! Runs the worker's main loop: it heartbeats the hub, pulls tasks, executes
//! them (whitelisted actions via fixed argv, free commands via a shell ONLY in
//! the hub-gated unrestricted mode, updates via the update module, uninstall),
//! and reports results. Pulling over an outbound connection keeps workers
//! usable behind NAT. Mirrors Go `internal/agent`.

use crate::config::{self, State};
use crate::exec::{ExecResult, Runner};
use crate::hubclient::{Client, HeartbeatRequest, Task, TaskResult};
use crate::update::{Hook, Spec, Updater};
use crate::whitelist;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};

/// How many times an idempotent action is tried before its last result is
/// reported. Non-idempotent actions are always tried once.
const MAX_ACTION_ATTEMPTS: usize = 3;

/// Caps the backoff applied when the queue is empty, so an idle worker does
/// not hammer the hub.
const MAX_IDLE_POLL_INTERVAL: Duration = Duration::from_secs(30);

pub struct Agent {
    pub client: Option<Arc<Client>>,
    pub runner: Arc<dyn Runner>,
    pub state: Arc<Mutex<State>>,
    pub heartbeat_interval: Duration,
    pub poll_interval: Duration,
    /// How long the hub holds an empty /tasks/next request. 0 disables
    /// long-polling (falls back to immediate-return polling with backoff).
    pub long_poll_seconds: u64,
    /// First delay between retries of an idempotent action (doubled each
    /// attempt, capped at 8s).
    pub retry_backoff_base: Duration,
    shutdown: watch::Receiver<()>,
    /// The VM's exec mode as last reported by the hub heartbeat. The worker
    /// refuses free-command tasks unless this is "unrestricted" — a local
    /// defense-in-depth gate so the hub alone cannot enable arbitrary shell.
    exec_mode: Mutex<String>,
}

impl Agent {
    pub fn new(client: Arc<Client>, state: State, shutdown: watch::Receiver<()>) -> Self {
        Self {
            client: Some(client),
            runner: Arc::new(crate::exec::CommandRunner),
            state: Arc::new(Mutex::new(state)),
            heartbeat_interval: Duration::from_secs(30),
            poll_interval: Duration::from_secs(2),
            long_poll_seconds: 25,
            retry_backoff_base: Duration::from_secs(1),
            shutdown,
            exec_mode: Mutex::new(String::new()),
        }
    }

    /// Test constructor: no hub client, small retry base.
    #[allow(dead_code)] // used by tests; kept public for parity tooling
    #[allow(dead_code)]
    pub fn without_client(runner: Arc<dyn Runner>, shutdown: watch::Receiver<()>) -> Self {
        Self {
            client: None,
            runner,
            state: Arc::new(Mutex::new(State::default())),
            heartbeat_interval: Duration::from_secs(30),
            poll_interval: Duration::from_secs(2),
            long_poll_seconds: 25,
            retry_backoff_base: Duration::from_millis(1),
            shutdown,
            exec_mode: Mutex::new(String::new()),
        }
    }

    async fn set_exec_mode(&self, mode: String) {
        *self.exec_mode.lock().await = mode;
    }

    async fn get_exec_mode(&self) -> String {
        self.exec_mode.lock().await.clone()
    }

    /// Runs until shutdown is signalled or an update requires a restart (in
    /// which case it returns Ok so the supervisor relaunches the new binary).
    pub async fn run(self: Arc<Self>) -> Result<(), String> {
        self.heartbeat().await;

        let hb = self.clone();
        let mut shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(hb.heartbeat_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => hb.heartbeat().await,
                    _ = shutdown.changed() => return,
                }
            }
        });

        let mut interval = self.poll_interval;
        loop {
            if self.shutdown_has_fired() {
                return Ok(());
            }
            let (did_work, restart) = self.poll_once().await;
            if restart {
                return Ok(()); // exit 0 so systemd relaunches the (new) binary
            }
            if self.long_poll_seconds > 0 {
                // The hub already blocked for us; loop straight back unless we
                // hit an error (did_work is false on both "no task" and
                // "error"), in which case a short pause avoids a tight loop.
                if !did_work && !self.sleep(self.poll_interval).await {
                    return Ok(());
                }
                continue;
            }
            // Immediate-return polling: back off when idle.
            if did_work {
                interval = self.poll_interval;
            } else if interval < MAX_IDLE_POLL_INTERVAL {
                interval = (interval * 2).min(MAX_IDLE_POLL_INTERVAL);
            }
            if !self.sleep(interval).await {
                return Ok(());
            }
        }
    }

    fn shutdown_has_fired(&self) -> bool {
        matches!(self.shutdown.has_changed(), Ok(true) | Err(_))
    }

    /// Waits for `d` or until shutdown. Returns true if the full duration
    /// elapsed, false if shutdown came first.
    async fn sleep(&self, d: Duration) -> bool {
        let mut rx = self.shutdown.clone();
        tokio::select! {
            _ = tokio::time::sleep(d) => true,
            _ = rx.changed() => false,
        }
    }

    async fn heartbeat(&self) {
        let Some(client) = self.client.clone() else {
            return;
        };
        let resp = match client
            .heartbeat(HeartbeatRequest {
                worker_version: config::VERSION.into(),
                ..Default::default()
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("huginn-worker: heartbeat failed: {e}");
                return;
            }
        };
        self.set_exec_mode(resp.exec_mode.clone()).await;
        // Merge hub-provided release domains into the built-in allowlist. The
        // hub can ADD domains but never remove the built-in defaults, and any
        // domain it pushes must pass local validation. A compromised hub
        // cannot point the worker at arbitrary internal hosts.
        if !resp.allowed_release_domains.is_empty() {
            let mut state = self.state.lock().await;
            let mut merged = config::DEFAULT_ALLOWED_RELEASE_DOMAINS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            for d in &resp.allowed_release_domains {
                if !merged.contains(d) && is_safe_release_domain(d) {
                    merged.push(d.clone());
                }
            }
            state.allowed_release_domains = Some(merged);
        }
    }

    /// Fetches and runs at most one task. Returns (handled a task, restart
    /// needed after an update).
    async fn poll_once(&self) -> (bool, bool) {
        let Some(client) = self.client.clone() else {
            return (false, false);
        };
        let task = match client.poll_next_task(self.long_poll_seconds as i64).await {
            Ok(Some(t)) => t,
            Ok(None) => return (false, false),
            Err(e) => {
                eprintln!("huginn-worker: poll failed: {e}");
                return (false, false);
            }
        };
        eprintln!(
            "huginn-worker: running task {} ({})",
            task.id, task.task_type
        );
        let task_id = task.id.clone();
        let (result, restart) = self.dispatch(task).await;
        if let Err(e) = client.submit_result(&task_id, result).await {
            eprintln!("huginn-worker: submit result failed: {e}");
            return (true, false);
        }
        (true, restart)
    }

    async fn dispatch(&self, task: Task) -> (TaskResult, bool) {
        match task.task_type.as_str() {
            "action" => (self.run_action(&task).await, false),
            "command" => (self.run_command(&task).await, false),
            "update" => self.run_update(&task).await,
            "uninstall" => (self.run_uninstall().await, false),
            other => (failure(&format!("unknown task type: {other}")), false),
        }
    }

    async fn run_action(&self, task: &Task) -> TaskResult {
        // A name the worker doesn't know built-in is an admin-defined custom
        // command: its fixed argv rides in the task payload, gated on the VM's
        // exec mode.
        if !whitelist::known(&task.action_name) {
            return self.run_custom(task).await;
        }
        let params = string_params(task.payload.get("params"));
        let argv = match whitelist::build_argv_checked(&task.action_name, &params) {
            Ok(a) => a,
            Err(e) => return failure(&e.to_string()),
        };
        let timeout = task_timeout(&task.payload);
        let attempts = if whitelist::idempotent(&task.action_name) {
            MAX_ACTION_ATTEMPTS
        } else {
            1
        };

        let mut attempt = 0usize;
        loop {
            attempt += 1;
            let result = match self.runner.run(argv.clone(), timeout, 0).await {
                Ok(res) => from_exec_result(res),
                Err(e) => failure(&e.to_string()),
            };
            if result.status == "succeeded" || attempt >= attempts {
                return result;
            }
            // Transient failure on an idempotent action (e.g. an apt mirror
            // briefly down): back off and retry. Re-running is side-effect-free.
            if !self.sleep(self.retry_backoff(attempt)).await {
                return result; // shutdown — report what we have
            }
        }
    }

    /// Exponential delay (base, 2×base, 4×base…) capped at 8s.
    fn retry_backoff(&self, attempt: usize) -> Duration {
        let base = if self.retry_backoff_base.is_zero() {
            Duration::from_secs(1)
        } else {
            self.retry_backoff_base
        };
        (base * (1 << (attempt - 1).min(20))).min(Duration::from_secs(8))
    }

    async fn run_command(&self, task: &Task) -> TaskResult {
        // Local defense in depth: even though the hub gates command tasks on
        // the VM's unrestricted mode, the worker independently refuses to run
        // a shell unless it has itself observed unrestricted mode via
        // heartbeat.
        if self.get_exec_mode().await != "unrestricted" {
            return failure("worker refused free command: unrestricted mode not enabled");
        }
        let command = as_string(task.payload.get("command"));
        if command.is_empty() {
            return failure("empty command");
        }
        // Free-command mode is the explicit, hub-gated, audited
        // "unrestricted" path; using a shell here is intentional. The
        // whitelist path never does this.
        match self
            .runner
            .run(
                vec!["sh".into(), "-c".into(), command],
                task_timeout(&task.payload),
                0,
            )
            .await
        {
            Ok(res) => from_exec_result(res),
            Err(e) => failure(&e.to_string()),
        }
    }

    /// Runs an admin-defined custom command: an ordered list of fixed argv
    /// vectors supplied by the hub in the task payload, each executed WITHOUT
    /// a shell. Commands run in sequence and stop at the first failure; the
    /// combined output is reported. Like free commands, the worker
    /// independently gates this on having observed 'custom' (or
    /// 'unrestricted') exec mode.
    async fn run_custom(&self, task: &Task) -> TaskResult {
        let mode = self.get_exec_mode().await;
        if mode != "custom" && mode != "unrestricted" {
            return failure("worker refused custom command: custom mode not enabled");
        }
        let commands = argv_list(task.payload.get("commands"));
        if commands.is_empty() {
            return failure("custom command has no commands");
        }
        let timeout = task_timeout(&task.payload);
        let mut stdout = String::new();
        let mut stderr = String::new();
        for (i, argv) in commands.iter().enumerate() {
            if argv.is_empty() {
                continue;
            }
            let res = match self.runner.run(argv.clone(), timeout, 0).await {
                Ok(r) => r,
                Err(e) => {
                    stderr.push_str(&e.to_string());
                    return task_result("failed", None, stdout, stderr);
                }
            };
            // Label each step so a multi-command result is readable.
            stdout.push_str(&format!("$ {}\n", argv.join(" ")));
            stdout.push_str(&res.stdout);
            stderr.push_str(&res.stderr);
            if res.timed_out {
                return task_result("timeout", Some(res.exit_code), stdout, stderr);
            }
            if res.exit_code != 0 {
                // Stop at the first failing command (sequential, fail-fast).
                stderr.push_str(&format!(
                    "command {}/{} failed (exit {})\n",
                    i + 1,
                    commands.len(),
                    res.exit_code
                ));
                return task_result("failed", Some(res.exit_code), stdout, stderr);
            }
        }
        task_result("succeeded", Some(0), stdout, stderr)
    }

    async fn run_update(&self, task: &Task) -> (TaskResult, bool) {
        let binary_path = self.state.lock().await.binary_location();
        let allowed_domains = self.state.lock().await.allowed_domains();
        let spec = Spec {
            binary_url: as_string(task.payload.get("binary_url")),
            checksums_url: as_string(task.payload.get("checksums_url")),
            asset_name: as_string(task.payload.get("asset_name")),
            version: as_string(task.payload.get("target_version")),
            binary_path: binary_path.clone(),
        };
        let version = spec.version.clone();
        // Health check validates the freshly swapped binary. No explicit
        // restart (parity with Go): exit 0 lets systemd relaunch the new one.
        let bin = binary_path.clone();
        let health: Hook = Arc::new(move || {
            let bin = bin.clone();
            Box::pin(async move {
                tokio::task::spawn_blocking(move || {
                    run_healthcheck_sync(&bin, &["healthcheck"], Duration::from_secs(30))
                })
                .await
                .map_err(|e| e.to_string())?
            })
        });
        let updater = Updater::new(allowed_domains, None, Some(health));
        match updater.apply(spec).await {
            Ok(()) => (
                TaskResult {
                    status: "succeeded".into(),
                    exit_code: Some(0),
                    stdout: format!("updated to {version}"),
                    ..Default::default()
                },
                true,
            ),
            Err(e) => (failure(&format!("update failed: {e}")), false),
        }
    }

    /// Removes the worker service and binary from the host. Best-effort
    /// cleanup triggered before VM revocation.
    async fn run_uninstall(&self) -> TaskResult {
        let _ = run_raw("systemctl", &["stop", "huginn-worker"]);
        let _ = run_raw("systemctl", &["disable", "huginn-worker"]);
        let _ = std::fs::remove_file("/etc/systemd/system/huginn-worker.service");
        let _ = run_raw("systemctl", &["daemon-reload"]);
        let binary_path = self.state.lock().await.binary_location();
        let _ = std::fs::remove_file(&binary_path);
        let _ = std::fs::remove_dir_all(config::DEFAULT_STATE_DIR);
        TaskResult {
            status: "succeeded".into(),
            exit_code: Some(0),
            stdout: "worker service removed, binary and state cleaned up".into(),
            ..Default::default()
        }
    }
}

// --- helpers ---

fn task_result(status: &str, exit_code: Option<i32>, stdout: String, stderr: String) -> TaskResult {
    TaskResult {
        status: status.into(),
        exit_code,
        stdout,
        stderr,
        ..Default::default()
    }
}

fn from_exec_result(res: ExecResult) -> TaskResult {
    let status = if res.timed_out {
        "timeout"
    } else if res.exit_code != 0 {
        "failed"
    } else {
        "succeeded"
    };
    TaskResult {
        status: status.into(),
        exit_code: Some(res.exit_code),
        stdout: res.stdout,
        stderr: res.stderr,
        ..Default::default()
    }
}

fn failure(msg: &str) -> TaskResult {
    TaskResult {
        status: "failed".into(),
        error: msg.into(),
        ..Default::default()
    }
}

fn task_timeout(payload: &serde_json::Map<String, Value>) -> Duration {
    match payload.get("timeout").and_then(Value::as_f64) {
        Some(v) if v > 0.0 => Duration::from_secs_f64(v),
        _ => Duration::from_secs(60),
    }
}

fn string_params(v: Option<&Value>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(Value::Object(m)) = v {
        for (k, val) in m {
            if let Some(s) = val.as_str() {
                out.insert(k.clone(), s.to_string());
            }
        }
    }
    out
}

fn argv_list(v: Option<&Value>) -> Vec<Vec<String>> {
    match v {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Array(argv) => argv
                    .iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect(),
                _ => Vec::new(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn as_string(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").to_string()
}

/// Rejects loopback/link-local/internal names a malicious hub might try to
/// push into the worker's allowlist.
fn is_safe_release_domain(host: &str) -> bool {
    let h = host.trim().to_lowercase();
    if h.is_empty() || h.contains('/') {
        return false;
    }
    if h == "localhost" || h.ends_with(".local") || h.ends_with(".internal") {
        return false;
    }
    !matches!(
        h.as_str(),
        "169.254.169.254" | "127.0.0.1" | "0.0.0.0" | "::1"
    )
}

fn run_raw(name: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new(name).args(args).output()
}

fn run_healthcheck_sync(binary: &str, args: &[&str], timeout: Duration) -> Result<(), String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let bin = binary.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    std::thread::spawn(move || {
        let out = std::process::Command::new(&bin).args(&args).output();
        let _ = tx.send(out);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(out)) if out.status.success() => Ok(()),
        Ok(Ok(out)) => Err(format!(
            "health check failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("health check timed out after {timeout:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::BoxFuture;
    use std::sync::Mutex as StdMutex;

    // A fake runner that records the argv it was asked to run.
    struct FakeRunner {
        got_argv: Arc<StdMutex<Option<Vec<String>>>>,
        result: ExecResult,
    }
    impl FakeRunner {
        fn new(result: ExecResult) -> Self {
            Self {
                got_argv: Arc::new(StdMutex::new(None)),
                result,
            }
        }
        fn argv(&self) -> Option<Vec<String>> {
            self.got_argv.lock().unwrap().clone()
        }
    }
    impl Runner for FakeRunner {
        fn run(
            &self,
            argv: Vec<String>,
            _timeout: Duration,
            _max_output: usize,
        ) -> BoxFuture<'static, std::io::Result<ExecResult>> {
            let got = self.got_argv.clone();
            let result = self.result.clone();
            Box::pin(async move {
                *got.lock().unwrap() = Some(argv);
                Ok(result)
            })
        }
    }

    // Returns a queued result per call (the last repeats); counts invocations.
    struct SeqRunner {
        results: Arc<Vec<ExecResult>>,
        calls: Arc<StdMutex<usize>>,
    }
    impl SeqRunner {
        fn new(results: Vec<ExecResult>) -> Self {
            Self {
                results: Arc::new(results),
                calls: Arc::new(StdMutex::new(0)),
            }
        }
        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }
    impl Runner for SeqRunner {
        fn run(
            &self,
            _argv: Vec<String>,
            _timeout: Duration,
            _max_output: usize,
        ) -> BoxFuture<'static, std::io::Result<ExecResult>> {
            let results = self.results.clone();
            let calls = self.calls.clone();
            Box::pin(async move {
                let mut idx = calls.lock().unwrap();
                let i = (*idx).min(results.len().saturating_sub(1));
                *idx += 1;
                Ok(results[i].clone())
            })
        }
    }

    fn exec(code: i32) -> ExecResult {
        ExecResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: code,
            timed_out: false,
        }
    }

    fn test_agent(runner: Arc<dyn Runner>) -> (Agent, watch::Sender<()>) {
        let (tx, rx) = watch::channel(());
        (Agent::without_client(runner, rx), tx)
    }

    fn task(id: &str, r#type: &str, action: &str, payload: Value) -> Task {
        Task {
            id: id.into(),
            task_type: r#type.into(),
            action_name: action.into(),
            payload: payload.as_object().cloned().unwrap_or_default(),
        }
    }

    fn custom_task(commands: Vec<Vec<&str>>) -> Task {
        let cmds: Vec<Value> = commands
            .iter()
            .map(|c| Value::Array(c.iter().map(|s| Value::from(*s)).collect()))
            .collect();
        task(
            "t",
            "action",
            "custom-x",
            serde_json::json!({"commands": cmds}),
        )
    }

    #[tokio::test]
    async fn idempotent_action_retries_then_succeeds() {
        let runner = Arc::new(SeqRunner::new(vec![exec(1), exec(0)]));
        let (a, _guard) = test_agent(runner.clone());
        let t = task(
            "t",
            "action",
            "list_upgradable_packages",
            serde_json::json!({}),
        );
        let res = a.run_action(&t).await;
        assert_eq!(res.status, "succeeded", "want succeeded after retry");
        assert_eq!(runner.calls(), 2, "one retry expected");
    }

    #[tokio::test]
    async fn idempotent_action_gives_up_after_max_attempts() {
        let runner = Arc::new(SeqRunner::new(vec![exec(1)]));
        let (a, _guard) = test_agent(runner.clone());
        let t = task("t", "action", "status", serde_json::json!({}));
        let res = a.run_action(&t).await;
        assert_eq!(res.status, "failed");
        assert_eq!(runner.calls(), MAX_ACTION_ATTEMPTS);
    }

    #[tokio::test]
    async fn custom_command_runs_sequence_in_custom_mode() {
        let runner = Arc::new(SeqRunner::new(vec![exec(0), exec(0)]));
        let (a, _guard) = test_agent(runner.clone());
        a.set_exec_mode("custom".into()).await;
        let t = custom_task(vec![
            vec!["systemctl", "restart", "nginx"],
            vec!["echo", "done"],
        ]);
        let res = a.run_action(&t).await;
        assert_eq!(res.status, "succeeded");
        assert_eq!(runner.calls(), 2, "both commands ran");
    }

    #[tokio::test]
    async fn custom_command_stops_at_first_failure() {
        let runner = Arc::new(SeqRunner::new(vec![exec(3), exec(0)]));
        let (a, _guard) = test_agent(runner.clone());
        a.set_exec_mode("custom".into()).await;
        let t = custom_task(vec![vec!["false"], vec!["echo", "never"]]);
        let res = a.run_action(&t).await;
        assert_eq!(res.status, "failed");
        assert_eq!(runner.calls(), 1, "stop at first failure");
    }

    #[tokio::test]
    async fn custom_command_refused_outside_custom_mode() {
        let runner = Arc::new(FakeRunner::new(exec(0)));
        let (a, _guard) = test_agent(runner.clone());
        let t = custom_task(vec![vec!["systemctl", "restart", "nginx"]]);
        let res = a.run_action(&t).await;
        assert_eq!(res.status, "failed");
        assert!(runner.argv().is_none(), "runner must not be invoked");
    }

    #[tokio::test]
    async fn non_idempotent_action_not_retried() {
        let runner = Arc::new(SeqRunner::new(vec![exec(1)]));
        let (a, _guard) = test_agent(runner.clone());
        let t = task("t", "action", "apt_upgrade", serde_json::json!({}));
        let res = a.run_action(&t).await;
        assert_eq!(res.status, "failed");
        assert_eq!(runner.calls(), 1, "no retry for mutating action");
    }

    #[tokio::test]
    async fn dispatch_action_uses_whitelist_argv() {
        let runner = Arc::new(FakeRunner::new(ExecResult {
            exit_code: 0,
            stdout: "linux".into(),
            ..Default::default()
        }));
        let (a, _guard) = test_agent(runner.clone());
        let t = task("t1", "action", "status", serde_json::json!({}));
        let (res, restart) = a.dispatch(t).await;
        assert!(!restart);
        assert_eq!(res.status, "succeeded");
        assert_eq!(runner.argv(), Some(vec!["uname".into(), "-a".into()]));
    }

    #[tokio::test]
    async fn dispatch_unknown_action_fails() {
        let runner = Arc::new(FakeRunner::new(exec(0)));
        let (a, _guard) = test_agent(runner.clone());
        let t = task("t1", "action", "nope", serde_json::json!({}));
        let (res, _) = a.dispatch(t).await;
        assert_eq!(res.status, "failed");
        assert!(runner.argv().is_none(), "runner should not be invoked");
    }

    #[tokio::test]
    async fn dispatch_command_uses_shell_when_unrestricted() {
        let runner = Arc::new(FakeRunner::new(exec(0)));
        let (a, _guard) = test_agent(runner.clone());
        a.set_exec_mode("unrestricted".into()).await;
        let t = task(
            "t1",
            "command",
            "",
            serde_json::json!({"command": "echo hi"}),
        );
        a.dispatch(t).await;
        assert_eq!(
            runner.argv(),
            Some(vec!["sh".into(), "-c".into(), "echo hi".into()])
        );
    }

    #[tokio::test]
    async fn dispatch_command_refused_when_not_unrestricted() {
        let runner = Arc::new(FakeRunner::new(exec(0)));
        let (a, _guard) = test_agent(runner.clone());
        let t = task(
            "t1",
            "command",
            "",
            serde_json::json!({"command": "echo hi"}),
        );
        let (res, _) = a.dispatch(t).await;
        assert_eq!(res.status, "failed");
        assert!(runner.argv().is_none(), "runner must not be invoked");
    }

    #[tokio::test]
    async fn dispatch_unknown_type_fails() {
        let (a, _guard) = test_agent(Arc::new(FakeRunner::new(exec(0))) as Arc<dyn Runner>);
        let (res, _) = a
            .dispatch(task("t", "mystery", "", serde_json::json!({})))
            .await;
        assert_eq!(res.status, "failed");
    }

    #[tokio::test]
    async fn is_safe_release_domain_rules() {
        assert!(is_safe_release_domain("github.com"));
        assert!(!is_safe_release_domain("localhost"));
        assert!(!is_safe_release_domain("box.local"));
        assert!(!is_safe_release_domain("svc.internal"));
        assert!(!is_safe_release_domain("169.254.169.254"));
        assert!(!is_safe_release_domain("127.0.0.1"));
        assert!(!is_safe_release_domain(""));
        assert!(!is_safe_release_domain("a/b"));
    }
}

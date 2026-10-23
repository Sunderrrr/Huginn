//! Manages the worker's own supervisor integration: a systemd unit on Linux,
//! a Windows service (SCM) on Windows. The CLI, wire protocol, and state file
//! are identical on both platforms; only the supervisor plumbing differs.
//!
//! Rust port of worker/internal/systemd (Linux) plus new Windows support.

// --- Linux: systemd -------------------------------------------------------

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(unix)]
use std::process::Stdio;

#[cfg(unix)]
use tokio::process::Command;

/// The service name as registered with the OS supervisor: the systemd unit
/// name on Linux, the SCM service name on Windows.
#[cfg(unix)]
pub const SERVICE_NAME: &str = "huginn-worker";
#[cfg(windows)]
pub const SERVICE_NAME: &str = "HuginnWorker";

#[cfg(unix)]
const UNIT_TEMPLATE: &str = "[Unit]
Description=Huginn fleet worker
After=network-online.target
Wants=network-online.target
# Bound the restart loop: without this, `Restart=always` + `RestartSec=5`
# restarts a crash-looping worker FOREVER (systemd's default start limit
# is 5 restarts / 10s, which a 5s backoff never reaches).
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart={bin} run --state-dir {dir}
Restart=always
RestartSec=5
# The worker resolves its helper programs (systemctl, uname, apt-get, sh…)
# through PATH: pin it to the system directories so a writable directory
# can never take the place of a system binary.
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Hardening
NoNewPrivileges=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
";

/// UnitContent renders the unit file for the given binary path and state dir.
///
/// The two interpolated values land in a systemd unit file: a newline (or
/// any control character) in a path would end the `ExecStart=` line and let
/// the rest of the string become a new directive — a unit-file injection.
/// Both paths are therefore rejected unless they are plain, single-line
/// paths.
#[cfg(unix)]
pub fn unit_content(binary_path: &str, state_dir: &str) -> Result<String, String> {
    for (what, value) in [("binary path", binary_path), ("state dir", state_dir)] {
        if value.is_empty() {
            return Err(format!("{what} must not be empty"));
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(format!("{what} must not contain control characters"));
        }
    }
    Ok(UNIT_TEMPLATE
        .replacen("{bin}", binary_path, 1)
        .replacen("{dir}", state_dir, 1))
}

/// Install writes the unit file (0644) and enables the service.
#[cfg(unix)]
pub async fn install(
    unit_path: &str,
    binary_path: &str,
    state_dir: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let content = unit_content(binary_path, state_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    tokio::fs::write(unit_path, content).await?; // unit files are world-readable
    tokio::fs::set_permissions(unit_path, std::fs::Permissions::from_mode(0o644)).await?;
    systemctl(&["daemon-reload"]).await?;
    systemctl(&["enable", "--now", SERVICE_NAME]).await?;
    Ok(())
}

/// RestartSelf restarts the worker service (used after a self-update).
#[cfg(unix)]
#[allow(dead_code)] // parity with Go systemd.RestartSelf
pub async fn restart_self() -> io::Result<()> {
    // Go's exec.Cmd discards stdout/stderr when nil; mirror that.
    let status = Command::new("systemctl")
        .args(["restart", SERVICE_NAME])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    check_exit(status)
}

#[cfg(unix)]
async fn systemctl(args: &[&str]) -> io::Result<()> {
    // Output is inherited, mirroring Go's cmd.Stdout = os.Stdout wiring in run().
    // PATH is pinned: `systemctl` is looked up in the CHILD's PATH, and the
    // worker runs as root.
    let status = Command::new("systemctl")
        .args(args)
        .env("PATH", crate::exec::SAFE_PATH)
        .status()
        .await?;
    check_exit(status)
}

#[cfg(unix)]
fn check_exit(status: std::process::ExitStatus) -> io::Result<()> {
    if status.success() {
        return Ok(());
    }
    let message = match status.code() {
        Some(code) => format!("exit status {code}"),
        None => format!("exit signal {}", status.signal().unwrap_or(-1)),
    };
    Err(io::Error::other(message))
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_content_matches_go_template() {
        let content =
            unit_content("/usr/local/bin/huginn-worker", "/etc/huginn").expect("unit content");
        assert_eq!(
            content,
            "[Unit]\n\
             Description=Huginn fleet worker\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             # Bound the restart loop: without this, `Restart=always` + `RestartSec=5`\n\
             # restarts a crash-looping worker FOREVER (systemd's default start limit\n\
             # is 5 restarts / 10s, which a 5s backoff never reaches).\n\
             StartLimitIntervalSec=300\n\
             StartLimitBurst=5\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart=/usr/local/bin/huginn-worker run --state-dir /etc/huginn\n\
             Restart=always\n\
             RestartSec=5\n\
             # The worker resolves its helper programs (systemctl, uname, apt-get, sh…)\n\
             # through PATH: pin it to the system directories so a writable directory\n\
             # can never take the place of a system binary.\n\
             Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
             # Hardening\n\
             NoNewPrivileges=true\n\
             ProtectHome=true\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
    }

    /// A crash-looping worker must not restart forever: the unit declares a
    /// start limit so systemd finally gives up.
    #[test]
    fn test_unit_bounds_the_restart_loop() {
        let content =
            unit_content("/usr/local/bin/huginn-worker", "/etc/huginn").expect("unit content");
        assert!(content.contains("StartLimitIntervalSec=300"), "{content}");
        assert!(content.contains("StartLimitBurst=5"), "{content}");
    }

    /// The unit file is a directive file: a path carrying a newline could
    /// append a directive of its own (unit-file injection).
    #[test]
    fn test_unit_content_rejects_control_characters() {
        let err = unit_content(
            "/usr/local/bin/huginn-worker\nExecStartPre=/bin/sh -c evil",
            "/etc/huginn",
        )
        .expect_err("newline in the binary path must be refused");
        assert!(err.contains("control characters"), "{err}");
        let err = unit_content("/usr/local/bin/huginn-worker", "/etc/huginn\r\nX=1")
            .expect_err("CRLF in the state dir must be refused");
        assert!(err.contains("control characters"), "{err}");
        let err = unit_content("", "/etc/huginn").expect_err("empty path must be refused");
        assert!(err.contains("must not be empty"), "{err}");
    }
}

// --- Windows: SCM service --------------------------------------------------
//
// The service is a plain "run as LocalSystem, own process, auto-start"
// registration. When the SCM starts the binary it launches
// `huginn-worker.exe run --state-dir <dir>`; `run` detects it was started by
// the SCM (via the dispatcher connect) and runs the same agent loop it runs in
// a console. Restart-on-failure failure actions mirror systemd's
// `Restart=always`/`RestartSec=5`.

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::sync::{mpsc, OnceLock};
    use std::time::Duration;

    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
        Result as WsResult,
    };

    use crate::config;

    use super::SERVICE_NAME;

    /// Description shown for the service in the SCM database.
    pub const SERVICE_DESCRIPTION: &str = "Huginn fleet worker";

    /// The state dir the service was started with; read by `service_main`
    /// (which the SCM invokes with no arguments on auto-start).
    static SERVICE_STATE_DIR: OnceLock<String> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Entry point the SCM calls on its own thread when the service starts.
    fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            eprintln!("huginn-worker: service failed: {e}");
        }
    }

    /// Reports a status transition to the SCM (best-effort).
    fn report_status(
        handle: &ServiceStatusHandle,
        state: ServiceState,
        accepts_stop: bool,
        exit_code: ServiceExitCode,
        wait_hint: Duration,
    ) {
        let _ = handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if accepts_stop {
                ServiceControlAccept::STOP
            } else {
                ServiceControlAccept::empty()
            },
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        });
    }

    fn run_service() -> WsResult<()> {
        let state_dir = SERVICE_STATE_DIR
            .get()
            .cloned()
            .unwrap_or_else(|| config::DEFAULT_STATE_DIR.to_string());

        // Bridge SCM stop events to the agent loop's shutdown watch.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
        // The control handler needs the status handle, but that handle is
        // only returned by `register` — hand it over through a cell once
        // registration succeeds (the SCM may stop us any time after that).
        let status_cell: OnceLock<ServiceStatusHandle> = OnceLock::new();
        let cell_for_handler = status_cell.clone();
        let shutdown_for_handler = shutdown_tx.clone();
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop => {
                    if let Some(handle) = cell_for_handler.get() {
                        // The agent loop exits within one poll cycle; ask
                        // the SCM for a 30s grace in the meantime.
                        report_status(
                            handle,
                            ServiceState::StopPending,
                            false,
                            ServiceExitCode::Win32(0),
                            Duration::from_secs(30),
                        );
                    }
                    let _ = shutdown_for_handler.send(());
                    ServiceControlHandlerResult::NoError
                }
                // All services must accept Interrogate even as a no-op.
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        let _ = status_cell.set(status_handle);

        report_status(
            &status_handle,
            ServiceState::Running,
            true,
            ServiceExitCode::Win32(0),
            Duration::default(),
        );

        // The agent loop is async; run it on its own runtime thread and wait
        // for it to finish (the SCM-spawned thread must stay alive to report
        // the final status).
        let (done_tx, done_rx) = mpsc::channel::<(i32, bool)>();
        let shutdown_probe = shutdown_rx.clone();
        std::thread::Builder::new()
            .name("huginn-agent".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                let code = runtime.block_on(crate::run_agent(&state_dir, shutdown_rx));
                // Did the SCM ask us to stop (clean), or did the loop end on
                // its own (update applied / crash)?
                let clean_stop = matches!(shutdown_probe.has_changed(), Ok(true));
                let _ = done_tx.send((code, clean_stop));
            })
            .expect("spawn agent thread");

        let (code, clean_stop) = done_rx.recv().unwrap_or((1, false));

        // Exit-code semantics (mirrors systemd Restart=always + exit 0 on
        // update): a clean SCM stop exits 0 and stays stopped; an applied
        // update (clean return without a stop request) or an error exits
        // non-zero so the configured failure action restarts the (possibly
        // new) binary.
        let exit_code = if clean_stop && code == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(1)
        };
        report_status(
            &status_handle,
            ServiceState::Stopped,
            false,
            exit_code,
            Duration::default(),
        );
        Ok(())
    }

    /// Runs the process under the SCM dispatcher. Returns:
    ///
    /// - `Ok(true)`  — the SCM launched us; the call blocked until the
    ///   service stopped and the run completed.
    /// - `Ok(false)` — we were NOT started by the SCM (console run): the
    ///   caller falls back to running the loop in the foreground.
    /// - `Err`       — a real dispatcher error.
    pub fn run_as_service(state_dir: &str) -> Result<bool, String> {
        let _ = SERVICE_STATE_DIR.set(state_dir.to_string());
        const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(true),
            // StartServiceCtrlDispatcherW fails with 1063 when the process
            // was not launched by the SCM — that's the console-mode case.
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
            {
                Ok(false)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Installs the "HuginnWorker" service (own process, LocalSystem,
    /// auto-start) launching `binary run --state-dir <dir>`.
    pub fn install(binary_path: &str, state_dir: &str) -> Result<(), String> {
        use windows_service::service::{
            ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
            ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
            ServiceType,
        };

        // The state dir must exist before the service first starts
        // (restricted ACLs — see config::ensure_state_dir).
        config::ensure_state_dir(std::path::Path::new(state_dir))
            .map_err(|e| format!("create state dir {state_dir}: {e}"))?;

        let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
        let manager = ServiceManager::local_computer(None::<&str>, manager_access)
            .map_err(|e| e.to_string())?;
        let info = ServiceInfo {
            name: SERVICE_NAME.into(),
            display_name: SERVICE_DESCRIPTION.into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: binary_path.into(),
            launch_arguments: vec!["run".into(), "--state-dir".into(), state_dir.into()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG)
            .map_err(|e| format!("create service: {e}"))?;
        service
            .set_description(SERVICE_DESCRIPTION)
            .map_err(|e| format!("set description: {e}"))?;

        // Restart on failure (5s/10s/60s backoff), counting non-zero clean
        // exits as failures: that is how the post-update exit gets the SCM
        // to relaunch the new binary — systemd Restart=always parity.
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(5),
                    },
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(10),
                    },
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(60),
                    },
                ]),
            })
            .map_err(|e| format!("set failure actions: {e}"))?;
        service
            .set_failure_actions_on_non_crash_failures(true)
            .map_err(|e| format!("set failure-actions flag: {e}"))?;
        Ok(())
    }

    /// Stops and deletes the service. Missing service is not an error
    /// (idempotent uninstall).
    pub fn uninstall() -> Result<(), String> {
        use windows_service::service::{ServiceAccess, ServiceState};

        const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| e.to_string())?;
        let service = match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            Ok(s) => s,
            // Already gone: nothing to do.
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
            {
                return Ok(());
            }
            Err(e) => return Err(e.to_string()),
        };
        // Mark for deletion first; the entry disappears once stopped and all
        // handles are closed.
        service.delete().map_err(|e| format!("delete: {e}"))?;
        if !matches!(service.query_status(), Ok(st) if st.current_state == ServiceState::Stopped) {
            service.stop().map_err(|e| format!("stop: {e}"))?;
        }
        drop(service);
        Ok(())
    }
}

#[cfg(windows)]
pub use windows::{install, run_as_service, uninstall};

//! huginn-worker — the fleet worker daemon. Subcommands:
//!
//!     enroll          register this machine with the hub (used by install.sh
//!                     on Linux / install.ps1 on Windows)
//!     run             run the agent loop (systemd ExecStart / SCM service)
//!     install-service write+enable the systemd unit (Linux) or create the
//!                     Windows service (Windows)
//!     healthcheck     exit 0 if this binary is runnable (used by self-update)
//!     version         print the build version
//!
//! Rust port of the Go worker; identical CLI, wire protocol, and state file
//! on Linux and Windows.

mod agent;
#[cfg(target_os = "linux")]
mod browser;
mod config;
mod exec;
mod hubclient;
mod service;
mod update;
mod whitelist;

use config::State;
use hubclient::{Client, EnrollRequest, Options};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::watch;

const USAGE: &str =
    "usage: huginn-worker <enroll|run|install-service|healthcheck|version> [--state-dir DIR]";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage_and_exit();
    }
    let mut state_dir = config::DEFAULT_STATE_DIR.to_string();
    let rest = parse_state_dir(&args[2..], &mut state_dir);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let code = match args[1].as_str() {
        "enroll" => runtime.block_on(cmd_enroll(&state_dir)),
        "run" => runtime.block_on(cmd_run(&state_dir)),
        "install-service" => runtime.block_on(cmd_install_service(&state_dir, &rest)),
        "healthcheck" => {
            println!("huginn-worker {} ok", config::VERSION);
            0
        }
        "version" => {
            println!("{}", config::VERSION);
            0
        }
        _ => usage_and_exit(),
    };
    std::process::exit(code);
}

fn usage_and_exit() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

/// Extracts a --state-dir flag from args, returning the remainder.
fn parse_state_dir(args: &[String], dir: &mut String) -> Vec<String> {
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--state-dir" && i + 1 < args.len() {
            *dir = args[i + 1].clone();
            i += 2;
            continue;
        }
        rest.push(args[i].clone());
        i += 1;
    }
    rest
}

fn machine_hostname() -> String {
    #[cfg(unix)]
    {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "localhost".into())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "localhost".into())
    }
}

/// OS reported to the hub in os_info (and used for the enroll arch mapping).
#[cfg(unix)]
fn os_name() -> &'static str {
    "linux"
}
#[cfg(windows)]
fn os_name() -> &'static str {
    "windows"
}

/// Go GOARCH names, which the hub stores as the VM architecture.
/// `std::env::consts::ARCH` is portable: "x86_64"/"aarch64" on both Linux
/// and Windows, mapped to the hub's "amd64"/"arm64".
fn goarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

async fn cmd_enroll(state_dir: &str) -> i32 {
    let hub_url = std::env::var("HUB_URL").unwrap_or_default();
    let token = std::env::var("TOKEN").unwrap_or_default();
    if hub_url.is_empty() || token.is_empty() {
        eprintln!("error: HUB_URL and TOKEN environment variables are required");
        return 1;
    }
    let name = std::env::var("NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(machine_hostname);
    let allow_insecure = std::env::var("HUGINN_ALLOW_INSECURE").as_deref() == Ok("1");
    // install.sh fetches the hub's self-signed root to a known path and
    // exports HUB_CA_CERT; honour it (and the explicit env) so a hub
    // reached via its IP/localhost enrols without HUGINN_ALLOW_INSECURE.
    let ca_cert_path = std::env::var("HUGINN_CA_CERT")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HUB_CA_CERT").ok().filter(|s| !s.is_empty()));

    let client = match Client::new(Options {
        base_url: hub_url.clone(),
        allow_insecure,
        ca_cert_path: ca_cert_path.clone(),
        ..Default::default()
    }) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let hostname = machine_hostname();
    let resp = match client
        .enroll(&EnrollRequest {
            token,
            name,
            hostname: hostname.clone(),
            ip_address: String::new(),
            arch: goarch().into(),
            os_info: Some(serde_json::json!({"os": os_name(), "arch": goarch()})),
            worker_version: config::VERSION.into(),
        })
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

    let state = State {
        hub_url,
        worker_id: resp.worker_id.clone(),
        worker_secret: resp.worker_secret,
        allow_insecure_transport: allow_insecure,
        ca_cert_path: ca_cert_path.clone(),
        ..Default::default()
    };
    if let Err(e) = config::save(&config::state_path(state_dir), &state) {
        eprintln!("error: {e}");
        return 1;
    }
    println!("enrolled as {} (state: {})", resp.worker_id, resp.state);
    println!("the VM is PENDING; approve it in the dashboard before it can run tasks");
    0
}

async fn cmd_run(state_dir: &str) -> i32 {
    #[cfg(windows)]
    {
        // When the SCM launched us, run under the service dispatcher (this
        // blocks until the service stops); a console run falls through.
        match service::run_as_service(state_dir) {
            Ok(true) => return 0, // service ran and reported Stopped
            Ok(false) => {}
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    }
    run_console(state_dir).await
}

/// Console mode: SIGINT/SIGTERM (ctrl-c on Windows) → clean shutdown.
async fn run_console(state_dir: &str) -> i32 {
    // SIGINT/SIGTERM → clean shutdown so the loop can exit.
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = ctrl_c.await;
                    let _ = shutdown_tx.send(());
                    return;
                }
            };
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        let _ = shutdown_tx.send(());
    });

    run_agent(state_dir, shutdown_rx).await
}

/// Loads the state, builds the hub client, and runs the agent loop until a
/// clean shutdown or an applied update. Shared by console mode and the
/// Windows service entry point. Returns the process exit code.
async fn run_agent(state_dir: &str, shutdown_rx: watch::Receiver<()>) -> i32 {
    let state = match config::load(&config::state_path(state_dir)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: load state (did you enroll?): {e}");
            return 1;
        }
    };
    let client = match Client::new(Options {
        base_url: state.hub_url.clone(),
        worker_id: state.worker_id.clone(),
        worker_secret: state.worker_secret.clone(),
        allow_insecure: state.allow_insecure_transport,
        ca_cert_path: state.ca_cert_path.clone(),
    }) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

    let a = Arc::new(agent::Agent::new(
        Arc::new(client),
        state,
        state_dir,
        shutdown_rx,
    ));
    // A clean return means either a clean shutdown or an applied update; exit
    // 0 so the supervisor relaunches the (possibly new) binary.
    match a.run().await {
        Ok(()) => 0,
        Err(e) => {
            let _ = std::io::stderr().write_fmt(format_args!("error: {e}\n"));
            1
        }
    }
}

async fn cmd_install_service(state_dir: &str, args: &[String]) -> i32 {
    let binary_path = args
        .first()
        .cloned()
        .unwrap_or_else(|| config::DEFAULT_BINARY_PATH.to_string());
    #[cfg(unix)]
    {
        let unit_path = format!("/etc/systemd/system/{}.service", service::SERVICE_NAME);
        match service::install(&unit_path, &binary_path, state_dir).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        }
    }
    #[cfg(windows)]
    {
        match service::install(&binary_path, state_dir) {
            Ok(()) => {
                println!(
                    "service {} installed (auto-start, LocalSystem)",
                    service::SERVICE_NAME
                );
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goarch_maps_go_names() {
        // Whatever this build's ARCH is, the mapping must be Go's GOARCH.
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(goarch(), "amd64"),
            "aarch64" => assert_eq!(goarch(), "arm64"),
            other => assert_eq!(goarch(), other),
        }
    }

    #[test]
    fn test_parse_state_dir_extracts_flag() {
        let mut dir = config::DEFAULT_STATE_DIR.to_string();
        let rest = parse_state_dir(
            &[
                "--state-dir".to_string(),
                "/x".to_string(),
                "extra".to_string(),
            ],
            &mut dir,
        );
        assert_eq!(dir, "/x");
        assert_eq!(rest, vec!["extra".to_string()]);

        // A dangling --state-dir is kept as a positional arg, not silently eaten.
        let mut dir2 = String::new();
        let rest2 = parse_state_dir(&["--state-dir".to_string()], &mut dir2);
        assert_eq!(rest2, vec!["--state-dir".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn test_os_name_is_linux() {
        assert_eq!(os_name(), "linux");
    }

    #[cfg(windows)]
    #[test]
    fn test_os_name_is_windows() {
        assert_eq!(os_name(), "windows");
    }
}

//! huginn-worker — the fleet worker daemon. Subcommands:
//!
//!     enroll          register this machine with the hub (used by install.sh)
//!     run             run the agent loop (systemd ExecStart)
//!     install-service write and enable the systemd unit
//!     healthcheck     exit 0 if this binary is runnable (used by self-update)
//!     version         print the build version
//!
//! Rust port of the Go worker; identical CLI, wire protocol, and state file.

mod agent;
mod config;
mod exec;
mod hubclient;
mod systemd;
mod update;
mod whitelist;

use config::State;
use hubclient::{Client, EnrollRequest, Options};
use std::io::Write;
use std::sync::Arc;

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
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".into())
}

/// Go GOARCH names, which the hub stores as the VM architecture.
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

    let client = match Client::new(Options {
        base_url: hub_url.clone(),
        allow_insecure,
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
            os_info: Some(serde_json::json!({"os": "linux", "arch": goarch()})),
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
    }) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

    // SIGINT/SIGTERM → clean shutdown so the loop can exit.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
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

    let a = Arc::new(agent::Agent::new(Arc::new(client), state, shutdown_rx));
    // A clean return means either a clean shutdown or an applied update; exit
    // 0 so systemd relaunches the (possibly new) binary.
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
    let unit_path = format!("/etc/systemd/system/{}.service", systemd::SERVICE_NAME);
    match systemd::install(&unit_path, &binary_path, state_dir).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

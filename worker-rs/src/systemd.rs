// Manages the worker's own systemd unit.
//
// Rust port of worker/internal/systemd.
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

use tokio::process::Command;

pub const SERVICE_NAME: &str = "huginn-worker";

const UNIT_TEMPLATE: &str = "[Unit]
Description=Huginn fleet worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} run --state-dir {dir}
Restart=always
RestartSec=5
# Hardening
NoNewPrivileges=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
";

/// UnitContent renders the unit file for the given binary path and state dir.
pub fn unit_content(binary_path: &str, state_dir: &str) -> String {
    UNIT_TEMPLATE
        .replacen("{bin}", binary_path, 1)
        .replacen("{dir}", state_dir, 1)
}

/// Install writes the unit file (0644) and enables the service.
pub async fn install(
    unit_path: &str,
    binary_path: &str,
    state_dir: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let content = unit_content(binary_path, state_dir);
    tokio::fs::write(unit_path, content).await?; // unit files are world-readable
    tokio::fs::set_permissions(unit_path, std::fs::Permissions::from_mode(0o644)).await?;
    systemctl(&["daemon-reload"]).await?;
    systemctl(&["enable", "--now", SERVICE_NAME]).await?;
    Ok(())
}

/// RestartSelf restarts the worker service (used after a self-update).
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

async fn systemctl(args: &[&str]) -> io::Result<()> {
    // Output is inherited, mirroring Go's cmd.Stdout = os.Stdout wiring in run().
    let status = Command::new("systemctl").args(args).status().await?;
    check_exit(status)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_content_matches_go_template() {
        let content = unit_content("/usr/local/bin/huginn-worker", "/etc/huginn");
        assert_eq!(
            content,
            "[Unit]\n\
             Description=Huginn fleet worker\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart=/usr/local/bin/huginn-worker run --state-dir /etc/huginn\n\
             Restart=always\n\
             RestartSec=5\n\
             # Hardening\n\
             NoNewPrivileges=true\n\
             ProtectHome=true\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
    }
}

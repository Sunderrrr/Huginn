// Package systemd manages the worker's own systemd unit.
package systemd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

const ServiceName = "huginn-worker"

const unitTemplate = `[Unit]
Description=Huginn fleet worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run --state-dir %s
Restart=always
RestartSec=5
# Hardening
NoNewPrivileges=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
`

// UnitContent renders the unit file for the given binary path and state dir.
func UnitContent(binaryPath, stateDir string) string {
	return fmt.Sprintf(unitTemplate, binaryPath, stateDir)
}

// Install writes the unit file and enables the service.
func Install(unitPath, binaryPath, stateDir string) error {
	content := UnitContent(binaryPath, stateDir)
	if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil { //nolint:gosec // unit files are world-readable
		return err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	return run("systemctl", "enable", "--now", ServiceName)
}

// RestartSelf restarts the worker service (used after a self-update).
func RestartSelf(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", ServiceName)
	return cmd.Run()
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

#!/bin/bash
# Huginn worker uninstaller.
#
# Run as root on the VM to remove the worker service, binary, and state.
# After running this, revoke the VM from the Huginn dashboard.
#
set -e

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "error: please run as root" >&2
  exit 1
fi

log "stopping huginn-worker service"
systemctl stop huginn-worker 2>/dev/null || true
systemctl disable huginn-worker 2>/dev/null || true

log "removing systemd unit"
rm -f /etc/systemd/system/huginn-worker.service
rm -rf /etc/systemd/system/huginn-worker.service.d
systemctl daemon-reload

log "removing binary"
rm -f /usr/local/bin/huginn-worker

log "removing state directory"
rm -rf /etc/huginn

log "removing hub CA (trust-on-first-use)"
rm -f /usr/local/share/ca-certificates/huginn-hub-ca.crt
update-ca-certificates 2>/dev/null || true

log "done. Revoke this VM from the Huginn dashboard."

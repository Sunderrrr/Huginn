#!/usr/bin/env bash
#
# ensure-stack.sh — make sure the Huginn stack is running.
#
# The host's own supervisor (the AMP instance manager) and some maintenance
# scripts stop containers from time to time; `restart: unless-stopped` does
# not bring a container back after an explicit stop, so the hub and the TLS
# edge can stay down for hours. This script is idempotent and cheap: it only
# starts what is not running, and recreates the project only if a container
# disappeared entirely.
#
# Run by systemd (huginn-ensure-stack.timer) every two minutes.
set -u

cd /opt/huginn/deploy || exit 1

ENGINE=podman
command -v podman >/dev/null 2>&1 || ENGINE=docker

CONTAINERS="huginn-postgres huginn-hub huginn-mcp huginn-dashboard huginn-caddy"
missing=0
for c in $CONTAINERS; do
  if ! $ENGINE container exists "$c" 2>/dev/null; then
    missing=1
    continue
  fi
  running="$($ENGINE inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo false)"
  if [ "$running" != "true" ]; then
    printf '==> starting %s\n' "$c" >> /var/log/huginn-ensure-stack.log 2>&1
    $ENGINE start "$c" >> /var/log/huginn-ensure-stack.log 2>&1 || true
  fi
done

# A container that vanished entirely (not just stopped) needs the project
# to be recreated.
if [ "$missing" = "1" ]; then
  printf '==> recreating the deploy project\n' >> /var/log/huginn-ensure-stack.log 2>&1
  if command -v podman-compose >/dev/null 2>&1; then
    podman-compose -f docker-compose.prod.yml --env-file .env.prod up -d \
      >> /var/log/huginn-ensure-stack.log 2>&1 || true
  else
    podman compose -f docker-compose.prod.yml --env-file .env.prod up -d \
      >> /var/log/huginn-ensure-stack.log 2>&1 || true
  fi
fi

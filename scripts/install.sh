#!/usr/bin/env bash
#
# Huginn worker installer.
#
#   curl -sSL https://<hub>/install.sh | HUB_URL=https://<hub> TOKEN=<token> bash
#
# Detects the architecture, downloads the matching release binary, verifies its
# SHA-256 against the published checksums, installs it, enrolls with the hub, and
# sets up the systemd service. The VM is then PENDING until approved.
#
# Environment:
#   HUB_URL   (required) base URL of the hub
#   TOKEN     (required) enrollment token from the dashboard
#   NAME      (optional) friendly VM name (defaults to hostname)
#   REPO      (optional) GitHub repo for releases (default Internal-website/Huginn)
#   VERSION   (optional) release tag to install (default: latest)
#   BIN_DIR   (optional) install directory (default /usr/local/bin)
#
set -euo pipefail

REPO="${REPO:-Internal-website/Huginn}"
VERSION="${VERSION:-latest}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
BINARY_NAME="huginn-worker"
STATE_DIR="${STATE_DIR:-/etc/huginn}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

main() {
  [ -n "${HUB_URL:-}" ] || err "HUB_URL is required"
  [ -n "${TOKEN:-}" ]   || err "TOKEN is required"

  require_cmd curl
  require_cmd sha256sum
  require_cmd uname

  if [ "$(id -u)" -ne 0 ]; then
    err "please run as root (the installer writes to ${BIN_DIR} and installs a systemd unit)"
  fi

  local arch
  arch="$(detect_arch)"
  log "detected architecture: ${arch}"

  if [ "$VERSION" = "latest" ]; then
    VERSION="$(resolve_latest)"
    log "latest release: ${VERSION}"
  fi

  local asset="${BINARY_NAME}-linux-${arch}"
  local base="https://github.com/${REPO}/releases/download/${VERSION}"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT

  log "downloading ${asset} (${VERSION})"
  curl -fsSL "${base}/${asset}" -o "${tmp}/${asset}"
  curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt"

  log "verifying checksum"
  ( cd "${tmp}" && grep " ${asset}\$" checksums.txt | sha256sum -c - ) \
    || err "checksum verification failed"

  log "installing to ${BIN_DIR}/${BINARY_NAME}"
  install -m 0755 "${tmp}/${asset}" "${BIN_DIR}/${BINARY_NAME}"

  log "enrolling with hub ${HUB_URL}"
  HUB_URL="${HUB_URL}" TOKEN="${TOKEN}" NAME="${NAME:-}" \
    "${BIN_DIR}/${BINARY_NAME}" enroll --state-dir "${STATE_DIR}"

  log "installing systemd service"
  "${BIN_DIR}/${BINARY_NAME}" install-service --state-dir "${STATE_DIR}" "${BIN_DIR}/${BINARY_NAME}"

  log "done. Approve this VM in the dashboard to activate it."
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) err "unsupported architecture: $(uname -m)" ;;
  esac
}

resolve_latest() {
  # Resolve the latest release tag via the GitHub API.
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' \
    || err "could not resolve latest release"
}

main "$@"

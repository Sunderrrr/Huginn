#!/usr/bin/env bash
#
# Huginn worker installer.
#
#   curl -fsSL  https://<hub>/install.sh | HUB_URL=https://<hub> TOKEN=<token> bash
#   # for a hub with a self-signed (internal CA) cert, fetch the script with -k:
#   curl -fsSLk https://<hub>/install.sh | HUB_URL=https://<hub> TOKEN=<token> bash
#
# Detects the architecture, downloads the matching worker binary FROM THE HUB,
# verifies its SHA-256 against the published checksums, installs it, enrolls with
# the hub, and sets up the systemd service. The VM is PENDING until approved.
#
# If the hub uses a self-signed/internal CA, the installer fetches the hub's CA
# root (trust-on-first-use) and installs it into the system trust store, so the
# binary download and the worker's own TLS connections are verified.
#
# Environment:
#   HUB_URL          (required) base URL of the hub, e.g. https://192.0.2.13
#   TOKEN            (required) enrollment token from the dashboard
#   NAME             (optional) friendly VM name (defaults to hostname)
#   BINARY_BASE_URL  (optional) where to fetch the binary + checksums.txt
#                    (default: $HUB_URL/dist; set to a GitHub releases URL to use
#                    published releases instead)
#   BIN_DIR          (optional) install directory (default /usr/local/bin)
#
set -euo pipefail

HUB_URL="${HUB_URL:-}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
BINARY_NAME="huginn-worker"
STATE_DIR="${STATE_DIR:-/etc/huginn}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
err() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

main() {
  [ -n "$HUB_URL" ]      || err "HUB_URL is required"
  [ -n "${TOKEN:-}" ]    || err "TOKEN is required"
  HUB_URL="${HUB_URL%/}"

  require_cmd curl
  require_cmd sha256sum
  require_cmd uname

  if [ "$(id -u)" -ne 0 ]; then
    err "please run as root (writes to ${BIN_DIR} and installs a systemd unit)"
  fi

  local arch
  arch="$(detect_arch)"
  log "architecture: ${arch}"

  ensure_hub_trust

  local base="${BINARY_BASE_URL:-${HUB_URL}/dist}"
  local asset="${BINARY_NAME}-linux-${arch}"
  local tmp
  tmp="$(mktemp -d)"
  # ${tmp:-} so the EXIT trap is safe under `set -u` after locals go out of scope.
  trap 'rm -rf "${tmp:-}"' EXIT

  log "downloading ${asset} from ${base}"
  curl -fsSL "${base}/${asset}" -o "${tmp}/${asset}"
  curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt"

  log "verifying checksum"
  ( cd "${tmp}" && grep " ${asset}\$" checksums.txt | sha256sum -c - ) \
    || err "checksum verification failed"

  log "installing ${BIN_DIR}/${BINARY_NAME}"
  install -m 0755 "${tmp}/${asset}" "${BIN_DIR}/${BINARY_NAME}"

  # If the hub is plaintext HTTP, the worker must opt into insecure transport.
  case "$HUB_URL" in
    http://*) export HUGINN_ALLOW_INSECURE=1 ;;
  esac

  log "enrolling with ${HUB_URL}"
  HUB_URL="$HUB_URL" TOKEN="$TOKEN" NAME="${NAME:-}" \
    "${BIN_DIR}/${BINARY_NAME}" enroll --state-dir "${STATE_DIR}"

  log "installing systemd service"
  "${BIN_DIR}/${BINARY_NAME}" install-service --state-dir "${STATE_DIR}" "${BIN_DIR}/${BINARY_NAME}"

  log "done. Approve this VM in the dashboard to activate it."
}

detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    *) err "unsupported architecture: $(uname -m)" ;;
  esac
}

# Make the hub's TLS trusted. No-op for HTTP or an already-trusted cert; otherwise
# fetch the hub's CA root (trust-on-first-use) and install it system-wide.
ensure_hub_trust() {
  case "$HUB_URL" in
    http://*) return 0 ;;
  esac
  if curl -fsS "${HUB_URL}/healthz" >/dev/null 2>&1; then
    return 0
  fi
  log "hub certificate not trusted; installing the hub CA (trust-on-first-use)"
  require_cmd update-ca-certificates
  local dst="/usr/local/share/ca-certificates/huginn-hub-ca.crt"
  curl -fsSLk "${HUB_URL}/caddy-root.crt" -o "$dst" \
    || err "could not fetch the hub CA from ${HUB_URL}/caddy-root.crt"
  update-ca-certificates >/dev/null 2>&1 || true
  curl -fsS "${HUB_URL}/healthz" >/dev/null 2>&1 \
    || err "hub still not trusted after installing its CA"
}

main "$@"

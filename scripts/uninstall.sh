#!/usr/bin/env bash
#
# uninstall.sh — reverse of install.sh.
#
# Removes everything Huginn added to this machine: the worker service + binary,
# the worker state, the hub CA root from the system trust store, and the
# optional Obscura browser engine. Safe to re-run (missing pieces are skipped).
#
#   curl -fsSL https://<hub>/uninstall.sh | bash
#   # or, for a self-signed hub:
#   curl -fsSLk https://<hub>/uninstall.sh | bash
#
# Optional env (mirrors install.sh):
#   STATE_DIR   worker state directory (default: /etc/huginn)
#   BIN_DIR     directory holding huginn-worker (default: /usr/local/bin)
#   ENGINE_DIR  Obscura engine root (default: /opt/huginn/obscura)
#
set -u

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
STATE_DIR="${STATE_DIR:-/etc/huginn}"
ENGINE_DIR="${ENGINE_DIR:-/opt/huginn/obscura}"
BINARY_NAME="huginn-worker"
SERVICE_NAME="huginn-worker"

log() { printf '==> %s\n' "$*"; }
warn() { printf '   warning: %s\n' "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root (writes to ${BIN_DIR} and ${STATE_DIR})" >&2
  exit 1
fi

# --- 1. stop + disable + remove the systemd service -------------------------
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    log "stopping ${SERVICE_NAME}"
    systemctl stop "${SERVICE_NAME}" || warn "could not stop ${SERVICE_NAME}"
  fi
  if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    log "disabling ${SERVICE_NAME}"
    systemctl disable "${SERVICE_NAME}" || warn "could not disable ${SERVICE_NAME}"
  fi
  if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
    log "removing /etc/systemd/system/${SERVICE_NAME}.service"
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
fi

# --- 2. remove the worker binary -------------------------------------------
if [ -f "${BIN_DIR}/${BINARY_NAME}" ]; then
  log "removing ${BIN_DIR}/${BINARY_NAME}"
  rm -f "${BIN_DIR}/${BINARY_NAME}"
fi

# --- 3. remove worker state -------------------------------------------------
if [ -d "${STATE_DIR}" ]; then
  log "removing ${STATE_DIR}"
  rm -rf "${STATE_DIR}"
fi

# --- 4. remove the hub CA from every supported trust store -------------------
ca_paths=(
  "/usr/local/share/ca-certificates/huginn-hub-ca.crt"      # Debian/Ubuntu/Alpine
  "/etc/pki/ca-trust/source/anchors/huginn-hub-ca.crt"     # RHEL/Fedora/Rocky/Alma
  "/etc/pki/trust/anchors/huginn-hub-ca.crt"                # openSUSE/SLES
  "/etc/ca-certificates/trust-source/anchors/huginn-hub-ca.crt"  # Arch/Manjaro
)
removed_ca=false
for ca in "${ca_paths[@]}"; do
  if [ -f "${ca}" ]; then
    log "removing ${ca}"
    rm -f "${ca}"
    removed_ca=true
  fi
done
if [ "${removed_ca}" = true ]; then
  if command -v update-ca-trust >/dev/null 2>&1; then
    update-ca-trust extract >/dev/null 2>&1 || true
  elif command -v trust >/dev/null 2>&1; then
    trust extract-compat >/dev/null 2>&1 || true
  elif command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates >/dev/null 2>&1 || true
  fi
fi

# --- 5. remove the Obscura browser engine (if installed) --------------------
if [ -d "${ENGINE_DIR}" ]; then
  log "removing ${ENGINE_DIR}"
  rm -rf "${ENGINE_DIR}"
fi

# --- 6. remove any leftover temp state --------------------------------------
rm -rf /tmp/huginn-worker-test-* 2>/dev/null || true

log "done. Huginn worker, CA root and browser engine removed."

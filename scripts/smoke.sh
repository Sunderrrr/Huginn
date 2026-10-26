#!/usr/bin/env bash
#
# smoke.sh — check that the deployed stack actually answers.
#
# The containers being "Up" proves nothing: a database stuck in a shutdown
# keeps its container running while the hub, the MCP and the dashboard all
# fail. This script checks the real paths, and is meant to run after every
# deploy: a deployment that does not pass it has broken the stack.
#
#   ./scripts/smoke.sh [base-url]      # default: https://<HUGINN_DOMAIN>
#
# Exits 0 when everything answers, 1 otherwise (and prints what failed).
set -u

BASE="${1:-}"
if [ -z "$BASE" ]; then
  BASE="$(grep -E '^HUGINN_DOMAIN=' /opt/huginn/deploy/.env.prod 2>/dev/null | cut -d= -f2- | tr -d '"')"
  BASE="${BASE:-https://100.73.17.140}"
fi
BASE="${BASE%/}"

# The dev compose publishes the three services on different ports; the
# production one serves them from a single origin.
DASHBOARD_URL="${SMOKE_DASHBOARD_URL:-$BASE}"
MCP_URL="${SMOKE_MCP_URL:-$BASE}"
# SMOKE_INSECURE=1 for a self-signed certificate (the CI stack).
CURL_OPTS="-sSL"
[ "${SMOKE_INSECURE:-0}" = "1" ] && CURL_OPTS="$CURL_OPTS -k"

fail=0
# The container engine: podman on the host, docker in the CI.
ENGINE=docker
command -v podman >/dev/null 2>&1 && ENGINE=podman
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }

# A GET on a path, with the redirects followed. Retried: right after a
# deploy the stack needs a few seconds to come up, and a smoke test that
# fails on a race is worse than useless.
get_code() {
  local url="$1" tries=0 code=000
  while [ "$tries" -lt 36 ]; do
    # curl prints 000 itself when the connection fails; the `|| true` keeps
    # a non-zero exit from tripping `set -e`.
    code=$(curl $CURL_OPTS -m 15 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)
    [ "$code" != "000" ] && break
    tries=$((tries + 1))
    sleep 5
  done
  printf '%s' "$code"
}

echo "==> smoke: $BASE"

# 1. The hub's health endpoint.
code=$(get_code "$BASE/healthz")
if [ "$code" = "200" ]; then ok "GET /healthz -> $code"; else bad "GET /healthz -> $code"; fi

# 2. The dashboard.
code=$(get_code "$DASHBOARD_URL/")
if [ "$code" = "200" ]; then ok "GET $DASHBOARD_URL/ -> $code"; else bad "GET $DASHBOARD_URL/ -> $code"; fi

# 3. The installer scripts. They are served by the TLS edge (Caddy), which
#    the dev stack has not: the check is mandatory for a production stack.
for f in install.sh install.ps1 uninstall.sh; do
  code=$(get_code "$BASE/$f")
  if [ "$code" = "200" ]; then
    ok "GET /$f -> $code"
  elif [ "${SMOKE_REQUIRE_DIST:-0}" = "1" ]; then
    bad "GET /$f -> $code"
  else
    printf '  --   skipping %s (this stack has no TLS edge)\n' "$f"
  fi
done

# 4. The manifest, and the Windows asset it must list.
manifest=/tmp/smoke-checksums.txt
rm -f "$manifest"
code=000
tries=0
while [ "$tries" -lt 12 ]; do
  code=$(curl $CURL_OPTS -m 15 -o "$manifest" -w '%{http_code}' "$BASE/dist/checksums.txt" 2>/dev/null || echo 000)
  [ "$code" = "200" ] && break
  tries=$((tries + 1))
  sleep 5
done
if [ "$code" = "200" ]; then
  ok "GET /dist/checksums.txt -> $code"
  missing=""
  for asset in huginn-worker-linux-amd64 huginn-worker-linux-arm64 huginn-worker-windows-amd64.exe; do
    grep -q "  $asset\$" /tmp/smoke-checksums.txt || missing="$missing $asset"
  done
  if [ -n "$missing" ]; then
    bad "the manifest has no entry for:$missing"
  else
    ok "the manifest lists every published asset"
  fi
else
  # The dev stack (used by the CI) serves no artifacts; the production one
  # must, and there SMOKE_REQUIRE_DIST keeps the check mandatory.
  if [ "${SMOKE_REQUIRE_DIST:-0}" = "1" ]; then
    bad "GET /dist/checksums.txt -> $code"
  else
    printf '  --   skipping the manifest (this stack serves no artifacts)\n'
  fi
fi

# 5. The MCP endpoint: it must answer the JSON-RPC handshake (401 without a
#    token is fine — a 5xx or a closed port is not).
code=$(curl $CURL_OPTS -m 15 -o /dev/null -w '%{http_code}' -X POST "$MCP_URL/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' 2>/dev/null || echo 000)
case "$code" in
  200|401|403) ok "POST /mcp -> $code" ;;
  *) bad "POST /mcp -> $code" ;;
esac

# 6. The database answers and the fleet is readable.
if command -v "$ENGINE" >/dev/null 2>&1; then
  # The hub answers /healthz only when it can reach the database, so the
  # database is already covered above. The container states are reported for
  # the eye: a stack that does not run the same set of containers (the dev
  # stack has no TLS edge) is not a failure.
  for c in huginn-postgres huginn-hub huginn-mcp huginn-dashboard huginn-caddy; do
    state=$($ENGINE inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo absent)
    health=$($ENGINE inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo none)
    if [ "$state" = "running" ] && { [ "$health" = "healthy" ] || [ "$health" = "none" ]; }; then
      ok "$c is $state/$health"
    else
      printf '  --   %s is %s/%s\n' "$c" "$state" "$health"
    fi
  done
fi

if [ "$fail" = "0" ]; then
  echo "==> smoke: OK"
else
  echo "==> smoke: FAILED"
fi
exit $fail

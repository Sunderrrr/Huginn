#!/usr/bin/env bash
#
# manage.sh — run the Huginn stack with Docker or Podman, your choice.
#
#   ./manage.sh up            # bring the stack up (builds if needed)
#   ./manage.sh down           # stop (data volumes are kept)
#   ./manage.sh ps             # status
#   ./manage.sh logs <service> # follow logs (hub, mcp, dashboard, caddy, postgres)
#   ./manage.sh build          # (re)build the images
#
# Engine selection (first match wins):
#   1. CONTAINER_ENGINE env var: CONTAINER_ENGINE=podman ./manage.sh up
#   2. The engine that is installed (podman preferred if both, so a migration
#      is a no-op on a machine that has both).
#
# Podman notes:
#   - rootless works: pods are namespaced under your user; the Caddy ports
#     (<1024) need either rootful podman or `sysctl net.ipv4.ip_unprivileged_port_start=80`.
#   - `podman-compose` OR `podman compose` (the docker-compatible shim) — this
#     script uses whichever is available, in that order of preference.
#   - migrating from docker: `podman system reset` is NOT needed; both can
#     coexist. To move existing volumes, see docs/deployment.md (Podman section).
#
set -euo pipefail

cd "$(dirname "$0")"

pick_engine() {
  if [ -n "${CONTAINER_ENGINE:-}" ]; then
    case "${CONTAINER_ENGINE}" in
      docker|podman) echo "${CONTAINER_ENGINE}"; return 0 ;;
      *) echo "error: CONTAINER_ENGINE must be 'docker' or 'podman'" >&2; exit 2 ;;
    esac
  fi
  # Prefer podman when both exist — that's the direction people migrate.
  if command -v podman >/dev/null 2>&1; then echo podman; return 0; fi
  if command -v docker >/dev/null 2>&1; then echo docker; return 0; fi
  echo "error: neither podman nor docker is installed" >&2
  exit 2
}

ENGINE="$(pick_engine)"
COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env.prod"

compose() {
  case "${ENGINE}" in
    docker)
      docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" "$@" ;;
    podman)
      if command -v podman-compose >/dev/null 2>&1; then
        podman-compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" "$@"
      elif podman compose version >/dev/null 2>&1; then
        podman compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" "$@"
      else
        echo "error: podman is installed but no compose plugin: install 'podman-compose' or the 'podman-docker' shim" >&2
        exit 2
      fi ;;
  esac
}

case "${1:-}" in
  up)     compose up -d --build ;;
  down)   compose down ;;
  ps)     compose ps ;;
  build)  compose build ;;
  logs)   shift; compose logs -f "${1:-}" ;;
  *)
    cat <<EOF
usage: ./manage.sh {up|down|ps|build|logs [service]}
engine: ${ENGINE} (override with CONTAINER_ENGINE=docker|podman)
EOF
    exit 2 ;;
esac

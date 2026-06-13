#!/usr/bin/env bash
# Apply database migrations, then exec the given command (the API server).
set -euo pipefail

echo "==> applying database migrations"
alembic upgrade head

echo "==> starting: $*"
exec "$@"

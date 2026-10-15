#!/usr/bin/env bash
#
# Huginn database backup (pg_dump of the fleet DB + retention).
#
#   ./backup-db.sh            # backup into BACKUP_DIR (default /var/backups/huginn)
#
# Env:
#   BACKUP_DIR     destination (default /var/backups/huginn)
#   RETENTION_DAYS days of backups to keep (default 14)
#
# Restore (see README-LOCAL.md for the full runbook):
#   gunzip -c <dump>.sql.gz | docker exec -i huginn-postgres psql -U huginn -d huginn
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/huginn}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
CONTAINER="${CONTAINER:-huginn-postgres}"
DB_USER="${DB_USER:-huginn}"
DB_NAME="${DB_NAME:-huginn}"

mkdir -p "$BACKUP_DIR"
stamp="$(date +%Y%m%d-%H%M%S)"
out="$BACKUP_DIR/huginn-$stamp.sql.gz"

# Stream the dump straight to gzip; fail loudly if pg_dump errors.
docker exec "$CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" --clean --if-exists | gzip > "$out"

# Never keep an empty/failed dump around.
[ -s "$out" ] || { rm -f "$out"; echo "backup produced an empty file" >&2; exit 1; }

# Retention: drop dumps older than RETENTION_DAYS (keep at least one).
find "$BACKUP_DIR" -name 'huginn-*.sql.gz' -mtime +"$RETENTION_DAYS" -delete

echo "backup ok: $out ($(du -h "$out" | cut -f1))"

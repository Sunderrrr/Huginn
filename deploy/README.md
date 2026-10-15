# deploy/ — running Huginn

Compose stacks + Caddy reverse proxy + Kubernetes manifests. Works with
**Docker or Podman** — same files, same commands (see `manage.sh`).

| File | What |
|---|---|
| `docker-compose.yml` | dev stack — hub `:8000`, dashboard `:5173`, MCP `:9000`, no TLS |
| `docker-compose.prod.yml` | production — Caddy in front, HTTPS on 80/443, everything behind one origin |
| `manage.sh` | one command for the stack, engine-agnostic (Docker or Podman) |
| `Caddyfile` | reverse proxy: `/` → dashboard, `/api` + `/healthz` + `/metrics` → hub, `/mcp` → MCP, `/install.sh` + `/dist` → worker artifacts |
| `k8s/` | Kubernetes manifests (hub, mcp, dashboard, ingress) |
| `../scripts/backup-db.sh` | database backup (schedule it with cron/systemd) |

## Production, step by step

```bash
cd deploy
cp .env.prod.example .env.prod        # set HUGINN_DOMAIN + real secrets (openssl rand -hex 32)
../scripts/build-artifacts.sh v1.4.4  # static worker binaries served at /dist
./manage.sh up                        # Docker or Podman — auto-detected
```

Open `https://<HUGINN_DOMAIN>/` and sign in with the bootstrap admin
(`HUGINN_BOOTSTRAP_ADMIN_*`). First login requires enrolling a second factor
(TOTP).

### Engine selection

`manage.sh` picks the engine for you: Podman if it is installed (that is the
direction people migrate), Docker otherwise. To pin one:

```bash
CONTAINER_ENGINE=docker ./manage.sh up
CONTAINER_ENGINE=podman ./manage.sh up
```

Everything below applies to both engines. If you call compose yourself,
replace `docker compose` with `podman-compose` (or `podman compose`).

## Podman

The whole stack runs unchanged under Podman, rootful or rootless.

```bash
# Prerequisites (Debian/Ubuntu)
sudo apt install -y podman podman-compose
./manage.sh up
```

Rootless notes:

- Publishing ports below 1024 (80/443) as a non-root user needs
  `sudo sysctl net.ipv4.ip_unprivileged_port_start=80` (or run rootful:
  `sudo podman-compose ...`).
- Volumes live under `~/.local/share/containers/storage/volumes` instead of
  Docker's `/var/lib/docker/volumes`.

### Migrating from Docker to Podman

Both engines can coexist — nothing is reset, and the migration is a standard
backup/restore of the database volume (the images are rebuilt from source, the
certs and env files live on the host):

```bash
# 1. Stop the Docker stack
docker compose -f docker-compose.prod.yml --env-file .env.prod down

# 2. Back up the database
docker exec huginn-postgres pg_dump -U huginn -d huginn > backup.sql

# 3. Start with Podman (same env files, same certs)
./manage.sh up                            # or: CONTAINER_ENGINE=podman ./manage.sh up

# 4. Restore the database
podman exec -i huginn-postgres psql -U huginn -d huginn < backup.sql
# then restart the hub so it picks the restored state:
./manage.sh logs hub   # watch the migrations apply, then:
# (the hub container restarts itself if the restore happens while it runs —
#  otherwise: ./manage.sh down && ./manage.sh up)

# 5. When satisfied, reclaim the Docker disk
docker system prune -a --volumes        # optional, frees the old images
```

If the `huginn-postgres` name is taken by a leftover container, remove it first:
`podman rm -f huginn-postgres`.

## TLS certificates

`Caddyfile` serves the certificate pair mounted from `./certs/` (generate your
own CA + server cert — `deploy/certs/huginn.crt` and `huginn.key`; the CA root
is `huginn-ca.crt`, also served at `/caddy-root.crt` for trust-on-first-use).
To use Let's Encrypt instead, replace the `tls` directive in the Caddyfile with
`tls <your-email>` and point `HUGINN_DOMAIN` at a public domain.

## Environment

`.env.prod` drives everything (see `.env.prod.example` for the full list):
domain, database credentials, four `openssl rand -hex 32` secrets, MFA policy,
proxy trust (`HUGINN_TRUST_FORWARDED_FOR`), bootstrap admin, and the target
worker version. The hub refuses to boot in `HUGINN_ENV=prod` with placeholder
secrets.

## Day-2 operations

```bash
./manage.sh ps              # status
./manage.sh logs hub        # follow one service
./manage.sh up              # upgrade (rebuild + restart)
../scripts/backup-db.sh     # DB dump
```

Enrolling a VM (token comes from the dashboard) — works on `amd64` and
`arm64`, detected automatically:

```bash
curl -fsSLk https://<HUGINN_DOMAIN>/install.sh | HUB_URL=https://<HUGINN_DOMAIN> TOKEN=<token> bash
```

The installer detects the architecture (`uname -m` → amd64/arm64), downloads the
matching static binary from the hub, verifies its SHA-256, installs a systemd
unit, and enrolls. The worker self-updates toward
`HUGINN_TARGET_WORKER_VERSION`; artifacts are served by the hub itself at
`/dist` (see `../scripts/build-artifacts.sh`, which cross-compiles both
architectures).

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
./build-artifacts.sh vX.Y.Z         # static worker binaries served at /dist
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
own CA + server cert: `deploy/certs/huginn.crt` and `deploy/certs/huginn.key`).
The CA root is `huginn-ca.crt`, also served at `/caddy-root.crt` for
trust-on-first-use.
To use Let's Encrypt instead, replace the `tls` directive in the Caddyfile with
`tls <your-email>` and point `HUGINN_DOMAIN` at a public domain.

### If a CDN sits in front (Cloudflare)

A CDN in front of the deployment may apply its own bot/browser rules. One
observed case: Cloudflare's *Browser Integrity Check* answers **403
`error code: 1010`** to the exact User-Agent `Python-urllib/3.14` (the
stdlib default of `urllib.request`), while `curl`, `python-requests`, `node`,
Go and every browser pass. A script that uses `urllib` without setting a
User-Agent is therefore refused *before* it reaches the hub.

Two ways out, both one-liners:

- client-side: set any User-Agent (`urllib.request.Request(..., headers={"User-Agent": "my-script/1.0"})`).
- edge-side: add a WAF **skip rule** for that path/UA, or turn the Browser
  Integrity Check off for the API paths (`/api/*`, `/mcp`).

The hub itself does not depend on any User-Agent, and nothing else in the
stack (worker, installer, MCP) is affected.

## Environment

`.env.prod` drives everything (see `.env.prod.example` for the full list):
domain, database credentials, four `openssl rand -hex 32` secrets, MFA policy,
proxy trust (`HUGINN_TRUST_FORWARDED_FOR`), bootstrap admin, and the target
worker version. The hub refuses to boot in `HUGINN_ENV=prod` with placeholder
secrets.

## Day-2 operations

### Keeping the stack up (watchdog)

The host's own supervisor (and some maintenance scripts) can stop the
containers. `restart: unless-stopped` does **not** restart a container that was
stopped explicitly, so the hub and the TLS edge can stay down for hours.

`scripts/ensure-stack.sh` is an idempotent check that starts whatever is not
running (and recreates the project only if a container vanished). Install it as
a systemd timer on the host:

```bash
systemctl enable --now huginn-ensure-stack.timer   # every 2 minutes
```

Logs: `/var/log/huginn-ensure-stack.log`.

```bash
./manage.sh ps              # status
./manage.sh logs hub        # follow one service
./manage.sh up              # upgrade (rebuild + restart)
../scripts/backup-db.sh     # DB dump
```

Enrolling a VM (token comes from the dashboard) — works on **Linux**
(`amd64`/`arm64`) and **Windows** (`amd64`), detected automatically:

### Linux

```bash
curl -fsSLk https://<HUGINN_DOMAIN>/install.sh | HUB_URL=https://<HUGINN_DOMAIN> TOKEN=<token> bash
```

The installer detects the architecture (`uname -m` → amd64/arm64), downloads the
matching static musl binary from the hub, verifies its SHA-256, installs a
systemd unit, and enrolls.

### Windows (PowerShell 7, as Administrator)

Run the commands **separately**, from a *PowerShell 7* console opened as
administrator. If the prompt is Windows PowerShell 5.1, start PowerShell 7
first:

```powershell
pwsh -NoProfile
$PSVersionTable.PSVersion        # expect 7.6.8
```

Then fetch the installer and run it **as a file** (do not pipe it to `iex`:
`Invoke-Expression` cannot bind `HUB_URL` and `Token` to the script's
`param()` block, and a failure would close your session):

```powershell
$installer = "$env:TEMP\huginn-install.ps1"
Invoke-WebRequest -Uri "https://<HUGINN_DOMAIN>/install.ps1" -OutFile $installer
pwsh -NoProfile -ExecutionPolicy Bypass -File $installer -HUB_URL "https://<HUGINN_DOMAIN>" -Token "<token>"
```

The installer detects the **OS** architecture (not the PowerShell process's:
a 32-bit shell on a 64-bit Windows would report x86), downloads the matching
`.exe` from `/dist`, verifies its SHA-256 against the hub's own manifest,
installs a **Windows Service** ("HuginnWorker", auto-start) and enrolls. Free
commands run through PowerShell (`unrestricted` mode), whitelisted actions use
OS-specific commands (`Get-CimInstance`, `Restart-Service` instead of
`uname`/`systemctl`).

Only **windows/amd64** is published (the release builds
`x86_64-pc-windows-gnu`); the installer refuses any other architecture
before downloading anything.

**Re-running the installer is safe.** When the node already has an identity
(`C:\ProgramData\Huginn\worker.json`), the enrollment is **not** redone: the
script only repairs the service, so no second worker is created and no token
is consumed. To repair the service alone:

```powershell
& "C:\Program Files\Huginn\huginn-worker.exe" install-service --state-dir "C:\ProgramData\Huginn" "C:\Program Files\Huginn\huginn-worker.exe"
```

The installer never starts the service: `Start-Service HuginnWorker` does.

If the hub sits behind a private CA, the installer fetches the CA root
(trust-on-first-use) and adds it to the LocalMachine Root store. That first
fetch runs with the TLS validation **disabled**, so the certificate it
returns is not proof of the hub's identity by itself: pass
`-CaSha256 <fingerprint>` (obtained over a trusted channel) to pin the real
root — the fetched certificate must then match.

To remove the worker from a machine, fetch `uninstall.ps1` the same way and
run it as a file:

```powershell
$uninstaller = "$env:TEMP\huginn-uninstall.ps1"
Invoke-WebRequest -Uri "https://<HUGINN_DOMAIN>/uninstall.ps1" -OutFile $uninstaller
pwsh -NoProfile -ExecutionPolicy Bypass -File $uninstaller
```

It stops and deletes the `HuginnWorker` service, removes the binary and the
state (`C:\ProgramData\Huginn`), and removes the hub CA from the LocalMachine
Root store. The node stays in the fleet until it is revoked in the dashboard.

The worker self-updates toward `HUGINN_TARGET_WORKER_VERSION`. Artifacts are
served by the hub itself at `/dist` (see `deploy/build-artifacts.sh`, which
cross-compiles all three: linux/amd64, linux/arm64, windows/amd64, and writes
one manifest line per published asset).

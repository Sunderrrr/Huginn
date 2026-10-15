# deploy/ — running Huginn

Docker Compose stacks + Caddy reverse proxy + Kubernetes manifests.

| File | What |
|---|---|
| `docker-compose.yml` | dev stack — hub `:8000`, dashboard `:5173`, MCP `:9000`, no TLS |
| `docker-compose.prod.yml` | production — Caddy in front, HTTPS on 80/443, everything behind one origin |
| `Caddyfile` | reverse proxy: `/` → dashboard, `/api` + `/healthz` + `/metrics` → hub, `/mcp` → MCP, `/install.sh` + `/dist` → worker artifacts |
| `k8s/` | Kubernetes manifests (hub, mcp, dashboard, ingress) |
| `../scripts/backup-db.sh` | database backup (schedule it with cron/systemd) |

## Production, step by step

```bash
cd deploy
cp .env.prod.example .env.prod        # set HUGINN_DOMAIN + real secrets (openssl rand -hex 32)
../scripts/build-artifacts.sh v1.4.3  # static worker binaries served at /dist
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

Open `https://<HUGINN_DOMAIN>/` and sign in with the bootstrap admin
(`HUGINN_BOOTSTRAP_ADMIN_*`). First login requires enrolling a second factor
(TOTP).

### TLS certificates

`Caddyfile` serves the certificate pair mounted from `./certs/` (generate your
own CA + server cert — `deploy/certs/huginn.{crt,key}` and `huginn-ca.crt`).
To use Let's Encrypt instead, replace the `tls` directive in the Caddyfile with
`tls <your-email>` and point `HUGINN_DOMAIN` at a public domain.

### Environment

`.env.prod` drives everything (see `.env.prod.example` for the full list):
domain, database credentials, four `openssl rand -hex 32` secrets, MFA policy,
bootstrap admin, and the target worker version. The hub refuses to boot in
`HUGINN_ENV=prod` with placeholder secrets.

### Day-2 operations

```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod ps        # status
docker compose -f docker-compose.prod.yml --env-file .env.prod logs -f hub
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build   # upgrade
../scripts/backup-db.sh                                                    # DB dump
```

Enrolling a VM (token comes from the dashboard):

```bash
curl -fsSLk https://<HUGINN_DOMAIN>/install.sh | HUB_URL=https://<HUGINN_DOMAIN> TOKEN=<token> bash
```

The worker self-updates toward `HUGINN_TARGET_WORKER_VERSION`; artifacts are
served by the hub itself at `/dist` (see `../scripts/build-artifacts.sh`).

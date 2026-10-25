# Deployment

Pick the path that fits your scale:

| Mode | Best for | What you get |
|---|---|---|
| **Local** (compose) | development | the full stack on `localhost`, ports exposed |
| **Docker production** (compose + Caddy) | a single host | hardened stack behind Caddy with **automatic HTTPS** |
| **Kubernetes** | clusters / HA | manifests for hub, MCP, dashboard, migration Job, ingress |

Docker and Kubernetes are first-class alternatives — you do **not** need
Kubernetes to run Huginn in production.

> **dev vs prod is just which compose file you run.** A plain `docker compose up`
> uses the default `docker-compose.yml` (dev — direct ports, no Caddy).
> Production requires `-f docker-compose.prod.yml --env-file .env.prod`. Each
> reads its own env file in `deploy/`: dev → `.env`, prod → `.env.prod`.

## Local (docker-compose)

```bash
cp deploy/.env.example deploy/.env   # then edit secrets
cd deploy && docker compose up --build
```

Brings up PostgreSQL, the hub (`:8000`), the dashboard (`:5173`), and the MCP
server (`:9000`). The hub applies its embedded schema migrations on startup
(idempotent) and bootstraps the first admin from `HUGINN_BOOTSTRAP_ADMIN_*`.

## Docker production (single host)

Caddy terminates TLS and routes everything under one domain, so the dashboard
and API share an origin (no CORS): `/` → dashboard, `/api` + `/healthz` → hub,
`/mcp` → MCP. Only Caddy publishes ports (80/443).

```bash
cd deploy
cp .env.prod.example .env.prod        # set HUGINN_DOMAIN=example.com + real secrets
./build-artifacts.sh vX.Y.Z           # build the worker binaries the hub serves
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

`build-artifacts.sh` cross-compiles the worker into `deploy/artifacts/`, which
Caddy serves at `https://example.com/dist/`. This makes the install one-liner
**self-contained** — workers download the binary (and the hub's CA root) from the
hub itself, with no external release required. Re-run it whenever the worker
changes.

The container base images are pinned **by digest**, not by tag: a tag can be
re-pointed silently, a digest cannot. Dependabot keeps the digests current.

### Certificates

The bundled `Caddyfile` serves the certificate pair mounted from `deploy/certs/`
(`huginn.crt` and `huginn.key`), issued by your own CA. Its root is
`huginn-ca.crt`, served at `/caddy-root.crt` so a machine can bootstrap trust
before it enrolls.

The connection is encrypted either way, but a private CA means **browsers show
a one-time "not trusted" warning**: accept it, or import the CA root. The
Caddyfile sets `default_sni`, so access by bare IP (which sends no SNI) still
presents the right certificate.

For a public domain, replace the `tls` line in the Caddyfile with
`tls <your-email>` and point `HUGINN_DOMAIN` at it: Caddy then gets trusted
Let's Encrypt certificates.

### Notes

- `HUGINN_ENV=prod` makes the hub refuse to boot with placeholder/weak secrets —
  generate `HUGINN_JWT_SECRET`, `HUGINN_SECRET_HASH_KEY`,
  `HUGINN_MCP_SERVICE_TOKEN`, and `HUGINN_MFA_ENCRYPTION_KEY` with
  `openssl rand -hex 32`.
- The hub sees `X-Forwarded-Proto: https` from Caddy, satisfying
  `HUGINN_REQUIRE_TLS`.
- Workers enroll against `https://example.com`, and the dashboard is at the same URL.
- **MFA / passkeys**: set `HUGINN_WEBAUTHN_RP_ID` / `HUGINN_WEBAUTHN_ORIGIN`
  (they default to `HUGINN_DOMAIN`). Passkeys require a real domain — they do not
  work over a bare IP. TOTP works regardless. See [auth.md](auth.md).

Upgrades: re-run the same `docker compose … up -d --build` (the hub re-applies
migrations on start).

### Keeping the stack up

Some hosts stop containers on their own (a supervisor, a maintenance script).
`restart: unless-stopped` does **not** bring back a container that was stopped
explicitly, so the hub and the TLS edge can stay down for hours.

`scripts/ensure-stack.sh` is an idempotent check that starts whatever is not
running and recreates the project only if a container vanished. Run it as a
systemd timer on the host:

```bash
systemctl enable --now huginn-ensure-stack.timer   # every two minutes
```

See `deploy/README.md` for the details.

### Verify the deployment

After `up -d`, confirm the stack end-to-end (use `-k` only for the `localhost`
internal CA, dropped with a real domain):

```bash
# All five services up (postgres healthy, hub/mcp/dashboard/caddy running)
docker compose -f docker-compose.prod.yml --env-file .env.prod ps

curl -sk https://$HUGINN_DOMAIN/healthz                  # {"status":"ok"}
curl -sk -o /dev/null -w "%{http_code}\n" https://$HUGINN_DOMAIN/          # 200 (dashboard)
curl -sk -o /dev/null -w "%{http_code}\n" https://$HUGINN_DOMAIN/fleet     # 200 (SPA fallback)
curl -sk -o /dev/null -w "%{http_code}\n" https://$HUGINN_DOMAIN/api/vms   # 401 (auth required)
curl -s  -o /dev/null -w "%{http_code}\n" http://$HUGINN_DOMAIN/           # 308 (-> https)

# Log in and confirm the audit chain is intact
TOKEN=$(curl -sk -X POST https://$HUGINN_DOMAIN/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<your-admin-password>"}' | jq -r .access_token)
curl -sk https://$HUGINN_DOMAIN/api/audit/verify -H "authorization: Bearer $TOKEN"
# {"intact": true}
```

## Kubernetes

Manifests live in `deploy/k8s/` (hub, MCP, dashboard, and an example ingress).
They assume an **external PostgreSQL** (set via the `huginn-secrets` Secret) and
are designed to run on any conformant cluster.

```bash
kubectl create namespace huginn

# 1. Secrets (edit with real values first — openssl rand -hex 32).
kubectl -n huginn apply -f deploy/k8s/secret.example.yaml

# 2. Workloads.
kubectl -n huginn apply -f deploy/k8s/hub-deployment.yaml -f deploy/k8s/hub-service.yaml
kubectl -n huginn apply -f deploy/k8s/mcp-deployment.yaml
kubectl -n huginn apply -f deploy/k8s/dashboard-deployment.yaml

# 3. Ingress (edit host/issuer first).
kubectl -n huginn apply -f deploy/k8s/ingress.example.yaml
```

Notes:

- The hub image runs the Rust `huginn-hub` binary, which applies its embedded
  migrations idempotently on start. `deploy/k8s/` ships no migration Job, so
  roll the hub out before the replicas that need the new schema.
- The **dashboard** calls the API **same-origin** by default (empty
  `VITE_HUB_URL` → relative `/api`). Route `/api` (and `/mcp`) to the hub on the
  same host the dashboard is served from and no CORS is needed. Only set
  `VITE_HUB_URL` (and matching `HUGINN_CORS_ORIGINS`) if you deliberately serve
  the dashboard on a *different* origin from the hub.
- The **MCP** server reads `HUGINN_MCP_SERVICE_TOKEN` from `huginn-secrets` and
  talks to the hub over the in-cluster `huginn-hub` Service.

### Production checklist

- Terminate TLS in front of the hub (Ingress / gateway) and keep
  `HUGINN_REQUIRE_TLS=true`.
- Store all secrets in Kubernetes Secrets (never in images or env files).
- Point `HUGINN_DATABASE_URL` at a managed/HA PostgreSQL.
- Set `HUGINN_TARGET_WORKER_VERSION` to a published release tag.

## Worker releases

Tagging `vX.Y.Z` triggers `.github/workflows/release.yml`, which cross-compiles
the Rust worker (`worker-rs/`) into static musl binaries for `linux/amd64` and
`linux/arm64` (via cargo-zigbuild), injects the version, generates
`checksums.txt`, and attaches everything to the GitHub Release. The same pipeline
builds and smoke-tests the `hub-rs/` and `mcp-rs/` container images. The
installer and the self-updater consume these release assets. Locally,
`deploy/build-artifacts.sh` produces the same artifacts for the self-hosted
`/dist` route.

To roll a release out to the fleet:

1. tag and push `vX.Y.Z`. The workflow publishes the artifacts and the images;
2. copy the released binaries into `deploy/artifacts/`, so the self-hosted
   `/dist` serves the same bytes as the release;
3. set `HUGINN_TARGET_WORKER_VERSION` to that tag. The hub's `settings` row is
   the source of truth — the env var only seeds it;
4. the workers pick the new version up at their next heartbeat and update
   themselves, rolling back if the health check fails.

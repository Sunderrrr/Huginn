# Deployment

Pick the path that fits your scale:

| Mode | Best for | What you get |
|---|---|---|
| **Local** (compose) | development | the full stack on `localhost`, ports exposed |
| **Docker production** (compose + Caddy) | a single host | hardened stack behind Caddy with **automatic HTTPS** |
| **Kubernetes** | clusters / HA | manifests for hub, MCP, dashboard, migration Job, ingress |

The Docker and Kubernetes paths are first-class alternatives — you do **not** need
Kubernetes to run Huginn in production.

> **dev vs prod is just which compose file you run.** A plain `docker compose up`
> uses the default `docker-compose.yml` (dev — direct ports, no Caddy). Production
> requires `-f docker-compose.prod.yml --env-file .env.prod`. Each reads its own
> env file in `deploy/`: dev → `.env`, prod → `.env.prod`.

## Local (docker-compose)

```bash
cp deploy/.env.example deploy/.env   # then edit secrets
cd deploy && docker compose up --build
```

Brings up PostgreSQL, the hub (`:8000`), the dashboard (`:5173`), and the MCP
server (`:9000`). The hub applies Alembic migrations on startup and bootstraps the
first admin from `HUGINN_BOOTSTRAP_ADMIN_*`.

## Docker production (single host, Caddy + automatic HTTPS)

For a real deployment without Kubernetes. Caddy terminates TLS and routes
everything under one domain, so the dashboard and API share an origin (no CORS
fuss): `/` → dashboard, `/api` + `/healthz` → hub, `/mcp` → MCP. Only Caddy
publishes ports (80/443).

```bash
cd deploy
cp .env.prod.example .env.prod        # set HUGINN_DOMAIN + real secrets
./build-artifacts.sh v1.4.0           # build worker binaries the hub will serve
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

`build-artifacts.sh` cross-compiles the worker into `deploy/artifacts/`, which
Caddy serves at `https://<host>/dist/`. This makes the install one-liner
**self-contained** — workers download the binary (and the hub's CA root) from the
hub itself, with no GitHub release required. Re-run it whenever the worker changes.

Certificates are controlled by `HUGINN_TLS_INTERNAL`:

- **Public domain** — set `HUGINN_DOMAIN` to a domain that resolves to the host and
  `HUGINN_TLS_INTERNAL=you@example.com`. Caddy gets trusted Let's Encrypt certs
  automatically.
- **IP / LAN / localhost** — set `HUGINN_DOMAIN` to the IP (e.g. `192.0.2.13`) or
  `localhost` and keep `HUGINN_TLS_INTERNAL=internal`. Caddy serves a self-signed
  cert from its internal CA; the connection is encrypted, but **browsers show a
  one-time "not trusted" warning** — accept it (Advanced → Proceed) or import
  Caddy's root CA. The Caddyfile sets `default_sni` so access by bare IP (which
  sends no SNI) still presents the right cert.

Other notes:

- `HUGINN_ENV=prod` is set, so the hub refuses to boot with placeholder/weak
  secrets — generate `HUGINN_JWT_SECRET`, `HUGINN_SECRET_HASH_KEY`,
  `HUGINN_MCP_SERVICE_TOKEN`, and `HUGINN_MFA_ENCRYPTION_KEY` with
  `openssl rand -hex 32`.
- The hub sees `X-Forwarded-Proto: https` from Caddy, satisfying `HUGINN_REQUIRE_TLS`.
- Workers enroll against `https://<HUGINN_DOMAIN>`; the dashboard is at the same URL.
- The dashboard calls the API **same-origin** (relative `/api`), so it works on
  whatever host/proxy serves it — no hub URL is baked into the build and no CORS
  is needed behind Caddy.
- **MFA / passkeys**: set `HUGINN_WEBAUTHN_RP_ID`/`HUGINN_WEBAUTHN_ORIGIN` (they
  default to `HUGINN_DOMAIN`). Passkeys require a real domain — they won't work
  over a bare IP. TOTP works regardless. See [auth.md](auth.md).

Upgrades: `docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build`
(the hub re-applies migrations on start).

### Verify the deployment

After `up -d`, confirm the stack end-to-end (use `-k` only for the `localhost`
internal CA; drop it with a real domain):

```bash
# All five services up (postgres healthy; hub/mcp/dashboard/caddy running)
docker compose -f docker-compose.prod.yml --env-file .env.prod ps

curl -sk https://$HUGINN_DOMAIN/healthz                 # {"status":"ok","env":"prod"}
curl -sk -o /dev/null -w "%{http_code}\n" https://$HUGINN_DOMAIN/         # 200 (dashboard)
curl -sk -o /dev/null -w "%{http_code}\n" https://$HUGINN_DOMAIN/fleet    # 200 (SPA fallback)
curl -sk -o /dev/null -w "%{http_code}\n" https://$HUGINN_DOMAIN/api/vms  # 401 (auth required)
curl -s  -o /dev/null -w "%{http_code}\n" http://$HUGINN_DOMAIN/          # 308 (-> https)

# Log in and confirm the audit chain is intact
TOKEN=$(curl -sk -X POST https://$HUGINN_DOMAIN/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<your-admin-password>"}' | jq -r .access_token)
curl -sk https://$HUGINN_DOMAIN/api/audit/verify -H "authorization: Bearer $TOKEN"
# {"intact": true}
```

Then open `https://<your-domain>/` and sign in with the bootstrap admin
credentials.

## Kubernetes

Manifests live in `deploy/k8s/` (hub, MCP, dashboard, a migration Job, and an
example ingress). They assume an **external PostgreSQL** (set via the
`huginn-secrets` Secret) and are designed to run on vanilla clusters and Talos.

```bash
kubectl create namespace huginn

# 1. Secrets (edit with real values first — openssl rand -hex 32).
kubectl -n huginn apply -f deploy/k8s/secret.example.yaml

# 2. Migrate the database (idempotent; run on every upgrade).
kubectl -n huginn apply -f deploy/k8s/migrate-job.yaml
kubectl -n huginn wait --for=condition=complete job/huginn-migrate --timeout=120s

# 3. Workloads.
kubectl -n huginn apply -f deploy/k8s/hub-deployment.yaml -f deploy/k8s/hub-service.yaml
kubectl -n huginn apply -f deploy/k8s/mcp-deployment.yaml
kubectl -n huginn apply -f deploy/k8s/dashboard-deployment.yaml

# 4. Ingress (edit host/issuer first).
kubectl -n huginn apply -f deploy/k8s/ingress.example.yaml
```

Notes:
- The hub Deployment overrides the image entrypoint with the plain `uvicorn`
  command, so replicas do **not** run migrations — the `huginn-migrate` Job owns that.
- The **dashboard** is a static SPA that calls the API **same-origin** by default
  (empty `VITE_HUB_URL` → relative `/api`). Route `/api` (and `/mcp`) to the hub
  on the same host the dashboard is served from (ingress path rules) and no CORS
  is needed. Only set `VITE_HUB_URL` (and matching `HUGINN_CORS_ORIGINS`) if you
  deliberately serve the dashboard on a *different* origin than the hub.
- The **MCP** server reads `HUGINN_MCP_SERVICE_TOKEN` from `huginn-secrets` and
  talks to the hub over the in-cluster `huginn-hub` Service.

### Production checklist
- Terminate TLS in front of the hub (Ingress / gateway) and keep
  `HUGINN_REQUIRE_TLS=true`.
- Store all secrets in Kubernetes Secrets (never in images or env files).
- Point `HUGINN_DATABASE_URL` at a managed/HA PostgreSQL.
- Set `HUGINN_TARGET_WORKER_VERSION` to a published GitHub release tag.

## Worker releases

Tagging `vX.Y.Z` triggers `.github/workflows/release.yml`, which cross-compiles the
**Rust worker** (`worker-rs/`) into static musl binaries for `linux/amd64` and
`linux/arm64` (via cargo-zigbuild), injects the version, generates
`checksums.txt`, and attaches everything to the GitHub Release — plus the legacy
Go binaries under `-go` checksums during the transition. `install.sh` and the
self-updater consume these assets. Locally, `deploy/build-artifacts.sh` produces
the same artifacts for the self-hosted `/dist` route.

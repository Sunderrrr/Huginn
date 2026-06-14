# Deployment

Pick the path that fits your scale:

| Mode | Best for | What you get |
|---|---|---|
| **Local** (compose) | development | the full stack on `localhost`, ports exposed |
| **Docker production** (compose + Caddy) | a single host | hardened stack behind Caddy with **automatic HTTPS** |
| **Kubernetes** | clusters / HA | manifests for hub, MCP, dashboard, migration Job, ingress |

The Docker and Kubernetes paths are first-class alternatives — you do **not** need
Kubernetes to run Huginn in production.

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
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

- Point your domain's DNS at the host; Caddy obtains/renews Let's Encrypt certs
  automatically. For a local trial set `HUGINN_DOMAIN=localhost` (Caddy uses its
  internal CA).
- `HUGINN_ENV=prod` is set, so the hub refuses to boot with placeholder/weak
  secrets — generate them with `openssl rand -hex 32`.
- The hub sees `X-Forwarded-Proto: https` from Caddy, satisfying `HUGINN_REQUIRE_TLS`.
- Workers enroll against `https://<your-domain>`; the dashboard is at the same URL.

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
- The **dashboard** is a static SPA; its hub URL is baked at image build time
  (`VITE_HUB_URL`). Build it with your public hub URL (e.g. `https://huginn.example.com`),
  since the browser calls the hub directly. Set `HUGINN_CORS_ORIGINS` on the hub
  to that same origin.
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
worker for `linux/amd64` and `linux/arm64`, generates `checksums.txt`, and attaches
them to the GitHub Release. `install.sh` and the self-updater consume these assets.

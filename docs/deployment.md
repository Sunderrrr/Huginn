# Deployment

## Local (docker-compose)

```bash
cp deploy/.env.example deploy/.env   # then edit secrets
cd deploy && docker compose up --build
```

Brings up PostgreSQL, the hub (`:8000`), and the MCP server (`:9000`). The hub
applies Alembic migrations on startup and bootstraps the first admin from
`HUGINN_BOOTSTRAP_ADMIN_*`.

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

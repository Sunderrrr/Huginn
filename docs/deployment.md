# Deployment

## Local (docker-compose)

```bash
cp deploy/.env.example deploy/.env   # then edit secrets
cd deploy && docker compose up --build
```

Brings up PostgreSQL, the hub (`:8000`), and the MCP server (`:9000`). The hub
applies Alembic migrations on startup and bootstraps the first admin from
`HUGINN_BOOTSTRAP_ADMIN_*`.

## Kubernetes (hub)

Manifests live in `deploy/k8s/`. They assume an **external PostgreSQL** (set via
the `huginn-secrets` Secret) and are designed to run on vanilla clusters and
Talos.

```bash
kubectl create namespace huginn
# Edit deploy/k8s/secret.example.yaml with real values, then:
kubectl -n huginn apply -f deploy/k8s/secret.example.yaml
kubectl -n huginn apply -f deploy/k8s/hub-deployment.yaml
kubectl -n huginn apply -f deploy/k8s/hub-service.yaml
```

Run migrations as a one-off Job or rely on the init behaviour (the image entrypoint
runs `alembic upgrade head` before serving). For multiple replicas, run migrations
as a separate Job and start replicas with the plain `uvicorn` command.

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

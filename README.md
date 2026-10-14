# Huginn

> Agent-pilotable fleet management for Linux VMs — a central hub, lightweight
> Rust workers, a web dashboard, and an MCP façade so an AI agent can drive the
> fleet.

Huginn lets you manage a fleet of Linux VMs from one place: enroll machines with a
one-line installer, approve them from a dashboard, run controlled actions (or
opt-in unrestricted commands), keep workers up to date, and audit everything. An
[MCP](https://modelcontextprotocol.io) server exposes the same capabilities to an
external AI agent (e.g. "Hermes") without duplicating any business logic.

> **Status:** hub-rs (Rust) + worker-rs (Rust) + mcp-rs (Rust) + React
> dashboard, with docker-compose and Kubernetes manifests for the hub. This is a
> remote command-execution system — read [docs/security.md](docs/security.md)
> before exposing it.

## Architecture

```
                ┌─────────────┐         ┌──────────────┐
 Hermes ──MCP─▶│             │         │  Dashboard   │
                │     HUB     │◀─REST──│   (React)    │
 vDashboard ──▶│ hub-rs      │         └──────────────┘
                │ (Rust) +    │
                │ PostgreSQL  │
                │  + MCP srv  │
                └──────┬──────┘
                       │ REST (per-worker token auth, TLS)
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
     ┌───────┐     ┌───────┐     ┌───────┐
     │Worker │     │Worker │     │Worker │   ← one per Linux VM (Rust)
     │ (VM1) │     │ (VM2) │     │ (VM3) │
     └───────┘     └───────┘     └───────┘
```

- **Hub** (`hub-rs/`) — Rust (axum) + PostgreSQL. The source of truth: inventory,
  enrollment, authz, audit, the target worker version, and task routing.
- **Worker** (`worker-rs/`) — a single static Rust binary installed natively on
  each VM via systemd. It long-polls the hub for tasks (NAT-friendly), runs them
  locally, and reports results. No runtime dependencies.
- **MCP server** (`mcp-rs/`) — a thin façade over the hub's REST API exposing
  tools for an external agent. No direct worker access, no duplicated logic.
- **Dashboard** (`/dashboard`) — a React SPA (Vite + TypeScript) with a
  distinctive "raven control-console" UI: a home overview, fleet roster, per-node
  actions/updates/unrestricted shell, custom tags/groups, scheduled commands,
  enrollment + MCP tokens, user management, and the audit log with hash-chain
  verification. Served same-origin behind the reverse proxy (no baked hub URL).

By default the worker **pulls** work from the hub over a single outbound HTTPS
connection, so it works behind NAT. A push listener can be enabled per-VM when the
machine is directly routable.

## Authentication

Multiple sign-in methods, all feeding the same admin / operator / read-only RBAC:

- **Local** password (Argon2id), **LDAP/LDAPS**, and **OIDC/SSO** (tested with
  Authentik).
- **Two-factor**: TOTP authenticator apps (with single-use backup codes) and
  **WebAuthn passkeys** for phishing-resistant passwordless login. 2FA can be
  required for admins.
- **SSO-first**: when OIDC is enabled the password form is hidden by default and
  re-enabled only via an explicit "unsafe" flag — never locking you out when OIDC
  is off. See [docs/auth.md](docs/auth.md).

## Deployment

There are **two compose files** in `deploy/`, and *which one you run* is what
makes it dev or prod — there is no "mode" flag:

| Stack | Command (run from `deploy/`) | What you get |
|---|---|---|
| **Local / dev** | `docker compose up --build` | ports exposed directly — hub `:8000`, dashboard `:5173`, MCP `:9000`. **No Caddy, no TLS.** |
| **Production** | `docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build` | **Caddy** in front, **HTTPS** on 80/443, everything under one domain. |
| **Kubernetes** | `kubectl apply -f deploy/k8s/…` (see below) | hub / MCP / dashboard + migration Job + ingress. |

> ⚠️ A plain `docker compose up` (no `-f`) always uses the default
> `docker-compose.yml` → the **dev** stack (direct ports, no Caddy). For
> production you **must** pass `-f docker-compose.prod.yml --env-file .env.prod`.

Each stack reads its **own** env file in `deploy/` (gitignored — copy the
matching `*.example`): dev → `.env`, prod → `.env.prod`.

### Prerequisites

The hub, MCP, and dashboard build **inside Docker** — you do **not** need a local
toolchain for them. Only `build-artifacts.sh` (which cross-compiles the worker
binaries the hub serves) needs a Rust toolchain on the host.

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y docker.io docker-compose-v2 git openssl
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"      # then re-login, so `docker` needs no sudo

# Rust toolchain for build-artifacts.sh (worker binaries)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
pip install ziglang                  # cross-linker for musl targets
cargo install cargo-zigbuild
```

| Tool | Needed for |
|---|---|
| Docker + the `docker compose` v2 plugin | running every stack |
| `git` | cloning the repo |
| `rustup` + `cargo-zigbuild` + `ziglang` | `build-artifacts.sh` only (static worker binaries) |
| `openssl` | generating secrets (`openssl rand -hex 32`) |

> The worker is written in Rust (`worker-rs/`); `build-artifacts.sh`
> cross-compiles static musl binaries. (You can skip local builds entirely if
> you point workers at prebuilt GitHub-release binaries instead of self-hosting
> them — see [docs/deployment.md](docs/deployment.md).)

### Local / dev (Docker)

```bash
git clone https://github.com/Sunderrrr/Huginn.git
cd Huginn/deploy
cp .env.example .env          # dev template — then edit the secrets
docker compose up --build
```

Starts PostgreSQL, the hub (`:8000`), the dashboard (`:5173`), and the MCP server
(`:9000`). A first admin is bootstrapped from `HUGINN_BOOTSTRAP_ADMIN_*`; log in
to the dashboard at `http://localhost:5173`. The hub, MCP server, and worker are
the Rust implementations (`hub-rs/`, `mcp-rs/`, `worker-rs/`) — parity-gated
against the API goldens kept in `hub-rs/golden/`.

### Production (Docker + Caddy + automatic HTTPS)

```bash
cd Huginn/deploy
cp .env.prod.example .env.prod        # set HUGINN_DOMAIN + real secrets (openssl rand -hex 32)
./build-artifacts.sh v1.4.0           # build the worker binaries the hub serves at /dist
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

Only Caddy publishes ports (80/443); the dashboard, `/api`, and `/mcp` share one
origin. Open `https://<HUGINN_DOMAIN>/` and sign in (accept the one-time
self-signed-cert warning if you used an IP/LAN with `HUGINN_TLS_INTERNAL=internal`).

### Kubernetes

```bash
kubectl create namespace huginn
kubectl -n huginn apply -f deploy/k8s/secret.example.yaml    # edit real secrets first
kubectl -n huginn apply -f deploy/k8s/migrate-job.yaml       # DB migrations (run on every upgrade)
kubectl -n huginn apply -f deploy/k8s/hub-deployment.yaml -f deploy/k8s/hub-service.yaml \
  -f deploy/k8s/mcp-deployment.yaml -f deploy/k8s/dashboard-deployment.yaml
kubectl -n huginn apply -f deploy/k8s/ingress.example.yaml   # edit host/issuer first
```

Assumes an **external PostgreSQL** (set in the `huginn-secrets` Secret).

Full details, TLS options, and a production checklist:
**[docs/deployment.md](docs/deployment.md)**.

### Enroll a VM

After generating an enrollment token (dashboard → Fleet → Add VM, or the API):

```bash
curl -fsSL https://<hub>/install.sh | HUB_URL=https://<hub> TOKEN=<token> bash
# add -k if the hub uses a self-signed/internal cert (see docs/enrollment.md)
```

The hub serves `install.sh` and the worker binaries itself, so this works without
a GitHub release. The VM appears as **PENDING**; approve it before it can receive
any command. Installed workers self-update toward `HUGINN_TARGET_WORKER_VERSION`
(v1.4.0 = the Rust worker, drop-in compatible with the old wire protocol).

See [docs/](docs/) for [architecture](docs/architecture.md),
[authentication & 2FA](docs/auth.md), [enrollment](docs/enrollment.md),
[security](docs/security.md), [deployment](docs/deployment.md), and
[MCP integration](docs/mcp.md).

## Repository layout

| Path | What |
|---|---|
| `hub-rs/` | Rust hub (axum + SQLx/PostgreSQL) — API goldens for the parity gate live in `hub-rs/golden/` |
| `worker-rs/` | Rust worker daemon (static binary, systemd) |
| `mcp-rs/` | MCP server (Rust) — façade over the hub |
| `dashboard/` | React SPA (Vite + TypeScript) |
| `deploy/` | docker-compose + Kubernetes manifests |
| `scripts/` | `install.sh` one-liner installer |
| `docs/` | documentation |

## Security

Auth on every endpoint, optional 2FA (TOTP + WebAuthn passkeys) with TOTP secrets
encrypted at rest, timing-safe secret comparison, TLS enforced for hub↔worker in
prod, secrets hashed at rest, no shell construction on the worker (separated argv,
never `sh -c`), opt-in + audited unrestricted mode, rate limits and body caps on
execution, SSRF allowlist on update sources, and an append-only hash-chained audit
log. Details in [docs/security.md](docs/security.md). Report vulnerabilities per
[SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under [Apache-2.0](LICENSE).

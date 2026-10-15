# Huginn

Huginn manages a fleet of Linux machines from one place. It enrolls machines with
a one-line installer, lets you approve them from a dashboard, run controlled
actions (or opt-in unrestricted commands), keep the workers up to date, and audit
everything. An [MCP](https://modelcontextprotocol.io) server exposes the same
capabilities to an AI agent without duplicating any business logic.

It is a **remote command-execution system**. Read
[docs/security.md](docs/security.md) before you expose it.

## Components

| Component | Path | What it is |
|---|---|---|
| **Hub** | `hub-rs/` | Rust (axum + PostgreSQL). The source of truth: inventory, enrollment, auth, task routing, audit. |
| **Worker** | `worker-rs/` | One static Rust binary per machine. Pulls work from the hub over HTTPS (NAT-friendly), runs it, reports back. |
| **MCP server** | `mcp-rs/` | Thin Rust façade over the hub's REST API, exposing tools for an external AI agent. |
| **Dashboard** | `dashboard/` | React SPA (Vite + TypeScript): fleet roster, per-node actions, updates, scheduling, tokens, users, audit. |

## Architecture

```
        ┌──────────────┐       ┌──────────────┐
        │  AI agent    │       │  Dashboard   │
        │  (MCP)       │       │   (React)    │
        └──────┬───────┘       └──────┬───────┘
               │ /mcp                 │ /api
               ▼                      ▼
        ┌────────────────────────────────────┐
        │              HUB (hub-rs)          │
        │        axum + PostgreSQL           │
        │  inventory · auth · tasks · audit  │
        └───────────────────┬────────────────┘
                            │  HTTPS (per-worker token)
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   ┌─────────┐         ┌─────────┐         ┌─────────┐
   │ worker  │         │ worker  │         │ worker  │   one per machine
   └─────────┘         └─────────┘         └─────────┘
```

The worker **pulls** work from the hub over a single outbound HTTPS connection,
so it works behind NAT. Only the hub needs an inbound port.

## Quick start (Docker)

The dev and prod stacks are two different compose files — there is no mode flag.
This quick start brings up the **dev** stack (direct ports, no TLS). For a real
deployment see [docs/deployment.md](docs/deployment.md).

```bash
git clone https://github.com/<you>/huginn.git
cd huginn/deploy
cp .env.example .env
# edit .env — generate secrets with: openssl rand -hex 32
docker compose up --build
```

That starts PostgreSQL, the hub (`:8000`), the dashboard (`:5173`), and the MCP
server (`:9000`). A first admin is created from `HUGINN_BOOTSTRAP_ADMIN_*`. Sign
in at `http://localhost:5173`.

For production, set `HUGINN_DOMAIN=example.com` in `deploy/.env.prod` and run the
prod compose file (Caddy in front, automatic HTTPS on 80/443):

```bash
cd deploy
cp .env.prod.example .env.prod          # set HUGINN_DOMAIN=example.com + real secrets
./build-artifacts.sh v1.0.0             # worker binaries the hub serves at /dist
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

## Configuration

The hub and its clients read `HUGINN_*` environment variables (see
`.env.example` for the full list). The important ones:

| Variable | Purpose |
|---|---|
| `HUGINN_ENV` | `dev` or `prod`. In `prod` the hub refuses weak/placeholder secrets. |
| `HUGINN_DATABASE_URL` | PostgreSQL connection string. |
| `HUGINN_JWT_SECRET` | Signs access tokens. `openssl rand -hex 32`. |
| `HUGINN_SECRET_HASH_KEY` | Keyed-HMAC for stored secrets. `openssl rand -hex 32`. |
| `HUGINN_MCP_SERVICE_TOKEN` | Trust between the MCP server and the hub. `openssl rand -hex 32`. |
| `HUGINN_MFA_ENCRYPTION_KEY` | Encrypts TOTP secrets at rest. `openssl rand -hex 32`. |
| `HUGINN_DOMAIN` | Public name of the deployment (TLS, passkeys). Use a domain in production. |
| `HUGINN_REQUIRE_TLS` | Enforce HTTPS for hub↔worker traffic (keep `true` in prod). |
| `HUGINN_REQUIRE_ADMIN_MFA` | Force local admins to enrol a second factor. |
| `HUGINN_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | First admin account, created on start. |
| `HUGINN_TARGET_WORKER_VERSION` | Worker version the fleet converges toward. |

Full reference, TLS options, and per-service settings:
[docs/deployment.md](docs/deployment.md).

## Deployment

| Mode | Best for | Guide |
|---|---|---|
| Local compose | development | [docs/deployment.md](docs/deployment.md#local-docker-compose) |
| Docker + Caddy (HTTPS) | a single host | [docs/deployment.md](docs/deployment.md#docker-production-single-host) |
| Kubernetes | clusters | [docs/deployment.md](docs/deployment.md#kubernetes) |

Also see [docs/enrollment.md](docs/enrollment.md) for adding machines and
[docs/](docs/) for everything else.

## Security

Auth on every endpoint; optional 2FA (TOTP + WebAuthn passkeys) with TOTP seeds
encrypted at rest; TLS enforced for hub↔worker in prod; secrets hashed with
keyed HMAC and compared timing-safe; the worker executes fixed argv vectors
(never `sh -c`) except in explicit, audited, per-VM **unrestricted** mode;
rate limits and body caps on execution; an SSRF allowlist on update sources; and
an append-only, hash-chained audit log. Details in
[docs/security.md](docs/security.md). Report vulnerabilities per
[SECURITY.md](SECURITY.md).

## Development & tests

Each crate is an independent Cargo project:

```bash
cd hub-rs && cargo test --release      # hub unit tests
cd worker-rs && cargo test --release   # worker unit tests
cd mcp-rs && cargo test --release      # MCP unit tests
```

**Parity gate** — `hub-rs` must answer exactly like the reference API. Capture
and diff golden responses with `hub-rs/tools/api_parity.py`:

```bash
cd hub-rs
python3 tools/api_parity.py capture --base http://127.0.0.1:8000 \
  --admin-user admin --admin-pass <pass> --out /tmp/golden-rust
python3 tools/api_parity.py diff golden/python /tmp/golden-rust
```

**CI** (`.github/workflows/ci-rust.yml`) runs per crate: `cargo fmt --check`,
`cargo clippy -- -D warnings`, `cargo test --release`, and a dependency audit.
`hub-rs` additionally runs the parity gate against its goldens. All must be green
before merge. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under [Apache-2.0](LICENSE).

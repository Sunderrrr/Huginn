# Huginn

Huginn manages a fleet of Linux VMs from one dashboard. Install a worker on a
machine with one command, approve it, then run approved actions or free shell
commands on it. An MCP server exposes the same operations to AI agents, so an
agent can drive the fleet through the same API and audit log as a human operator.

The stack is four pieces: a hub that owns the database and the API, one worker
per VM that pulls work over outbound HTTPS, a web dashboard, and the MCP server.
Every action is recorded in a tamper-evident audit log, and every user-facing
endpoint enforces one of three roles (admin, operator, readonly).

## Quick start

You need Docker with the Compose plugin. The hub, MCP server and dashboard build
inside containers; the worker binaries are static and cross-compiled locally
(see `deploy/README.md` for the toolchain).

```bash
git clone https://github.com/Sunderrrr/Huginn
cd Huginn/deploy
cp .env.prod.example .env.prod
# Edit .env.prod: set HUGINN_DOMAIN and generate each secret with:
#   openssl rand -hex 32
../scripts/build-artifacts.sh v1.4.3     # worker binaries served at /dist
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

Open `https://<HUGINN_DOMAIN>/` and sign in with the bootstrap admin from your
env file. The first login requires enrolling a second factor (TOTP). The hub
refuses to start in production with placeholder secrets.

Enroll a VM from the dashboard (Fleet → Add VM) to get a one-time token, then
run on the machine:

```bash
curl -fsSLk https://<HUGINN_DOMAIN>/install.sh | HUB_URL=https://<HUGINN_DOMAIN> TOKEN=<token> bash
```

The installer downloads the worker binary from the hub itself, verifies its
SHA-256, installs a systemd unit and registers the machine. The VM appears as
PENDING and cannot receive tasks until you approve it. If the hub serves a
certificate the machine does not trust, the installer fetches the hub's CA and
installs it (trust on first use).

## Components

| Path | What it does |
|---|---|
| `hub-rs/` | HTTP API, authentication, task routing, audit log. Rust (axum, sqlx). Runs the database migrations at startup. |
| `worker-rs/` | Per-VM agent. Static Rust binary, systemd service, long-polls the hub, executes tasks, self-updates. |
| `mcp-rs/` | MCP server exposing fleet tools to AI agents. Per-user bearer tokens, each action attributed to that user. |
| `dashboard/` | React SPA served behind the reverse proxy. |
| `deploy/` | Compose files, Caddyfile, Kubernetes manifests. |
| `scripts/` | Worker installer, artifact build, database backup. |

## How work flows

The worker never listens for incoming connections. It long-polls
`GET /api/worker/tasks/next` and the hub hands out one queued task at a time,
transactionally (two workers racing for one task get one claim each). Results
post back to the hub, which wakes anyone waiting on that task and notifies the
dashboard. Workers behind NAT work without port forwarding.

Task types and their execution rules:

| Type | Who can run it | How it executes |
|---|---|---|
| `action` | any VM in whitelist mode | fixed argv from a built-in table (`status`, `metrics`, `restart_service{service}`, `list_upgradable_packages`, `apt_upgrade`) or an admin-defined custom command |
| `command` | only VMs an admin switched to `unrestricted` | free shell, audited, size-capped |
| `update` | hub-triggered | downloads a release, checks SHA-256, swaps the binary, rolls back if the health check fails |
| `uninstall` | hub-triggered | removes the service and state before a VM is revoked |

The worker never builds a shell string from parameters: whitelisted arguments
are passed as separate argv elements, and custom commands are lists of argv
vectors run without a shell.

## Authentication

Passwords (Argon2id), TOTP with backup codes, WebAuthn passkeys, OIDC/SSO, and
LDAP are supported and can all be enabled at once. Each identity maps to one of
three roles. 2FA can be required for admins. See [docs/auth.md](docs/auth.md).

Audit entries are chained: each row's hash covers the previous row, so removing
or editing an entry breaks verification (`GET /api/audit/verify` recomputes the
chain).

## Configuration

`deploy/.env.prod.example` lists every variable. The ones that matter most:

| Variable | Effect |
|---|---|
| `HUGINN_DOMAIN` | host the reverse proxy serves |
| `HUGINN_DATABASE_URL` | PostgreSQL connection string |
| `HUGINN_JWT_SECRET`, `HUGINN_SECRET_HASH_KEY`, `HUGINN_MCP_SERVICE_TOKEN`, `HUGINN_MFA_ENCRYPTION_KEY` | auth and encryption keys; the hub refuses short or placeholder values in production |
| `HUGINN_REQUIRE_ADMIN_MFA` | force admins to enrol a second factor |
| `HUGINN_TARGET_WORKER_VERSION` | version workers converge to |

## Development

```bash
cd hub-rs && cargo test --release          # 314 tests, incl. the parity suite
cargo clippy --all-targets -- -D warnings  # zero warnings policy
```

The API is under contract test: `huginn-parity` captures golden HTTP responses
and diffs them against `hub-rs/golden/python`, responses recorded from the
previous (Python) implementation. A clean diff is required before a release, and
CI runs it on every pull request. The security primitives carry test vectors
generated from the previous implementation, so password hashes, tokens and
audit chains stay byte-compatible across the rewrite.

## Limits

- The event bus is in-process: one hub instance wakes its own long-polls. If you
  run several hub replicas, task pickup still works but a queued task may wait
  up to the long-poll timeout (25 s) on another replica. A shared broker or
  PostgreSQL `LISTEN/NOTIFY` would fix this; neither is implemented.
- WebAuthn requires a real domain: passkeys do not register over a bare IP.
- Error `422` bodies are a single `{"detail": "..."}` string, not the field
  array FastAPI produced.
- The parity suite covers the endpoints the reference implementation exposed;
  behavior added afterwards is covered by unit tests only.

## Links

- [Deployment guide](docs/deployment.md) · [Architecture](docs/architecture.md) · [Enrollment](docs/enrollment.md)
- [Security notes](docs/security.md) · [MCP integration](docs/mcp.md) · [Contributing](CONTRIBUTING.md)

[Apache-2.0 license](LICENSE).

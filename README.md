# Huginn

Huginn manages a fleet of machines from one dashboard — Linux and Windows
workers, with browser automation on Linux only. Install a worker on a machine
with one command, approve it, then run approved actions or free shell commands
on it. An MCP server exposes the same operations to AI agents, so an agent can
drive the fleet through the same API and audit log as a human operator.

The running stack is four pieces: a hub that owns the database and the API, one
worker per VM that pulls work over outbound HTTPS, a web dashboard, and the MCP
server.
Every action is recorded in a tamper-evident audit log, and every user-facing
endpoint enforces one of three roles (admin, operator, readonly).

## Quick start

You need Docker with the Compose plugin. The hub, MCP server and dashboard build
inside containers; the worker binaries are static and cross-compiled locally
(the toolchain is listed at the top of `deploy/build-artifacts.sh`).

```bash
git clone https://github.com/Sunderrrr/Huginn
cd Huginn/deploy
cp .env.prod.example .env.prod
# Edit .env.prod: set HUGINN_DOMAIN and generate each secret with:
#   openssl rand -hex 32
./build-artifacts.sh vX.Y.Z             # worker binaries served at /dist
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

## Repository layout

| Path | What it does |
|---|---|
| `hub-rs/` | HTTP API, authentication, task routing, audit log. Rust (axum, sqlx). Runs the database migrations at startup. |
| `worker-rs/` | Per-VM agent. Static Rust binary, systemd service, long-polls the hub, executes tasks, self-updates. Drives the Obscura headless browser for browser tasks. |
| `mcp-rs/` | MCP server exposing fleet tools to AI agents. Per-user bearer tokens, each action attributed to that user. |
| `dashboard/` | React SPA served behind the reverse proxy. |
| `deploy/` | Compose files, Caddyfile, Kubernetes manifests. |
| `scripts/` | Worker installer, artifact build, database backup. |

## How work flows

The worker never listens for incoming connections. It long-polls
`GET /api/worker/tasks/next` and the hub hands out one queued task at a time,
transactionally: two workers racing for the same task produce a single claim,
and the loser finds nothing and parks again. Results post back to the hub,
which wakes anyone waiting on that task and notifies the dashboard. Workers
behind NAT work without port forwarding.

Task types and their execution rules:

| Type | Who can run it | How it executes |
|---|---|---|
| `action` | any VM in whitelist mode | fixed argv from a built-in table (`status`, `metrics`, `restart_service{service}`, `list_upgradable_packages`, `apt_upgrade`) or an admin-defined custom command |
| `command` | only VMs an admin switched to `unrestricted` | free shell, audited, size-capped |
| `update` | hub-triggered | downloads a release, checks SHA-256, swaps the binary, rolls back if the health check fails |
| `browser` | VMs with the browser capability enabled | headless browser steps (navigate, click, type, screenshot, PDF…) driven by the Obscura engine |
| `browser_install` | admin-triggered | downloads the pinned Obscura release on the worker, verifies its SHA-256, installs it |
| `uninstall` | hub-triggered | removes the service and state before a VM is revoked |

The worker never builds a shell string from parameters: whitelisted arguments
are passed as separate argv elements, and custom commands are lists of argv
vectors run without a shell.

## Browser automation

Linux workers can drive a headless browser. Two things must be true on a node:

1. the **capability** is enabled for it by an admin
   (`PUT /api/vms/{id}/browser-enabled`, or the dashboard toggle);
2. the **Obscura engine** is installed on the worker — a ~70 MB download the
   hub pins by version *and* SHA-256, verified on the worker before anything is
   unpacked.

A node reports its engine version in every heartbeat, so the dashboard shows a
green dot with the version when it is installed and a red dot when it is not —
you never have to guess whether a run will work. The 17 step actions
(`navigate`, `click`, `type`, `press_key`, `hover`, `scroll`, `eval`,
`set_viewport`, `screenshot`, `pdf`, `get_text`, `get_html`, `title`,
`wait_for`, `wait_for_text`, `get_cookies`, `set_cookies`) are validated by the
hub before the task is queued. See [docs/browser.md](docs/browser.md).

## Authentication

Passwords (Argon2id), TOTP with backup codes, WebAuthn passkeys, OIDC/SSO, and
LDAP are supported and can all be enabled at once. Each identity maps to one of
three roles. 2FA can be required for admins. Sessions are revocable: the
access token carries a per-user session counter, so a logout, a password
change or an MFA reset invalidates the tokens issued before it, immediately.
See [docs/auth.md](docs/auth.md).

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
cd hub-rs && cargo test --release          # 419 tests (417 + the parity binary's 2)
cargo clippy --all-targets -- -D warnings  # zero warnings policy
```

The API is under contract test: `huginn-parity` captures golden HTTP responses
and diffs them against `hub-rs/golden/python`, responses recorded from the
previous (Python) implementation. A clean diff is required before a release, and
CI runs it on every pull request. The security primitives carry test vectors
generated from the previous implementation, so password hashes, tokens and
audit chains stay byte-compatible across the rewrite.

`main` is protected: a pull request is required, the CI checks are required
status checks (a merge is blocked while one is red), force-pushes and branch
deletions are refused. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Limits

- The event bus is in-process: one hub instance wakes its own long-polls. If you
  run several hub replicas, task pickup still works but a queued task may wait
  up to the long-poll timeout (25 s) on another replica. A shared broker or
  PostgreSQL `LISTEN/NOTIFY` would fix this; neither is implemented.
- WebAuthn requires a real domain: passkeys do not register over a bare IP.
- Browser automation is **Linux only**, and the engine needs glibc ≥ 2.35
  (Ubuntu 22.04+, Debian 12+, RHEL 9+, Fedora 36+) — not Alpine/musl.
- Error `422` bodies are a single `{"detail": "..."}` string, not the field
  array FastAPI produced.
- The parity suite covers the endpoints the reference implementation exposed;
  behavior added afterwards is covered by unit tests only.

## Links

- [Deployment guide](docs/deployment.md) · [Architecture](docs/architecture.md) · [Enrollment](docs/enrollment.md)
- [Browser automation](docs/browser.md) · [Security notes](docs/security.md) · [MCP integration](docs/mcp.md) · [Contributing](CONTRIBUTING.md)

[Apache-2.0 license](LICENSE).

# Contributing to Huginn

Huginn is a remote command-execution system, so we hold contributions to a high
bar for security and for test coverage, and we expect the code to stay clear.

## Ground rules

- **Open an issue first** for anything non-trivial so we can agree on the
  approach.
- **Tests are required.** New behaviour ships with tests; bug fixes ship with a
  regression test.
- **Security first.** Never weaken the guarantees in
  [docs/security.md](docs/security.md): auth on every endpoint, timing-safe
  comparisons, no shell construction on the worker, audited unrestricted mode,
  SSRF allowlist on updates.
- **Conventional, readable commits.** Follow
  [Semantic Versioning](https://semver.org) and update [CHANGELOG.md](CHANGELOG.md)
  under `Unreleased`.

## Repository layout

Everything is Rust + a React dashboard. Each crate is an independent Cargo
project with its own `Cargo.lock`:

| Path | What |
|---|---|
| `hub-rs/` | Rust hub (axum + SQLx/PostgreSQL) — API goldens for the parity gate live in `hub-rs/golden/` |
| `worker-rs/` | Rust worker daemon (static binary, systemd) |
| `mcp-rs/` | Rust MCP server (façade over the hub) |
| `dashboard/` | React SPA (Vite + TypeScript) |
| `deploy/` | docker-compose + Kubernetes manifests |
| `scripts/` | `install.sh` one-liner installer and helpers |
| `docs/` | documentation |

Per-crate notes live in `hub-rs/README.md`, `worker-rs/README.md`, and
`mcp-rs/README.md`.

## Development

```bash
# Hub
cd hub-rs && cargo test --release

# Worker
cd worker-rs && cargo test --release

# MCP server
cd mcp-rs && cargo test --release

# Full stack (containers)
cd deploy && docker compose up --build
```

## Quality gates

Every PR must be green on these, enforced in CI:

- `cargo fmt --check` — formatting is not optional.
- `cargo clippy --release --all-targets -- -D warnings` — **warnings are
  errors** (the test code is linted too).
- `cargo test --release` — all tests pass.
- Dependency audit (`rustsec/audit-check`) — no known vulnerabilities (see
  `audit.toml` for documented exceptions).
- **Live-database suites** (`hub-rs`): the suites that need a real PostgreSQL
  (RBAC, enrollment, session revocation, browser endpoints, audit chain) run
  in CI against a service database — not only locally.
- **Browser end-to-end** (`worker-rs`): the E2E test downloads the real
  Obscura release, installs it, drives every step action against a local
  fixture and checks the teardown. It needs network access to the release
  CDN.
- **Security gate** (`.github/workflows/security.yml`): gitleaks (full
  history), dependency review on PRs, npm/cargo audits, and Trivy image +
  IaC scans.
- **Dashboard**: lint, vitest, type-check and build.

### Parity gate (hub-rs)

`hub-rs` must answer exactly like the reference API. If you touch an endpoint,
regenerate the goldens and reconcile the diff:

```bash
cd hub-rs
python3 tools/api_parity.py capture --base http://127.0.0.1:8000 \
  --admin-user admin --admin-pass <pass> --out /tmp/golden-rust
python3 tools/api_parity.py diff golden/python /tmp/golden-rust
```

A diff must be intentional and explained in the PR. See `hub-rs/PARITY_HUB.md`.

## Adding things

### An API endpoint (hub-rs)

1. Add/extend a module under `hub-rs/src/routes/` in the right group (`worker`,
   `authapi`, `fleet`, `admin`, `metrics`).
2. Wire it into that group's `router()`.
3. Keep the **auth extractor** on it — no unauthenticated paths.
4. Put any new row types in `hub-rs/src/models/`, add a migration under
   `hub-rs/migrations/` if the schema changes.
5. Add tests, and update the parity goldens if the endpoint is part of the
   reference surface.

### A database migration (hub-rs)

1. Add a **new** numbered file under `hub-rs/migrations/` — never edit one that
   has already been applied. sqlx stores a checksum of every applied migration
   and **refuses to start** the hub when a file changed afterwards
   (`migration N was previously applied but has been modified`). A comment-only
   edit is still a checksum change.
2. Keep the SQL idempotent where it can be (`IF NOT EXISTS`), so a repaired
   environment can re-apply it.

### A worker action (worker-rs)

1. Add the action to `worker-rs/src/whitelist.rs` as a **fixed argv vector** —
   never `sh -c`, never string concatenation.
2. Validate any parameters against a conservative pattern (both hub- and
   worker-side).
3. If it needs free-form shell, that is the explicit, audited **unrestricted**
   mode — do not widen the whitelist to reach it.
4. Add tests covering the argv and parameter validation.

## Pull requests

- Keep PRs focused: one change per PR.
- Describe **what** changed and **why**; link the issue.
- Call out any security-relevant or parity-relevant change explicitly.
- Update docs (and `CHANGELOG.md`) alongside the code.
- Green CI + a reviewed parity diff before merge.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. See
[SECURITY.md](SECURITY.md).

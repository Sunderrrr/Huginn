# hub-rs

The Huginn **hub** — the Rust API server and the single source of truth for the
fleet. Built on axum + SQLx with PostgreSQL.

**Role:** hold inventory and enrollment, authenticate users and workers, route
tasks to workers, and record an append-only audit trail. Everything else (worker,
MCP server, dashboard) talks to this API.

## Build & test

```bash
cd hub-rs
cargo build --release          # binary: target/release/huginn-hub
cargo test --release           # unit tests (inline #[cfg(test)] modules)
cargo fmt --check && cargo clippy --release -- -D warnings
```

It is an independent Cargo project (its own `Cargo.lock`). The Docker image is
built from `hub-rs/Dockerfile`; the binary applies embedded migrations on startup.

### Parity gate

`hub-rs` must answer exactly like the reference API. Golden responses live in
`golden/python/`; the harness is `tools/api_parity.py`:

```bash
python3 tools/api_parity.py capture --base http://127.0.0.1:8000 \
  --admin-user admin --admin-pass <pass> --out /tmp/golden-rust
python3 tools/api_parity.py diff golden/python /tmp/golden-rust
```

CI runs this gate on every PR touching `hub-rs/`. See `PARITY_HUB.md` and
`API_SURFACE.json` for the full surface.

## Module structure

```
- `bin/huginn-parity.rs`
- `config.rs`
- `db.rs`
- `error.rs`
- `main.rs`
- `models/audit.rs`
- `models/custom_action.rs`
- `models/enrollment.rs`
- `models/enums.rs`
- `models/mcp_token.rs`
- `models/mod.rs`
- `models/scheduled_command.rs`
- `models/setting.rs`
- `models/tag.rs`
- `models/task.rs`
- `models/user.rs`
- `models/vm.rs`
- `models/webauthn.rs`
- `routes/admin/custom_actions/mod.rs`
- `routes/admin/custom_actions/shlex.rs`
- `routes/admin/enrollment.rs`
- `routes/admin/mcp_tokens.rs`
- `routes/admin/mod.rs`
- `routes/admin/schedules/cron.rs`
- `routes/admin/schedules/mod.rs`
- `routes/admin/schemas.rs`
- `routes/admin/settings/mod.rs`
- `routes/admin/settings/schemas.rs`
- `routes/admin/store.rs`
- `routes/admin/tags.rs`
- `routes/admin/testing.rs`
- `routes/authapi/auth/mod.rs`
- `routes/authapi/auth/oidc.rs`
- `routes/authapi/auth/schemas.rs`
- `routes/authapi/mfa/backup_codes.rs`
- `routes/authapi/mfa/live_tests.rs`
- `routes/authapi/mfa/mod.rs`
- `routes/authapi/mfa/totp.rs`
- `routes/authapi/mfa/webauthn.rs`
- `routes/authapi/middleware.rs`
- `routes/authapi/mod.rs`
- `routes/authapi/principal.rs`
- `routes/authapi/schemas.rs`
- `routes/authapi/service.rs`
- `routes/authapi/users.rs`
- `routes/fleet/audit.rs`
- `routes/fleet/events.rs`
- `routes/fleet/execution.rs`
- `routes/fleet/mod.rs`
- `routes/fleet/principal.rs`
- `routes/fleet/tasks/actions.rs`
- `routes/fleet/tasks/create.rs`
- `routes/fleet/tasks/mod.rs`
- `routes/fleet/tasks/release_urls.rs`
- `routes/fleet/vms.rs`
- `routes/metrics.rs`
- `routes/mod.rs`
- `routes/worker/enroll.rs`
- `routes/worker/heartbeat.rs`
- `routes/worker/longpoll.rs`
- `routes/worker/mod.rs`
- `routes/worker/results.rs`
- `security/audit.rs`
- `security/fernet.rs`
- `security/jwt.rs`
- `security/mod.rs`
- `security/password.rs`
- `security/secret.rs`
- `security/totp.rs`
- `services/ldap.rs`
- `services/metrics.rs`
- `services/mod.rs`
- `services/notifications/discord.rs`
- `services/notifications/mod.rs`
- `services/notifications/webhook.rs`
- `services/oidc/mod.rs`
- `services/oidc/verify.rs`
- `services/task_events.rs`
- `services/versioning.rs`
- `services/webauthn/assertion.rs`
- `services/webauthn/attestation.rs`
- `services/webauthn/helpers.rs`
- `services/webauthn/mod.rs`
- `services/webauthn/options.rs`
- `services/webauthn/test_support.rs`
```

## API entry points

The router is assembled in `main.rs` and merges five groups (see
`routes/mod.rs`):

| Group | Router | Handles |
|---|---|---|
| Worker | `routes/worker.rs` | `/api/worker/*` — enroll, heartbeat, poll task, submit result |
| Auth | `routes/authapi/` | `/api/auth/*`, `/api/users/*` — login, MFA/passkeys, user CRUD |
| Fleet | `routes/fleet/` | `/api/vms`, `/api/tasks`, execution, `/api/audit`, SSE events |
| Admin | `routes/admin/` | enrollment tokens, MCP tokens, custom actions, schedules, settings, tags |
| Metrics | `routes/metrics.rs` | Prometheus scrape endpoint |

To add an endpoint: create/extend a module under `routes/`, wire it in that
group's `router()`, keep the auth extractor on it, and add any new row types
under `models/`. See [CONTRIBUTING.md](../CONTRIBUTING.md).

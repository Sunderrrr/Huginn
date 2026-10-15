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
hub-rs/
├── migrations/               # embedded SQL schema (idempotent, applied on start)
├── tools/api_parity.py       # parity-gate capture/diff harness
├── golden/{python,rust}/     # golden API responses for the parity gate
├── API_SURFACE.json          # machine-readable list of endpoints
└── src/
    ├── main.rs               # app assembly: builds the router and serves
    ├── config.rs             # env config + prod fail-closed validation
    ├── db.rs                 # SQLx pool + migrations
    ├── error.rs              # API error type -> HTTP responses
    ├── models/               # DB row types & domain structs
    │   ├── vm.rs, user.rs, task.rs, enrollment.rs
    │   ├── audit.rs, mcp_token.rs, custom_action.rs
    │   ├── scheduled_command.rs, setting.rs, tag.rs
    │   ├── webauthn.rs, enums.rs
    ├── routes/               # HTTP layer (axum routers)
    │   ├── worker.rs         #   worker API: enroll / heartbeat / poll / result
    │   ├── metrics.rs        #   Prometheus metrics
    │   ├── authapi/          #   auth.rs, mfa.rs, users.rs
    │   ├── fleet/            #   vms, tasks, execution, audit, events (SSE)
    │   └── admin/            #   enrollment, mcp_tokens, custom_actions,
    │                         #   schedules, settings, tags
    ├── security/             # crypto primitives
    │   ├── jwt.rs, password.rs, secret.rs
    │   ├── fernet.rs, totp.rs, audit.rs
    └── services/             # business logic behind the routes
        ├── oidc.rs, ldap.rs, webauthn.rs
        ├── metrics.rs, notifications.rs
        ├── task_events.rs, versioning.rs
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

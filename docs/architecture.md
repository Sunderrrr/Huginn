# Architecture

Huginn is a hub-and-spoke system for managing a fleet of Linux machines.

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
   │ worker  │         │ worker  │         │ worker  │
   └─────────┘         └─────────┘         └─────────┘
```

## Components

### Hub (`hub-rs/`)

Rust (axum + SQLx) backed by PostgreSQL. Schema is managed by embedded SQL
migrations (`hub-rs/migrations/`), applied idempotently on startup. It is the
single source of truth:

- **Inventory & lifecycle** — machines, their state
  (PENDING / ACTIVE / OFFLINE / REVOKED), and exec mode.
- **Enrollment** — limited-use, revocable tokens; manual approval by default.
- **AuthN/Z** — local (Argon2id), LDAP, and OIDC/SSO users with admin / operator
  / read-only RBAC; optional 2FA (TOTP + WebAuthn); per-worker secrets.
- **Task queue** — a DB-backed queue routes actions, commands, and updates to
  workers.
- **Audit** — append-only, hash-chained log of every sensitive operation.
- **Versioning** — the target worker version and the SSRF allowlist for releases.

A background sweeper re-queues or dead-letters stuck tasks and flags offline
machines.

### Worker (`worker-rs/`)

A single static Rust binary, installed natively via systemd. It **pulls** work
from the hub over one outbound HTTPS connection (NAT-friendly), executes it
locally, and reports results. An optional push listener can be enabled where a
machine is directly routable.

### MCP server (`mcp-rs/`)

A thin Rust MCP façade over the hub's REST API, exposing tools for an external AI
agent. It holds no business logic and never contacts workers directly.

### Dashboard (`dashboard/`)

React SPA (Vite + TypeScript). It calls the hub **same-origin** (relative
`/api`), so it works behind any reverse proxy without a baked-in hub URL or CORS.

## Communication model

The worker is the connection initiator:

1. **Heartbeat** (`POST /api/worker/heartbeat`) — liveness and installed version;
   the hub replies with the desired target version and the machine's exec mode.
2. **Poll** (`GET /api/worker/tasks/next`) — claims the oldest pending task
   (row-locked in PostgreSQL); returns `null` when idle.
3. **Result** (`POST /api/worker/tasks/{id}/result`) — submits the outcome
   (size-capped, idempotent).

Because workers dial out, only the hub needs an inbound port.

## Task lifecycle

```
pending ──poll──▶ dispatched ──result──▶ succeeded | failed | timeout
   ▲                  │
   └── sweeper ◀──────┘  (requeue, then dead_letter after the retry budget)
```

## Data model

See `hub-rs/src/models/`. Key tables: `users` (with TOTP columns),
`enrollment_tokens`, `vms`, `tasks`, `audit_log` (append-only, hash-chained), a
single-row `settings`, `user_vm_access`, `tags` + `vm_tags`,
`scheduled_commands`, `mfa_backup_codes`, and `webauthn_credentials` /
`webauthn_challenges`.

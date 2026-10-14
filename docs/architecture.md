# Architecture

Huginn is a hub-and-spoke system for managing a fleet of Linux VMs.

```
                ┌─────────────┐         ┌──────────────┐
   Hermes ──MCP─▶│             │         │  Dashboard   │
                │     HUB     │◀──REST──│   (React)    │
   Dashboard ──▶│ hub-rs      │         └──────────────┘
                │ (Rust) +    │
                │ PostgreSQL  │
                │  + MCP srv  │
                └──────┬──────┘
                       │ REST (per-worker token auth, TLS)
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
     ┌───────┐     ┌───────┐     ┌───────┐
     │Worker │     │Worker │     │Worker │
     └───────┘     └───────┘     └───────┘
```

## Components

### Hub (`hub-rs/`)
Rust (axum + SQLx) with PostgreSQL. The schema is managed by embedded SQL
migrations (`hub-rs/migrations/`) that reproduce the baseline Alembic schema, so
databases migrated by either implementation are interchangeable. The single
source of truth:
- **Inventory & lifecycle** — VMs, their state (PENDING/ACTIVE/OFFLINE/REVOKED), and exec mode.
- **Enrollment** — limited-use, revocable tokens; manual approval.
- **AuthN/Z** — local (Argon2id), LDAP, and OIDC/SSO users with admin/operator/
  read-only RBAC; optional 2FA (TOTP + WebAuthn passkeys); per-worker secrets.
- **Task queue** — a DB-backed queue routes actions, commands, and updates to workers.
- **Audit** — append-only, hash-chained log of every sensitive operation.
- **Versioning** — the target worker version and the SSRF allowlist for releases.

A background sweeper re-queues/dead-letters stuck tasks and flags offline VMs.

### Worker (`worker-rs/`)
A single static Rust binary, installed natively via systemd. It **pulls** work
from the hub over one outbound HTTPS connection (NAT-friendly), executes it
locally, and reports results. An optional push listener can be enabled where a VM
is routable.

### MCP server (`mcp-rs/`)
A thin Rust MCP façade over the hub's REST API, exposing tools for an external AI
agent. It holds no business logic and never contacts workers directly.

### Dashboard (`/dashboard`)
React SPA (Vite + TypeScript). Calls the hub **same-origin** (relative `/api`),
so it works behind any reverse proxy without a baked-in hub URL or CORS.

## Communication model

The worker is the connection initiator:

1. **Heartbeat** (`POST /api/worker/heartbeat`) — liveness + installed version; the
   hub replies with the desired target version and the VM's exec mode.
2. **Poll** (`GET /api/worker/tasks/next`) — claims the oldest pending task
   (row-locked on PostgreSQL); returns `null` when idle.
3. **Result** (`POST /api/worker/tasks/{id}/result`) — submits the outcome
   (size-capped, idempotent).

This keeps workers usable behind NAT and means only the hub needs an inbound port.

## Task lifecycle

```
pending ──poll──▶ dispatched ──result──▶ succeeded | failed | timeout
   ▲                  │
   └── sweeper ◀───────┘ (requeue, then dead_letter after the retry budget)
```

## Data model

See `hub-rs/src/models/`. Key tables: `users` (with TOTP columns),
`enrollment_tokens`, `vms`, `tasks`, `audit_log` (append-only, hash-chained), a
single-row `settings`, `user_vm_access`, `tags` + `vm_tags`,
`scheduled_commands`, `mfa_backup_codes`, and `webauthn_credentials` /
`webauthn_challenges`.

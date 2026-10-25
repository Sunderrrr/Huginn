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
  (PENDING / ACTIVE / OFFLINE / REVOKED), exec mode, and the browser
  capability gate.
- **Enrollment** — limited-use, revocable tokens. Approval is manual by default.
- **AuthN/Z** — local (Argon2id), LDAP, and OIDC/SSO users with admin / operator
  / read-only RBAC. Optional 2FA (TOTP + WebAuthn) is supported, and each worker
  gets its own secret. Sessions are revocable server-side (a per-user epoch
  travels in the token).
- **Task queue** — a DB-backed queue routes work to workers. It delivers the
  actions and commands they run, plus the updates they install.
- **Browser automation** — the per-VM capability gate, the pinned Obscura
  release (version + per-arch SHA-256) and the daily update check.
- **Audit** — append-only, hash-chained log of every sensitive operation.
- **Versioning** — the target worker version and the SSRF allowlist for releases.

A background sweeper re-queues or dead-letters stuck tasks and flags offline
machines.

### Worker (`worker-rs/`)

A single static Rust binary, installed natively via systemd. It **pulls** work
from the hub over one outbound HTTPS connection (NAT-friendly), executes it
locally, and reports results. It never listens for inbound traffic.

It also drives the **Obscura** headless browser for browser tasks: it spawns
the engine locally, speaks CDP to it, and reports each step's output. The
engine is installed on demand under `/opt/huginn/obscura/<version>/` — never
embedded in the worker binary.

### MCP server (`mcp-rs/`)

A thin Rust MCP façade over the hub's REST API, exposing tools for an external AI
agent. It holds no business logic and never contacts workers directly.

### Dashboard (`dashboard/`)

React SPA (Vite + TypeScript). It calls the hub **same-origin** (relative
`/api`), so it works behind any reverse proxy without a baked-in hub URL or CORS.

## Communication model

The worker is the connection initiator:

1. **Heartbeat** (`POST /api/worker/heartbeat`) — liveness, installed worker
   version, the node's own address, and the version of the Obscura engine it
   has installed. The hub replies with the desired target version and the
   machine's exec mode.
2. **Poll** (`GET /api/worker/tasks/next`) — claims the oldest pending task
   (row-locked in PostgreSQL) and returns `null` when idle.
3. **Result** (`POST /api/worker/tasks/{id}/result`) — submits the outcome
   (size-capped, idempotent).

Because workers dial out, only the hub needs an inbound port.

## Task lifecycle

```
pending ──poll──▶ dispatched ──result──▶ succeeded | failed | timeout
   ▲                  │
   └── sweeper ◀──────┘  (requeue, then dead_letter after the retry budget)
```

## Browser automation

```
dashboard / MCP agent
        │  POST /api/vms/{id}/browser  {steps}
        ▼
     HUB  ── validates the steps (action, fields, caps) ──▶ queues a `browser` task
        │
        ▼  (the worker long-polls it)
     WORKER ── spawns `obscura serve` on an ephemeral port
        │     speaks CDP (a minimal client, no browser SDK)
        ▼
     OBSCURA ── the page runs ──▶ screenshots / PDF / text back to the hub
```

Each step's output is one line (`step 3 (click): #button`), captures ride as
`data:` URLs in the task stdout. The engine is per-task: it is started, used
and killed with the task, so nothing is left listening on the node.

## Data model

See `hub-rs/src/models/`. Key tables:

| Table | Holds |
|---|---|
| `users` | credentials, TOTP columns, `session_epoch` (the revocation counter) |
| `enrollment_tokens` | limited-use join tokens |
| `vms` | inventory, exec mode, `browser_enabled`, and the engine version the worker reported |
| `tasks` | the queue: one row per unit of work |
| `audit_log` | append-only, hash-chained |
| `settings` | a single row: target worker version, pinned Obscura release, MFA and OIDC policy |
| `user_vm_access`, `tags`, `vm_tags` | who sees which VM, and the labels used to scope custom commands |
| `scheduled_commands`, `mfa_backup_codes` | schedules, and the hashed single-use 2FA backup codes |
| `webauthn_credentials`, `webauthn_challenges` | passkeys and their short-lived challenges |


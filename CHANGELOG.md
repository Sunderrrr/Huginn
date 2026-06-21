# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Custom commands (admin-defined)**: admins can define commands in the
  dashboard (Commands page) that VMs run **without a shell** — **one full command
  per line**; the commands run in order and **stop at the first failure**. Lines
  are tokenized respecting quotes (`echo "a b"` → two tokens) but never executed
  through a shell. A new third exec mode, `custom`, sits between `whitelist`
  (built-ins only) and `unrestricted` (free shell). A custom command runs on a VM
  only if it's **double-gated**: the VM is in `custom`/`unrestricted` mode AND
  carries one of the command's tags. The fixed-argv commands ship to the worker
  in the task payload; the worker independently refuses them outside custom mode.
  Admin-only CRUD, fully audited. Requires worker ≥ v1.3.0. Custom commands run
  via MCP `execute_action` by name like built-ins; the new `list_actions(vm_id?)`
  MCP tool discovers them (optionally only those runnable on a given VM).
- **MCP tools accept a VM name or id**: `get_vm_status`, `execute_action`,
  `execute_command`, and `trigger_update` now resolve a VM **name** as well as an
  id, case-insensitively (exact match preferred, then active record; ambiguous
  names error). Names are stable across
  re-enrollment — which mints a new id, so a cached id starts returning 404 — so
  agents should prefer the name.
- **Live dashboard (SSE)**: a `GET /api/events` Server-Sent Events stream pushes
  tiny hints (`{"type":"tasks"}` / `"vms"`) to connected dashboards, which
  invalidate the matching query cache — so worker results and background state
  changes (offline detection, swept tasks) appear instantly instead of waiting
  for the next poll. The dashboard reads it via fetch streaming so the JWT stays
  in the Authorization header (never in a URL/log); reconnects with backoff. The
  DB connection is released before streaming; periodic polling stays as a
  fallback. Built on the same in-process notifier as the task wait endpoint.
- **Event-driven task completion**: a new `GET /api/tasks/{id}/wait` long-poll
  blocks until a task is terminal (or a timeout), woken the instant the worker
  submits its result instead of polling. `wait=true` on actions/commands now uses
  the same mechanism (no more internal 0.25s poll loop). New MCP tool
  `wait_for_task(task_id, timeout?)` so agents stop poll-looping `get_task` after
  launching a long task with `wait=false`.
- **Compact roster**: MCP `list_vms(brief=true)` returns just id, name, state,
  mode per VM — a low-token session-opening overview.
- **Worker retry**: idempotent read-only actions (status, metrics,
  list_upgradable_packages) retry with exponential backoff on transient failure;
  mutating actions and free commands still run exactly once.
- **Telemetry on approval**: approving a pending VM auto-queues a status+metrics
  refresh so the dashboard shows live data on the pending→active transition.
- **Per-user MCP tokens**: each user creates, names, and revokes their own MCP
  tokens in the dashboard (MCP Tokens page). Actions taken through MCP now run
  with the user's **real role** and are attributed to them in the audit log as
  `mcp · <username>`, with the originating client IP.
- **Per-token IP allow-list**: an MCP token can be pinned to a single IP or CIDR
  (editable later). Requests from any other source are rejected. The check uses
  the real client IP stamped by Caddy as `X-Real-IP` (overwriting client-supplied
  values), so it cannot be bypassed by forging a header.

### Changed
- The single shared MCP **client token** (`HUGINN_MCP_MCP_CLIENT_TOKEN`,
  hub-generated and dashboard-rotatable) is **replaced** by the per-user tokens
  above. The MCP server no longer takes a client-token env var; the HTTP endpoint
  is gated by per-user tokens validated against the hub. `HUGINN_MCP_SERVICE_TOKEN`
  (MCP↔hub trust) is unchanged. Existing agents must switch to a per-user token.
- The MCP streamable-http server now runs stateless, so each request is
  attributed to the user that made it (not the user that opened the session).

### Removed
- `GET/PUT /api/settings/mcp-token` and the `settings.mcp_client_token` column.

## [1.0.0] - 2026-06-18

### Added
- **Two-factor authentication**: TOTP authenticator support (with single-use
  backup codes) and **WebAuthn passkeys** for phishing-resistant passwordless
  login. Self-service enrollment on a new Account/Security page; admins can
  reset a locked-out user's factors. TOTP secrets encrypted at rest.
- **SSO-first login**: when OIDC is enabled the password form is disabled by
  default, re-enabled via `HUGINN_ALLOW_PASSWORD_LOGIN`; admin 2FA can be
  enforced (`HUGINN_REQUIRE_ADMIN_MFA`). See `docs/auth.md`.
- **LDAP / LDAPS** authentication backend (admin-configurable).
- **Tags / groups**: admin-created colored tags, fleet filtering, bulk actions
  by tag, and per-VM assignment.
- **Scheduled commands**: cron/preset-driven actions or commands targeting a VM,
  a tag, or the whole active fleet.
- **Home dashboard**: fleet-health overview, recent activity, upcoming
  schedules, and stale-worker updates.
- **Permanent deletion** of revoked VMs (audit history preserved).
- **Offline notifications** (Discord + generic webhook) for VM offline/recovered
  and task-failure events.
- MCP client token is generated by the hub and rotatable from the dashboard;
  agent setup snippets are shown ready-to-paste.
- The dashboard now calls the API **same-origin** (no baked hub URL), so it works
  behind any reverse proxy / SSO forward-auth without CORS.
- Core iteration: hub (FastAPI + PostgreSQL), Go worker, MCP façade.
- Two production deployment options you can choose between: **Docker Compose +
  Caddy** (single host, automatic HTTPS) and **Kubernetes** manifests. Plus the
  local dev compose.
- React dashboard (Vite + TypeScript): local + OIDC login, fleet roster,
  per-node actions/updates/unrestricted shell, enrollment tokens, audit log with
  chain verification, and settings. Configurable CORS on the hub; OIDC can hand
  the token back to the SPA via fragment redirect.
- Worker enrollment with one-line installer, manual approval, and per-worker
  secrets.
- Whitelisted action execution and opt-in, audited unrestricted command mode.
- Sync and async (task-queue) execution with polling and dead-lettering.
- Atomic, rollback-safe worker self-update gated by an SSRF allowlist.
- Append-only, hash-chained audit log.
- Local (Argon2id) and OIDC (Authentik) authentication with read-only/operator/
  admin capability tiers.

### Security
- The post-password MFA "challenge token" is scope-restricted and rejected by
  every business endpoint; TOTP verification is replay-guarded and rate-limited.
- Passkey login requires user verification and a registrable-domain RP id (bare
  IPs rejected); challenges are single-use and signature counters checked for
  cloned authenticators.
- The OIDC flow fetches JWKS over httpx, verifies a nonce, and rate-limits its
  endpoints; the hub also fails closed on a weak `HUGINN_MFA_ENCRYPTION_KEY`.
- The MCP agent is an operator, not an admin: a leaked service token cannot
  approve VMs, toggle unrestricted mode, manage tokens, or change settings.
- Free-command execution requires operator privileges and is refused locally by
  the worker unless it has observed unrestricted mode (defense in depth).
- The hub fails closed in production when started with placeholder/weak secrets.
- Release-update SSRF allowlist rejects IP literals and internal hostnames; repo
  and version are pattern-validated.
- Audit-log appends are serialized to keep the hash chain consistent under
  concurrency.

[1.0.0]: https://github.com/Sunderrrr/Huginn/releases/tag/v1.0.0

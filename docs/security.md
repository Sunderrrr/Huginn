# Security

Huginn executes commands on remote machines. Treat it as privileged
infrastructure: lock down the hub, use TLS, and keep the audit log.

## Threat model (summary)

- The hub is the trust anchor and must be deployed behind TLS with strong secrets.
- Workers are semi-trusted: they only ever run what an authenticated principal
  asked for, and only after manual approval.
- The MCP agent ("Hermes") is a trusted, admin-level automation principal,
  authenticated by a service token.

## Controls

### Authentication & authorization
- **Every** endpoint requires authentication. There is no unauthenticated
  execution path. (`hub/app/api/deps.py`)
- Users authenticate via local Argon2id login, OIDC (SSO), or LDAP/LDAPS;
  JWTs carry the role. The OIDC flow follows the standard authorization-code +
  JWKS-verified id_token spec, but has only been **tested against Authentik** —
  other compliant IdPs should work but are unverified.
- RBAC has three capability tiers:
  - **read-only user** — list/inspect only; cannot execute.
  - **operator** (admin user *or* the automation agent) — run actions/commands,
    trigger updates, read the audit log.
  - **admin** (human admin user only) — control-plane operations: approve/revoke
    VMs, toggle unrestricted mode, manage enrollment tokens, change settings.
- The MCP façade authenticates with a service token and acts as an **operator,
  not an admin**: a leaked service token cannot approve VMs, enable unrestricted
  mode, or change the release allowlist.
- Workers authenticate with their VM id + a per-worker secret on every request;
  PENDING/REVOKED workers are rejected.

### Fail-closed configuration
- In production (`HUGINN_ENV=prod`) the hub **refuses to start** if any of
  `HUGINN_JWT_SECRET`, `HUGINN_SECRET_HASH_KEY`, or `HUGINN_MCP_SERVICE_TOKEN` is
  still a placeholder or shorter than 32 bytes. (`config.validate_for_prod`)

### Secrets
- Passwords are hashed with **Argon2id**. High-entropy secrets (enrollment
  tokens, per-worker secrets) are stored as a **keyed HMAC-SHA256**, never in
  plaintext. (`hub/app/core/security.py`)
- All secret/token comparisons are **timing-safe**: `hmac.compare_digest`
  (Python) and `crypto/subtle.ConstantTimeCompare` (Go).
- The worker writes its credentials file with `0600` permissions.

### Command injection
- Whitelisted actions map to **fixed argv vectors** executed with
  `exec.CommandContext` — **never** `sh -c`, never string concatenation.
  (`worker/internal/exec`, `worker/internal/whitelist`)
- Action parameters are validated against a conservative pattern on **both** the
  hub and the worker before they are placed into a separate argv slot.
- Free-form commands use a shell **by design**, but only in the explicit,
  admin-enabled, audited **unrestricted** mode — off by default, per VM. The
  worker independently enforces this too: it refuses to run a shell command
  unless it has itself observed unrestricted mode via heartbeat (defense in
  depth, so the hub alone cannot enable shell).

### Transport
- TLS is enforced for hub↔worker traffic in production (`HUGINN_REQUIRE_TLS`);
  the worker refuses plaintext unless `allow_insecure` is set (dev only).

### Updates / SSRF
- Update downloads are restricted to an **allowlist of release hosts**
  (`github.com`, `objects.githubusercontent.com` by default). The host is checked
  on the hub, on the worker, and on **every redirect hop**. Allowlist entries are
  validated (no IP literals, no `localhost`/`.local`/`.internal`), and the
  `repo`/`version` used to build release URLs are pattern-checked.
- Binaries are verified by **SHA-256** against the published checksums before an
  **atomic, rollback-safe** swap.

### Abuse protection
- Execution endpoints are **rate-limited** per principal and reject oversized
  bodies; stored output is capped.

### Auditability
- The audit log is **append-only and hash-chained**: each row commits to the
  previous one, so tampering is detectable via `GET /api/audit/verify`. There is
  no update/delete path. Login, enrollment, approval, execution, unrestricted
  toggles, and updates are all recorded.

## Operational guidance
- Generate real secrets: `openssl rand -hex 32` for `HUGINN_JWT_SECRET`,
  `HUGINN_SECRET_HASH_KEY`, and `HUGINN_MCP_SERVICE_TOKEN`.
- Rotate the bootstrap admin password immediately.
- Keep `HUGINN_REQUIRE_TLS=true` in production and terminate TLS in front of the hub.
- Enable unrestricted mode only when necessary, and review the audit log.

Report vulnerabilities per [SECURITY.md](../SECURITY.md).

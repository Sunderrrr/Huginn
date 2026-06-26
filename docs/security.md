# Security

Huginn executes commands on remote machines. Treat it as privileged
infrastructure: lock down the hub, use TLS, and keep the audit log.

## Threat model (summary)

- The hub is the trust anchor and must be deployed behind TLS with strong secrets.
- Workers are semi-trusted: they only ever run what an authenticated principal
  asked for, and only after approval. Approval is manual by default; an admin may
  issue an `auto_approve` enrollment token for unattended/bulk provisioning, which
  deliberately trades that human gate for convenience — such a token lets anyone
  holding it add a live worker, so it must be kept secret and revoked after use.
- The MCP server is a trusted façade authenticated by a service token. It acts
  either as the anonymous automation agent (operator, not admin) or, when an
  agent presents a per-user MCP token, **on behalf of that user with the user's
  real role** — every such action is attributed to the user in the audit log.

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
  - **operator** (admin user *or* the anonymous automation agent) — run
    actions/commands, trigger updates, read the audit log. A per-user MCP token
    grants exactly its owner's role, no more (a read-only user's token cannot
    execute).
  - **admin** (human admin user only) — control-plane operations: approve/revoke
    VMs, toggle unrestricted mode, manage enrollment tokens, change settings.
- **Two-factor authentication** for local accounts: TOTP (with single-use backup
  codes) and WebAuthn **passkeys** (phishing-resistant, passwordless). The
  intermediate post-password "challenge token" is scope-restricted and rejected
  by every business endpoint. Admin 2FA can be enforced. Full details and the
  threat properties are in [auth.md](auth.md).
- The MCP façade authenticates with a service token. Service-token-only calls
  act as an **operator, not an admin**: they cannot approve VMs, enable
  unrestricted mode, or change the release allowlist. Agents authenticate with
  **per-user MCP tokens** (created/revoked in the dashboard, stored HMAC-hashed,
  shown once); the hub resolves each to its owner and enforces that user's real
  role. A per-user token is only honoured alongside the server-held service
  token, so a leaked user token cannot reach the hub on its own. Tokens may be
  pinned to an IP/CIDR; the allow-list is checked against the real client IP
  (stamped by the edge proxy as `X-Real-IP`, not client-forgeable).
- Workers authenticate with their VM id + a per-worker secret on every request;
  PENDING/REVOKED workers are rejected.

### Fail-closed configuration
- In production (`HUGINN_ENV=prod`) the hub **refuses to start** if any of
  `HUGINN_JWT_SECRET`, `HUGINN_SECRET_HASH_KEY`, `HUGINN_MCP_SERVICE_TOKEN`, or
  `HUGINN_MFA_ENCRYPTION_KEY` is still a placeholder or shorter than 32 bytes.
  (`config.validate_for_prod`)

### Secrets
- Passwords are hashed with **Argon2id**. High-entropy secrets (enrollment
  tokens, per-worker secrets, TOTP backup codes) are stored as a **keyed
  HMAC-SHA256**, never in plaintext. (`hub/app/core/security.py`)
- TOTP secrets need to be reversible, so they are **encrypted at rest** with
  Fernet under a dedicated `HUGINN_MFA_ENCRYPTION_KEY` — kept separate from the
  JWT and HMAC keys so one key's compromise can't both forge tokens and decrypt
  MFA seeds.
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
- **Custom commands** (admin-defined, `custom` exec mode) are also **fixed argv,
  no shell**. They shift one trust boundary deliberately — an admin can now
  define which binary+args run on a VM — but are constrained: admin-only +
  audited to define; double-gated to run (VM in `custom`/`unrestricted` mode AND
  carrying one of the command's tags); and the worker refuses them outside custom
  mode, mirroring the unrestricted gate. There is no parameter/shell surface.

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
  `HUGINN_SECRET_HASH_KEY`, `HUGINN_MCP_SERVICE_TOKEN`, and
  `HUGINN_MFA_ENCRYPTION_KEY`.
- Rotate the bootstrap admin password immediately, and enrol a second factor
  (TOTP or a passkey) — keep `HUGINN_REQUIRE_ADMIN_MFA=true`.
- Keep `HUGINN_REQUIRE_TLS=true` in production and terminate TLS in front of the hub.
- Enable unrestricted mode only when necessary, and review the audit log.
- Rotating `HUGINN_MFA_ENCRYPTION_KEY` invalidates existing TOTP secrets (users
  re-enrol); it does not affect passkeys.

Report vulnerabilities per [SECURITY.md](../SECURITY.md).

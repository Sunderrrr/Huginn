# Security

Huginn executes commands on remote machines. Treat it as privileged
infrastructure: lock down the hub, use TLS, and keep the audit log.

## Threat model (summary)

- The hub is the trust anchor and must be deployed behind TLS with strong secrets.
- Workers are semi-trusted: they only ever run what an authenticated principal
  asked for, and only after approval. Approval is manual by default. An admin may
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
  execution path. (`hub-rs/src/routes/` — auth extractors on every route group)
- Users authenticate via local Argon2id login, OIDC (SSO), or LDAP/LDAPS.
  JWTs carry the role. The OIDC flow follows the standard authorization-code +
  JWKS-verified id_token spec, but has only been **tested against Authentik** —
  other compliant IdPs should work but are unverified.
- RBAC has three capability tiers:
  - **read-only user** — list/inspect only, and cannot execute.
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
  shown once). The hub resolves each to its owner and enforces that user's real
  role. A per-user token is only honoured alongside the server-held service
  token, so a leaked user token cannot reach the hub on its own. Tokens may be
  pinned to an IP/CIDR. The allow-list is checked against the real client IP
  (stamped by the edge proxy as `X-Real-IP`, not client-forgeable).
- Workers authenticate with their VM id + a per-worker secret on every request.
  PENDING/REVOKED workers are rejected.
- **The worker routes authenticate before they read the payload.** A request
  without valid worker credentials is answered 401 whatever its body, so an
  anonymous caller cannot probe the endpoints or learn what their body got
  wrong.
- **Sessions are revocable.** The access token carries a per-user session
  counter (`users.session_epoch`), compared with the stored value on every
  request. A logout, a password change or an MFA reset bumps it and kills
  every token issued before that moment, immediately and with no denylist to
  keep. The role in a token is not authoritative: the hub reads the account's
  role from the database, so a tampered claim changes nothing.

### Fail-closed configuration
- In production (`HUGINN_ENV=prod`) the hub **refuses to start** if any of
  `HUGINN_JWT_SECRET`, `HUGINN_SECRET_HASH_KEY`, `HUGINN_MCP_SERVICE_TOKEN`, or
  `HUGINN_MFA_ENCRYPTION_KEY` is still a placeholder or shorter than 32 bytes.
  (`config.validate_for_prod`)

### Secrets
- Passwords are hashed with **Argon2id**. High-entropy secrets (enrollment
  tokens, per-worker secrets, TOTP backup codes) are stored as a **keyed
  HMAC-SHA256**, never in plaintext. (`hub-rs/src/security/secret.rs`)
- TOTP secrets need to be reversible, so they are **encrypted at rest** with a
  Fernet-compatible AEAD under a dedicated `HUGINN_MFA_ENCRYPTION_KEY` — kept
  separate from the JWT and HMAC keys so one key's compromise can't both forge
  tokens and decrypt MFA seeds. (`hub-rs/src/security/fernet.rs`)
- All secret/token comparisons are **timing-safe** (`subtle::ConstantTimeEq`).
- The worker writes its credentials file with `0600` permissions.

### Cryptography
- The signing stack is **pure Rust**: HS256 tokens (hand-rolled, PyJWT-compatible
  claim order), Argon2id passwords, and an `aws_lc_rs`-backed verifier for the
  OIDC/RS256 and ES256 id_tokens. No C library is compiled into the hub
  binary.
- The elliptic-curve stack is on `crypto-bigint` ≥ 0.7.6 (the release that
  fixed the constant-time issues of RUSTSEC-2026-0387) — `p256` 0.14 for the
  WebAuthn ES256 path.
- RSA is used only to **verify** WebAuthn RS256 attestations. That path is
  constant-time (`rsa`'s PKCS#1 v1.5 verification compares every byte with
  `subtle::ConstantTimeEq` and has no early exit), and the hub never performs
  RSA decryption, which is what the Marvin attack (RUSTSEC-2023-0071) targets.

### Command injection
- Whitelisted actions map to **fixed argv vectors** executed directly
  (`Command::new(argv[0])` + separated args) — **never** `sh -c`, never string
  concatenation. (`worker-rs/src/exec.rs`, `worker-rs/src/whitelist.rs`)
- Action parameters are validated against a conservative pattern on **both** the
  hub and the worker before they are placed into a separate argv slot.
- Free-form commands use a shell **by design**, but only in the explicit,
  admin-enabled, audited **unrestricted** mode — off by default, per VM. The
  worker independently enforces this too: it refuses to run a shell command
  unless it has itself observed unrestricted mode via heartbeat (defense in
  depth, so the hub alone cannot enable shell).
- **Custom commands** (admin-defined, `custom` exec mode) are also **fixed argv,
  no shell**. They shift one trust boundary deliberately. An admin can now define
  which binary+args run on a VM. The constraints stay tight. Defining them is
  admin-only and audited. Running them is double-gated (VM in `custom`/`unrestricted`
  mode AND carrying one of the command's tags). The worker also refuses them outside
  custom mode, mirroring the unrestricted gate. There is no parameter/shell surface.

### Transport
- TLS is enforced for hub↔worker traffic in production (`HUGINN_REQUIRE_TLS`).
  The worker refuses plaintext unless `allow_insecure` is set (dev only).

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
  bodies. Stored output is capped.

### Browser automation
- **Off by default per VM.** An admin arms the capability
  (`PUT /api/vms/{id}/browser-enabled`, audited `toggle_browser`); browser
  tasks are refused with a 403 until then. Operators can run them, read-only
  users never can.
- **The engine is installed on the node, never embedded.** The hub pins the
  release (version plus per-arch SHA-256) in the fleet settings, the worker
  refuses any download that does not hash to the pin, and the extraction is
  strict (no symlink or path escape). The install is admin-only and audited.
- **The engine cannot reach the network's private side.** Page navigation to
  private or link-local addresses is refused by the engine itself, and the
  install download rides the updater's allowlist-validated client.
- **No shell, no secrets in argv.** The engine is spawned as a separated argv
  (never `sh -c`) with the CDP token in the environment.
- **The audit records the step count, never the content.** A `type` step can
  carry a password.
- **Nothing survives a task.** The engine and its process group are killed on
  every exit path, and no cookie or storage state is carried over.

### Auditability
- The audit log is **append-only and hash-chained**: each row commits to the
  previous one, so tampering is detectable via `GET /api/audit/verify`. There is
  no update/delete path. Login, enrollment, approval, execution, unrestricted
  toggles, and updates are all recorded.

### Supply chain and CI
- Every GitHub action is pinned to a **commit SHA**, every container base image
  to a **digest** (Dependabot keeps the digests current), and the worker
  releases to a **SHA-256** published in `checksums.txt`.
- `cargo audit` and `npm audit` run on every pull request, and a Trivy scan
  covers the container images and the deployment manifests. The only advisory
  ignored is documented in `audit.toml` with the reason it does not apply.
- The workflows themselves are linted (`actionlint`), so a broken gate is
  caught before it silently stops running.
- `main` is protected: a pull request is required, the CI checks are required
  status checks, force-pushes and branch deletions are refused.
- **No personal data.** Nothing that identifies a machine, a network or a
  person may enter the tree, the commit messages or the pull-request
  descriptions — the repository is public. See
  [CONTRIBUTING.md](../CONTRIBUTING.md#no-personal-data-in-the-repository).

## Operational guidance
- Generate real secrets: `openssl rand -hex 32` for `HUGINN_JWT_SECRET`,
  `HUGINN_SECRET_HASH_KEY`, `HUGINN_MCP_SERVICE_TOKEN`, and
  `HUGINN_MFA_ENCRYPTION_KEY`.
- Rotate the bootstrap admin password immediately, and enrol a second factor
  (TOTP or a passkey) — keep `HUGINN_REQUIRE_ADMIN_MFA=true`.
- Keep `HUGINN_REQUIRE_TLS=true` in production and terminate TLS in front of the hub.
- Enable unrestricted mode only when necessary, and review the audit log.
- Rotating `HUGINN_MFA_ENCRYPTION_KEY` invalidates existing TOTP secrets (users
  re-enrol). It does not affect passkeys.

Report vulnerabilities per [SECURITY.md](../SECURITY.md).

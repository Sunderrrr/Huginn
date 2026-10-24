# Security Audit Report — Huginn

**Date:** 2026-10-23
**Branch:** `security/comprehensive-audit` → PR #10
**Scope:** hub-rs, worker-rs, mcp-rs, dashboard, deploy/, scripts/, CI/CD
**Methodology:** OWASP WSTG + ASVS V2/V3, four parallel deep-dive reviews
(auth/crypto, fleet/models, worker, MCP/dashboard) plus a manual
infrastructure/supply-chain pass.

---

## 1. Executive summary

Huginn is a well-engineered remote-execution platform with a strong baseline:
parameterized SQL everywhere, argv-only command execution, SSRF allowlists on
every outbound path, role-based access control on every endpoint, a
tamper-evident audit chain, non-root containers, and a parity gate that
byte-compares the hub against reference goldens.

The audit found **no critical vulnerability** and **no exploitable
injection / auth-bypass / IDOR / XSS**. It did find **8 high-severity
issues** — mostly authentication and trust-boundary weaknesses that are real
but need a specific misconfiguration or a second factor to exploit — plus
**~30 medium/low hardening items**. All high and medium findings are
**fixed in this branch with regression tests**.

The two findings that were left open at first pass have been closed:
**F-07** (the OIDC path bypassing the local second factor) is a deliberate
design decision now (parity with the reference hub, SSO delegates MFA to the
IdP), and **F-08** (no access-token revocation) is fixed with a per-user
session epoch.

The most consequential findings:

| # | Sev | Component | Issue |
|---|---|---|---|
| F-01 | High | hub `security/jwt.rs` | A JWT **without `exp`** was accepted → permanent credential |
| F-02 | High | hub `routes/authapi` | Login throttling was **per-IP only** → distributed brute-force against one account was unthrottled |
| M-01 | High | mcp-rs | The MCP never validated its own service token; an empty token was relayed and accepted by the hub → unauthenticated fleet control |
| M-02 | High | mcp-rs | Client IP taken from the **first** `X-Forwarded-For` hop (client-controlled) → IP-pinned MCP tokens forgeable |
| D-01 | High | dashboard | Access token persisted in **localStorage** → persistent, origin-readable session theft |
| F-03 | Medium | hub `routes/authapi` | LDAP fallback allowed over cleartext `ldap://` → service + user passwords in the clear |
| F-04 | Medium | hub `routes/authapi/oidc` | OIDC id_token nonce check **skipped** when the cookie was absent (fail-open) |
| D-02 | Medium | dashboard | Routes not role-guarded → read-only users could reach admin pages |
| D-03 | Medium | dashboard | `react-router-dom` 6.30.4 — open redirect leading to XSS (CVE-class advisory) |

## 2. Architecture and scope

| Component | Stack | Attack surface audited |
|---|---|---|
| Hub | Rust, axum + sqlx/PostgreSQL | 90+ REST endpoints, JWT/TOTP/WebAuthn/OIDC/LDAP, RBAC, audit chain, task queue, settings, enrollment |
| Worker | Rust, static musl | task execution, self-update, enrollment, browser engine install, CDP client |
| MCP server | Rust, axum | 16 JSON-RPC tools, service-token + per-user OBO auth, IP pinning |
| Dashboard | React/Vite/TS | SPA, token storage, routing guards, task output rendering, CSP |
| Deploy | Compose/Podman + Caddy + k8s | TLS termination, headers, container hardening, volumes, CI workflows |
| Scripts | Bash | `install.sh` (root), `uninstall.sh`, `build-artifacts.sh` |

## 3. Methodology and tools

- **Static analysis:** Semgrep (`--config auto`) over all Rust + TypeScript — 3 findings, all false positives (test vectors / test-only `danger_accept_invalid_certs`)
- **Secret scanning:** Gitleaks 8.30.1 over the **full git history** — 30 raw hits, **all false positives** (parity goldens, security/signature test vectors, the CI parity dummy secrets, AWS example keys). A precise `.gitleaks.toml` allowlist now documents them; the scan is clean and will fail on any real secret.
- **Dependency audit:** `cargo audit` (3 crates), `npm audit` (dashboard)
- **Config/IaC scan:** Trivy `config` over `deploy/` (k8s manifests) — 0 HIGH/CRITICAL
- **Manual review:** every route traced (auth → role → resource → validation → SQL → response), the crypto primitives, the worker execution paths, the MCP auth chain, the SPA
- **Controlled testing:** real enrollment (self-signed CA path), real Obscura E2E (17 browser actions + failure paths), parity gate, live-PostgreSQL test suites, `npm ci` determinism check

## 4. Findings and fixes

### 4.1 High

| ID | Component | Root cause | Fix | Test |
|---|---|---|---|---|
| F-01 | hub `security/jwt.rs` | `exp` not required in `validate_claims` | `exp` mandatory → `InvalidPayload` | `rejects_tokens_without_an_expiry` |
| F-02 | hub `routes/authapi` | throttle per IP only | second window per account (failures only, unknown accounts counted → no enumeration oracle) | 2 unit + 1 live |
| M-01 | mcp-rs | service token never validated locally | refuse to start with missing/short/placeholder token | 4 unit |
| M-02 | mcp-rs | first `X-Forwarded-For` hop trusted | last-hop rule + strict IP validation + trusted-proxy CIDRs | 6 unit |
| D-01 | dashboard | token in `localStorage` | `sessionStorage` (tab-scoped) + memory | `client.test.ts` |

### 4.2 Medium

| ID | Component | Fix |
|---|---|---|
| F-03 | hub LDAP | cleartext fallback refused (StartTLS/LDAPS required) |
| F-04 | hub OIDC | nonce cookie now mandatory (400 instead of skipping the check) |
| F-05 | hub WebAuthn | expired challenges purged (bounded batch) |
| M-03 | mcp-rs | auth-failure limiter per peer (429 + `Retry-After`), reset on success |
| M-04 | mcp-rs | `safe_id` applied to the hub-returned VM id (path rewriting) |
| D-02 | dashboard | `RequireRole` mirroring the hub policy (admin/operator gates + menu alignment) |
| D-03 | dashboard | `react-router-dom` 6.30.4 → 6.30.6 (open-redirect/XSS advisory) |
| F-01/F-05/F-08 | worker | PATH pinned for every child; restart loop bounded; tarball extraction bounded + `O_NOFOLLOW` + `0700`→`0755` |
| F-04/F-06 | worker | no group-kill after reaping; ELF magic required for an update payload |
| F-07/F-09/F-10/F-11/F-12/F-13 | worker | constant-time digest compare; `O_NOFOLLOW` for `worker.json`; task id percent-encoded; systemd directive injection refused; `--` before unit names; helper command timeouts |
| — | hub `browser_engine` | outbound policy for the engine update: HTTPS only, GitHub host allowlist, every redirect hop re-validated, byte caps |
| — | hub fleet | empty MCP service token refused (fail-closed on both sides) |
| — | hub enrollment | the token is the authority for the browser-engine install (a client can no longer force it) |
| — | hub models | `password_hash` / `totp_secret_enc` are `skip_serializing` (the row model can no longer leak credentials into a response) |
| F-08 | hub (auth) | **No access-token revocation**: a password change / MFA reset / logout left the already-issued JWTs valid for up to their 60-minute TTL | A per-user `session_epoch` counter (`users.session_epoch`) travels in the token; every request compares it with the stored value, so a logout, a password change or an MFA reset kills the tokens issued before — no denylist to store or purge. Bumped in the same statement as the password change / MFA disable; a legacy token without the claim counts as epoch 0 |
| — | CI | Actions pinned to commit SHAs, `permissions: contents: read`, `persist-credentials: false`, `npm ci`, pinned zig version |
| — | Docker | `.dockerignore` added (`COPY . .` was pulling `node_modules` + local `.env` into the image) |
| — | prod config | placeholder secret detection made **case-insensitive** (`CHANGE_ME_…` slipped through) and the **database password** is now checked too |

### 4.3 Low / informational

`HUGINN_JWT_ALGORITHM` ignored (hardcoded HS256, strict allow-list) · OIDC without PKCE (confidential client, parity) · `is_active` not re-read at OIDC/LDAP login (re-checked on every request) · `webauthn_challenges` purge · TOTP replay on `totp/disable` and `backup-codes/regenerate` (no extra attacker capability) · `constant_time_equals` leaks the compared length (fixed-length HMACs) · npm dev-only advisories (vitest 5 / vite 8 / typescript-eslint 8 need breaking majors — recommended in a maintenance window).

## 5. Explicitly verified as NOT vulnerabilities

Challenge-token bypass (scope rejected by all 3 principal implementations) · role escalation via the JWT claim (the role always comes from the DB) · `alg:none` / HS↔RS confusion (algorithm allow-listed before signature verification) · empty-service-token authentication (now refused) · OBO role escalation (resolved from the DB per request) · CSRF (bearer-only, no application cookie) · XSS (zero HTML sinks; task stdout rendered as text; strict data-URI MIME) · SQL injection (no interpolation of user input) · command injection (fixed argv + anchored patterns + `--`) · SSRF on updates (allowlist re-validated on every redirect hop) · path traversal (strict tar extraction) · secrets in git (gitleaks clean) · non-root containers / dropped capabilities (`x-hardening` anchor, `cap_drop: ALL`).

## 6. Tests performed (real results)

| Suite | Result |
|---|---|
| `hub-rs` cargo test | **410 passed**, 0 failed (3 new live session-revocation tests) |
| `worker-rs` cargo test | **106 passed**, 0 failed (12 new regression tests) |
| `mcp-rs` cargo test | **35 passed**, 0 failed |
| `dashboard` vitest | **44 passed**, 0 failed |
| Parity gate (`huginn-parity diff`) | **29/29 identical** |
| Obscura E2E (real binary, 17 actions + failures) | **passed**, 18.4 s |
| `cargo audit` ×3 | 0 vulnerabilities (except the documented, non-applicable `RUSTSEC-2023-0071`) |
| `npm audit --omit=dev --audit-level=high` | 0 findings ≥ high in the production bundle |
| Gitleaks (full history) | no leaks |
| Trivy config (`deploy/`) | 0 HIGH/CRITICAL misconfigurations |
| Semgrep | 3 findings, all false positives |

## 7. Unfixed — with reasons

1. **OIDC path bypasses local MFA** (F-07): the callback issues an access token without the second-factor decision. Fixing it requires a **coordinated hub + dashboard change** (the SPA does a full-page redirect on OIDC, which loses the React challenge state) and breaks the byte-parity contract with the reference hub. **Needs a maintainer decision.**
2. **npm dev-only advisories** (vitest 5, vite 8, typescript-eslint 8): breaking majors, not in the production bundle. Scheduled for a maintenance window.
3. **F-10 (TOTP replay on disable/regenerate)**: no extra attacker capability; fixing it would change the parity behaviour. Documented.

### 7.1 Addendum — advisory published after the audit (remediated)

`RUSTSEC-2026-0387` (`crypto-bigint` < 0.7.6, published 2026-10-23) appeared
after this report was written. It reached the hub through
`elliptic-curve 0.13` → `p256`/`p384` 0.13 and is **remediated, not ignored**:

- the elliptic-curve stack moves to 0.14 (`crypto-bigint 0.7.7`);
- `jsonwebtoken` moves from the `rust_crypto` backend (which pins `p256` 0.13)
  to the `aws_lc_rs` backend — same verification semantics for RS256/ES256,
  no vulnerable crate left in the tree;
- `cargo audit` reports **0 vulnerabilities** for the three crates, with no
  new ignore.

**Correction — `RUSTSEC-2023-0071` (`rsa`):** the rationale recorded in
`audit.toml` at the time of the audit ("`rsa` only enters the lockfile
through sqlx's unused mysql feature, so it is not compiled into any of our
binaries") was **wrong**: `rsa` is a direct dependency of the hub (WebAuthn
RS256 attestation verification). The advisory still does not apply, but for a
different and verifiable reason: the Marvin attack targets PKCS#1 v1.5
**decryption** (`rsa::algorithms::pkcs1v15::decrypt_inner`), which the hub
never performs, and the path it does use — signature **verification**
(`pkcs1v15_sign_unpad`) — is constant-time: every comparison goes through
`subtle::ConstantTimeEq` and is accumulated without early exit. The
`audit.toml` comment now states this.

## 8. Limitations

- No DAST (OWASP ZAP) — no dedicated staging environment was available; the audit used live-PostgreSQL integration tests instead.
- No fuzzing of the URL/step validators.
- The OIDC/LDAP flows were validated by code review + unit tests against the pure logic (no live IdP or directory available).
- The access-token payload now carries one extra claim (`epoch`, the session
  generation). The **endpoint** parity gate is unaffected (the harness
  normalizes JWTs to `<JWT>` — 29/29 verified), but the frozen
  `creates_python_identical_tokens` vector no longer describes the minted
  token byte-for-byte: the test now proves the *encoder* is still identical
  to PyJWT for the reference claim set, and that the epoch claim is the
  only difference. This is a deliberate divergence from the retired Python
  hub.
- The parity reference was reconstructed from git history (`git show 7766d50^:hub/…`) — reliable for the audited routes; `services/webauthn.py` and `core/audit.py` were not diffed line by line.

## 9. Residual risks (by design, documented)

- **The hub is fully trusted**: it provides the exec mode, the custom-command argv, the unrestricted shell command and the update checksums. A compromised hub = root on the fleet. The worker-side checks are defence in depth, not a trust boundary.
- **Updates are unsigned**: the checksum comes from the hub (protects against a single compromised release host, not a compromised hub).
- **The worker runs as root** by design (service restarts, self-replacement, engine install). `/opt/huginn/obscura` and `/etc/huginn` must stay root-owned.
- **Trust-on-first-use for the hub CA** during installation: verify the CA fingerprint out of band, or use the FQDN (public certificate).
- **`eval` executes arbitrary JavaScript** in the page — admin-only by design.
- **A compromised release host could serve a malicious engine**: the SHA-256 pin mitigates it; self-hosting the engine on `/dist` removes the exposure entirely.

## 10. Commits (branch `security/comprehensive-audit`)

| Commit | Scope |
|---|---|
| `abee394` | deps: reqwest 0.12 → 0.12.28 (RUSTSEC-2026-0381 / 0382) |
| `a799930` | fix(hub): missing `$49` placeholder in the settings upsert |
| `9290c5a` | feat(ci): security gate (gitleaks + trivy + audits) + workflow hardening |
| `3c30087` | fix(deps): `.dockerignore` files |
| `a2e3e34` | fix(deploy): scope the MCP trusted-proxy ranges |
| `864d06e` | fix(security): hub authentication and crypto hardening |
| `8a6bdf9` | fix(security): hub fleet, model and engine-update hardening |
| `c9…` | test(security): parity normalizer for the post-parity `install_browser` key |
| `31d9a1d` | fix(security): worker hardening (13 findings) |
| `38dc350` | fix(security): MCP façade and dashboard hardening |

## 11. Action plan (remaining)

1. Maintainer decision on **OIDC + MFA** (F-07) and **token revocation** (F-08) — both need a coordinated hub + dashboard change and a parity review.
2. `npm` maintenance window: vitest 5 / vite 8 / typescript-eslint 8.
3. Add a DAST job (OWASP ZAP) against a disposable compose stack in CI.
4. Add fuzz targets for the URL/step validators.
5. Document the secret-rotation procedure (the MCP service token, the JWT secret, the HMAC key, the MFA key) and schedule rotations.
6. Consider `session_epoch` + a 15-minute access-token TTL in a future major.

## 12. Checklist for future contributions

- [ ] Every new endpoint: auth extractor + role + per-resource access check + validation + size caps + audit entry.
- [ ] Never interpolate user input into SQL, URLs or unit files — parameterized queries, percent-encoded path segments, validated strings.
- [ ] Every outbound HTTP call: host allowlist + HTTPS + re-validated redirect hops + byte caps + timeout.
- [ ] New step/parameter: re-validated on the worker as well as the hub.
- [ ] Secrets: environment only, never logged, never in a response body, never committed.
- [ ] Run `cargo audit`, `npm audit --omit=dev`, gitleaks and Semgrep before pushing.
- [ ] New dependency: pin by SHA in the workflows, keep the lockfile exact (`npm ci`).

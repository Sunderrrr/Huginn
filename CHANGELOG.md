# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **A Windows worker could keep running with a stale identity.** After a
  re-enrollment, the running service still held the previous (revoked)
  credentials in memory: the hub refused every heartbeat and poll, so the
  queued tasks stayed **pending forever** with no visible cause (the
  worker's log is lost when it runs as a service). The installer now
  restarts the service when it was already running, so it picks up the
  current identity.
- **The browser automation section appeared on Windows nodes.** The Obscura
  engine is Linux-only, so the whole section (the engine state, the install
  button and the step runner) is now hidden on a node that cannot run it — the
  hub exposes the OS the worker reported at enrollment.
- **A revoked node could not be deleted from the dashboard.** The API has
  always accepted `DELETE /api/vms/{id}` for a revoked node; the page had
  the confirmation modal but no button to open it. The fleet page now offers
  **Delete permanently** on a revoked node.

### Added
- **A stack smoke test** (`scripts/smoke.sh`): it checks the real paths
  (health, dashboard, installer scripts, manifest, MCP endpoint, database,
  container health) instead of trusting that the containers are "Up" — a
  database stuck in a shutdown keeps its container running while the whole
  stack answers errors. `deploy/manage.sh up` now runs it and **fails** when
  the stack does not answer, and a new `ci-stack` workflow starts the stack
  on every pull request and runs the same check.

### Fixed
- **The watchdog could not recover a broken container.** It recycled an
  unhealthy container with a kill, but podman refuses to kill a container
  that belongs to the project pod: the attempt failed, the container stayed
  broken and the watchdog repeated the same failing action every two
  minutes. It now escalates to recreating the project (with a cooldown) when
  the kill is refused.
- **The Windows service could not be configured.** `ChangeServiceConfig2`
  requires `SERVICE_START` in addition to `SERVICE_CHANGE_CONFIG` when the
  failure actions include `SC_ACTION_RESTART`: the install failed with
  `Win32 error 5 (Access denied)`. The service is now opened (and created)
  with both rights, and its configuration — binary path, launch arguments,
  account, start type — is reconciled on every install, so a reinstall with
  another `BinDir` cannot leave the SCM launching an old executable.
- **The installer is idempotent.** When the node already has an identity
  (`worker.json`), the enrollment is not redone: the script only repairs the
  service, so no second worker is created and no token is consumed.
- **The state directory is locked down before anything secret lands in it.**
  The ACL is applied on every run (not only when the directory is created),
  a failure is fatal instead of a warning, the effective ACL is read back and
  the install stops if `Users`, `Authenticated Users` or `Everyone` can still
  read it.
- **The worker's CA file is no longer optional.** A configured hub CA that
  cannot be read, or that is not a PEM certificate, now fails with the path
  and the reason, instead of being silently skipped and surfacing later as a
  misleading "invalid peer certificate: UnknownIssuer".
- **The enrollment message follows the real state** returned by the hub: an
  auto-approved node comes back ACTIVE and is no longer announced as PENDING.
- **Windows ARM64 is refused before any download**: only windows/amd64 is
  published, and the installer now says so exactly instead of asking for an
  asset that does not exist.

### Fixed
- **The Windows service could not be configured.** `ChangeServiceConfig2`
  requires `SERVICE_START` in addition to `SERVICE_CHANGE_CONFIG` when the
  failure actions include `SC_ACTION_RESTART`: the install failed with
  `Win32 error 5 (Access denied)`. The service is now opened (and created)
  with both rights, and its configuration — binary path, launch arguments,
  account, start type — is reconciled on every install, so a reinstall with
  another `BinDir` cannot leave the SCM launching an old executable.
- **The installer is idempotent.** When the node already has an identity
  (`worker.json`), the enrollment is not redone: the script only repairs the
  service, so no second worker is created and no token is consumed.
- **The state directory is locked down before anything secret lands in it.**
  The ACL is applied on every run (not only when the directory is created),
  a failure is fatal instead of a warning, the effective ACL is read back and
  the install stops if `Users`, `Authenticated Users` or `Everyone` can still
  read it.
- **The worker's CA file is no longer optional.** A configured hub CA that
  cannot be read, or that is not a PEM certificate, now fails with the path
  and the reason, instead of being silently skipped and surfacing later as a
  misleading "invalid peer certificate: UnknownIssuer".
- **The enrollment message follows the real state** returned by the hub: an
  auto-approved node comes back ACTIVE and is no longer announced as PENDING.
- **Windows ARM64 is refused before any download**: only windows/amd64 is
  published, and the installer now says so exactly instead of asking for an
  asset that does not exist.

### Fixed
- **The stack could stay up but serve nothing.** A stop request to the host
  (SIGTERM) asks PostgreSQL for a *smart* shutdown, which waits for every open
  client session: the hub's pool kept its sessions forever, so the database
  stayed in "shutting down" — the container was running, the hub could not
  reach it, and the whole stack (API, MCP, dashboard) answered errors. Two
  fixes: the hub's pool closes idle sessions (`idle_timeout`) and recycles
  its connections, and the watchdog now recycles a container that is running
  but *unhealthy* — it only used to restart the ones that were stopped.

### Fixed
- **The Windows worker could not be installed or updated.** The manifest
  published at `/dist/checksums.txt` listed only the Linux assets, so the
  Windows installer downloaded the binary correctly and then failed with "no
  checksum entry". The build script now writes one manifest line per
  published asset, and the release pipeline builds and publishes the Windows
  binary (mingw-w64, the same target as the local build) next to the two
  Linux ones.
- **The worker no longer compiles for Windows**: the heartbeat now reports
  the installed Obscura engine version, and that module only exists on Linux.
  The report is `None` elsewhere, and the Windows-only code path is clean
  again under `-D warnings`.
- **The Windows installer** runs the CA fetch with `-SkipCertificateCheck`
  under PowerShell 7 (the `ServicePointManager` callback does not affect the
  PowerShell 6+ web cmdlets) and keeps that callback for Windows PowerShell
  5.1. It no longer calls `exit`, so a failure cannot close an interactive
  session. The download goes to a `.part` file, is verified in full, and only
  then replaces the binary (with a rollback if the replacement fails). The
  checksum parser accepts CRLF and LF, tolerates the usual spacing, and
  matches the asset name exactly. The hub's published assets are listed when
  the manifest has no entry for the expected one.

### Changed
- **The documentation was refreshed** against the code it describes, and now
  passes an automated writing check. The pages cover what actually shipped in
  this cycle: the browser automation subsystem (engine state, step reference,
  validation), the MCP tools that now return the result instead of a handle,
  the revocable sessions, the crypto stack, the browser security model, the
  supply-chain and CI gates, and the release rollout. A new `ci-docs` workflow
  runs the SlopMonster checker over the shipped copy on every pull request, so
  a draft that reads like machine output fails the build instead of shipping.

## [1.10.1] — 2026-10.25

### Fixed
- **The fleet list showed the wrong IP**: the hub stored the address it saw
  at enrollment — the NAT/bridge address of the node's network, which
  podman allocates *identically* on different hosts (two nodes showed the
  same `10.89.0.1`). The worker now reports the address the kernel
  actually picks to reach the hub (its route's source address), at
  enrollment and at every heartbeat.

## [1.10.0] — 2026-10-25

### Added
- **The Obscura engine state of a node is now visible** (the engine lives on
  the *worker's* filesystem, so only the worker can answer): the worker
  reports the installed engine version in its heartbeat, the hub stores it
  (`vms.browser_engine_version`, migration 0009) and exposes it on the VM
  payload, and the dashboard's browser card shows a **status dot** — green
  with the version when the engine is installed, **red** when it is missing
  (with the run button disabled and the reason spelled out), grey while the
  worker has not reported yet (a worker that predates the report never
  reports, so its state stays "unknown" and the run is not blocked). The
  install button becomes "Reinstall browser engine" once the engine is
  there. A worker that reports no engine says so explicitly — the field's
  absence (an older worker) is never read as "not installed".

## [1.9.0] — 2026-10-25

### Security
- **The container base images are pinned by digest** (`rust:1-slim`,
  `debian:stable-slim`, `postgres:16-alpine`, `caddy:2-alpine`): a tag can be
  re-pointed silently, a digest cannot. Dependabot keeps the digests current
  (the `docker` ecosystem is now configured for `hub-rs/`, `mcp-rs/` and
  `deploy/`).
- **`main` is protected by a repository ruleset**: a pull request is required
  (admins included), the 15 CI checks are *required status checks* (a merge is
  blocked while one is red), no force-push, no branch deletion, linear
  history. The rules are documented in CONTRIBUTING.md.
- **The workflows are linted** (`actionlint`) on every pull request: a syntax
  error, a wrong `permissions:` block or an unresolvable action reference is
  caught before it can silently disable a gate.
- **RUSTSEC-2026-0387 (crypto-bigint) — remediated, not ignored**: a new
  advisory (published 2026-10-23) flags timing variability in operations that
  were meant to be constant-time in `crypto-bigint` < 0.7.6, which reached the
  hub through `elliptic-curve 0.13` → `p256`/`p384` 0.13. The fix requires the
  elliptic-curve stack to move to 0.14, which in turn requires `jsonwebtoken`
  to stop pinning `p256` 0.13 — it now runs on the `aws_lc_rs` backend
  (same verification semantics for RS256/ES256, no vulnerable crate in the
  tree), and the hub's own `p256` dependency moves to 0.14 for the WebAuthn
  ES256 path. `cargo audit` now reports **0 vulnerabilities** for all three
  crates, with no new ignore. The build needs `cmake` + `make` for
  `aws-lc-sys` (build stage only; the runtime image is unchanged).
  The `RUSTSEC-2023-0071` (`rsa`) ignore is also restated with an accurate
  rationale: `rsa` *is* compiled into the hub (WebAuthn RS256 attestation
  verification), but the Marvin attack targets PKCS#1 v1.5 *decryption*, which
  the hub never performs, and the verification path it does use is
  constant-time (`subtle::ConstantTimeEq` accumulation, no early exit).
  
### Changed
- **The MCP tools that create a task now return the RESULT, not a handle**:
  `browser_start`, `browser_navigate`, `browser_screenshot`, `browser_pdf`,
  `browser_eval`, `browser_install`, `execute_action` and `execute_command`
  wait for their task and hand back the finished task (stdout/stderr inline)
  — the agent no longer has to guess that it must call `wait_for_task`
  afterwards. The wait uses the hub's `GET /api/tasks/{id}/wait` endpoint
  (the hub holds it server-side), bounded by the task's own timeout and by a
  90 s ceiling that keeps the response under the 100 s limit a CDN in front
  of the MCP imposes. `wait=false` restores the previous behaviour (the task
  handle straight away) for the long ones. The MCP no longer asks the hub
  for its own 30 s create-side wait — that window collided with the MCP's
  own request timeout.
  
### Fixed
- **The hub now validates the browser steps it queues** (it was the only front
  door that did not): a step naming an action the worker cannot execute
  (`"naviguer"`), or missing its own required field (`click` without a
  selector, `type` without a text, `eval` without JavaScript, a `scroll`
  without `selector`/`to`, a `set_viewport` outside 200-5000 px, a cookie
  whose URL is not http(s)), is refused with **400** instead of being queued
  and failing on the worker. The hub's validator is now the canonical gate and
  mirrors the worker's bounds **exactly** (selector 512, `type` text 10 KiB,
  `eval` script 64 KiB, `wait_for_text` 512, 20 cookies, URL 2048) — the MCP
  keeps its own copy as defence in depth.
- **The worker routes authenticate before parsing the payload**:
  `POST /api/worker/heartbeat` and `POST /api/worker/tasks/{id}/result`
  answered **400** about the caller's own body before checking the
  credentials, which let an anonymous caller tell that the endpoint was
  alive (and what was wrong with its body). They now answer **401** whatever
  they send.
- **The worker is now compiled for Windows** in CI (weekly job): the Windows
  path (`install.ps1`, `#[cfg(windows)]` code) had never been built by any
  pipeline, so a Windows-only break could only surface on a user's machine.
  The job compiles the worker and its test binaries on a Windows runner; it is
  not a merge gate yet — the Windows test code is not known to compile — it
  exists to make the rot visible instead of silent.
- **Server-side session revocation** (audit finding F-08): a per-user
  `session_epoch` counter now travels in the access token and is compared
  with the stored value on every request. A logout, a password change or an
  MFA reset therefore kills the sessions opened with the old credentials —
  immediately, with no denylist to store or purge. Tokens issued before the
  migration carry no epoch and count as epoch 0 (they stay valid until they
  expire, exactly as before). The access-token payload gains one claim
  (`epoch`); the endpoint parity gate is unaffected (JWTs are normalized),
  and the frozen Python byte-vector test now pins the encoder rather than
  the whole claim set.
- **Full security audit** (OWASP WSTG + ASVS, four parallel deep-dive reviews
  plus an infrastructure and supply-chain pass). 8 high-severity findings and
  ~30 medium/low ones were fixed, each with a regression test. See
  [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the complete report.
  - Hub: a JWT without `exp` was accepted (permanent credential) — `exp` is
    now mandatory; the login throttle was per-IP only (distributed brute-force
    against one account was unthrottled) — a second per-account window was
    added; the LDAP fallback was allowed over cleartext `ldap://` — an
    encrypted transport is now required; the OIDC id_token nonce check was
    skipped when the cookie was missing — it is now mandatory; the
    `webauthn_challenges` table was never purged — expired rows are now
    purged; the MCP service token was compared fail-open on an empty value —
    both sides now refuse an empty token; the Obscura engine download now
    goes through an outbound policy (HTTPS only, GitHub host allowlist, every
    redirect hop re-validated, byte caps); the enrollment token is the
    authority for the browser-engine install; `password_hash` /
    `totp_secret_enc` are never serialized by the row model; the prod
    fail-closed secret gate now detects placeholders case-insensitively and
    also checks the database password.
  - Worker: the root worker resolved `systemctl`/`apt-get`/`sh` through the
    inherited PATH (local code execution as root) — every child now runs with
    a pinned PATH; the Obscura tarball extraction was unbounded and followed
    symlinks — it is now a bounded, `O_NOFOLLOW`, 0700→0755 write; the
    process-group kill could race with the child's reaping; a hanging
    health-check left a root child alive; the downloaded update could be a
    script (ELF magic is now required); the CDP port could be pre-bound by a
    local attacker (ownership is now verified through /proc); `worker.json`
    could be written through a symlink; the task id was interpolated raw into
    the result URL; the systemd unit accepted control characters in a path.
  - MCP: the service token was never validated locally (an empty token was
    relayed and accepted by a hub configured with one — an unauthenticated
    fleet-control proxy); the client IP came from the first
    `X-Forwarded-For` hop (client-controlled, so IP-pinned tokens were
    forgeable) — the last-hop rule and a trusted-proxy list now apply;
    authentication failures were not rate-limited; the resolved VM id was not
    filtered before being interpolated into a URL.
  - Dashboard: the access token was persisted in `localStorage` — it now
    lives in `sessionStorage`; routes were not role-guarded — they now mirror
    the hub's policy; `react-router-dom` 6.30.4 → 6.30.6 (open redirect
    leading to XSS); the CSP gained `form-action` and `frame-src`.
  - CI/CD: every action is pinned to a commit SHA, the workflows declare
    `permissions: contents: read`, checkouts no longer persist the job
    token, installs use `npm ci`, and a new `security` workflow runs
    gitleaks, cargo/npm audits and Trivy image/IaC scans. `.dockerignore`
    files stop `COPY . .` from baking `node_modules` and local `.env` files
    into an image layer.

### Added
- **`browser_enable` MCP tool** (17 tools): the browser capability gate was
  only reachable from the dashboard, so an agent could not arm a VM for
  browser automation. The new tool calls the existing admin hub route
  (`PUT /api/vms/{id}/browser-enabled`, audited `toggle_browser`) through the
  hub client, with the on-behalf-of identity carried like every other fleet
  call. Covered by a wiremock test asserting the PUT route, the body and the
  400s on a missing `vm_id` / `enabled`.
- **Full Obscura step vocabulary** (v1.7.0): `press_key` (Enter/Tab/arrows or
  one ASCII char — forms submit for real), `hover` (trusted mouse move),
  `scroll` (into view / top / bottom), `wait_for_text`, `title`,
  `set_viewport` (200-5000 px), `full_page` screenshots
  (`captureBeyondViewport`), `pdf` (Obscura's `Page.printToPDF` — base64
  `data:application/pdf` in stdout), `get_cookies`, and `set_cookies` (fills
  Obscura's request cookie jar; the page's `document.cookie` is a separate
  DOM store). MCP gains the `browser_pdf` shortcut (15 tools) and the
  dashboard a PDF preset + PDF download links in task results. Every step
  is verified against the real Obscura v0.2.4 binary by the E2E test, which
  now drives all 17 actions plus the failure paths (missing selector,
  wait timeouts, global timeout, unknown release). Step output is one line
  per step (multi-line details escaped) so captures stay parseable, and
  captures now ride the 1 MiB stdout budget instead of the per-step text
  cap (fixes latent truncation of large screenshots/PDFs).
- **Browser automation on Linux workers (Obscura)**: drive a headless browser
  on any Linux VM from the dashboard or through MCP tools (`browser_install`,
  `browser_start`, `browser_navigate`, `browser_screenshot`, `browser_eval`).
  Steps: navigate, click, type, eval, wait_for, get_text, get_html, screenshot.
  The engine is Obscura (Apache-2.0, third-party notice added) downloaded
  on-demand — never embedded in the worker binary. Linux only; Windows
  responds "not supported". See docs/browser.md.
- **`browser_install` task type** (admin-triggered): the worker downloads the
  hub-pinned engine release (fleet settings `browser_engine_version` +
  per-arch `browser_engine_sha256_*`, defaults: Obscura v0.2.4), verifies the
  SHA-256, checks glibc ≥ 2.35 (clear refusal on musl/Alpine), extracts
  strictly into `/opt/huginn/obscura/<version>/` with the Apache-2.0 license,
  smoke-tests `obscura --version`, and removes the engine on uninstall.
- **Per-VM browser capability gate** (`browser_enabled`, off by default):
  browser tasks are refused until an admin enables the VM
  (`PUT /api/vms/{id}/browser-enabled`, audited `toggle_browser`) — the
  browser equivalent of the exec-mode gate. Engine install is admin-only and
  audited (`browser_install_task`).
- **Resource caps on the engine process**: `obscura serve` runs with
  `--workers 2 --max-connections 4` and `--worker-max-rss <MB>` whenever the
  installed release supports the flag (probed from its `serve --help`; the
  pinned v0.2.4 predates it). Default cap 512 MB, env-overridable
  (`HUGINN_BROWSER_MAX_RSS_MB`).

### Fixed
- **`PUT /api/settings` returned 500 on every save** (regression from the
  enrollment migration): the settings upsert had a bind for
  `enrollment_base_url` but no INSERT column for it. The column is now part
  of the INSERT (and the new engine columns with it), covered by a live
  round-trip regression test on both the INSERT and ON CONFLICT paths.
- **`enrollment_base_url` was not writable through `PUT /api/settings`** —
  the update schema never had the field; the dashboard value could only be
  changed via psql. The field is now part of the settings update (validated:
  empty or absolute http(s)://).
- **The parity gate was failing on `settings_get`** (28/29) since the
  enrollment migration: the post-parity settings keys are now filtered by the
  harness normalizer like the backup keys, and the gate is green again
  (29/29, re-verified end to end).

### Removed
- **The superseded Python/Go implementations — `hub/`, `mcp/`, `worker/` — are
  removed**; they are fully replaced by `hub-rs/`, `mcp-rs/`, and `worker-rs/`,
  which are in production and parity-gated (29/29 golden responses identical).
  The parity goldens and the security test vectors remain versioned in `hub-rs/`
  (`hub-rs/golden/`, `hub-rs/security_vectors.json`) for regression testing.
  Legacy CI (`.github/workflows/ci-hub.yml`, `ci-worker.yml`) is gone, and
  `release.yml` now builds only the Rust artifacts (worker binaries + checksums,
  `mcp-rs` and `hub-rs` images). Related auth work (WebAuthn/OIDC/LDAP ports to
  Rust) is landing separately on this branch.

## [1.4.0] — Rust worker + Rust MCP server, event-driven hub long-poll

### Added
- **`worker-rs/` — the fleet worker in Rust** (full behavioral port of the Go
  worker: identical CLI, wire protocol, and `worker.json` state file — the hub
  and `install.sh` see no difference). Static musl binaries (`linux/amd64`,
  `linux/arm64`): **3.2–3.6 MB vs 6.0 MB Go (−45 %)** and ~1–3 MB idle RAM vs
  10–20 MB (no GC runtime) — across a 100-VM fleet that is ~1.5 GB → ~200 MB
  aggregate. 46 tests ported from the Go suite (no-shell exec, output caps,
  whitelist injection rejection, retry policy, exec-mode gating,
  SSRF allowlist incl. every redirect hop, atomic update + rollback).
  The Go worker in `worker/` is kept during fleet validation; see
  `worker-rs/PARITY.md`.
- **`mcp-rs/` — the MCP server in Rust** (port of the Python/FastMCP server:
  same 9 tools, same per-user Bearer auth validated against
  `/api/mcp/whoami`, same on-behalf-of attribution and client-IP forwarding).
  Hand-rolled JSON-RPC 2.0 + MCP streamable-HTTP (stateless, json-response)
  and stdio transports — fully unit- and e2e-tested (10 tests). Single static
  binary instead of a ~250 MB Python image; ~3–5 MB RAM vs 41 MB. See
  `mcp-rs/PARITY.md`.
- `deploy/build-artifacts.sh` builds the Rust worker by default
  (cargo-zigbuild musl cross-compilation); `--go` keeps the legacy pipeline.
- Release CI (`.github/workflows/release.yml`): Rust worker cross-build +
  checksums (same asset names), MCP build/test/clippy + Docker smoke, hub test
  suite, and the legacy Go assets kept under `-go` suffixed checksums.

### Changed
- **Hub worker long-poll is now event-driven**: instead of re-checking the
  queue every 0.5 s per waiting worker (2N queries/s at N workers idle), a
  queued task now wakes only that VM's parked poll via a commit-scoped
  notifier — task pickup latency **≤0.5 s → <200 ms**, idle DB load **~0**.
  No API/schema change (same `/api/worker/tasks/next?wait=N`).
- The MCP service in `deploy/docker-compose*.yml` now builds from `mcp-rs/`.
  The Python server in `mcp/` remains as reference during the transition.


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

[1.0.0]: releases/tag/v1.0.0

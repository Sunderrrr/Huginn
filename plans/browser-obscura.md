# Plan — Browser automation via Obscura on Huginn workers

## Architecture

```
Dashboard / MCP agent
       │ POST /api/vms/{id}/browser  (steps: [navigate, click, type, eval, ...])
       ▼
   Hub (new task type `browser`, screenshots stored in DB)
       │ poll /api/worker/tasks/next
       ▼
  Worker (Linux only, #[cfg(target_os = "linux")])
       │ 1. obscura install check (or install task)
       │ 2. spawn `obscura serve` on 127.0.0.1:<ephemeral> with random CDP token
       │ 3. connect WebSocket to ws://127.0.0.1:<port>/devtools/browser
       │ 4. execute steps via CDP (Target.createTarget, Page.navigate, etc.)
       │ 5. screenshot → JPEG → base64 → submit_result
       │ 6. kill obscura process (process-group)
       ▼
  VM (obscura binary at /opt/huginn/obscura/<version>/obscura)
```

## Key decisions

### CDP client: minimal tokio-tungstenite

- `chromiumoxide` adds ~2 MB to the binary (too heavy for static musl)
- `headless_chrome` is blocking + designed for launching Chrome (wrong model)
- **Minimal client**: tokio-tungstenite + serde_json. We only need:
  - `Target.createTarget` (new tab)
  - `Target.attachToTarget` (CDP session)
  - `Page.navigate` (goto URL)
  - `Page.captureScreenshot` (PNG → convert to JPEG)
  - `Runtime.evaluate` (JS eval, get text/HTML, click via JS)
  - `Input.insertText` (type text into focused element)
  - `Input.dispatchMouseEvent` (click coordinates)
  - `Target.closeTarget` (close tab)
- Verified in Obscura source: all these methods exist in `crates/obscura-cdp/src/domains/`

### Task type: new `browser` enum

- PostgreSQL: `ALTER TYPE task_type ADD VALUE 'browser'` (migration 0004)
- Hub: `TaskType::Browser`, `BrowserTaskNew`, `create_browser_task`
- Worker: dispatch → `run_browser` (Linux) / "not supported" (Windows)

### Screenshot: JPEG in task result (≤ 1 MiB)

- `Page.captureScreenshot` returns PNG (Obscura)
- Worker converts PNG → JPEG (quality configurable, default 80) to stay under 1 MiB
- Stored as base64 in the task result `stdout` field
- Dashboard detects image results and renders them inline
- If JPEG > 900 KB → reduce quality, max 3 retries, then truncate

### Obscura installation: separate task type `browser_install`

- Admin-only, reuses update.rs SSRF allowlist (github.com)
- Downloads pinned version (v0.2.4) from github.com/h4ckf0r0day/obscura/releases
- Verifies glibc ≥ 2.35 (not musl/Alpine)
- Installs to `/opt/huginn/obscura/v0.2.4/` with LICENSE + THIRD_PARTY_NOTICES
- SHA-256 pinned in hub settings (admin can update)

### Session lifecycle

- Worker spawns `obscura serve --port <ephemeral> --cdp-token <random>` per browser task
- Timeout: configurable per-task (default 120s)
- Kill: process-group (existing exec.rs mechanism), `kill_on_drop(true)`
- No orphan obscura processes (verify in E2E test)

## Files to create/modify

### Worker (worker-rs)
- NEW `src/browser.rs` — obscura process management + CDP client + task handler
- `src/agent.rs` — dispatch `browser` task type
- `src/exec.rs` — reuse process-group kill (no changes needed, already #[cfg(unix)])
- `Cargo.toml` — add tokio-tungstenite (target unix only)

### Hub (hub-rs)
- `migrations/0004_browser_task.sql` — new enum value
- `src/models/enums.rs` — TaskType::Browser
- `src/models/task.rs` — BrowserTaskNew, create_browser_task
- `src/routes/fleet/browser.rs` — POST /api/vms/{id}/browser
- `src/routes/fleet/mod.rs` — merge browser routes

### Dashboard
- `src/pages/VMDetailPage.tsx` — browser task UI + screenshot display

### MCP
- `src/tools.rs` — browser_start, browser_navigate, browser_click, browser_type, browser_eval, browser_screenshot

### Docs/Legal
- `THIRD_PARTY_NOTICES.md` — Obscura
- `worker-rs/README.md` — browser capability
- `CHANGELOG.md` — Unreleased entry

## Security mitigations

1. **URL validation**: http/https only, no file://, size-limited
2. **SSRF**: Obscura's built-in SSRF protection (blocks private IPs by default)
3. **Admin gate**: browser_install + browser_exec_mode are admin-only toggles per VM
4. **No shell**: argv-pure spawn of obscura (never sh -c)
5. **Token**: random ≥ 32 bytes for CDP auth, never logged
6. **Audit**: every browser task logs URL + steps (not content of typed fields)
7. **Resource**: obscura process killed at timeout, memory limited via --worker-max-rss

## Binary size estimate

- tokio-tungstenite + tungstenite: ~150 KB added to the worker binary
- Current worker: ~3.3 MB → ~3.5 MB (acceptable)
- Obscura binary: 68 MB (downloaded to VM, NOT in the worker)

## Implementation order

1. [x] Read Obscura source, verify CDP methods
2. [ ] Write plan (this file)
3. [ ] Worker: browser.rs (CDP client + process management)
4. [ ] Worker: Cargo.toml + agent dispatch
5. [ ] Hub: migration + model + API
6. [ ] Worker E2E test (download Obscura, install, connect, navigate, screenshot)
7. [ ] Verify musl + Windows builds
8. [ ] Dashboard + MCP tools
9. [ ] Docs + CHANGELOG

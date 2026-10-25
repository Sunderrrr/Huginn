# Browser automation on Huginn workers (Obscura)

Huginn can drive a headless browser on a Linux VM in the fleet, from the
dashboard or through the MCP tools. The engine is
[Obscura](https://github.com/h4ckf0r0day/obscura), an open-source Rust-native
headless browser (Apache-2.0) that speaks CDP (Chrome DevTools Protocol).

## What you can do

| Action | Dashboard | MCP tool |
|---|---|---|
| Navigate to a URL and read the text | ✅ | `browser_navigate` |
| Full step sequences (click, type, keys, hover, scroll, cookies…) | ✅ | `browser_start` (see the step reference) |
| Take a screenshot (viewport or full page, shown inline) | ✅ | `browser_screenshot` (JPEG) · `browser_start` (JPEG/PNG) |
| Export the page as a PDF (download link) | ✅ | `browser_pdf` |
| Evaluate JavaScript and get the result | ✅ | `browser_eval` |
| Enable the capability on a VM (admin) | ✅ | `browser_enable` |
| Install the engine on a VM (admin) | ✅ | `browser_install` |

Linux only — Windows VMs answer "not supported".

## Prepare a VM

Two admin actions, once per VM. The engine needs glibc ≥ 2.35 (Ubuntu 22.04+,
Debian 12+, RHEL 9+, Fedora 36+), not Alpine/musl.

1. **Enable the capability** — the dashboard toggle, or
   `PUT /api/vms/{id}/browser-enabled {"enabled": true}` (admin only, audited
   as `toggle_browser`). Browser tasks are refused with a clear 403 until this
   is on. It is the browser equivalent of the exec-mode gate.
2. **Install the engine** — the dashboard button, or
   `POST /api/vms/{id}/browser-install` (admin only, audited as
   `browser_install_task`, MCP tool `browser_install`). The worker downloads the
   **hub-pinned** release (fleet settings: `browser_engine_version` plus
   per-arch `browser_engine_sha256_*`, default Obscura v0.2.4) from GitHub
   through the allowlist-validated client, verifies the SHA-256, and extracts
   it strictly into `/opt/huginn/obscura/<version>/` with the Apache-2.0
   license and a third-party notice. The worker then smoke-tests
   `obscura --version` before publishing the directory, so a failed install
   leaves nothing behind. `uninstall` removes the engine along with the rest of
   the worker.

The hub can check for a newer release on demand (`POST /api/browser-engine/check`,
MCP tool `browser_engine_check`) and re-pin the fleet settings when one ships.
A daily check does the same at the configured hour, but only when an admin
enables it: `browser_engine_auto_update` is off by default and
`browser_engine_check_time` holds the hour. Both are editable in the
dashboard.

**How do I know whether a node has the engine?** The engine lives on the
worker's filesystem, so the worker reports it: every heartbeat carries the
installed version (`vms.browser_engine_version`, migration 0009, where `null`
means "the worker says it has no engine"). The dashboard's browser card shows a
status dot — green with the version when it is installed, **red** when it is
missing (the run button is then disabled and the reason is spelled out), grey
while the worker has not reported yet. A worker that predates the report never
sends the field, so its state stays "unknown" and the run is **not** blocked.
"Unknown" is not "missing".

## Run a task

Through the API, with the steps of your choice:

```bash
curl -X POST https://<hub>/api/vms/<vm-id>/browser \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"steps":[{"action":"navigate","url":"https://example.com"},
                {"action":"get_text"}],"timeout":120}'
```

The hub answers `400` with the reason when a step is invalid, and `202` with
the task once it is queued. The MCP tools do the same thing with the presets
of your choice.

## How it works

```
Dashboard / MCP agent
       │  steps: navigate, click, type, eval, screenshot
       ▼
   Hub (task type `browser`, audit-logged)
       │  long-poll (existing model)
       ▼
  Worker spawns `obscura serve` on 127.0.0.1:<ephemeral-port>
       │  random CDP token, memory-limited, process-group isolated
       ▼
  CDP session: Target → Page.navigate → Input.insertText → Runtime.evaluate
       │  → Page.captureScreenshot (PNG → JPEG if needed)
       ▼
  Result submitted to hub (text + screenshot base64, ≤ 1 MiB)
  Obscura process killed (no orphans)
```

The worker never listens for inbound connections — the browser task uses the
existing long-poll task model. The CDP port is loopback-only with a random
authentication token, and the engine is bound by `--workers 2` and
`--max-connections 4`. `--worker-max-rss` is applied when the installed release
supports the flag (probed from its `serve --help`, the pinned v0.2.4 predates
it).

Sessions are per-task: each task spawns a fresh engine, executes its steps in
one tab, and tears everything down. No state (cookies, storage, logged-in
sessions) survives a task. Keeping a session open between tasks was considered
and deliberately left out: it would hold a browser process alive between polls
and leak login state across tasks.

## Validation

A step is checked three times (by the hub, by the MCP server, and again by
the worker), so an invalid step never reaches the browser:

- the **action** must be one of the 17 known ones, and each action's own
  fields must be present (`click` needs a selector, `type` needs a text, `eval`
  needs JavaScript, `scroll` needs a selector or `to`, `set_viewport` needs a
  width and a height between 200 and 5000 px);
- the **caps** are the worker's own: selector 512 characters, typed text
  10 KiB, evaluated script 64 KiB, awaited text 512 characters, 20 cookies,
  URL 2048 characters;
- the **URL** must be http(s), and the engine refuses private or link-local
  addresses.

The hub's validator is the canonical gate: a step it rejects comes back as a
400 with the reason, instead of being queued and failing on the worker.

## Security model

- **Off by default**: the capability is disabled per VM and an admin must
  enable it (like `unrestricted` mode), audited as `toggle_browser`. Operators
  can then run browser tasks, read-only users never can.
- **Hub-pinned install**: the engine version and the per-arch SHA-256 digests
  live in the fleet settings (admin-updatable), and the worker refuses any
  download that does not hash to the pin. Version tags are path-safe on both
  sides, so the install directory cannot be escaped.
- **SSRF**: the install download rides the updater's allowlist-validated client,
  and Obscura blocks private addresses with its own protection.
- **Resource limits**: the engine runs with `--workers 2` and
  `--max-connections 4`, and `--worker-max-rss` when the installed release
  supports it (512 MB by default, overridable with
  `HUGINN_BROWSER_MAX_RSS_MB`). The whole task also runs under the request's
  own timeout (≤ 300 s).
- **No shell**: Obscura is spawned as a separated argv, never `sh -c`, and the
  CDP token rides in the environment rather than in argv.
- **Audit**: every browser task records the user, the VM and the step count,
  never the content of typed fields (a `type` step can carry a password).
- **Guaranteed teardown**: the engine process, and its whole process group, is
  killed on every exit path, including a timeout or a panic
  (`kill_on_drop` plus a synchronous group-kill backstop). No orphan browser
  process survives a task.

## Step reference

A browser task is a sequence of steps executed in the same tab (1-50 steps,
whole-task `timeout` 1-300 s). The result is one `step N (action): detail`
line per step in the task stdout, and captures ride as base64 `data:` tags:

```json
{
  "steps": [
    { "action": "navigate", "url": "https://example.com" },
    { "action": "type", "selector": "#search", "text": "rust lang" },
    { "action": "press_key", "key": "enter" },
    { "action": "wait_for_text", "text": "results", "timeout_ms": 5000 },
    { "action": "get_text" },
    { "action": "screenshot", "format": "png", "full_page": true },
    { "action": "pdf" }
  ],
  "timeout": 120
}
```

| Step | Params | What it does |
|---|---|---|
| `navigate` | `url` | Loads the URL (http(s) only) and waits for the load |
| `click` | `selector` | Clicks the element (CSS selector) |
| `type` | `selector`, `text` | Focuses the element and types (the text is never echoed) |
| `press_key` | `key` | Presses a control key (`enter`, `tab`, `escape`, arrows, `pageup`…) or one ASCII character |
| `hover` | `selector` | Moves the mouse over the element (trusted `mouseenter`/`mouseover`) |
| `scroll` | `selector` or `to` | Scrolls an element into view, or to `top`/`bottom` |
| `eval` | `js` | Evaluates JavaScript and returns the result |
| `set_viewport` | `width`, `height` | Sets the page viewport (200-5000 px), so screenshots and layout follow |
| `wait_for` | `selector`, `timeout_ms` | Waits for a selector to appear in the DOM |
| `wait_for_text` | `text`, `timeout_ms` | Waits until the text appears in the page |
| `get_text` | — | Returns the page's inner text |
| `get_html` | — | Returns the page's outer HTML |
| `title` | — | Returns the page's title |
| `screenshot` | `format` (jpeg/png), `quality`, `full_page` | Captures the viewport, or the whole page with `full_page: true` (`data:image/…` tag) |
| `pdf` | `landscape`, `print_background`, `paper_width`, `paper_height` (inches, A4 default) | Exports the page as a PDF (`data:application/pdf` tag, Obscura's `Page.printToPDF`) |
| `get_cookies` | — | Lists the page's cookies (values can be session credentials, so only ask when you mean it) |
| `set_cookies` | `cookies: [{name, value, url}]` (1-20) | Fills Obscura's **request cookie jar** (carried by subsequent navigations). The page's `document.cookie` is a separate DOM store |

**Output format**: each step is exactly one line (`step N (action): detail`,
with multi-line details escaped as `\n`). Screenshots are ≤ 900 KiB, PDFs
≤ 768 KiB of base64, and the whole stdout is capped at 1 MiB. The dashboard
renders screenshots inline and PDFs as download links. The MCP tools return the
finished task with its stdout as is, so a caller gets the result in one round
trip.

## Binary size impact

The CDP client (tokio-tungstenite) adds ~150-200 KB to the Linux worker
binary. Obscura itself (~70 MB) is not embedded: it is downloaded to the VM at
install time.

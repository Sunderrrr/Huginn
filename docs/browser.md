# Browser automation on Huginn workers (Obscura)

Huginn can drive a headless browser on any Linux VM in the fleet, from the
dashboard or through the MCP tools. The engine is
[Obscura](https://github.com/h4ckf0r0day/obscura) — an open-source, Rust-native
headless browser (Apache-2.0) with a CDP (Chrome DevTools Protocol) server.

## What you can do

| Action | Dashboard | MCP tool |
|---|---|---|
| Navigate to a URL and read the text | ✅ | `browser_navigate` |
| Full step sequences (click, type, keys, hover, scroll, cookies…) | ✅ | `browser_start` (see the step reference) |
| Take a screenshot (JPEG/PNG, viewport or full page, shown inline) | ✅ | `browser_screenshot` |
| Export the page as a PDF (download link) | ✅ | `browser_pdf` |
| Evaluate JavaScript and get the result | ✅ | `browser_eval` |
| Install the engine on a VM (admin) | ✅ | `browser_install` |

Linux only — Windows VMs respond "not supported".

## Install the engine on a VM

Two admin actions, once per VM (Linux, glibc ≥ 2.35 — Ubuntu 22.04+, Debian
12+, RHEL 9+, Fedora 36+; not Alpine/musl):

1. **Enable the capability** — dashboard VM toggle, or
   `PUT /api/vms/{id}/browser-enabled {"enabled": true}` (admin only, audited
   `toggle_browser`). Browser tasks are refused with a clear 403 until this
   is on — the browser equivalent of the exec-mode gate.
2. **Install the engine** — dashboard button, or
   `POST /api/vms/{id}/browser-install` (admin only, audited
   `browser_install_task`; MCP tool `browser_install`). The worker downloads
   the **hub-pinned** release (fleet settings: `browser_engine_version`,
   per-arch `browser_engine_sha256_*`; defaults: Obscura v0.2.4) from GitHub
   (SSRF-allowlisted, redirect hops validated), verifies the SHA-256,
   extracts strictly into `/opt/huginn/obscura/<version>/` with the
   Apache-2.0 license and a third-party notice, smoke-tests
   `obscura --version`, and only then publishes the directory. A failed
   install leaves nothing behind; `uninstall` removes the engine with the
   rest of the worker.

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
authentication token, and the engine is bound by `--workers 2` /
`--max-connections 4` (plus `--worker-max-rss` when the installed release
supports it).

Sessions are per-task: each task spawns a fresh engine, executes its steps
in one tab, and tears everything down — no state (cookies, storage, logged-in
sessions) survives a task. Keeping a session open between tasks was
considered and deliberately left out: it would hold a browser process alive
between polls and leak login state across tasks.

## Security model

- **Off by default**: browser capability is disabled per VM; an admin must
  enable it (like `unrestricted` mode) — audited `toggle_browser`. Operators
  can then run browser tasks; readonly never can.
- **Hub-pinned install**: the engine version and per-arch SHA-256 digests
  live in the fleet settings (admin-updatable); the worker refuses any
  download that does not hash to the pin. Version tags are path-safe on both
  sides (no traversal in the install directory).
- **URL validation**: http(s):// only, size-limited.
- **SSRF**: Obscura blocks private IPs by default (its own SSRF protection);
  the install download rides the updater's allowlist-validated client.
- **Resource limits**: `obscura serve` runs with `--workers 2` and
  `--max-connections 4`; `--worker-max-rss <MB>` is applied when the
  installed engine supports the flag (probed from its `serve --help`; the
  pinned v0.2.4 predates it) and defaults to 512 MB, overridable via
  `HUGINN_BROWSER_MAX_RSS_MB`. The whole task additionally runs under the
  request's own timeout (≤ 300 s).
- **No shell**: Obscura is spawned as separated argv, never `sh -c` — the
  CDP token rides in the environment, never in argv.
- **Audit**: every browser task logs the URL count/step count, user, and VM
  — never the content of typed fields (a `type` step can carry a password).
- **Guaranteed teardown**: the engine process (whole process group) is
  killed on success, failure, timeout, and panics (`kill_on_drop` + a
  synchronous group-kill backstop) — no orphan browser processes.

## Step reference

A browser task is a sequence of steps executed in the same tab (1-50 steps,
whole-task `timeout` 1-300 s). Every step is validated by the hub, the MCP
server, and again by the worker (defense in depth). The result is one
`step N (action): detail` line per step in the task stdout — captures ride as
base64 `data:` tags:

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
| `navigate` | `url` | Loads the URL (http(s) only), waits for the load |
| `click` | `selector` | Clicks the element (CSS selector) |
| `type` | `selector`, `text` | Focuses the element and types (text never echoed) |
| `press_key` | `key` | Presses a control key (`enter`, `tab`, `escape`, arrows, `pageup`…) or one ASCII character |
| `hover` | `selector` | Moves the mouse over the element (trusted `mouseenter`/`mouseover`) |
| `scroll` | `selector` or `to` | Scrolls an element into view, or to `top`/`bottom` |
| `eval` | `js` | Evaluates JavaScript, returns the result |
| `set_viewport` | `width`, `height` | Sets the page viewport (200-5000 px) — screenshots and layout follow |
| `wait_for` | `selector`, `timeout_ms` | Waits for a selector to appear in the DOM |
| `wait_for_text` | `text`, `timeout_ms` | Waits until the text appears in the page |
| `get_text` | — | Returns the page's inner text |
| `get_html` | — | Returns the page's outer HTML |
| `title` | — | Returns the page's title |
| `screenshot` | `format` (jpeg/png), `quality`, `full_page` | Captures the viewport — or the whole page with `full_page: true` (`data:image/…` tag) |
| `pdf` | `landscape`, `print_background`, `paper_width`, `paper_height` (inches, A4 default) | Exports the page as a PDF (`data:application/pdf` tag, Obscura's `Page.printToPDF`) |
| `get_cookies` | — | Lists the page's cookies (values can be session credentials — only ask when you mean it) |
| `set_cookies` | `cookies: [{name, value, url}]` (1-20) | Fills Obscura's **request cookie jar** (carried by subsequent navigations); the page's `document.cookie` is a separate DOM store |

**Output format**: each step is exactly one line (`step N (action): detail`,
multi-line details escaped as `\n`) — screenshots ≤ 900 KiB, PDFs ≤ 768 KiB of
base64, the whole stdout capped at 1 MiB. The dashboard renders screenshots
inline and PDFs as download links; the MCP returns the task with stdout as
is.

## Binary size impact

The CDP client (tokio-tungstenite) adds ~150-200 KB to the Linux worker
binary. Obscura itself (~68 MB) is NOT embedded — it's downloaded to the VM
at install time.

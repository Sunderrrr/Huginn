# Browser automation on Huginn workers (Obscura)

Huginn can drive a headless browser on any Linux VM in the fleet, from the
dashboard or through the MCP tools. The engine is
[Obscura](https://github.com/h4ckf0r0day/obscura) — an open-source, Rust-native
headless browser (Apache-2.0) with a CDP (Chrome DevTools Protocol) server.

## What you can do

| Action | Dashboard | MCP tool |
|---|---|---|
| Navigate to a URL and read the text | ✅ | `browser_navigate` |
| Click an element, type text, run JS | ✅ | `browser_start` (step sequences) |
| Take a screenshot (JPEG, shown inline) | ✅ | `browser_screenshot` |
| Evaluate JavaScript and get the result | ✅ | `browser_eval` |

Linux only — Windows VMs respond "not supported".

## Install Obscura on a VM

The VM admin triggers an install (one-time, per VM):

```
Dashboard → VM detail → Install browser engine
```

or through the hub API (`POST /api/vms/{id}/browser-install`). The worker
downloads the pinned Obscura release from GitHub (SSRF allowlisted, SHA-256
verified), installs it to `/opt/huginn/obscura/<version>/` with the license,
and runs a smoke test (`obscura --version`).

Requirements on the VM: Linux with glibc ≥ 2.35 (Ubuntu 22.04+, Debian 12+,
RHEL 9+, Fedora 36+). Not supported on Alpine/musl.

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
authentication token.

## Security model

- **Off by default**: browser capability is disabled per VM; an admin must
  enable it (like `unrestricted` mode).
- **URL validation**: http(s):// only, size-limited.
- **SSRF**: Obscura blocks private IPs by default (its own SSRF protection).
- **Resource limits**: memory capped via `--worker-max-rss`, hard timeout.
- **No shell**: Obscura is spawned as separated argv (`["obscura", "serve",
  "--port", port]`), never `sh -c`.
- **Audit**: every browser task logs the URL, step count, user, and VM —
  never the content of typed fields.

## Step reference

A browser task is a sequence of steps executed in the same tab:

```json
{
  "steps": [
    { "action": "navigate", "url": "https://example.com" },
    { "action": "type", "selector": "#search", "text": "rust lang" },
    { "action": "click", "selector": "#submit" },
    { "action": "wait_for", "selector": "#results", "timeout_ms": 5000 },
    { "action": "get_text" },
    { "action": "screenshot", "format": "jpeg", "quality": 80 }
  ],
  "timeout": 120
}
```

| Step | Params | What it does |
|---|---|---|
| `navigate` | `url` | Loads the URL, waits for the page |
| `click` | `selector` | Clicks the element (CSS selector) |
| `type` | `selector`, `text` | Focuses the element and types |
| `eval` | `js` | Evaluates JavaScript, returns the result |
| `wait_for` | `selector`, `timeout_ms` | Waits for the selector to appear |
| `get_text` | — | Returns the page's inner text |
| `get_html` | — | Returns the page's outer HTML |
| `screenshot` | `format`, `quality` | Captures a screenshot (JPEG) |

## Binary size impact

The CDP client (tokio-tungstenite) adds ~150-200 KB to the Linux worker
binary. Obscura itself (~68 MB) is NOT embedded — it's downloaded to the VM
at install time.

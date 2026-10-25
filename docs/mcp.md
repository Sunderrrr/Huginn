# MCP integration

The MCP server exposes the hub's capabilities as tools for an external AI agent
(that is, any MCP-capable client). It is a thin façade over the hub REST API — no
business logic is duplicated, and it never contacts workers directly.

## Tools

| Tool | Purpose |
|---|---|
| `list_vms(state?, brief?)` | List fleet VMs, optionally filtered by state. `brief=true` returns a compact roster. |
| `get_vm_status(vm_id)` | Full status of one VM. |
| `execute_action(vm_id, action, params?, wait?)` | Run a whitelisted action. |
| `execute_command(vm_id, command, wait?)` | Run a free command (unrestricted VMs only). |
| `trigger_update(vm_id)` | Update a worker toward the target version. |
| `list_actions(vm_id?)` | List admin-defined custom commands (optionally only those runnable on a VM). |
| `get_task(task_id)` | Read a task's status/result once. |
| `wait_for_task(task_id, timeout?)` | Block until the task finishes (or timeout) — no poll loop. |
| `get_audit_log(vm_id?, event_type?, limit?)` | Read audit entries. |
| `browser_enable(vm_id, enabled)` | Arm (or disarm) the browser capability of a VM (admin). |
| `browser_engine_check()` | Check the pinned Obscura release now and re-pin it if a newer one ships (admin). |
| `browser_install(vm_id, wait?)` | Install the pinned Obscura engine on a VM (admin). |
| `browser_start(vm_id, steps, timeout?, wait?)` | Run a step sequence on a headless browser. |
| `browser_navigate(vm_id, url, timeout?, wait?)` | Load a URL and return the page text. |
| `browser_screenshot(vm_id, url, quality?, timeout?, wait?)` | Load a URL and return a JPEG capture. PNG is reachable through `browser_start`. |
| `browser_pdf(vm_id, url, timeout?, wait?)` | Load a URL and return a PDF. |
| `browser_eval(vm_id, url, js, timeout?, wait?)` | Load a URL and evaluate JavaScript in the page. |

> **A tool that creates a task returns the result, not a handle.** The browser
> family and the action/command tools wait for their task (the hub holds the
> wait server-side) and hand back the finished task with its stdout inline —
> one round trip for what is usually a one-second operation. Pass `wait=false`
> for the long ones (a ~70 MB engine install): you then get the task id and
> call `wait_for_task(task_id)` **once** — never poll `get_task` in a loop.
>
> `list_vms(brief=true)` returns a compact roster (id, name, state, mode) —
> handy as a session-opening overview.
>
> The VM-targeting tools (`get_vm_status`, `execute_action`, `execute_command`,
> `trigger_update`, the browser tools) accept a VM **id or name** (name match is
> case-insensitive). Prefer the **name** — it's stable across re-enrollment,
> which mints a new id (a cached id then 404s).
>
> **Custom commands** (admin-defined, see the dashboard Commands page) run via
> `execute_action` by name, exactly like built-ins. Discover them with
> `list_actions` — pass a `vm_id` to get only those runnable on that VM right now
> (it must be in `custom`/`unrestricted` mode and carry a matching tag).

### Browser tools in practice

`browser_start` takes a list of steps, executed in order on one tab:

```json
{ "vm_id": "web-01",
  "steps": [
    { "action": "navigate", "url": "https://example.com" },
    { "action": "type", "selector": "#q", "text": "rust" },
    { "action": "click", "selector": "#go" },
    { "action": "get_text" }
  ],
  "timeout": 120 }
```

The 17 actions are `navigate`, `click`, `type`, `press_key`, `hover`, `scroll`,
`eval`, `set_viewport`, `screenshot`, `pdf`, `get_text`, `get_html`, `title`,
`wait_for`, `wait_for_text`, `get_cookies`, `set_cookies` — see
[browser.md](browser.md) for the reference.

Two prerequisites, both outside the agent's reach: the **capability** must be
enabled on the VM (`browser_enable`, admin) and the **Obscura engine** must be
installed on it (`browser_install`, admin). The hub refuses a browser task
with a 403 naming the missing step when the capability is off, and refuses the
task at creation time when a step is invalid. The engine is a ~70 MB download
the hub pins by version *and* SHA-256.

## Authentication model

Two layers, kept distinct:

| Token | Where it lives | Purpose |
|---|---|---|
| **Service token** (`HUGINN_MCP_SERVICE_TOKEN`) | Env var on the MCP server + hub | Proves "I am the MCP server" on every MCP→hub call. Server-held, never given to agents. |
| **Per-user MCP token** | Created by each user in the dashboard → **MCP Tokens** | Identifies the *end user*. The agent sends it as `Authorization: Bearer <token>`. |

How a request flows on **streamable-http**:

1. The agent sends `Authorization: Bearer <per-user-token>`.
2. The MCP server validates that token against the hub and forwards it as
   `X-MCP-On-Behalf-Of` alongside the service token.
3. The hub resolves the token → its owning user and acts **as that user**: the
   action runs with the user's real role and is attributed to them in the audit
   log as `mcp · <username>`.

A per-user token alone is useless: it is only honoured when presented *together*
with the server-held service token, so a leaked user token cannot hit the hub
directly. Tokens are stored HMAC-hashed and shown in plaintext only once.

> **stdio** has no HTTP layer and therefore no per-user token. In stdio mode the
> MCP server calls the hub with the service token only, acting as the anonymous
> automation agent (**operator, not admin**, no per-user attribution). Use
> **streamable-http** when you want per-user identity, real-role enforcement, and
> `mcp · <username>` attribution.

### Per-token IP allow-list (optional)

Each token can be pinned to a single IP or CIDR (set at creation, editable
later, or left blank for "any"). A request from any other source is rejected.
For this to be a real control rather than a header anyone can forge, the edge
proxy must stamp the real client IP into `X-Real-IP` (the bundled Caddyfile does
this on `/mcp`, overwriting client-supplied values). The MCP server only
honours that header when `HUGINN_MCP_TRUST_PROXY=true` (the bundled compose
files set it), and `HUGINN_MCP_TRUSTED_PROXY_CIDRS` narrows which peers may
stamp it. With the default, the forwarded headers are ignored and the
allow-list is checked against the proxy's own address. See
[mcp-agents.md](mcp-agents.md#network-security).

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `HUGINN_MCP_HUB_URL` | `http://hub:8000` | Hub base URL. |
| `HUGINN_MCP_SERVICE_TOKEN` | — | Service token (must match the hub's `HUGINN_MCP_SERVICE_TOKEN`). |
| `HUGINN_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http`. |
| `HUGINN_MCP_HOST` / `HUGINN_MCP_PORT` | `127.0.0.1` / `9000` | HTTP bind (streamable-http). The bundled compose file sets `0.0.0.0`. |

There is **no** client-token env var — the HTTP endpoint is gated by
per-user tokens validated against the hub.

## Adding it to an agent

### stdio (local subprocess)

```json
{
  "mcpServers": {
    "huginn": {
      "command": "/path/to/Huginn/mcp-rs/target/release/huginn-mcp",
      "env": {
        "HUGINN_MCP_HUB_URL": "https://hub.example.com",
        "HUGINN_MCP_SERVICE_TOKEN": "<service-token>"
      }
    }
  }
}
```

### Streamable HTTP (remote)

1. Create a token in the dashboard → **MCP Tokens** (copy it — shown once).
2. Run the server (or the `mcp` compose service) with
   `HUGINN_MCP_TRANSPORT=streamable-http`.
3. Point the agent at it, sending your per-user token:

```json
{
  "mcpServers": {
    "huginn": {
      "url": "https://your-host/mcp",
      "headers": {
        "Authorization": "Bearer <your-per-user-token>"
      }
    }
  }
}
```

## Connecting to other agents

See [MCP Agent Integrations](mcp-agents.md) for detailed setup guides for
Claude Desktop, Claude Code, Cursor, Continue, OpenAI proxies, and more.

## Security notes

- The **service token** grants automation access to the hub (operator-level for
  service-only calls). Keep it secret and scope network access to the endpoint.
- **Per-user tokens** carry the owner's real role. Make one per agent/machine,
  pin it to an IP where practical, and revoke any you no longer use — each is
  individually revocable from the dashboard.
- Every action flows through the same hub authz, rate limits, and tamper-evident
  audit log as the dashboard, attributed to the acting user.
- `execute_command` still requires the target VM to be in unrestricted mode.
- The **browser** family needs an admin: `browser_enable` arms the capability
  for one VM, `browser_install` puts the engine on it. The download is pinned by
  SHA-256, and the engine refuses to reach private or link-local addresses. An
  agent that can run browser steps on a node can therefore read what that
  node's browser can read — arm the capability deliberately.
- `eval` runs arbitrary JavaScript **in the page**, under the admin who
  enabled the capability. It is not sandboxed beyond the browser's own origin
  rules.

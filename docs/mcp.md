# MCP integration

The MCP server exposes the hub's capabilities as tools for an external AI agent
(e.g. "Hermes"). It is a thin façade over the hub REST API — no business logic is
duplicated, and it never contacts workers directly.

## Tools

| Tool | Purpose |
|---|---|
| `list_vms(state?)` | List fleet VMs, optionally filtered by state. |
| `get_vm_status(vm_id)` | Full status of one VM. |
| `execute_action(vm_id, action, params?, wait?)` | Run a whitelisted action. |
| `execute_command(vm_id, command, wait?)` | Run a free command (unrestricted VMs only). |
| `trigger_update(vm_id)` | Update a worker toward the target version. |
| `list_actions(vm_id?)` | List admin-defined custom commands (optionally only those runnable on a VM). |
| `get_task(task_id)` | Poll a task's status/result once. |
| `wait_for_task(task_id, timeout?)` | Block until the task finishes (or timeout) — no poll loop. |
| `get_audit_log(vm_id?, event_type?, limit?)` | Read audit entries. |

> For a long action/command launched with `wait=false`, call `wait_for_task` to
> be returned the result the instant the worker reports it, instead of polling
> `get_task` repeatedly. `list_vms(brief=true)` returns a compact roster (id,
> name, state, mode) — handy as a session-opening overview.
>
> The VM-targeting tools (`get_vm_status`, `execute_action`, `execute_command`,
> `trigger_update`) accept a VM **id or name** (name match is case-insensitive).
> Prefer the **name** — it's stable across re-enrollment, which mints a new id (a
> cached id then 404s).
>
> **Custom commands** (admin-defined, see the dashboard Commands page) run via
> `execute_action` by name, exactly like built-ins. Discover them with
> `list_actions` — pass a `vm_id` to get only those runnable on that VM right now
> (it must be in `custom`/`unrestricted` mode and carry a matching tag).

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
this on `/mcp`, overwriting client-supplied values); the MCP server trusts that
and forwards it to the hub. See [mcp-agents.md](mcp-agents.md#network-security).

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `HUGINN_MCP_HUB_URL` | `http://localhost:8000` | Hub base URL. |
| `HUGINN_MCP_SERVICE_TOKEN` | — | Service token (must match the hub's `HUGINN_MCP_SERVICE_TOKEN`). |
| `HUGINN_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http`. |
| `HUGINN_MCP_HOST` / `HUGINN_MCP_PORT` | `0.0.0.0` / `9000` | HTTP bind (streamable-http). |

There is **no** client-token env var anymore — the HTTP endpoint is gated by
per-user tokens validated against the hub.

## Adding it to an agent

### stdio (local subprocess)

```json
{
  "mcpServers": {
    "huginn": {
      "command": "python",
      "args": ["-m", "app.server"],
      "cwd": "/path/to/Huginn/mcp",
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
Hermes, Claude Desktop, Claude Code, Cursor, Continue, OpenAI proxies, and more.

## Security notes

- The **service token** grants automation access to the hub (operator-level for
  service-only calls). Keep it secret and scope network access to the endpoint.
- **Per-user tokens** carry the owner's real role. Make one per agent/machine,
  pin it to an IP where practical, and revoke any you no longer use — each is
  individually revocable from the dashboard.
- Every action flows through the same hub authz, rate limits, and tamper-evident
  audit log as the dashboard, attributed to the acting user.
- `execute_command` still requires the target VM to be in unrestricted mode.

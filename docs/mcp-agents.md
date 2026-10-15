# Connecting MCP to AI Agents

The Huginn MCP server is a thin façade over the hub REST API. Any agent that
supports the [Model Context Protocol](https://modelcontextprotocol.io) can drive
your fleet. Claude is a common choice. Cursor and Continue work too, and other
MCP-capable agents can connect as well.

## Prerequisites

1. A running Huginn stack (hub + MCP server).
2. The **service token** (`HUGINN_MCP_SERVICE_TOKEN`) — used by the MCP server to
   call the hub API. Set in `.env`; it must match the hub's value. Generate with
   `openssl rand -hex 32`. This is server-side only; agents never see it.
3. A **per-user MCP token** for streamable-http: open the dashboard →
   **MCP Tokens**, click *Create*, give it a name (e.g. `my-laptop`), and copy
   the token — it is shown only once. Each token belongs to you: actions run with
   *your* role and appear as `mcp · <your-username>` in the audit log. Optionally
   pin it to an IP/CIDR so it only works from one machine.
4. Choose a transport:
   - **stdio** — agent and MCP server run on the same machine (the agent spawns
     the process). No per-user token; calls run as the anonymous automation agent
     (operator, no per-user attribution).
   - **streamable-http** — MCP server runs remotely (recommended). Each agent
     authenticates with its own per-user token, giving real-role enforcement and
     per-user audit attribution.

## Transport setup

### stdio (local)

No extra setup — the agent launches the `huginn-mcp` binary (built from
`mcp-rs/`, stdio by default) as a subprocess. The hub URL and service token are
passed via environment variables in the agent config.

### streamable-http (remote)

Start the MCP server with HTTP transport:

```bash
HUGINN_MCP_TRANSPORT=streamable-http \
HUGINN_MCP_HUB_URL=https://hub.example.com \
HUGINN_MCP_SERVICE_TOKEN=<service-token> \
HUGINN_MCP_HOST=0.0.0.0 \
HUGINN_MCP_PORT=9000 \
huginn-mcp
```

Or use the `mcp` service from `docker-compose.yml` (already configured for
streamable-http on port 9000, behind Caddy at `/mcp`).

> The HTTP endpoint is gated by **per-user tokens** validated against the hub —
> there is no shared client token to configure. A request without a valid token
> gets `401`.

---

## Agent configurations

In every **HTTP** example below, `<your-mcp-token>` is the per-user token you
created in the dashboard → **MCP Tokens**. Replace `https://example.com/mcp` with
your deployment's MCP URL. In the **stdio** examples, replace the binary path
with where you built `huginn-mcp`.

Most agents share the same two shapes:

**stdio:**

```json
{
  "mcpServers": {
    "huginn": {
      "command": "/path/to/mcp-rs/target/release/huginn-mcp",
      "env": {
        "HUGINN_MCP_HUB_URL": "https://hub.example.com",
        "HUGINN_MCP_SERVICE_TOKEN": "<service-token>"
      }
    }
  }
}
```

**HTTP (remote):**

```json
{
  "mcpServers": {
    "huginn": {
      "url": "https://example.com/mcp",
      "headers": {
        "Authorization": "Bearer <your-mcp-token>"
      }
    }
  }
}
```

### Claude Desktop

Add the block above (stdio or HTTP) to
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
`%APPDATA%\Claude\claude_desktop_config.json` (Windows), then restart Claude
Desktop. The Huginn tools appear in the tool list.

### Claude Code (CLI)

```bash
# stdio
claude mcp add huginn -- /path/to/mcp-rs/target/release/huginn-mcp

# HTTP (remote)
claude mcp add --transport http \
  huginn https://example.com/mcp \
  --header "Authorization: Bearer <your-mcp-token>"
```

Or define it in a project `.mcp.json` using the shared stdio/HTTP shapes above.

### Cursor

Add the block (stdio or HTTP) to `.cursor/mcp.json` in your project root (or the
global settings).

### Continue (VS Code / JetBrains)

Add to `~/.continue/config.json`. The `mcpServers` entry is an array with an
explicit `transport` object:

```json
{
  "mcpServers": [
    {
      "name": "huginn",
      "transport": {
        "type": "streamable-http",
        "url": "https://example.com/mcp",
        "headers": { "Authorization": "Bearer <your-mcp-token>" }
      }
    }
  ]
}
```

For stdio, use `"type": "stdio"` with `command` + `env` as in the shared shape.

### OpenAI / ChatGPT (function calling via proxy)

OpenAI does not natively speak MCP. Bridge it with an MCP-to-OpenAI proxy such as
[mcp-proxy](https://github.com/sparfenyuk/mcp-proxy):

```bash
mcp-proxy --mcp-url https://example.com/mcp \
  --header "Authorization: Bearer <your-mcp-token>" \
  --openai-port 8080
```

Then point your OpenAI client at `http://localhost:8080`.

### Any agent via mcp-cli (testing)

For quick testing or scripting, use [mcp-cli](https://github.com/wong2/mcp-cli):

```bash
npm install -g mcp-cli

mcp-cli --url https://example.com/mcp \
  --header "Authorization: Bearer <your-mcp-token>" \
  list-tools

mcp-cli --url https://example.com/mcp \
  --header "Authorization: Bearer <your-mcp-token>" \
  call list_vms '{"state": "active"}'
```

---

## Available tools

Once connected, the agent has access to these tools:

| Tool | Description |
|---|---|
| `list_vms(state?, brief?)` | List fleet VMs, optionally by state (`brief` = compact roster) |
| `get_vm_status(vm_id)` | Full VM status (state, mode, version, heartbeat) |
| `list_actions(vm_id?)` | List admin-defined custom commands (runnable on a VM with `vm_id`) |
| `execute_action(vm_id, action, params?, wait?)` | Run a built-in or custom action |
| `execute_command(vm_id, command, wait?)` | Free shell command (unrestricted VMs only) |
| `trigger_update(vm_id)` | Trigger worker self-update |
| `get_task(task_id)` | Poll task status and result once |
| `wait_for_task(task_id, timeout?)` | Block until the task finishes (or timeout) — avoids a poll loop |
| `get_audit_log(vm_id?, event_type?, limit?)` | Read audit entries |

> **Long tasks — do not poll `get_task` in a loop.** Either pass `wait=true` to
> `execute_action`/`execute_command` to get the result inline, or after launching
> with `wait=false` call `wait_for_task(task_id)` **once** — it blocks server-side
> (event-driven, no busy polling) and returns the instant the worker reports a
> result. Only call it again if it returned still-running at the timeout.
> `get_task` is a one-off status check, not a busy-wait. Use
> `list_vms(brief=true)` for a compact roster (id, name, state, mode).
>
> The MCP server ships these usage rules as connection `instructions`, so a
> compliant client surfaces them to the model automatically.

### Whitelisted actions

`execute_action` supports these built-in actions (no unrestricted mode needed):

| Action | Params | Description |
|---|---|---|
| `status` | — | System status report |
| `metrics` | — | CPU, memory, disk usage |
| `restart_service` | `service` | Restart a systemd service |
| `list_upgradable_packages` | — | Available package upgrades |
| `apt_upgrade` | — | Run package upgrade |
| `update_worker` | — | Self-update the worker binary |

### Example agent prompts

- *"List all active VMs and their uptime"*
- *"Check disk usage on vm-prod-01"*
- *"Restart nginx on vm-web-02"*
- *"Run `df -h` on all VMs and show me which ones are over 80%"*
- *"Update the worker on vm-staging-01 to the latest version"*
- *"Show me the last 20 audit log entries"*

---

## Security

Two token layers, kept distinct:

| Token | Where | Direction | Purpose |
|---|---|---|---|
| **Service token** | `HUGINN_MCP_SERVICE_TOKEN` (env) | MCP server → Hub | Internal trust. The MCP server uses it on every hub call. Never shared with agents. |
| **Per-user MCP token** | Dashboard → MCP Tokens | Agent → MCP server | Identifies the end user. Sent as `Authorization: Bearer <token>`; the action runs with that user's role and is attributed to them. |

- A per-user token is only honoured **together with** the server-held service
  token, so a leaked user token cannot hit the hub directly.
- Per-user tokens carry the owner's **real role**: a read-only user's token cannot
  execute; an admin's can. The anonymous service-token agent (stdio, or HTTP with
  no per-user token) is **operator, not admin**.
- All agent actions are **logged in the audit trail** as `mcp · <username>`, with
  the originating client IP.
- `execute_command` requires the VM to be in **unrestricted mode** (set by an
  admin in the dashboard, audited on every toggle).
- Rate limits apply: `HUGINN_RATE_LIMIT_EXEC_PER_MINUTE` (default: 30).
- The MCP server never contacts workers directly — everything goes through the
  hub's auth and authorization layer.

### Network security

Put the MCP server behind a reverse proxy with TLS. The bundled **Caddy** config
already proxies `/mcp` and stamps the real client IP into `X-Real-IP`
(overwriting any client-supplied value), which is what makes the per-token IP
allow-list trustworthy:

```caddyfile
handle /mcp* {
    reverse_proxy mcp:9000 {
        header_up X-Real-IP {remote_host}
    }
}
```

With **nginx** instead, set the same trusted header (and ensure nginx is the only
thing that can write it):

```nginx
location /mcp {
    proxy_pass http://localhost:9000/mcp;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;   # overwrites any client value
    # Optionally restrict at the proxy too:
    # allow 192.0.2.0/24; deny all;
}
```

The MCP server trusts `X-Real-IP` (over `X-Forwarded-For`) and forwards it to the
hub, which enforces each token's IP allow-list at connect time and on every tool
call.

### Pinning a token to an IP

In the dashboard → **MCP Tokens**, set *Allowed IP / CIDR* when creating a token
(or edit it later). Examples: `203.0.113.7` (one host) or `192.0.2.0/24` (a
subnet). Leave it blank to allow any source. A request from a different IP is
rejected with `401`.

### Token rotation / revocation

- **Per-user token**: revoke it in the dashboard → **MCP Tokens** (the agent
  using it stops working immediately), then create a new one and update that
  agent's config. No restart needed.
- **Service token**: rotate the env value and restart the hub + MCP together:

```bash
SERVICE_TOKEN=$(openssl rand -hex 32)
sed -i "s/HUGINN_MCP_SERVICE_TOKEN=.*/HUGINN_MCP_SERVICE_TOKEN=$SERVICE_TOKEN/" deploy/.env
cd deploy && docker compose up -d hub mcp
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `401 Unauthorized` from MCP | Missing / wrong / revoked per-user token | Create a fresh token in the dashboard and send it as `Authorization: Bearer <token>` |
| `401` only from one machine | Token pinned to a different IP | Update the token's *Allowed IP* (or clear it); check the proxy sets `X-Real-IP` |
| Actions attributed to the wrong user | Sharing one token across people | Give each user/agent its own token |
| `401 Unauthorized` from hub | Service token mismatch | Ensure `HUGINN_MCP_SERVICE_TOKEN` matches the hub's |
| `execute_command` fails | VM not in unrestricted mode | Enable unrestricted mode in the dashboard |
| `Connection refused` | MCP server not running | `docker compose up mcp` or check logs |
| Tools not appearing in agent | Config not loaded | Restart the agent after editing config |
| `HubError 500` | Hub is down | Check `docker compose logs hub` |

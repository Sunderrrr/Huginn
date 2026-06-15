# Connecting MCP to AI Agents

The Huginn MCP server is a thin façade over the hub REST API. Any agent that
supports the [Model Context Protocol](https://modelcontextprotocol.io) can drive
your fleet — Hermes, Claude, Cursor, Continue, and more.

## Prerequisites

1. A running Huginn stack (hub + MCP server).
2. Two tokens (generate with `openssl rand -hex 32`):
   - **Service token** (`HUGINN_MCP_SERVICE_TOKEN`) — used by the MCP server to
     call the hub API. Set in `.env`, must match the hub's value.
   - **Client token** (`HUGINN_MCP_MCP_CLIENT_TOKEN`) — agents must send this as
     `Authorization: Bearer <token>` to reach the HTTP endpoint. Set in `.env`.
3. Choose a transport:
   - **stdio** — agent and MCP server run on the same machine (agent spawns the
     process). No client token needed (process-level isolation).
   - **streamable-http** — MCP server runs remotely (recommended). Requires the
     client token on every request.

## Transport setup

### stdio (local)

No extra setup needed — the agent launches `python -m app.server` as a
subprocess. The hub URL and service token are passed via environment variables in
the agent config.

### streamable-http (remote)

Start the MCP server with HTTP transport:

```bash
HUGINN_MCP_TRANSPORT=streamable-http \
HUGINN_MCP_HUB_URL=https://hub.example.com \
HUGINN_MCP_SERVICE_TOKEN=<service-token> \
HUGINN_MCP_MCP_CLIENT_TOKEN=<client-token> \
HUGINN_MCP_HOST=0.0.0.0 \
HUGINN_MCP_PORT=9000 \
python -m app.server
```

Or use the `mcp` service from `docker-compose.yml` (already configured for
streamable-http on port 9000).

> **Without `HUGINN_MCP_MCP_CLIENT_TOKEN`**, the HTTP endpoint is open to anyone
> who can reach it. Always set this token in production.

---

## Agent configurations

### Hermes (custom agent)

**stdio:**
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

**HTTP:**
```json
{
  "mcpServers": {
    "huginn": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <client-token>"
      }
    }
  }
}
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

**stdio:**
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

**HTTP (remote):**
```json
{
  "mcpServers": {
    "huginn": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <client-token>"
      }
    }
  }
}
```

Restart Claude Desktop after saving. The Huginn tools will appear in the tool
list.

### Claude Code (CLI)

stdio:
```bash
claude mcp add huginn \
  -- python -m app.server
```

HTTP:
```bash
claude mcp add huginn \
  --transport http \
  --url https://mcp.example.com/mcp \
  --header "Authorization: Bearer <client-token>"
```

With env vars, create a `.mcp.json` in your project root:

**stdio:**
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

**HTTP:**
```json
{
  "mcpServers": {
    "huginn": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <client-token>"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project root (or global settings):

**stdio:**
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

**HTTP:**
```json
{
  "mcpServers": {
    "huginn": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <client-token>"
      }
    }
  }
}
```

### Continue (VS Code / JetBrains)

Add to `~/.continue/config.json`:

**HTTP:**
```json
{
  "mcpServers": [
    {
      "name": "huginn",
      "transport": {
        "type": "streamable-http",
        "url": "https://mcp.example.com/mcp",
        "headers": {
          "Authorization": "Bearer <client-token>"
        }
      }
    }
  ]
}
```

**stdio:**
```json
{
  "mcpServers": [
    {
      "name": "huginn",
      "transport": {
        "type": "stdio",
        "command": "python",
        "args": ["-m", "app.server"],
        "cwd": "/path/to/Huginn/mcp",
        "env": {
          "HUGINN_MCP_HUB_URL": "https://hub.example.com",
          "HUGINN_MCP_SERVICE_TOKEN": "<service-token>"
        }
      }
    }
  ]
}
```

### OpenAI / ChatGPT (function calling via proxy)

OpenAI doesn't natively support MCP, but you can use an MCP-to-OpenAI proxy
like [mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) or
[toolhouse](https://toolhouse.ai) to bridge the gap:

```bash
# Start the proxy (converts MCP tools to OpenAI function definitions)
mcp-proxy --mcp-url https://mcp.example.com/mcp \
  --header "Authorization: Bearer <client-token>" \
  --openai-port 8080
```

Then point your OpenAI client at `http://localhost:8080`.

### Any agent via mcp-cli (testing)

For quick testing or scripting, use the
[mcp-cli](https://github.com/wong2/mcp-cli):

```bash
# Install
npm install -g mcp-cli

# List available tools
mcp-cli --url https://mcp.example.com/mcp \
  --header "Authorization: Bearer <client-token>" \
  list-tools

# Call a tool
mcp-cli --url https://mcp.example.com/mcp \
  --header "Authorization: Bearer <client-token>" \
  call list_vms '{"state": "active"}'
```

---

## Available tools

Once connected, the agent has access to these tools:

| Tool | Description |
|---|---|
| `list_vms(state?)` | List fleet VMs, optionally by state |
| `get_vm_status(vm_id)` | Full VM status (state, mode, version, heartbeat) |
| `execute_action(vm_id, action, params?, wait?)` | Run a whitelisted action |
| `execute_command(vm_id, command, wait?)` | Free shell command (unrestricted VMs only) |
| `trigger_update(vm_id)` | Trigger worker self-update |
| `get_task(task_id)` | Poll task status and result |
| `get_audit_log(vm_id?, event_type?, limit?)` | Read audit entries |

### Whitelisted actions

`execute_action` supports these built-in actions (no unrestricted mode needed):

| Action | Params | Description |
|---|---|---|
| `status` | — | System status report |
| `metrics` | — | CPU, memory, disk usage |
| `restart_service` | `service` | Restart a systemd service |
| `list_upgradable_packages` | — | Available apt upgrades |
| `apt_upgrade` | — | Run apt upgrade |
| `update_worker` | — | Self-update the worker binary |

### Example agent prompts

Once connected, you can ask your agent things like:

- *"List all active VMs and their uptime"*
- *"Check disk usage on vm-prod-01"*
- *"Restart nginx on vm-web-02"*
- *"Run `df -h` on all VMs and show me which ones are over 80%"*
- *"Update the worker on vm-staging-01 to the latest version"*
- *"Show me the last 20 audit log entries"*

---

## Security

Two tokens are involved — don't confuse them:

| Token | Env var | Direction | Purpose |
|---|---|---|---|
| **Service token** | `HUGINN_MCP_SERVICE_TOKEN` | MCP server → Hub | Internal. The MCP server uses this to authenticate with the hub API. |
| **Client token** | `HUGINN_MCP_MCP_CLIENT_TOKEN` | Agent → MCP server | External. Agents must send this as `Authorization: Bearer <token>` to reach the HTTP endpoint. |

- The **service token** grants admin-equivalent access to the hub. Keep it secret.
- The **client token** protects the MCP HTTP endpoint itself. Without it, anyone
  who can reach port 9000 can execute commands on your fleet.
- All agent actions are **logged in the audit trail** (actor type: `agent`).
- `execute_command` requires the VM to be in **unrestricted mode** (set by an
  admin in the dashboard, audited on every toggle).
- Rate limits apply: `HUGINN_RATE_LIMIT_EXEC_PER_MINUTE` (default: 30).
- The MCP server never contacts workers directly — everything goes through the
  hub's auth and authorization layer.

### Network security

For production, put the MCP server behind a reverse proxy with TLS:

```nginx
location /mcp {
    proxy_pass http://localhost:9000/mcp;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    # Restrict to known IPs if possible
    allow 10.0.0.0/8;
    deny all;
}
```

### Token rotation

```bash
# Generate new tokens
SERVICE_TOKEN=$(openssl rand -hex 32)
CLIENT_TOKEN=$(openssl rand -hex 32)

# Update .env
sed -i "s/HUGINN_MCP_SERVICE_TOKEN=.*/HUGINN_MCP_SERVICE_TOKEN=$SERVICE_TOKEN/" deploy/.env
sed -i "s/HUGINN_MCP_CLIENT_TOKEN=.*/HUGINN_MCP_CLIENT_TOKEN=$CLIENT_TOKEN/" deploy/.env

# Restart
cd deploy && docker compose restart hub mcp

# Update all agent configs with the new client token
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `401 Unauthorized` from MCP | Missing or wrong client token | Add `Authorization: Bearer <client-token>` header |
| `401 Unauthorized` from hub | Service token mismatch | Ensure `HUGINN_MCP_SERVICE_TOKEN` matches hub |
| `execute_command` fails | VM not in unrestricted mode | Enable unrestricted mode in dashboard |
| `Connection refused` | MCP server not running | `docker compose up mcp` or check logs |
| Tools not appearing in agent | Config not loaded | Restart the agent after editing config |
| `HubError 500` | Hub is down | Check `docker compose logs hub` |
| WARNING: no auth on startup | `MCP_CLIENT_TOKEN` not set | Set the token in `.env` and restart |

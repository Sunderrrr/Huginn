# Connecting MCP to AI Agents

The Huginn MCP server is a thin façade over the hub REST API. Any agent that
supports the [Model Context Protocol](https://modelcontextprotocol.io) can drive
your fleet — Hermes, Claude, Cursor, Continue, and more.

## Prerequisites

1. A running Huginn stack (hub + MCP server).
2. A **service token** — set `HUGINN_MCP_SERVICE_TOKEN` in your `.env` and
   restart the hub. This token grants admin-equivalent access to the agent.
3. Choose a transport:
   - **stdio** — agent and MCP server run on the same machine (agent spawns the
     process).
   - **streamable-http** — MCP server runs remotely (recommended for most setups).

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
HUGINN_MCP_SERVICE_TOKEN=<token> \
HUGINN_MCP_HOST=0.0.0.0 \
HUGINN_MCP_PORT=9000 \
python -m app.server
```

Or use the `mcp` service from `docker-compose.yml` (already configured for
streamable-http on port 9000).

---

## Agent configurations

### Hermes (custom agent)

Hermes connects via the MCP server config in its settings. Use stdio for local
or HTTP for remote:

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
      "url": "https://mcp.example.com/mcp"
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
      "url": "https://mcp.example.com/mcp"
    }
  }
}
```

Restart Claude Desktop after saving. The Huginn tools will appear in the tool
list.

### Claude Code (CLI)

```bash
claude mcp add huginn \
  --transport http \
  --url https://mcp.example.com/mcp
```

Or for stdio:

```bash
claude mcp add huginn \
  -- python -m app.server
```

With env vars, create a `.mcp.json` in your project root:

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
      "url": "https://mcp.example.com/mcp"
    }
  }
}
```

### Continue (VS Code / JetBrains)

Add to `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "huginn",
      "transport": {
        "type": "streamable-http",
        "url": "https://mcp.example.com/mcp"
      }
    }
  ]
}
```

For stdio:
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
mcp-proxy --mcp-url https://mcp.example.com/mcp --openai-port 8080
```

Then point your OpenAI client at `http://localhost:8080`.

### Any agent via mcp-cli (testing)

For quick testing or scripting, use the
[mcp-cli](https://github.com/wong2/mcp-cli):

```bash
# Install
npm install -g mcp-cli

# List available tools
mcp-cli --url https://mcp.example.com/mcp list-tools

# Call a tool
mcp-cli --url https://mcp.example.com/mcp call list_vms '{"state": "active"}'
```

---

## Available tools

Once connected, the agent has access to these tools:

| Tool | Description | Auth |
|---|---|---|
| `list_vms(state?)` | List fleet VMs, optionally by state | service token |
| `get_vm_status(vm_id)` | Full VM status (state, mode, version, heartbeat) | service token |
| `execute_action(vm_id, action, params?, wait?)` | Run a whitelisted action | service token |
| `execute_command(vm_id, command, wait?)` | Free shell command (unrestricted VMs only) | service token |
| `trigger_update(vm_id)` | Trigger worker self-update | service token |
| `get_task(task_id)` | Poll task status and result | service token |
| `get_audit_log(vm_id?, event_type?, limit?)` | Read audit entries | service token |

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

- The **service token grants admin-equivalent access**. Treat it like a password:
  - Don't commit it to git.
  - Don't share it across environments (use a different token per agent).
  - Rotate it if compromised (update `.env` + restart hub + update agent config).
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
# Generate a new token
NEW_TOKEN=$(openssl rand -hex 32)

# Update hub
sed -i "s/HUGINN_MCP_SERVICE_TOKEN=.*/HUGINN_MCP_SERVICE_TOKEN=$NEW_TOKEN/" deploy/.env
cd deploy && docker compose restart hub mcp

# Update all agent configs with the new token
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Agent can't connect | Wrong URL or port | Check `HUGINN_MCP_HOST` / `HUGINN_MCP_PORT` |
| `401 Unauthorized` | Token mismatch | Ensure token matches hub's `HUGINN_MCP_SERVICE_TOKEN` |
| `execute_command` fails | VM not in unrestricted mode | Enable unrestricted mode in dashboard |
| `Connection refused` | MCP server not running | `docker compose up mcp` or check logs |
| Tools not appearing in agent | Config not loaded | Restart the agent after editing config |
| `HubError 500` | Hub is down | Check `docker compose logs hub` |

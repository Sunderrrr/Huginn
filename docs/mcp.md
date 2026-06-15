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
| `get_task(task_id)` | Poll a task's status/result. |
| `get_audit_log(vm_id?, event_type?, limit?)` | Read audit entries. |

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `HUGINN_MCP_HUB_URL` | `http://localhost:8000` | Hub base URL. |
| `HUGINN_MCP_SERVICE_TOKEN` | — | Service token (must match the hub's `HUGINN_MCP_SERVICE_TOKEN`). |
| `HUGINN_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http`. |
| `HUGINN_MCP_HOST` / `HUGINN_MCP_PORT` | `0.0.0.0` / `9000` | HTTP bind (streamable-http). |

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

Run the server (or the `mcp` compose service) with
`HUGINN_MCP_TRANSPORT=streamable-http`, then point the agent at it:

```json
{
  "mcpServers": {
    "huginn": {
      "url": "https://mcp.example.com/mcp"
    }
  }
}
```

## Connecting to other agents

See [MCP Agent Integrations](mcp-agents.md) for detailed setup guides for
Hermes, Claude Desktop, Claude Code, Cursor, Continue, OpenAI proxies, and more.

## Security notes
- The service token grants admin-equivalent agent access — keep it secret and
  scope network access to the MCP endpoint.
- All actions flow through the same hub authz, rate limits, and audit log as the
  dashboard. `execute_command` still requires the target VM to be in unrestricted
  mode.

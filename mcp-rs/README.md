# mcp-rs

The Huginn **MCP server** — a thin [Model Context Protocol](https://modelcontextprotocol.io)
façade over the hub's REST API. It exposes the fleet's capabilities as tools an
external AI agent can call.

**Role:** translate MCP tool calls into hub REST calls. It holds **no business
logic** and never contacts workers directly — every action goes through the hub's
auth and authorization layer.

## Build & test

```bash
cd mcp-rs
cargo build --release          # binary: target/release/huginn-mcp
cargo test --release           # unit tests + e2e protocol tests
cargo fmt --check && cargo clippy --release -- -D warnings
```

Container image is built from `mcp-rs/Dockerfile` and used by the `mcp` compose
service.

## Module structure

```
mcp-rs/
└── src/
    ├── main.rs          # transport setup (stdio + streamable-http) + dispatch
    ├── config.rs        # env config: hub URL, service token, transport, bind
    ├── auth.rs          # per-user token validation, cache, client-IP extraction
    ├── hub_client.rs    # REST client to the hub (service token + on-behalf-of)
    ├── protocol.rs      # MCP handshake: initialize, tools/list
    └── tools.rs         # tool definitions + call_tool dispatch (17 tools)
```

## Tools

`list_vms`, `get_vm_status`, `list_actions`, `execute_action`, `execute_command`,
`trigger_update`, `get_task`, `wait_for_task`, `get_audit_log`. Browser
automation: `browser_enable`, `browser_engine_check`, `browser_install`,
`browser_start`, `browser_navigate`, `browser_screenshot`, `browser_pdf`,
`browser_eval`. Signatures and
docstrings live in `tools.rs::tool_definitions()`. Usage rules ship as connection
`instructions` so compliant clients surface them to the model.

**Every tool that creates a task waits for it and returns the result** — the
task's stdout/stderr come back inline, so the agent does not have to poll.
`wait=false` returns the task handle instead, for the long ones (a ~70 MB
engine install): then call `wait_for_task(task_id)` once. The wait uses the
hub's `GET /api/tasks/{id}/wait` endpoint (the hub holds it server-side),
bounded by the task's own timeout and by a 90 s ceiling that keeps the
response under the 100 s limit a CDN in front of the MCP imposes.

## Transports

| Transport | Env | Notes |
|---|---|---|
| `stdio` (default) | `HUGINN_MCP_TRANSPORT=stdio` | Agent spawns the process. Calls act as the anonymous automation agent (operator). |
| `streamable-http` | `HUGINN_MCP_TRANSPORT=streamable-http` | Remote. Each agent authenticates with a per-user MCP token → real role + per-user audit attribution. |

Config env vars: `HUGINN_MCP_HUB_URL`, `HUGINN_MCP_SERVICE_TOKEN`,
`HUGINN_MCP_TRANSPORT`, `HUGINN_MCP_HOST`, `HUGINN_MCP_PORT`. The HTTP endpoint
is gated by per-user tokens validated against the hub — there is no shared client
token.

## Entry points

- `main.rs` — picks the transport, builds the hub client, and serves.
- `tools.rs::call_tool` — dispatches a tool call by name; `tool_definitions()`
  returns the MCP tool schema.
- `auth.rs` — validates the bearer token (and optional per-token IP allow-list)
  before any hub call.

See `PARITY.md` for the behaviour/test map against the reference server, and
[../docs/mcp.md](../docs/mcp.md) for configuration and the token model.

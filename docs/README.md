# Huginn documentation

One subject per page. Pick what you need below. The reading path for a
first-time reader is at the bottom.

| Page | What it covers |
|---|---|
| [architecture.md](architecture.md) | System shape: hub, worker, MCP server, dashboard, and the task lifecycle. |
| [deployment.md](deployment.md) | Running Huginn: local compose, single-host Docker + Caddy, Kubernetes. |
| [enrollment.md](enrollment.md) | Adding a machine: enrollment tokens, the installer, approval. |
| [auth.md](auth.md) | Sign-in methods, TOTP/WebAuthn second factors, SSO-first behaviour, session revocation. |
| [browser.md](browser.md) | Headless browser automation on Linux workers: the Obscura engine, the step reference. |
| [security.md](security.md) | Threat model and the concrete controls behind it. |
| [mcp.md](mcp.md) | The MCP server: tools, token model, configuration. |
| [mcp-agents.md](mcp-agents.md) | Pointing specific AI agents at the MCP server. |

If you are new: read [architecture.md](architecture.md), then follow
[deployment.md](deployment.md) and [enrollment.md](enrollment.md) to get a
machine under management.

What changed in each release is in the
[CHANGELOG](../CHANGELOG.md) at the repository root.

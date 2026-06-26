"""Per-request context shared between the ASGI auth layer and the hub client."""

from __future__ import annotations

import contextvars

# The end-user's MCP token for the current request. Set by the bearer-auth ASGI
# middleware and read by HubClient so each hub call is made on behalf of that
# user (forwarded as the X-MCP-On-Behalf-Of header).
current_obo_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_obo_token", default=None
)

# The originating client IP for the current request (the agent that called the
# MCP server), forwarded to the hub so the audit log shows the real source IP
# instead of the MCP container.
current_client_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_client_ip", default=None
)

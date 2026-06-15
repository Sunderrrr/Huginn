"""Huginn MCP server.

Exposes the hub's fleet-management capabilities as MCP tools so an external agent
(e.g. "Hermes") can drive the fleet. Every tool is a thin delegation to the hub's
REST API via :class:`HubClient` — no business logic is duplicated here, and the
MCP server never talks to workers directly.

Run with stdio (default) or as a remote streamable-HTTP server:

    python -m app.server                 # stdio
    HUGINN_MCP_TRANSPORT=streamable-http python -m app.server

When using streamable-http, set ``HUGINN_MCP_MCP_CLIENT_TOKEN`` to require
``Authorization: Bearer <token>`` on every incoming request. Without it the
HTTP endpoint is open to anyone who can reach it.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.config import Settings, get_settings
from app.hub_client import HubClient, HubError

logger = logging.getLogger("huginn.mcp")

settings = get_settings()
mcp = FastMCP("Huginn", host=settings.host, port=settings.port)
hub = HubClient(settings)


# ---------------------------------------------------------------------------
# HTTP bearer-token wrapper (streamable-http only)
# ---------------------------------------------------------------------------

def _make_auth_wrapper(inner_app: Any, token: str) -> Any:  # noqa: ANN401
    """Wrap a Starlette/ASGI app with bearer-token validation.

    Every request must carry ``Authorization: Bearer <token>``. Requests without
    a valid token receive ``401 Unauthorized`` before reaching the MCP layer.
    """
    from starlette.applications import Starlette
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    class _BearerAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Any) -> Any:  # noqa: ANN401
            auth = request.headers.get("authorization", "")
            if not auth.startswith("Bearer ") or auth[7:] != token:
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await call_next(request)

    return _BearerAuthMiddleware(inner_app)


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

async def _safe(coro: Any) -> Any:
    """Await a hub call, converting HubError into a structured tool error."""
    try:
        return await coro
    except HubError as exc:
        return {"error": {"status": exc.status_code, "detail": exc.detail}}


@mcp.tool()
async def list_vms(state: str | None = None) -> Any:
    """List fleet VMs. Optionally filter by state: pending, active, offline, revoked."""
    return await _safe(hub.list_vms(state))


@mcp.tool()
async def get_vm_status(vm_id: str) -> Any:
    """Get a single VM's full status (state, mode, worker version, heartbeat)."""
    return await _safe(hub.get_vm(vm_id))


@mcp.tool()
async def execute_action(
    vm_id: str, action: str, params: dict[str, str] | None = None, wait: bool = False
) -> Any:
    """Run a whitelisted action on a VM.

    Allowed actions: status, metrics, restart_service (param: service),
    list_upgradable_packages, apt_upgrade, update_worker. With ``wait=true`` the
    call blocks briefly for a result; otherwise it returns a task to poll.
    """
    return await _safe(hub.execute_action(vm_id, action, params or {}, wait))


@mcp.tool()
async def execute_command(vm_id: str, command: str, wait: bool = False) -> Any:
    """Run a free-form shell command on a VM.

    Only permitted when the VM is in 'unrestricted' mode (enabled by an admin in
    the dashboard). Subject to the same auth, rate-limit, and audit rules as the
    dashboard.
    """
    return await _safe(hub.execute_command(vm_id, command, wait))


@mcp.tool()
async def trigger_update(vm_id: str) -> Any:
    """Trigger a worker self-update on a VM toward the hub's target version."""
    return await _safe(hub.trigger_update(vm_id))


@mcp.tool()
async def get_task(task_id: str) -> Any:
    """Poll a previously-created task by id for its status and result."""
    return await _safe(hub.get_task(task_id))


@mcp.tool()
async def get_audit_log(
    vm_id: str | None = None, event_type: str | None = None, limit: int = 100
) -> Any:
    """Read recent audit-log entries, optionally filtered by VM or event type."""
    return await _safe(hub.get_audit_log(vm_id, event_type, limit))


def main() -> None:
    if settings.transport == "streamable-http" and settings.mcp_client_token:
        # Wrap the FastMCP ASGI app with bearer-token validation.
        import uvicorn

        raw_app = mcp.streamable_http_app()
        app = _make_auth_wrapper(raw_app, settings.mcp_client_token)
        logger.info("HTTP bearer-token auth enabled")

        uvicorn.run(
            app,
            host=settings.host,
            port=settings.port,
            log_level="info",
        )
    else:
        if settings.transport == "streamable-http" and not settings.mcp_client_token:
            logger.warning(
                "streamable-http transport has NO authentication — "
                "set HUGINN_MCP_MCP_CLIENT_TOKEN to secure the endpoint"
            )
        mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()

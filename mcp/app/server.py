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

import asyncio
import hmac
import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.config import _fetch_client_token_from_hub, get_settings
from app.hub_client import HubClient, HubError

logger = logging.getLogger("huginn.mcp")

settings = get_settings()
mcp = FastMCP("Huginn", host=settings.host, port=settings.port)
hub = HubClient(settings)


# ---------------------------------------------------------------------------
# HTTP bearer-token ASGI middleware (streamable-http only)
# ---------------------------------------------------------------------------

class TokenValidator:
    """Validates bearer tokens against the live hub token (DB-backed).

    The hub is the source of truth for the client token, so regenerating it from
    the dashboard takes effect without restarting the MCP server. The current
    value is cached for ``ttl`` seconds; on a mismatch the cache is refreshed
    once and the token re-checked, so a freshly-rotated token works immediately.
    """

    def __init__(self, initial: str, ttl: float = 30.0) -> None:
        self._token = initial
        self._ttl = ttl
        self._fetched_at = 0.0

    async def _refresh(self, force: bool = False) -> None:
        import time

        if not force and (time.monotonic() - self._fetched_at) < self._ttl:
            return
        latest = await asyncio.to_thread(
            _fetch_client_token_from_hub, settings.hub_url, settings.service_token
        )
        if latest:
            self._token = latest
        self._fetched_at = time.monotonic()

    async def valid(self, presented: str) -> bool:
        if not presented:
            return False
        await self._refresh()
        if self._token and hmac.compare_digest(presented, self._token):
            return True
        # Token may have just been rotated — force one refresh and re-check.
        await self._refresh(force=True)
        return bool(self._token) and hmac.compare_digest(presented, self._token)


class BearerAuthASGI:
    """Pure ASGI middleware: reject requests without a valid Bearer token.

    Checks every HTTP request for ``Authorization: Bearer <token>`` before
    passing it to the inner app. Returns 401 for missing or wrong tokens.
    WebSocket connections are rejected unconditionally.
    """

    def __init__(self, app: Any, validator: TokenValidator) -> None:  # noqa: ANN401
        self._app = app
        self._validator = validator

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:  # noqa: ANN401
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"").decode()
            presented = auth[7:] if auth.startswith("Bearer ") else ""
            if await self._validator.valid(presented):
                await self._app(scope, receive, send)
                return
            # Reject with 401
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [[b"content-type", b"application/json"]],
            })
            await send({
                "type": "http.response.body",
                "body": json.dumps({"error": "unauthorized"}).encode(),
            })
        elif scope["type"] == "websocket":
            # Reject WebSocket connections (MCP uses HTTP POST, not WS)
            await send({"type": "websocket.close", "code": 4001})
        else:
            await self._app(scope, receive, send)


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
    if settings.transport == "streamable-http":
        import time

        # The hub generates/holds the client token. On a cold start the hub may
        # not be ready yet, so retry the fetch before giving up (fail-closed).
        token = settings.mcp_client_token
        if not token:
            for attempt in range(30):
                token = _fetch_client_token_from_hub(
                    settings.hub_url, settings.service_token
                )
                if token:
                    break
                logger.info("waiting for hub to provide MCP client token (%d)...", attempt + 1)
                time.sleep(2)
        if not token:
            raise SystemExit(
                "refusing to start streamable-http without a client token — "
                "hub unreachable or has no token after retries"
            )

        import uvicorn

        raw_app = mcp.streamable_http_app()
        validator = TokenValidator(token)
        app = BearerAuthASGI(raw_app, validator)
        logger.info("HTTP bearer-token auth enabled (token validated against hub)")

        uvicorn.run(
            app,
            host=settings.host,
            port=settings.port,
            log_level="info",
        )
    else:
        mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()

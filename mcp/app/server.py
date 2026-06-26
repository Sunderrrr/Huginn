"""Huginn MCP server.

Exposes the hub's fleet-management capabilities as MCP tools so an external agent
(e.g. "Hermes") can drive the fleet. Every tool is a thin delegation to the hub's
REST API via :class:`HubClient` — no business logic is duplicated here, and the
MCP server never talks to workers directly.

Run with stdio (default) or as a remote streamable-HTTP server:

    python -m app.server                 # stdio
    HUGINN_MCP_TRANSPORT=streamable-http python -m app.server

When using streamable-http, each agent authenticates with a **per-user MCP
token** (``Authorization: Bearer <token>``). The server validates it against the
hub and forwards the user identity, so every action is attributed to that user.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from app.config import get_settings
from app.context import current_client_ip, current_obo_token
from app.hub_client import HubClient, HubError

logger = logging.getLogger("huginn.mcp")

settings = get_settings()
# Stateless HTTP: each request is handled in its own task started from the
# request context, so the per-request on-behalf-of token (set by BearerAuthASGI)
# reliably reaches the tool's hub call. A long-lived session task would instead
# capture the token from session-creation time and reuse it for every later
# request — attributing all calls to whoever opened the session.
_INSTRUCTIONS = """\
Huginn — fleet control. How to use these tools as designed:

1. Start with list_vms(brief=true) for a compact roster (id, name, state, mode).
   Target a VM by name or id (name is case-sensitive).
2. Act with execute_action (built-ins: status, metrics, restart_service{service},
   list_upgradable_packages, apt_upgrade, update_worker; plus admin custom commands
   — discover them with list_actions(vm_id)). execute_command (free shell) works
   ONLY on a VM in 'unrestricted' mode. If an action is refused, check the mode
   with get_vm_status.
3. Waiting on a task — IMPORTANT: do NOT poll get_task in a loop. Either pass
   wait=true to execute_action/execute_command to get the result inline, or, after
   launching with wait=false, call wait_for_task(task_id) ONCE — it blocks
   server-side and returns the instant the worker reports a result. Only if it
   returns still-running (timeout) should you call wait_for_task again. get_task is
   for a single one-off status check, not for busy-waiting.
4. Every action is audited and attributed to your user. Stay within scope.
"""

mcp = FastMCP(
    "Huginn",
    host=settings.host,
    port=settings.port,
    stateless_http=True,
    json_response=True,
    instructions=_INSTRUCTIONS,
)
hub = HubClient(settings)


# ---------------------------------------------------------------------------
# HTTP bearer-token ASGI middleware (streamable-http only)
# ---------------------------------------------------------------------------

class TokenValidator:
    """Validates a presented per-user MCP token against the hub.

    Calls the hub's ``/api/mcp/whoami`` (authenticated with the service token +
    the presented token as on-behalf-of). Results are cached briefly; the hub
    re-validates on every actual tool call, so this is just a connect-time gate.
    """

    # Cap so a flood of distinct bogus bearers can't grow the cache unbounded.
    _MAX_ENTRIES = 1024

    def __init__(self, ttl: float = 30.0) -> None:
        self._ttl = ttl
        self._cache: dict[tuple[str, str], tuple[bool, float]] = {}

    async def valid(self, presented: str, client_ip: str | None) -> bool:
        if not presented:
            return False
        now = time.monotonic()
        # Cache per (token, ip) so the IP allow-list is honoured at the gate too.
        key = (presented, client_ip or "")
        cached = self._cache.get(key)
        if cached is not None and (now - cached[1]) < self._ttl:
            return cached[0]
        ok = await self._check(presented, client_ip)
        if len(self._cache) >= self._MAX_ENTRIES:
            self._cache.clear()  # cheap bound; entries are short-lived anyway
        self._cache[key] = (ok, now)
        return ok

    async def _check(self, presented: str, client_ip: str | None) -> bool:
        headers = {
            "X-MCP-Service-Token": settings.service_token,
            "X-MCP-On-Behalf-Of": presented,
        }
        if client_ip:
            # Forward the (trusted) client IP so the hub enforces the token's IP
            # allow-list already at the connect-time gate, not just per tool call.
            headers["X-Forwarded-For"] = client_ip
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{settings.hub_url.rstrip('/')}/api/mcp/whoami", headers=headers
                )
            return resp.status_code == 200
        except Exception:  # noqa: BLE001 - hub unreachable → deny
            logger.warning("could not validate MCP token against hub")
            return False


def _client_ip(scope: dict, headers: dict) -> str | None:
    """Originating client IP. Prefer ``X-Real-IP`` (stamped by the trusted edge
    proxy and not forwardable by the client), then the first X-Forwarded-For hop,
    then the direct peer."""
    real = headers.get(b"x-real-ip", b"").decode().strip()
    if real:
        return real
    xff = headers.get(b"x-forwarded-for", b"").decode()
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    client = scope.get("client")
    return client[0] if client else None


class BearerAuthASGI:
    """Pure ASGI middleware: require a valid per-user Bearer token.

    Validates ``Authorization: Bearer <token>`` against the hub, stashes the
    token in the request context (so HubClient forwards it as on-behalf-of), then
    passes the request to the inner app. 401 for missing/invalid tokens.
    """

    def __init__(self, app: Any, validator: TokenValidator) -> None:  # noqa: ANN401
        self._app = app
        self._validator = validator

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:  # noqa: ANN401
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"").decode()
            presented = auth[7:] if auth.startswith("Bearer ") else ""
            ip = _client_ip(scope, headers)
            if await self._validator.valid(presented, ip):
                ctx_token = current_obo_token.set(presented)
                ctx_ip = current_client_ip.set(ip)
                try:
                    await self._app(scope, receive, send)
                finally:
                    current_obo_token.reset(ctx_token)
                    current_client_ip.reset(ctx_ip)
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


async def _resolve_vm(vm: str) -> Any:
    """Accept a VM id **or name** and return the id.

    Names are stable across re-enrollment (which mints a new id), so an agent can
    refer to ``"web-01"`` instead of a UUID that may have changed. Returns a
    structured error dict if a name is unknown or ambiguous.
    """
    try:
        uuid.UUID(vm)
        return vm  # already an id
    except ValueError:
        pass
    vms = await _safe(hub.list_vms())
    if not isinstance(vms, list):
        return vms  # propagate a hub error
    # Exact match first; fall back to case-insensitive so "vm-plane-global"
    # resolves "VM-Plane-Global" without the agent guessing the casing.
    matches = [v for v in vms if v.get("name") == vm]
    if not matches:
        matches = [v for v in vms if (v.get("name") or "").lower() == vm.lower()]
    if not matches:
        return {"error": {"status": 404, "detail": f"no VM named {vm!r}"}}
    # Prefer the active record if a name was reused across re-enrollments.
    chosen = [v for v in matches if v.get("state") == "active"] or matches
    if len(chosen) > 1:
        return {"error": {"status": 409, "detail": f"{vm!r} matches {len(chosen)} VMs; use the id"}}
    return chosen[0]["id"]


@mcp.tool()
async def list_vms(state: str | None = None, brief: bool = False) -> Any:
    """List fleet VMs. Optionally filter by state: pending, active, offline, revoked.

    With ``brief=true`` each VM is reduced to just id, name, state, and mode —
    a compact roster ideal for a session-opening overview (far fewer tokens).
    """
    vms = await _safe(hub.list_vms(state))
    if brief and isinstance(vms, list):
        return [
            {"id": v.get("id"), "name": v.get("name"),
             "state": v.get("state"), "mode": v.get("exec_mode")}
            for v in vms
        ]
    return vms


@mcp.tool()
async def get_vm_status(vm_id: str) -> Any:
    """Get a single VM's full status (state, mode, worker version, heartbeat).

    ``vm_id`` may be a VM id or its name.
    """
    target = await _resolve_vm(vm_id)
    if isinstance(target, dict):
        return target
    return await _safe(hub.get_vm(target))


def _brief_action(a: dict) -> dict:
    return {
        "name": a.get("name"),
        "description": a.get("description"),
        "commands": a.get("commands"),  # human-readable command lines
    }


@mcp.tool()
async def list_actions(vm_id: str | None = None) -> Any:
    """List admin-defined custom commands (fixed argv, run in 'custom' exec mode).

    These run via ``execute_action`` like built-in actions. With ``vm_id`` (id or
    name), returns only the commands runnable on that VM right now — i.e. the VM
    is in custom/unrestricted mode and carries one of the command's tags.
    """
    actions = await _safe(hub.list_actions())
    if not isinstance(actions, list):
        return actions
    enabled = [a for a in actions if a.get("enabled")]
    if vm_id is None:
        return [_brief_action(a) for a in enabled]
    target = await _resolve_vm(vm_id)
    if isinstance(target, dict):
        return target
    vm = await _safe(hub.get_vm(target))
    if not isinstance(vm, dict):
        return vm
    if vm.get("exec_mode") not in ("custom", "unrestricted"):
        return []  # VM can't run custom commands in its current mode
    vm_tags = {t.get("id") for t in vm.get("tags", [])}
    return [_brief_action(a) for a in enabled if set(a.get("tag_ids", [])) & vm_tags]


@mcp.tool()
async def execute_action(
    vm_id: str, action: str, params: dict[str, str] | None = None, wait: bool = False
) -> Any:
    """Run an action on a VM (``vm_id`` may be a VM id or its name).

    Built-in actions: status, metrics, restart_service (param: service),
    list_upgradable_packages, apt_upgrade, update_worker. Admin-defined custom
    commands (see ``list_actions``) run the same way by name. With ``wait=true``
    the call blocks briefly and returns the result inline (prefer this for short
    actions). Otherwise it returns a task — then call wait_for_task(task_id) once;
    do NOT poll get_task in a loop.
    """
    target = await _resolve_vm(vm_id)
    if isinstance(target, dict):
        return target
    return await _safe(hub.execute_action(target, action, params or {}, wait))


@mcp.tool()
async def execute_command(vm_id: str, command: str, wait: bool = False) -> Any:
    """Run a free-form shell command on a VM (``vm_id`` may be a VM id or its name).

    Only permitted when the VM is in 'unrestricted' mode (enabled by an admin in
    the dashboard). Subject to the same auth, rate-limit, and audit rules as the
    dashboard. With ``wait=true`` the result is returned inline; otherwise call
    wait_for_task(task_id) once — do NOT poll get_task in a loop.
    """
    target = await _resolve_vm(vm_id)
    if isinstance(target, dict):
        return target
    return await _safe(hub.execute_command(target, command, wait))


@mcp.tool()
async def trigger_update(vm_id: str) -> Any:
    """Trigger a worker self-update on a VM toward the hub's target version.

    ``vm_id`` may be a VM id or its name.
    """
    target = await _resolve_vm(vm_id)
    if isinstance(target, dict):
        return target
    return await _safe(hub.trigger_update(target))


@mcp.tool()
async def get_task(task_id: str) -> Any:
    """Fetch a task's current status/result ONCE (a single snapshot).

    To await a still-running task, use wait_for_task(task_id) instead of calling
    this repeatedly — looping on get_task busy-waits and wastes calls.
    """
    return await _safe(hub.get_task(task_id))


@mcp.tool()
async def wait_for_task(task_id: str, timeout: int = 60) -> Any:
    """Block until a task finishes (succeeded/failed/timeout) or ``timeout``
    seconds pass, then return it — instead of polling get_task in a loop.

    Ideal after launching a long action/command with wait=false: the call returns
    the instant the worker reports a result. If still running when the timeout
    elapses, the task's current state is returned; just call again to keep waiting.
    """
    return await _safe(hub.wait_task(task_id, timeout))


@mcp.tool()
async def get_audit_log(
    vm_id: str | None = None, event_type: str | None = None, limit: int = 100
) -> Any:
    """Read recent audit-log entries, optionally filtered by VM or event type."""
    return await _safe(hub.get_audit_log(vm_id, event_type, limit))


def main() -> None:
    if settings.transport == "streamable-http":
        import uvicorn

        raw_app = mcp.streamable_http_app()
        app = BearerAuthASGI(raw_app, TokenValidator())
        logger.info("per-user MCP token auth enabled (validated against hub)")

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

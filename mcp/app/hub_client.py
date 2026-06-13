"""Async HTTP client for the hub's REST API.

The MCP server is a pure façade: every tool delegates to one of these methods.
There is no business logic here beyond shaping requests and surfacing errors.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.config import Settings


class HubError(Exception):
    """Raised when the hub returns a non-success response."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"hub returned {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class HubClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.hub_url.rstrip("/"),
            headers={"X-MCP-Service-Token": settings.service_token},
            timeout=settings.request_timeout_seconds,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:  # noqa: BLE001 - best-effort detail extraction
                pass
            raise HubError(resp.status_code, str(detail))
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.json()

    # --- Façade methods (one per hub endpoint the agent needs) ---

    async def list_vms(self, state: str | None = None) -> list[dict]:
        params = {"state": state} if state else None
        return await self._request("GET", "/api/vms", params=params)

    async def get_vm(self, vm_id: str) -> dict:
        return await self._request("GET", f"/api/vms/{vm_id}")

    async def execute_action(
        self, vm_id: str, action: str, params: dict[str, str], wait: bool
    ) -> dict:
        body = {"action": action, "params": params, "wait": wait}
        return await self._request("POST", f"/api/vms/{vm_id}/actions", json=body)

    async def execute_command(self, vm_id: str, command: str, wait: bool) -> dict:
        body = {"command": command, "wait": wait}
        return await self._request("POST", f"/api/vms/{vm_id}/commands", json=body)

    async def trigger_update(self, vm_id: str) -> dict:
        return await self._request("POST", f"/api/vms/{vm_id}/update")

    async def get_task(self, task_id: str) -> dict:
        return await self._request("GET", f"/api/tasks/{task_id}")

    async def get_audit_log(
        self, vm_id: str | None, event_type: str | None, limit: int
    ) -> list[dict]:
        params: dict[str, Any] = {"limit": limit}
        if vm_id:
            params["vm_id"] = vm_id
        if event_type:
            params["event_type"] = event_type
        return await self._request("GET", "/api/audit", params=params)

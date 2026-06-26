"""Best-effort outbound notifications for fleet events (Discord + generic webhook).

Failures are logged and swallowed — a webhook outage must never break the sweep
loop or a worker result submission.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from app.models.setting import Setting
from app.models.task import Task
from app.models.vm import VM

logger = logging.getLogger("huginn.hub.notifications")

_TIMEOUT = 10

# event_type -> (settings toggle attr, human label)
_EVENTS = {
    "vm_offline": ("notify_vm_offline", "VM went offline"),
    "vm_recovered": ("notify_vm_recovered", "VM recovered"),
    "task_failure": ("notify_task_failure", "Task failed"),
}


def _message(event_type: str, vm: VM | None, task: Task | None) -> str:
    label = _EVENTS.get(event_type, (None, event_type))[1]
    name = vm.name if vm else "?"
    if event_type == "task_failure" and task is not None:
        return f"⚠️ {label}: `{task.action_name or task.type}` on **{name}** ({task.status})"
    if event_type == "vm_offline":
        return f"🔴 {label}: **{name}** ({vm.ip_address if vm else '?'})"
    if event_type == "vm_recovered":
        return f"🟢 {label}: **{name}** is back online"
    return f"{label}: {name}"


async def notify(
    settings_row: Setting | None,
    event_type: str,
    *,
    vm: VM | None = None,
    task: Task | None = None,
) -> None:
    """Send the event to the configured webhooks if enabled. Never raises."""
    if settings_row is None or not settings_row.notifications_enabled:
        return
    toggle_attr = _EVENTS.get(event_type, (None, None))[0]
    if toggle_attr is None or not getattr(settings_row, toggle_attr, False):
        return

    text = _message(event_type, vm, task)
    payloads: list[tuple[str, dict[str, Any]]] = []
    if settings_row.discord_webhook_url:
        payloads.append((settings_row.discord_webhook_url, {"content": text}))
    if settings_row.generic_webhook_url:
        payloads.append(
            (
                settings_row.generic_webhook_url,
                {
                    "event": event_type,
                    "message": text,
                    "vm": {"id": str(vm.id), "name": vm.name} if vm else None,
                    "task": {"id": str(task.id), "status": task.status} if task else None,
                    "ts": datetime.now(UTC).isoformat(),
                },
            )
        )
    if not payloads:
        return

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for url, body in payloads:
            try:
                await client.post(url, json=body)
            except Exception as exc:  # noqa: BLE001 - best-effort, never raise
                logger.warning("notification POST failed (%s): %s", event_type, exc)

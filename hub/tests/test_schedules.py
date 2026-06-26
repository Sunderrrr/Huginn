"""Scheduled commands: CRUD, cron validation, due-time execution."""

from __future__ import annotations

from datetime import timedelta

from app.models.enums import VMState, WorkerArch
from app.models.mixins import utcnow
from app.models.scheduled_command import ScheduledCommand
from app.models.vm import VM
from app.services import scheduled_commands as schedules_service


async def _active_vm(session) -> VM:
    vm = VM(name="vm", arch=WorkerArch.amd64, state=VMState.active)
    session.add(vm)
    await session.flush()
    return vm


async def test_create_schedule_validates_cron(client, admin_headers, enrolled_worker) -> None:
    await enrolled_worker()
    bad = await client.post(
        "/api/schedules",
        json={
            "name": "bad",
            "target_kind": "all_active",
            "task_kind": "action",
            "action_name": "status",
            "cron_expression": "not a cron",
        },
        headers=admin_headers,
    )
    assert bad.status_code == 422  # pydantic validation error


async def test_create_schedule_and_list(client, admin_headers) -> None:
    resp = await client.post(
        "/api/schedules",
        json={
            "name": "nightly status",
            "target_kind": "all_active",
            "task_kind": "action",
            "action_name": "status",
            "cron_expression": "0 3 * * *",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert out["next_run_at"] is not None

    listing = await client.get("/api/schedules", headers=admin_headers)
    assert any(s["id"] == out["id"] for s in listing.json())


async def test_run_due_creates_tasks_for_all_active(session) -> None:
    vm = await _active_vm(session)
    # A schedule whose last run was long ago and fires every minute.
    sched = ScheduledCommand(
        name="uptime",
        enabled=True,
        target_kind="all_active",
        task_kind="action",
        action_name="status",
        params={},
        cron_expression="* * * * *",
        last_run_at=utcnow() - timedelta(hours=1),
    )
    session.add(sched)
    await session.flush()

    created = await schedules_service.run_due(session)
    assert created == 1
    assert sched.last_run_at is not None

    # The trigger is recorded in the audit log (filterable, actor = schedule name).
    from sqlalchemy import select

    from app.models.audit import AuditLog

    rows = (
        await session.execute(
            select(AuditLog).where(AuditLog.event_type == "scheduled_action")
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].actor_id == "uptime"
    assert rows[0].detail["schedule_id"] == str(sched.id)

    # Immediately re-running should not fire again (last_run_at just updated).
    again = await schedules_service.run_due(session)
    assert again == 0
    _ = vm


async def test_run_due_skips_disabled(session) -> None:
    await _active_vm(session)
    sched = ScheduledCommand(
        name="off",
        enabled=False,
        target_kind="all_active",
        task_kind="action",
        action_name="status",
        params={},
        cron_expression="* * * * *",
        last_run_at=utcnow() - timedelta(hours=1),
    )
    session.add(sched)
    await session.flush()
    assert await schedules_service.run_due(session) == 0

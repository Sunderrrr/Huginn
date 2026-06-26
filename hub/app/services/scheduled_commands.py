"""Scheduled command CRUD and due-time execution (called from the sweeper)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from croniter import croniter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.actions import validate_action
from app.models.enums import ActorType, VMState
from app.models.mixins import as_aware_utc, utcnow
from app.models.scheduled_command import ScheduledCommand
from app.models.vm import VM
from app.services import tags as tags_service
from app.services import tasks as tasks_service
from app.services import vms as vms_service

logger = logging.getLogger("huginn.hub.schedules")


def next_run_at(sched: ScheduledCommand, *, after: datetime | None = None) -> datetime:
    """Next cron occurrence after ``after`` (defaults to last_run_at or created_at)."""
    base = after or sched.last_run_at or sched.created_at
    itr = croniter(sched.cron_expression, as_aware_utc(base))
    return itr.get_next(datetime)


# --- CRUD ---

async def list_schedules(session: AsyncSession) -> list[ScheduledCommand]:
    result = await session.execute(
        select(ScheduledCommand).order_by(ScheduledCommand.created_at.desc())
    )
    return list(result.scalars().all())


async def get(session: AsyncSession, schedule_id: uuid.UUID) -> ScheduledCommand | None:
    return await session.get(ScheduledCommand, schedule_id)


async def create(
    session: AsyncSession, data: dict, created_by: uuid.UUID | None
) -> ScheduledCommand:
    # Defensive: validate the action again at persistence time.
    if data.get("task_kind") == "action":
        validate_action(data["action_name"], data.get("params") or {})
    sched = ScheduledCommand(created_by=created_by, **data)
    session.add(sched)
    await session.flush()
    return sched


async def update(session: AsyncSession, sched: ScheduledCommand, data: dict) -> ScheduledCommand:
    for key, value in data.items():
        setattr(sched, key, value)
    await session.flush()
    return sched


async def delete(session: AsyncSession, sched: ScheduledCommand) -> None:
    await session.delete(sched)


# --- Execution ---

async def _resolve_targets(session: AsyncSession, sched: ScheduledCommand) -> list[VM]:
    """Active VMs this schedule targets."""
    if sched.target_kind == "vm" and sched.target_vm_id is not None:
        vm = await vms_service.get(session, sched.target_vm_id)
        return [vm] if vm and vm.state in (VMState.active, VMState.offline) else []
    if sched.target_kind == "tag" and sched.target_tag_id is not None:
        vm_ids = await tags_service.vm_ids_for_tags(session, [sched.target_tag_id])
        return await vms_service.list_vms(session, allowed_vm_ids=vm_ids)
    if sched.target_kind == "all_active":
        return await vms_service.list_vms(session, state=VMState.active)
    return []


async def run_due(session: AsyncSession) -> int:
    """Create tasks for every enabled schedule whose cron time has passed.

    Returns the number of tasks created. Best-effort per VM/schedule.
    """
    now = utcnow()
    result = await session.execute(
        select(ScheduledCommand).where(ScheduledCommand.enabled.is_(True))
    )
    created = 0
    for sched in result.scalars():
        try:
            if next_run_at(sched) > now:
                continue
            targets = await _resolve_targets(session, sched)
            for vm in targets:
                try:
                    if sched.task_kind == "action":
                        task = await tasks_service.create_action_task(
                            session,
                            vm=vm,
                            action_name=sched.action_name or "",
                            params=dict(sched.params or {}),
                            created_by=f"schedule:{sched.id}",
                        )
                        event_type, action_name, command = (
                            "scheduled_action",
                            sched.action_name,
                            None,
                        )
                    else:
                        task = await tasks_service.create_command_task(
                            session,
                            vm=vm,
                            command=sched.command or "",
                            created_by=f"schedule:{sched.id}",
                        )
                        event_type, action_name, command = (
                            "scheduled_command",
                            None,
                            sched.command,
                        )
                    # Record the trigger in the audit log so scheduled runs are
                    # visible/filterable. actor_id = schedule name (shown verbatim
                    # for system events); the id lives in detail for traceability.
                    await audit.record(
                        session,
                        actor_type=ActorType.system,
                        actor_id=sched.name,
                        event_type=event_type,
                        vm_id=vm.id,
                        action_name=action_name,
                        command=command,
                        detail={"schedule_id": str(sched.id), "task_id": str(task.id)},
                    )
                    created += 1
                except Exception as exc:  # noqa: BLE001 - skip this VM, keep going
                    logger.warning("schedule %s: vm %s failed: %s", sched.id, vm.id, exc)
            sched.last_run_at = now
        except Exception as exc:  # noqa: BLE001 - keep the sweep alive
            logger.warning("schedule %s failed: %s", sched.id, exc)
    await session.flush()
    return created

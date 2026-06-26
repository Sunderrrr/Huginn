"""Scheduled command management endpoints (admin only)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, require_admin
from app.core.audit import record
from app.core.principal import Principal
from app.db import get_session
from app.schemas.scheduled_command import ScheduleCreate, ScheduleOut, ScheduleUpdate
from app.services import scheduled_commands as schedules_service

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _to_out(sched) -> ScheduleOut:  # type: ignore[no-untyped-def]
    out = ScheduleOut.model_validate(sched)
    try:
        return out.model_copy(update={"next_run_at": schedules_service.next_run_at(sched)})
    except Exception:  # noqa: BLE001 - never let a bad cron break the listing
        return out


@router.get("", response_model=list[ScheduleOut])
async def list_schedules(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> list[ScheduleOut]:
    rows = await schedules_service.list_schedules(session)
    return [_to_out(s) for s in rows]


@router.post("", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    body: ScheduleCreate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> ScheduleOut:
    created_by = principal.user.id if principal.user else None
    try:
        sched = await schedules_service.create(session, body.model_dump(), created_by)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="schedule_create",
        detail={"name": sched.name, "cron": sched.cron_expression},
        source_ip=client_ip(request),
    )
    await session.commit()
    return _to_out(sched)


@router.put("/{schedule_id}", response_model=ScheduleOut)
async def update_schedule(
    schedule_id: uuid.UUID,
    body: ScheduleUpdate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> ScheduleOut:
    sched = await schedules_service.get(session, schedule_id)
    if sched is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    # exclude_unset so a PATCH-like edit only touches the fields the client sent
    # (and can explicitly clear target ids by sending null when switching kind).
    sched = await schedules_service.update(session, sched, body.model_dump(exclude_unset=True))
    await record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="schedule_update",
        detail={"schedule_id": str(schedule_id)},
        source_ip=client_ip(request),
    )
    await session.commit()
    return _to_out(sched)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> None:
    sched = await schedules_service.get(session, schedule_id)
    if sched is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    await schedules_service.delete(session, sched)
    await record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="schedule_delete",
        detail={"schedule_id": str(schedule_id), "name": sched.name},
        source_ip=client_ip(request),
    )
    await session.commit()

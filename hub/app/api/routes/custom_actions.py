"""Admin-defined custom commands: CRUD.

Anyone who can execute (operator+) may *list* the catalog (to run them / show them
in the UI); only admins may create, edit, or delete. Every mutation is audited.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_principal, require_admin
from app.core import audit
from app.core.principal import Principal
from app.db import get_session
from app.models.custom_action import CustomAction
from app.schemas.custom_action import CustomActionCreate, CustomActionOut, CustomActionUpdate
from app.services import custom_actions as svc

router = APIRouter(prefix="/api/actions", tags=["custom-actions"])


async def _to_out(session: AsyncSession, action: CustomAction) -> CustomActionOut:
    commands = [list(argv) for argv in action.commands]
    return CustomActionOut(
        id=action.id,
        name=action.name,
        description=action.description,
        commands=svc.lines_of(commands),
        argv=commands,
        enabled=action.enabled,
        tag_ids=await svc.tag_ids_for(session, action.id),
        created_at=action.created_at,
    )


@router.get("", response_model=list[CustomActionOut])
async def list_actions(
    _: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[CustomActionOut]:
    return [await _to_out(session, a) for a in await svc.list_all(session)]


@router.post("", response_model=CustomActionOut, status_code=status.HTTP_201_CREATED)
async def create_action(
    body: CustomActionCreate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> CustomActionOut:
    try:
        action = await svc.create(
            session,
            name=body.name,
            description=body.description,
            lines=body.commands,
            tag_ids=body.tag_ids,
            created_by=principal.actor_id,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="custom_action_created",
        detail={"name": action.name, "commands": [list(a) for a in action.commands]},
        source_ip=client_ip(request),
    )
    await session.commit()
    return await _to_out(session, action)


@router.patch("/{action_id}", response_model=CustomActionOut)
async def update_action(
    action_id: uuid.UUID,
    body: CustomActionUpdate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> CustomActionOut:
    try:
        action = await svc.update(
            session,
            action_id,
            description=body.description,
            lines=body.commands,
            enabled=body.enabled,
            tag_ids=body.tag_ids,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "action not found")
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="custom_action_updated",
        detail={
            "name": action.name,
            "commands": [list(a) for a in action.commands],
            "enabled": action.enabled,
        },
        source_ip=client_ip(request),
    )
    await session.commit()
    return await _to_out(session, action)


@router.delete("/{action_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_action(
    action_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> None:
    action = await svc.get(session, action_id)
    if action is None or not await svc.remove(session, action_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "action not found")
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="custom_action_deleted",
        detail={"name": action.name},
        source_ip=client_ip(request),
    )
    await session.commit()

"""Tag management endpoints. Reads are operator+; mutations are admin-only."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, require_admin, require_operator
from app.core.audit import record
from app.core.principal import Principal
from app.db import get_session
from app.schemas.tag import TagCreate, TagOut, TagUpdate
from app.services import tags as tags_service

router = APIRouter(prefix="/api/tags", tags=["tags"])


@router.get("", response_model=list[TagOut])
async def list_tags(
    principal: Principal = Depends(require_operator),
    session: AsyncSession = Depends(get_session),
) -> list[TagOut]:
    tags = await tags_service.list_tags(session)
    return [TagOut.model_validate(t) for t in tags]


@router.post("", response_model=TagOut, status_code=status.HTTP_201_CREATED)
async def create_tag(
    body: TagCreate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> TagOut:
    try:
        tag = await tags_service.create_tag(session, name=body.name, color=body.color)
    except tags_service.TagError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="tag_create",
        detail={"name": tag.name, "color": tag.color},
        source_ip=client_ip(request),
    )
    await session.commit()
    return TagOut.model_validate(tag)


@router.put("/{tag_id}", response_model=TagOut)
async def update_tag(
    tag_id: uuid.UUID,
    body: TagUpdate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> TagOut:
    tag = await tags_service.get_tag(session, tag_id)
    if tag is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tag not found")
    try:
        tag = await tags_service.update_tag(session, tag, name=body.name, color=body.color)
    except tags_service.TagError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="tag_update",
        detail={"tag_id": str(tag_id), "name": tag.name},
        source_ip=client_ip(request),
    )
    await session.commit()
    return TagOut.model_validate(tag)


@router.delete("/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tag(
    tag_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> None:
    tag = await tags_service.get_tag(session, tag_id)
    if tag is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tag not found")
    await tags_service.delete_tag(session, tag)
    await record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="tag_delete",
        detail={"tag_id": str(tag_id), "name": tag.name},
        source_ip=client_ip(request),
    )
    await session.commit()

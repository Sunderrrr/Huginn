"""Admin endpoints for enrollment-token lifecycle."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, require_admin
from app.core import audit
from app.core.principal import Principal
from app.db import get_session
from app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollmentTokenOut,
)
from app.services import enrollment as enrollment_service

router = APIRouter(prefix="/api/enrollment-tokens", tags=["enrollment"])


@router.post("", response_model=EnrollmentTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    body: EnrollmentTokenCreate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> EnrollmentTokenCreated:
    created_by = principal.user.id if principal.user else uuid.UUID(int=0)
    token, plaintext = await enrollment_service.create_token(
        session,
        created_by=created_by,
        label=body.label,
        ttl_seconds=body.ttl_seconds,
        max_uses=body.max_uses,
    )
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="token_create",
        detail={"token_id": str(token.id), "max_uses": body.max_uses},
        source_ip=client_ip(request),
    )
    base = EnrollmentTokenOut.model_validate(token)
    return EnrollmentTokenCreated(**base.model_dump(), token=plaintext)


@router.get("", response_model=list[EnrollmentTokenOut])
async def list_tokens(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> list[EnrollmentTokenOut]:
    tokens = await enrollment_service.list_tokens(session)
    return [EnrollmentTokenOut.model_validate(t) for t in tokens]


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    token_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> None:
    token = await enrollment_service.revoke_token(session, token_id)
    if token is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="token_revoke",
        detail={"token_id": str(token_id)},
        source_ip=client_ip(request),
    )

"""Audit log read endpoint (admin only) and chain verification."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core import audit as audit_core
from app.core.principal import Principal
from app.db import get_session
from app.models.audit import AuditLog
from app.schemas.audit import AuditEntryOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditEntryOut])
async def list_audit(
    vm_id: uuid.UUID | None = None,
    event_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> list[AuditEntryOut]:
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if vm_id is not None:
        stmt = stmt.where(AuditLog.vm_id == vm_id)
    if event_type is not None:
        stmt = stmt.where(AuditLog.event_type == event_type)
    result = await session.execute(stmt)
    return [AuditEntryOut.model_validate(row) for row in result.scalars()]


@router.get("/verify")
async def verify_audit(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> dict[str, bool]:
    """Recompute the audit hash chain and report whether it is intact."""
    return {"intact": await audit_core.verify_chain(session)}

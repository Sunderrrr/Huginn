"""Audit log read endpoint (admin only) and chain verification."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin, require_operator
from app.core import audit as audit_core
from app.core.principal import Principal
from app.db import get_session
from app.models.audit import AuditLog
from app.models.enums import ActorType
from app.models.user import User
from app.schemas.audit import AuditEntryOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _label_for(row: AuditLog, usernames: dict[str, str]) -> str:
    """Human-friendly actor label for an audit row."""
    if row.actor_type is ActorType.agent:
        # MCP on-behalf-of: actor_id is the user's UUID → "mcp · <username>".
        username = usernames.get(row.actor_id)
        return f"mcp · {username}" if username else "mcp"
    if row.actor_type is ActorType.user:
        return usernames.get(row.actor_id, row.actor_id)
    # system events: login_failed records the attempted username as actor_id.
    return row.actor_id


@router.get("", response_model=list[AuditEntryOut])
async def list_audit(
    vm_id: uuid.UUID | None = None,
    event_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    principal: Principal = Depends(require_operator),
    session: AsyncSession = Depends(get_session),
) -> list[AuditEntryOut]:
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if vm_id is not None:
        stmt = stmt.where(AuditLog.vm_id == vm_id)
    if event_type is not None:
        stmt = stmt.where(AuditLog.event_type == event_type)
    result = await session.execute(stmt)
    rows = list(result.scalars())

    # Resolve user actor_ids to usernames in one query. Agent rows whose actor_id
    # is a UUID are MCP-on-behalf-of actions — resolve those too (so the label can
    # show "mcp · <username>").
    user_ids: set[uuid.UUID] = set()
    for r in rows:
        if r.actor_type in (ActorType.user, ActorType.agent):
            try:
                user_ids.add(uuid.UUID(r.actor_id))
            except ValueError:
                pass
    usernames: dict[str, str] = {}
    if user_ids:
        users = await session.execute(select(User).where(User.id.in_(user_ids)))
        usernames = {str(u.id): u.username for u in users.scalars()}

    out: list[AuditEntryOut] = []
    for r in rows:
        entry = AuditEntryOut.model_validate(r)
        entry.actor_label = _label_for(r, usernames)
        out.append(entry)
    return out


@router.get("/verify")
async def verify_audit(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> dict[str, bool]:
    """Recompute the audit hash chain and report whether it is intact."""
    return {"intact": await audit_core.verify_chain(session)}

"""Append-only audit writer with a tamper-evident hash chain.

``record()`` is the *only* supported way to write to ``audit_log``. Entries are
never updated or deleted. Each row commits to the previous one via
``row_hash = sha256(prev_hash || canonical_json(fields))``; ``verify_chain()``
recomputes the chain to detect tampering.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.enums import ActorType

GENESIS_HASH = "0" * 64

# Arbitrary constant key for the PostgreSQL transaction-level advisory lock that
# serializes audit appends (so concurrent writers can't fork the hash chain).
_AUDIT_LOCK_KEY = 0x4855_4749_4E41  # "HUGINA"


async def _serialize_appends(session: AsyncSession) -> None:
    """Take a per-transaction advisory lock so chain appends are serialized.

    On PostgreSQL this blocks concurrent ``record()`` calls until the holder's
    transaction commits, guaranteeing each row commits to the true chain head.
    SQLite (tests) serializes writers anyway, so this is a no-op there.
    """
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY}
        )


def _canonical(fields: dict[str, Any]) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)


def _compute_row_hash(prev_hash: str, fields: dict[str, Any]) -> str:
    payload = prev_hash + _canonical(fields)
    return hashlib.sha256(payload.encode()).hexdigest()


async def _chain_head(session: AsyncSession) -> str:
    result = await session.execute(select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1))
    head = result.scalar_one_or_none()
    return head or GENESIS_HASH


async def record(
    session: AsyncSession,
    *,
    actor_type: ActorType,
    actor_id: str,
    event_type: str,
    vm_id: uuid.UUID | None = None,
    action_name: str | None = None,
    command: str | None = None,
    result_status: str | None = None,
    exit_code: int | None = None,
    detail: dict[str, Any] | None = None,
    source_ip: str | None = None,
) -> AuditLog:
    """Append one immutable audit entry, extending the hash chain."""
    detail = detail or {}
    await _serialize_appends(session)
    prev_hash = await _chain_head(session)
    fields = {
        "actor_type": actor_type.value,
        "actor_id": actor_id,
        "event_type": event_type,
        "vm_id": str(vm_id) if vm_id else None,
        "action_name": action_name,
        "command": command,
        "result_status": result_status,
        "exit_code": exit_code,
        "detail": detail,
        "source_ip": source_ip,
    }
    row_hash = _compute_row_hash(prev_hash, fields)
    entry = AuditLog(
        actor_type=actor_type,
        actor_id=actor_id,
        event_type=event_type,
        vm_id=vm_id,
        action_name=action_name,
        command=command,
        result_status=result_status,
        exit_code=exit_code,
        detail=detail,
        source_ip=source_ip,
        prev_hash=prev_hash,
        row_hash=row_hash,
    )
    session.add(entry)
    await session.flush()
    return entry


async def verify_chain(session: AsyncSession) -> bool:
    """Recompute every row_hash and confirm the chain is intact."""
    result = await session.execute(select(AuditLog).order_by(AuditLog.id.asc()))
    prev = GENESIS_HASH
    for row in result.scalars():
        fields = {
            "actor_type": row.actor_type.value,
            "actor_id": row.actor_id,
            "event_type": row.event_type,
            "vm_id": str(row.vm_id) if row.vm_id else None,
            "action_name": row.action_name,
            "command": row.command,
            "result_status": row.result_status,
            "exit_code": row.exit_code,
            "detail": row.detail,
            "source_ip": row.source_ip,
        }
        if row.prev_hash != prev or row.row_hash != _compute_row_hash(prev, fields):
            return False
        prev = row.row_hash
    return True

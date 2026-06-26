"""Append-only, tamper-evident audit log.

Each row stores ``row_hash = H(prev_hash || canonical(payload))`` forming a hash
chain. Rows are only ever inserted (the application exposes no update/delete
path), so any retroactive tampering breaks the chain and is detectable.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Enum, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, JSONType
from app.models.enums import ActorType
from app.models.mixins import utcnow


class AuditLog(Base):
    __tablename__ = "audit_log"

    # BIGINT on PostgreSQL; SQLite only autoincrements INTEGER PRIMARY KEY, so use
    # a plain INTEGER variant there (test suite only).
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    actor_type: Mapped[ActorType] = mapped_column(
        Enum(ActorType, name="actor_type"), nullable=False
    )
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    vm_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True, index=True)
    action_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    command: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    result_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Tamper-evidence chain.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

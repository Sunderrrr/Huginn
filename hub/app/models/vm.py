"""Fleet VMs and their workers."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, JSONType
from app.models.enums import ExecMode, VMState, WorkerArch
from app.models.mixins import TimestampMixin


class VM(Base, TimestampMixin):
    __tablename__ = "vms"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    arch: Mapped[WorkerArch] = mapped_column(Enum(WorkerArch, name="worker_arch"), nullable=False)
    os_info: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    state: Mapped[VMState] = mapped_column(
        Enum(VMState, name="vm_state"), default=VMState.pending, nullable=False, index=True
    )
    exec_mode: Mapped[ExecMode] = mapped_column(
        Enum(ExecMode, name="exec_mode"), default=ExecMode.whitelist, nullable=False
    )
    worker_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # HMAC of the per-worker secret issued at approval; used to authenticate the
    # worker on every subsequent request.
    worker_secret_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    enrollment_token_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_active(self) -> bool:
        return self.state is VMState.active

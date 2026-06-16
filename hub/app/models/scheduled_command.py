"""Scheduled commands: recurring actions/commands the hub auto-queues."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, JSONType
from app.models.mixins import TimestampMixin

# target_kind: "vm" | "tag" | "all_active"
# task_kind:   "action" | "command"
# Stored as plain strings (validated in the schema) to avoid extra DB enum types.


class ScheduledCommand(Base, TimestampMixin):
    __tablename__ = "scheduled_commands"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Target
    target_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    target_vm_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    target_tag_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    # What to run
    task_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    action_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    params: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)

    # When (cron); presets are converted to cron client-side.
    cron_expression: Mapped[str] = mapped_column(String(128), nullable=False)

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

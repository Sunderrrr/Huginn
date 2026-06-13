"""Single-row settings table: the hub is the source of truth for fleet config."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, JSONType
from app.models.mixins import utcnow

SETTINGS_SINGLETON_ID = 1


class Setting(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=SETTINGS_SINGLETON_ID)
    target_worker_version: Mapped[str] = mapped_column(String(64), nullable=False)
    target_release_repo: Mapped[str] = mapped_column(String(255), nullable=False)
    # Stored as a JSON list for cross-dialect portability.
    allowed_release_domains: Mapped[list[str]] = mapped_column(
        JSONType, default=list, nullable=False
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

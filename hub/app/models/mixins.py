"""Shared column mixins."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_aware_utc(dt: datetime) -> datetime:
    """Coerce a possibly-naive datetime to aware UTC.

    SQLite (used in tests) drops tzinfo even on timezone-aware columns; PostgreSQL
    preserves it. Normalizing on read keeps comparisons against ``utcnow()`` safe
    across both backends.
    """
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

"""Single-use TOTP backup/recovery codes (stored hashed)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.mixins import TimestampMixin


class MfaBackupCode(Base, TimestampMixin):
    """A recovery code for a user's TOTP. Only the HMAC hash is persisted."""

    __tablename__ = "mfa_backup_codes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # HMAC-SHA256 (keyed) of the plaintext code; unique to detect collisions.
    code_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # Set on consumption — codes are single-use; row kept for audit.
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

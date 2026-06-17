"""Server-side WebAuthn challenges (single-use, expiring)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.mixins import TimestampMixin


class WebAuthnChallenge(Base, TimestampMixin):
    """A pending registration/authentication challenge.

    Challenges are generated server-side, stored here, and consumed exactly once
    — never trust a client-echoed challenge.
    """

    __tablename__ = "webauthn_challenges"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    challenge: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    # Set for registration / 2-step; null for usernameless (discoverable) login.
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)  # register | login
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

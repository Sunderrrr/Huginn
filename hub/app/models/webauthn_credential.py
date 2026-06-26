"""Registered WebAuthn (passkey) credentials per user."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, JSONType
from app.models.mixins import TimestampMixin


class WebAuthnCredential(Base, TimestampMixin):
    """A FIDO2/WebAuthn authenticator bound to a user account."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # User-supplied label, e.g. "MacBook Touch ID".
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # base64url of the raw credential id (unique across all users).
    credential_id: Mapped[str] = mapped_column(
        String(512), unique=True, nullable=False, index=True
    )
    # COSE public key bytes returned by py_webauthn.
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Signature counter — persisted and checked for clone detection.
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    transports: Mapped[list[str] | None] = mapped_column(JSONType, nullable=True)
    aaguid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

"""Per-user MCP tokens: named, revocable bearer tokens for the MCP server.

An agent presents one of these to the MCP server, which forwards it to the hub
on behalf of the owning user — so MCP actions are attributed to that user in the
audit log. Only the HMAC of the secret is stored; the plaintext is shown once.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.mixins import TimestampMixin


class McpToken(Base, TimestampMixin):
    __tablename__ = "mcp_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # HMAC of the secret token; the plaintext is shown once at creation.
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    # Optional IP allow-list: a single IP or CIDR the token may be used from.
    # NULL = usable from anywhere. Enforced against the (trusted) client IP.
    allowed_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

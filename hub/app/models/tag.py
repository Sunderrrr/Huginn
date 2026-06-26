"""Custom tags for grouping/categorizing VMs, and the VM↔tag association."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, PrimaryKeyConstraint, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.mixins import TimestampMixin


class Tag(Base, TimestampMixin):
    """A named, colored label admins assign to VMs for grouping and filtering."""

    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    # Hex color like "#46d39a".
    color: Mapped[str] = mapped_column(String(7), nullable=False)


class VMTag(Base):
    """Many-to-many between VMs and tags (mirror of user_vm_access)."""

    __tablename__ = "vm_tags"
    __table_args__ = (PrimaryKeyConstraint("vm_id", "tag_id"),)

    vm_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vms.id", ondelete="CASCADE"))
    tag_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"))

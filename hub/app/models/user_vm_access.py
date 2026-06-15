"""Association table linking users to the VMs they may access."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, PrimaryKeyConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class UserVMAccess(Base):
    """Grants a user access to a specific VM.

    Only meaningful for ``operator`` and ``readonly`` roles — admins always have
    full access.  A user with no rows in this table sees nothing in the fleet.
    """

    __tablename__ = "user_vm_access"
    __table_args__ = (PrimaryKeyConstraint("user_id", "vm_id"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    vm_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vms.id", ondelete="CASCADE"))

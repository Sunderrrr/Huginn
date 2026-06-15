"""add operator role, user_vm_access table, and mcp_client_token setting

Revision ID: c3d4e5f6a7b8
Revises: b1a2c3d4e5f6
Create Date: 2026-06-15 18:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c3d4e5f6a7b8"
down_revision: str | None = "b1a2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add 'operator' to the user_role enum
    op.execute("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'operator'")

    # Add 'uninstall' to the task_type enum
    op.execute("ALTER TYPE task_type ADD VALUE IF NOT EXISTS 'uninstall'")

    # Create user_vm_access association table
    op.create_table(
        "user_vm_access",
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vm_id", sa.Uuid(), sa.ForeignKey("vms.id", ondelete="CASCADE"), nullable=False),
        sa.PrimaryKeyConstraint("user_id", "vm_id"),
    )

    # Add mcp_client_token to settings table
    op.add_column("settings", sa.Column("mcp_client_token", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("settings", "mcp_client_token")
    op.drop_table("user_vm_access")
    # Note: PostgreSQL does not support removing enum values.

"""add composite index on tasks(vm_id, status)

Speeds up the hot worker-poll query (oldest pending task for a VM).

Revision ID: b1a2c3d4e5f6
Revises: 9c0fef947969
Create Date: 2026-06-13 23:05:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "b1a2c3d4e5f6"
down_revision: str | None = "9c0fef947969"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_tasks_vm_status", "tasks", ["vm_id", "status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_tasks_vm_status", table_name="tasks")

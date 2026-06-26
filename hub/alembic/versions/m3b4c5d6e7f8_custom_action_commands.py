"""custom_actions: argv (single) -> commands (list of argv)

Revision ID: m3b4c5d6e7f8
Revises: l2a3b4c5d6e7
Create Date: 2026-06-21 14:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "m3b4c5d6e7f8"
down_revision: str | None = "l2a3b4c5d6e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A custom action becomes a sequence of commands. The JSON column is reused;
    # the value shape changes from list[str] to list[list[str]].
    op.alter_column("custom_actions", "argv", new_column_name="commands")


def downgrade() -> None:
    op.alter_column("custom_actions", "commands", new_column_name="argv")

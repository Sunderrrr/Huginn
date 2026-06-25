"""enrollment_tokens: add auto_approve flag

Revision ID: n4c5d6e7f8a9
Revises: m3b4c5d6e7f8
Create Date: 2026-06-25 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "n4c5d6e7f8a9"
down_revision: str | None = "m3b4c5d6e7f8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # VMs enrolled with an auto_approve token come up ACTIVE instead of PENDING.
    # (max_uses == 0 = unlimited reuse needs no schema change; it's just a value.)
    op.add_column(
        "enrollment_tokens",
        sa.Column(
            "auto_approve",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("enrollment_tokens", "auto_approve")

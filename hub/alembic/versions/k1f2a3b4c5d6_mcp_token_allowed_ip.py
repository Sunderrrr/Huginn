"""add allowed_ip to mcp_tokens (per-token IP allow-list)

Revision ID: k1f2a3b4c5d6
Revises: j0e1f2a3b4c5
Create Date: 2026-06-19 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "k1f2a3b4c5d6"
down_revision: str | None = "j0e1f2a3b4c5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("mcp_tokens", sa.Column("allowed_ip", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("mcp_tokens", "allowed_ip")

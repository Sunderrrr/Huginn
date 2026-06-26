"""per-user MCP tokens; drop the single shared mcp_client_token

Revision ID: j0e1f2a3b4c5
Revises: i9d0e1f2a3b4
Create Date: 2026-06-18 20:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "j0e1f2a3b4c5"
down_revision: str | None = "i9d0e1f2a3b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mcp_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f("ix_mcp_tokens_user_id"), "mcp_tokens", ["user_id"])
    op.create_index(op.f("ix_mcp_tokens_token_hash"), "mcp_tokens", ["token_hash"], unique=True)

    # The single shared client token is replaced by per-user MCP tokens.
    op.drop_column("settings", "mcp_client_token")


def downgrade() -> None:
    op.add_column("settings", sa.Column("mcp_client_token", sa.String(255), nullable=True))
    op.drop_index(op.f("ix_mcp_tokens_token_hash"), table_name="mcp_tokens")
    op.drop_index(op.f("ix_mcp_tokens_user_id"), table_name="mcp_tokens")
    op.drop_table("mcp_tokens")

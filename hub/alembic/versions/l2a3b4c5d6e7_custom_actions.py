"""custom actions (admin-defined commands) + ExecMode.custom

Revision ID: l2a3b4c5d6e7
Revises: k1f2a3b4c5d6
Create Date: 2026-06-20 14:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "l2a3b4c5d6e7"
down_revision: str | None = "k1f2a3b4c5d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    # Add the new 'custom' exec mode value (Postgres enum). ADD VALUE cannot run
    # inside a transaction, so use an autocommit block. SQLite stores the enum as
    # plain text, so nothing to alter there.
    if bind.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE exec_mode ADD VALUE IF NOT EXISTS 'custom'")

    op.create_table(
        "custom_actions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("argv", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f("ix_custom_actions_name"), "custom_actions", ["name"], unique=True)

    op.create_table(
        "custom_action_tags",
        sa.Column(
            "action_id",
            sa.Uuid(),
            sa.ForeignKey("custom_actions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tag_id",
            sa.Uuid(),
            sa.ForeignKey("tags.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("action_id", "tag_id"),
    )


def downgrade() -> None:
    op.drop_table("custom_action_tags")
    op.drop_index(op.f("ix_custom_actions_name"), table_name="custom_actions")
    op.drop_table("custom_actions")
    # The 'custom' enum value is left in place (Postgres can't easily drop a value).

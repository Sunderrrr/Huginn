"""tags, vm_tags, scheduled_commands tables

Revision ID: g7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-06-16 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "g7b8c9d0e1f2"
down_revision: str | None = "f6a7b8c9d0e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tags",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("color", sa.String(7), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f("ix_tags_name"), "tags", ["name"], unique=True)

    op.create_table(
        "vm_tags",
        sa.Column("vm_id", sa.Uuid(), sa.ForeignKey("vms.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tag_id", sa.Uuid(), sa.ForeignKey("tags.id", ondelete="CASCADE"), nullable=False),
        sa.PrimaryKeyConstraint("vm_id", "tag_id"),
    )

    op.create_table(
        "scheduled_commands",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("target_kind", sa.String(16), nullable=False),
        sa.Column("target_vm_id", sa.Uuid(), nullable=True),
        sa.Column("target_tag_id", sa.Uuid(), nullable=True),
        sa.Column("task_kind", sa.String(16), nullable=False),
        sa.Column("action_name", sa.String(64), nullable=True),
        sa.Column(
            "params",
            sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("cron_expression", sa.String(128), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        op.f("ix_scheduled_commands_enabled"), "scheduled_commands", ["enabled"], unique=False
    )


def downgrade() -> None:
    op.drop_table("scheduled_commands")
    op.drop_table("vm_tags")
    op.drop_index(op.f("ix_tags_name"), table_name="tags")
    op.drop_table("tags")

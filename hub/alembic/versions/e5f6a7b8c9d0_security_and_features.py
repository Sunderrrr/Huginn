"""ldap_dn, idempotency unique index, notification settings

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-06-15 19:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e5f6a7b8c9d0"
down_revision: str | None = "d4e5f6a7b8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # LDAP DN on users (dedup key for LDAP-provisioned users).
    op.add_column("users", sa.Column("ldap_dn", sa.String(512), nullable=True))
    op.create_index(op.f("ix_users_ldap_dn"), "users", ["ldap_dn"], unique=True)

    # Partial unique index: at most one task per (vm_id, idempotency_key).
    op.create_index(
        "uq_tasks_vm_idempotency",
        "tasks",
        ["vm_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    # Notification settings.
    op.add_column("settings", sa.Column("notifications_enabled", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("settings", sa.Column("discord_webhook_url", sa.String(512), nullable=True))
    op.add_column("settings", sa.Column("generic_webhook_url", sa.String(512), nullable=True))
    op.add_column("settings", sa.Column("notify_vm_offline", sa.Boolean(), nullable=False, server_default="true"))
    op.add_column("settings", sa.Column("notify_vm_recovered", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("settings", sa.Column("notify_task_failure", sa.Boolean(), nullable=False, server_default="false"))


def downgrade() -> None:
    op.drop_column("settings", "notify_task_failure")
    op.drop_column("settings", "notify_vm_recovered")
    op.drop_column("settings", "notify_vm_offline")
    op.drop_column("settings", "generic_webhook_url")
    op.drop_column("settings", "discord_webhook_url")
    op.drop_column("settings", "notifications_enabled")
    op.drop_index("uq_tasks_vm_idempotency", table_name="tasks")
    op.drop_index(op.f("ix_users_ldap_dn"), table_name="users")
    op.drop_column("users", "ldap_dn")

"""add TOTP 2FA, WebAuthn passkeys, MFA/SSO settings

Revision ID: i9d0e1f2a3b4
Revises: h8c9d0e1f2a3
Create Date: 2026-06-17 18:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "i9d0e1f2a3b4"
down_revision: str | None = "h8c9d0e1f2a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- users: TOTP columns ---
    op.add_column("users", sa.Column("totp_secret_enc", sa.String(512), nullable=True))
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column("users", sa.Column("totp_confirmed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger(), nullable=True))

    # --- settings: MFA / WebAuthn config ---
    op.add_column(
        "settings",
        sa.Column("require_admin_mfa", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column(
        "settings",
        sa.Column("allow_password_login", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "settings", sa.Column("webauthn_rp_id", sa.String(255), nullable=False, server_default="")
    )
    op.add_column(
        "settings",
        sa.Column("webauthn_rp_name", sa.String(255), nullable=False, server_default="Huginn"),
    )
    op.add_column(
        "settings", sa.Column("webauthn_origin", sa.String(512), nullable=False, server_default="")
    )

    # --- mfa_backup_codes ---
    op.create_table(
        "mfa_backup_codes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(128), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f("ix_mfa_backup_codes_user_id"), "mfa_backup_codes", ["user_id"])
    op.create_index(
        op.f("ix_mfa_backup_codes_code_hash"), "mfa_backup_codes", ["code_hash"], unique=True
    )

    # --- webauthn_credentials ---
    op.create_table(
        "webauthn_credentials",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("credential_id", sa.String(512), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "transports",
            sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"),
            nullable=True,
        ),
        sa.Column("aaguid", sa.String(64), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f("ix_webauthn_credentials_user_id"), "webauthn_credentials", ["user_id"])
    op.create_index(
        op.f("ix_webauthn_credentials_credential_id"),
        "webauthn_credentials",
        ["credential_id"],
        unique=True,
    )

    # --- webauthn_challenges ---
    op.create_table(
        "webauthn_challenges",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("challenge", sa.String(255), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        op.f("ix_webauthn_challenges_challenge"), "webauthn_challenges", ["challenge"], unique=True
    )


def downgrade() -> None:
    op.drop_table("webauthn_challenges")
    op.drop_index(op.f("ix_webauthn_credentials_credential_id"), table_name="webauthn_credentials")
    op.drop_index(op.f("ix_webauthn_credentials_user_id"), table_name="webauthn_credentials")
    op.drop_table("webauthn_credentials")
    op.drop_index(op.f("ix_mfa_backup_codes_code_hash"), table_name="mfa_backup_codes")
    op.drop_index(op.f("ix_mfa_backup_codes_user_id"), table_name="mfa_backup_codes")
    op.drop_table("mfa_backup_codes")
    op.drop_column("settings", "webauthn_origin")
    op.drop_column("settings", "webauthn_rp_name")
    op.drop_column("settings", "webauthn_rp_id")
    op.drop_column("settings", "allow_password_login")
    op.drop_column("settings", "require_admin_mfa")
    op.drop_column("users", "totp_last_step")
    op.drop_column("users", "totp_confirmed_at")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret_enc")

"""add SSO and LDAP settings columns

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-06-15 19:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "c3d4e5f6a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SSO / OIDC columns
    op.add_column("settings", sa.Column("oidc_enabled", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("settings", sa.Column("oidc_issuer", sa.String(512), nullable=False, server_default=""))
    op.add_column("settings", sa.Column("oidc_client_id", sa.String(255), nullable=False, server_default=""))
    op.add_column("settings", sa.Column("oidc_client_secret", sa.String(512), nullable=True))
    op.add_column("settings", sa.Column("oidc_redirect_url", sa.String(512), nullable=False, server_default=""))
    op.add_column("settings", sa.Column("oidc_post_login_redirect", sa.String(512), nullable=False, server_default=""))

    # LDAP columns
    op.add_column("settings", sa.Column("ldap_enabled", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("settings", sa.Column("ldap_server_url", sa.String(512), nullable=False, server_default=""))
    op.add_column("settings", sa.Column("ldap_bind_dn", sa.String(512), nullable=False, server_default=""))
    op.add_column("settings", sa.Column("ldap_bind_password", sa.String(512), nullable=True))
    op.add_column("settings", sa.Column("ldap_user_search_base", sa.String(512), nullable=False, server_default=""))
    op.add_column("settings", sa.Column("ldap_user_search_filter", sa.String(512), nullable=False, server_default=""))
    op.add_column("settings", sa.Column("ldap_start_tls", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("settings", sa.Column("ldap_use_ldaps", sa.Boolean(), nullable=False, server_default="false"))


def downgrade() -> None:
    op.drop_column("settings", "ldap_use_ldaps")
    op.drop_column("settings", "ldap_start_tls")
    op.drop_column("settings", "ldap_user_search_filter")
    op.drop_column("settings", "ldap_user_search_base")
    op.drop_column("settings", "ldap_bind_password")
    op.drop_column("settings", "ldap_bind_dn")
    op.drop_column("settings", "ldap_server_url")
    op.drop_column("settings", "ldap_enabled")
    op.drop_column("settings", "oidc_post_login_redirect")
    op.drop_column("settings", "oidc_redirect_url")
    op.drop_column("settings", "oidc_client_secret")
    op.drop_column("settings", "oidc_client_id")
    op.drop_column("settings", "oidc_issuer")
    op.drop_column("settings", "oidc_enabled")

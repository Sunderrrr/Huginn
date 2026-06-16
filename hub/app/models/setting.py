"""Single-row settings table: the hub is the source of truth for fleet config."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, JSONType
from app.models.mixins import utcnow

SETTINGS_SINGLETON_ID = 1


class Setting(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=SETTINGS_SINGLETON_ID)
    target_worker_version: Mapped[str] = mapped_column(String(64), nullable=False)
    target_release_repo: Mapped[str] = mapped_column(String(255), nullable=False)
    # When true, the hub auto-queues an update task for any worker that heartbeats
    # with a version different from target_worker_version.
    auto_update_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Stored as a JSON list for cross-dialect portability.
    allowed_release_domains: Mapped[list[str]] = mapped_column(
        JSONType, default=list, nullable=False
    )
    mcp_client_token: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # SSO / OIDC settings (admin-configurable from dashboard)
    oidc_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    oidc_issuer: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    oidc_client_id: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    oidc_client_secret: Mapped[str | None] = mapped_column(String(512), nullable=True)
    oidc_redirect_url: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    oidc_post_login_redirect: Mapped[str] = mapped_column(String(512), default="", nullable=False)

    # LDAP settings (admin-configurable from dashboard)
    ldap_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ldap_server_url: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    ldap_bind_dn: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    ldap_bind_password: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ldap_user_search_base: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    ldap_user_search_filter: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    ldap_start_tls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ldap_use_ldaps: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Notifications (admin-configurable from dashboard)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    discord_webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    generic_webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    notify_vm_offline: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_vm_recovered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notify_task_failure: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

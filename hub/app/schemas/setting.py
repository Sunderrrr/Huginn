"""Fleet settings schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SettingsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    target_worker_version: str
    target_release_repo: str
    allowed_release_domains: list[str]
    updated_at: datetime

    # SSO / OIDC
    oidc_enabled: bool
    oidc_issuer: str
    oidc_client_id: str
    oidc_redirect_url: str
    oidc_post_login_redirect: str

    # LDAP
    ldap_enabled: bool
    ldap_server_url: str
    ldap_bind_dn: str
    ldap_user_search_base: str
    ldap_user_search_filter: str
    ldap_start_tls: bool
    ldap_use_ldaps: bool

    # Notifications
    notifications_enabled: bool
    discord_webhook_url: str | None
    generic_webhook_url: str | None
    notify_vm_offline: bool
    notify_vm_recovered: bool
    notify_task_failure: bool


class SettingsUpdate(BaseModel):
    target_worker_version: str | None = Field(default=None, max_length=64)
    target_release_repo: str | None = Field(default=None, max_length=255)
    allowed_release_domains: list[str] | None = None

    # SSO / OIDC
    oidc_enabled: bool | None = None
    oidc_issuer: str | None = Field(default=None, max_length=512)
    oidc_client_id: str | None = Field(default=None, max_length=255)
    oidc_client_secret: str | None = Field(default=None, max_length=512)
    oidc_redirect_url: str | None = Field(default=None, max_length=512)
    oidc_post_login_redirect: str | None = Field(default=None, max_length=512)

    # LDAP
    ldap_enabled: bool | None = None
    ldap_server_url: str | None = Field(default=None, max_length=512)
    ldap_bind_dn: str | None = Field(default=None, max_length=512)
    ldap_bind_password: str | None = Field(default=None, max_length=512)
    ldap_user_search_base: str | None = Field(default=None, max_length=512)
    ldap_user_search_filter: str | None = Field(default=None, max_length=512)
    ldap_start_tls: bool | None = None
    ldap_use_ldaps: bool | None = None

    # Notifications
    notifications_enabled: bool | None = None
    discord_webhook_url: str | None = Field(default=None, max_length=512)
    generic_webhook_url: str | None = Field(default=None, max_length=512)
    notify_vm_offline: bool | None = None
    notify_vm_recovered: bool | None = None
    notify_task_failure: bool | None = None

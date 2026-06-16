"""Access to the single-row settings table (fleet-wide configuration)."""

from __future__ import annotations

import secrets

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings as AppSettings
from app.models.setting import SETTINGS_SINGLETON_ID, Setting


async def get_settings_row(session: AsyncSession) -> Setting | None:
    return await session.get(Setting, SETTINGS_SINGLETON_ID)


async def ensure_settings(session: AsyncSession, app_settings: AppSettings) -> Setting:
    """Seed the settings row on first boot; return it.

    The MCP client token comes from the env var if set, otherwise the hub
    generates a random one — so operators never have to provision it manually.
    The MCP server fetches whatever value the hub holds.
    """
    row = await get_settings_row(session)
    if row is None:
        row = Setting(
            id=SETTINGS_SINGLETON_ID,
            target_worker_version=app_settings.target_worker_version,
            target_release_repo=app_settings.target_release_repo,
            allowed_release_domains=list(app_settings.allowed_release_domains),
            mcp_client_token=app_settings.mcp_client_token or secrets.token_hex(32),
            # SSO / OIDC
            oidc_enabled=app_settings.oidc_enabled,
            oidc_issuer=app_settings.oidc_issuer,
            oidc_client_id=app_settings.oidc_client_id,
            oidc_client_secret=app_settings.oidc_client_secret or None,
            oidc_redirect_url=app_settings.oidc_redirect_url,
            oidc_post_login_redirect=app_settings.oidc_post_login_redirect,
        )
        session.add(row)
        await session.flush()
    elif not row.mcp_client_token:
        # Backfill: prefer the env value, else generate one.
        row.mcp_client_token = app_settings.mcp_client_token or secrets.token_hex(32)
        await session.flush()
    return row

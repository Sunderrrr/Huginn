"""Access to the single-row settings table (fleet-wide configuration)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings as AppSettings
from app.models.setting import SETTINGS_SINGLETON_ID, Setting


async def get_settings_row(session: AsyncSession) -> Setting | None:
    return await session.get(Setting, SETTINGS_SINGLETON_ID)


async def ensure_settings(session: AsyncSession, app_settings: AppSettings) -> Setting:
    """Seed the settings row from env defaults on first boot; return it."""
    row = await get_settings_row(session)
    if row is None:
        row = Setting(
            id=SETTINGS_SINGLETON_ID,
            target_worker_version=app_settings.target_worker_version,
            target_release_repo=app_settings.target_release_repo,
            allowed_release_domains=list(app_settings.allowed_release_domains),
            mcp_client_token=app_settings.mcp_client_token or None,
        )
        session.add(row)
        await session.flush()
    else:
        # Backfill mcp_client_token from env if not yet set in DB
        if row.mcp_client_token is None and app_settings.mcp_client_token:
            row.mcp_client_token = app_settings.mcp_client_token
            await session.flush()
    return row

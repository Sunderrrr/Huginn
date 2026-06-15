"""MCP server configuration (prefix ``HUGINN_MCP_``)."""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("huginn.mcp.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HUGINN_MCP_", extra="ignore")

    # Hub connection.
    hub_url: str = "http://localhost:8000"
    service_token: str = "change-me-mcp-service-token"
    request_timeout_seconds: float = 30.0

    # Transport.
    transport: Literal["stdio", "streamable-http"] = "stdio"
    host: str = "0.0.0.0"  # noqa: S104 - intended to bind all interfaces in a container
    port: int = 9000

    # HTTP auth: agents must send `Authorization: Bearer <this token>`.
    # Only enforced for streamable-http transport. Ignored for stdio.
    # If empty, the server will try to fetch it from the hub's /api/settings/mcp-token.
    mcp_client_token: str = ""


def _fetch_client_token_from_hub(hub_url: str, service_token: str) -> str:
    """Fetch the MCP client token from the hub's settings API."""
    import httpx

    try:
        resp = httpx.get(
            f"{hub_url.rstrip('/')}/api/settings/mcp-token",
            headers={"X-MCP-Service-Token": service_token},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("token", "")
            if token:
                logger.info("fetched MCP client token from hub (%s)", data.get("masked", ""))
                return token
    except Exception:
        logger.warning("could not fetch MCP client token from hub")
    return ""


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    # If no client token is set in env, try to fetch it from the hub
    if not s.mcp_client_token and s.transport == "streamable-http":
        s.mcp_client_token = _fetch_client_token_from_hub(s.hub_url, s.service_token)
    return s

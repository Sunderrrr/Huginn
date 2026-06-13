"""MCP server configuration (prefix ``HUGINN_MCP_``)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


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


@lru_cache
def get_settings() -> Settings:
    return Settings()

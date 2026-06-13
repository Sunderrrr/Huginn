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


class SettingsUpdate(BaseModel):
    target_worker_version: str | None = Field(default=None, max_length=64)
    target_release_repo: str | None = Field(default=None, max_length=255)
    allowed_release_domains: list[str] | None = None

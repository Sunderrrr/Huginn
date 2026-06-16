"""Tag schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

_HEX = r"^#[0-9a-fA-F]{6}$"


class TagCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    color: str = Field(pattern=_HEX)


class TagUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    color: str | None = Field(default=None, pattern=_HEX)


class TagOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    color: str
    created_at: datetime


class VMTagsUpdate(BaseModel):
    tag_ids: list[uuid.UUID]

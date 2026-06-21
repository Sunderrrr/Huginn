"""Schemas for admin-defined custom commands."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.core.actions import ACTION_CATALOG

_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


def _check_name(value: str) -> str:
    if not _NAME.match(value):
        raise ValueError("name must be lowercase letters, digits, '-' or '_' (2-64 chars)")
    if value in ACTION_CATALOG:
        raise ValueError(f"{value!r} is a built-in action name")
    return value


class CustomActionCreate(BaseModel):
    name: str
    description: str = Field(default="", max_length=255)
    commands: list[str] = Field(min_length=1)  # one full command line per entry
    tag_ids: list[uuid.UUID] = Field(min_length=1)  # explicit scope: runs nowhere if empty

    _v_name = field_validator("name")(_check_name)


class CustomActionUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=255)
    commands: list[str] | None = Field(default=None, min_length=1)
    enabled: bool | None = None
    tag_ids: list[uuid.UUID] | None = Field(default=None, min_length=1)


class CustomActionOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    commands: list[str]  # canonical command lines
    argv: list[list[str]]  # parsed argv vectors (what actually runs)
    enabled: bool
    tag_ids: list[uuid.UUID]
    created_at: datetime

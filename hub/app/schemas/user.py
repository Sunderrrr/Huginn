"""User management schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import UserRole


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=128)
    email: str | None = None
    role: UserRole = UserRole.readonly
    vm_ids: list[uuid.UUID] = []


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None
    email: str | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str | None
    role: UserRole
    is_active: bool
    vm_ids: list[uuid.UUID] = []


class PasswordChange(BaseModel):
    old_password: str | None = None  # Required for self-change, optional for admin reset
    new_password: str = Field(min_length=12, max_length=128)


class UserVmAccessUpdate(BaseModel):
    vm_ids: list[uuid.UUID]

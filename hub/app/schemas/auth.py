"""Auth request/response schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict

from app.models.enums import UserRole


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str | None
    role: UserRole
    is_active: bool
    vm_ids: list[uuid.UUID] = []


class OIDCStartResponse(BaseModel):
    authorization_url: str
    state: str

"""Per-user MCP token schemas."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import UserRole


def _validate_allowed_ip(value: str | None) -> str | None:
    """Accept a single IP or a CIDR (or blank/None for "any")."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValueError(
            "must be a valid IP address or CIDR (e.g. 203.0.113.7 or 10.0.0.0/24)"
        ) from exc


class McpTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    allowed_ip: str | None = Field(default=None, max_length=64)

    _v_ip = field_validator("allowed_ip")(_validate_allowed_ip)


class McpTokenUpdate(BaseModel):
    # None / blank clears the restriction (usable from anywhere).
    allowed_ip: str | None = Field(default=None, max_length=64)

    _v_ip = field_validator("allowed_ip")(_validate_allowed_ip)


class McpTokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    allowed_ip: str | None
    created_at: datetime
    last_used_at: datetime | None


class McpTokenCreated(BaseModel):
    id: uuid.UUID
    name: str
    allowed_ip: str | None
    token: str  # plaintext, shown once


class WhoAmI(BaseModel):
    username: str
    role: UserRole

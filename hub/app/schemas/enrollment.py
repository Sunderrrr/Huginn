"""Enrollment token and worker-enrollment schemas."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import WorkerArch


def _validate_ip(value: str | None) -> str | None:
    """Reject anything that is not a valid IP literal (blocks stored XSS)."""
    if value is None:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("ip_address must be a valid IP literal") from exc
    return value


def _validate_os_info(value: dict) -> dict:
    """Bound os_info: at most 20 keys, string values <= 256 chars."""
    if len(value) > 20:
        raise ValueError("os_info has too many keys (max 20)")
    for k, v in value.items():
        if not isinstance(k, str) or len(k) > 64:
            raise ValueError("os_info keys must be strings <= 64 chars")
        if isinstance(v, str) and len(v) > 256:
            raise ValueError("os_info string values must be <= 256 chars")
    return value


class EnrollmentTokenCreate(BaseModel):
    label: str = Field(default="", max_length=255)
    # 0 = never expires
    ttl_seconds: int = Field(default=3600, ge=0, le=30 * 24 * 3600)
    max_uses: int = Field(default=1, ge=1, le=1000)


class EnrollmentTokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    label: str
    max_uses: int
    uses_count: int
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime


class EnrollmentTokenCreated(EnrollmentTokenOut):
    # The plaintext token is returned exactly once, at creation.
    token: str


class WorkerEnrollRequest(BaseModel):
    token: str
    name: str = Field(max_length=255)
    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=64)
    arch: WorkerArch
    os_info: dict = Field(default_factory=dict)
    worker_version: str | None = Field(default=None, max_length=64)

    _check_ip = field_validator("ip_address")(_validate_ip)
    _check_os = field_validator("os_info")(_validate_os_info)


class WorkerEnrollResponse(BaseModel):
    worker_id: uuid.UUID
    # Per-worker secret, delivered once over TLS at enrollment. The worker stores
    # it (0600) and presents it on every subsequent request. The VM remains
    # PENDING and inert until an admin approves it.
    worker_secret: str
    state: str

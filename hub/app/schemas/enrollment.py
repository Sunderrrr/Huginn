"""Enrollment token and worker-enrollment schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import WorkerArch


class EnrollmentTokenCreate(BaseModel):
    label: str = Field(default="", max_length=255)
    ttl_seconds: int = Field(default=3600, ge=60, le=30 * 24 * 3600)
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


class WorkerEnrollResponse(BaseModel):
    worker_id: uuid.UUID
    # Per-worker secret, delivered once over TLS at enrollment. The worker stores
    # it (0600) and presents it on every subsequent request. The VM remains
    # PENDING and inert until an admin approves it.
    worker_secret: str
    state: str

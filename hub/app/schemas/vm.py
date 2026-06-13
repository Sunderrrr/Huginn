"""VM inventory schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import ExecMode, VMState, WorkerArch


class VMOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    hostname: str | None
    ip_address: str | None
    arch: WorkerArch
    state: VMState
    exec_mode: ExecMode
    worker_version: str | None
    last_heartbeat_at: datetime | None
    enrolled_at: datetime | None
    approved_at: datetime | None
    created_at: datetime


class ExecModeUpdate(BaseModel):
    exec_mode: ExecMode

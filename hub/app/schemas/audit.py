"""Audit log read schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import ActorType


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    actor_type: ActorType
    actor_id: str
    event_type: str
    vm_id: uuid.UUID | None
    action_name: str | None
    command: str | None
    result_status: str | None
    exit_code: int | None
    detail: dict[str, Any]
    source_ip: str | None

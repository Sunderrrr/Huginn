"""Task and execution request/response schemas."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import TaskStatus, TaskType


class ActionRequest(BaseModel):
    action: str = Field(max_length=64)
    params: dict[str, str] = Field(default_factory=dict)
    wait: bool = False
    idempotency_key: str | None = Field(default=None, max_length=128)


class BulkActionRequest(BaseModel):
    vm_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    action: str = Field(max_length=64)
    params: dict[str, str] = Field(default_factory=dict)


class BulkActionResult(BaseModel):
    vm_id: uuid.UUID
    task_id: uuid.UUID | None = None
    status: str  # "queued" | "error"
    error: str | None = None


class CommandRequest(BaseModel):
    command: str = Field(max_length=65536)
    timeout: int | None = Field(default=None, ge=1, le=3600)
    wait: bool = False
    idempotency_key: str | None = Field(default=None, max_length=128)


class TaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vm_id: uuid.UUID
    type: TaskType
    action_name: str | None
    status: TaskStatus
    exit_code: int | None
    stdout: str | None
    stderr: str | None
    error: str | None
    created_at: datetime
    finished_at: datetime | None


# --- Worker-facing schemas ---

class HeartbeatRequest(BaseModel):
    worker_version: str | None = Field(default=None, max_length=64)
    ip_address: str | None = Field(default=None, max_length=64)

    @field_validator("ip_address")
    @classmethod
    def _validate_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("ip_address must be a valid IP literal") from exc
        return value


class HeartbeatResponse(BaseModel):
    target_worker_version: str
    exec_mode: str
    allowed_release_domains: list[str] = []


class WorkerTask(BaseModel):
    """A task as handed to a worker for execution."""

    id: uuid.UUID
    type: TaskType
    action_name: str | None
    payload: dict[str, Any]


class TaskResultSubmit(BaseModel):
    status: TaskStatus
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    error: str | None = None

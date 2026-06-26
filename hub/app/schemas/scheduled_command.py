"""Scheduled command schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from croniter import croniter
from pydantic import BaseModel, ConfigDict, Field, model_validator

TargetKind = Literal["vm", "tag", "all_active"]
TaskKind = Literal["action", "command"]


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    target_kind: TargetKind
    target_vm_id: uuid.UUID | None = None
    target_tag_id: uuid.UUID | None = None
    task_kind: TaskKind
    action_name: str | None = Field(default=None, max_length=64)
    params: dict[str, str] = Field(default_factory=dict)
    command: str | None = Field(default=None, max_length=65536)
    cron_expression: str = Field(max_length=128)

    @model_validator(mode="after")
    def _check(self) -> ScheduleCreate:
        if not croniter.is_valid(self.cron_expression):
            raise ValueError("invalid cron expression")
        if self.target_kind == "vm" and self.target_vm_id is None:
            raise ValueError("target_vm_id required when target_kind=vm")
        if self.target_kind == "tag" and self.target_tag_id is None:
            raise ValueError("target_tag_id required when target_kind=tag")
        if self.task_kind == "action" and not self.action_name:
            raise ValueError("action_name required when task_kind=action")
        if self.task_kind == "command" and not self.command:
            raise ValueError("command required when task_kind=command")
        return self


class ScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    target_kind: TargetKind | None = None
    target_vm_id: uuid.UUID | None = None
    target_tag_id: uuid.UUID | None = None
    task_kind: TaskKind | None = None
    action_name: str | None = Field(default=None, max_length=64)
    params: dict[str, str] | None = None
    command: str | None = Field(default=None, max_length=65536)
    cron_expression: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _check(self) -> ScheduleUpdate:
        if self.cron_expression is not None and not croniter.is_valid(self.cron_expression):
            raise ValueError("invalid cron expression")
        if self.target_kind == "vm" and self.target_vm_id is None:
            raise ValueError("target_vm_id required when target_kind=vm")
        if self.target_kind == "tag" and self.target_tag_id is None:
            raise ValueError("target_tag_id required when target_kind=tag")
        if self.task_kind == "action" and not self.action_name:
            raise ValueError("action_name required when task_kind=action")
        if self.task_kind == "command" and not self.command:
            raise ValueError("command required when task_kind=command")
        return self


class ScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    enabled: bool
    target_kind: str
    target_vm_id: uuid.UUID | None
    target_tag_id: uuid.UUID | None
    task_kind: str
    action_name: str | None
    params: dict[str, str]
    command: str | None
    cron_expression: str
    last_run_at: datetime | None
    next_run_at: datetime | None = None
    created_at: datetime

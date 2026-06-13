"""Enumerations shared across models and schemas."""

from __future__ import annotations

import enum


class UserRole(enum.StrEnum):
    admin = "admin"
    readonly = "readonly"


class WorkerArch(enum.StrEnum):
    amd64 = "amd64"
    arm64 = "arm64"


class VMState(enum.StrEnum):
    pending = "pending"
    active = "active"
    offline = "offline"
    revoked = "revoked"


class ExecMode(enum.StrEnum):
    whitelist = "whitelist"
    unrestricted = "unrestricted"


class TaskType(enum.StrEnum):
    action = "action"
    command = "command"
    update = "update"


class TaskStatus(enum.StrEnum):
    pending = "pending"
    dispatched = "dispatched"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    timeout = "timeout"
    dead_letter = "dead_letter"
    cancelled = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in {
            TaskStatus.succeeded,
            TaskStatus.failed,
            TaskStatus.timeout,
            TaskStatus.dead_letter,
            TaskStatus.cancelled,
        }


class ActorType(enum.StrEnum):
    user = "user"
    agent = "agent"
    system = "system"

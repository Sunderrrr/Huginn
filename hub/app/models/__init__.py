"""SQLAlchemy models for the Huginn hub."""

from app.models.audit import AuditLog
from app.models.custom_action import CustomAction, CustomActionTag
from app.models.enrollment import EnrollmentToken
from app.models.enums import (
    ActorType,
    ExecMode,
    TaskStatus,
    TaskType,
    UserRole,
    VMState,
    WorkerArch,
)
from app.models.mcp_token import McpToken
from app.models.mfa_backup_code import MfaBackupCode
from app.models.scheduled_command import ScheduledCommand
from app.models.setting import Setting
from app.models.tag import Tag, VMTag
from app.models.task import Task
from app.models.user import User
from app.models.user_vm_access import UserVMAccess
from app.models.vm import VM
from app.models.webauthn_challenge import WebAuthnChallenge
from app.models.webauthn_credential import WebAuthnCredential

__all__ = [
    "ActorType",
    "AuditLog",
    "CustomAction",
    "CustomActionTag",
    "EnrollmentToken",
    "ExecMode",
    "McpToken",
    "MfaBackupCode",
    "ScheduledCommand",
    "Setting",
    "Tag",
    "Task",
    "TaskStatus",
    "TaskType",
    "User",
    "UserRole",
    "UserVMAccess",
    "VM",
    "VMState",
    "VMTag",
    "WebAuthnChallenge",
    "WebAuthnCredential",
    "WorkerArch",
]

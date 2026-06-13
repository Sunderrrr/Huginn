"""The DB-backed task queue: creation, dispatch to workers, results, sweeping."""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.actions import validate_action
from app.models.enums import ExecMode, TaskStatus, TaskType, VMState
from app.models.mixins import as_aware_utc, utcnow
from app.models.task import Task
from app.models.vm import VM
from app.services import versioning


class ExecForbidden(Exception):
    """Raised when execution is not permitted for a VM's current state/mode."""


class TaskInputError(Exception):
    """Raised on invalid task input (oversized command, bad action, etc.)."""


def _require_active(vm: VM) -> None:
    if vm.state not in (VMState.active, VMState.offline):
        raise ExecForbidden("VM is not approved/active")


async def _find_idempotent(
    session: AsyncSession, vm_id: uuid.UUID, key: str | None
) -> Task | None:
    if not key:
        return None
    result = await session.execute(
        select(Task).where(Task.vm_id == vm_id, Task.idempotency_key == key)
    )
    return result.scalar_one_or_none()


async def create_action_task(
    session: AsyncSession,
    *,
    vm: VM,
    action_name: str,
    params: dict[str, str] | None,
    created_by: str,
    idempotency_key: str | None = None,
) -> Task:
    _require_active(vm)
    existing = await _find_idempotent(session, vm.id, idempotency_key)
    if existing:
        return existing
    # validate_action raises ActionError on unknown action / unsafe params.
    normalized = validate_action(action_name, params)
    # "update_worker" is a named action but is fulfilled as an update task (with
    # SSRF-validated release URLs) rather than a shell command on the worker.
    if action_name == "update_worker":
        from app.services import settings_service

        row = await settings_service.get_settings_row(session)
        if row is None:
            raise TaskInputError("settings not initialized")
        return await create_update_task(
            session,
            vm=vm,
            target_version=row.target_worker_version,
            repo=row.target_release_repo,
            allowed_domains=list(row.allowed_release_domains),
            created_by=created_by,
        )
    settings = get_settings()
    task = Task(
        vm_id=vm.id,
        type=TaskType.action,
        action_name=action_name,
        payload={
            "action": action_name,
            "params": normalized,
            "timeout": settings.default_task_timeout_seconds,
        },
        status=TaskStatus.pending,
        created_by=created_by,
        idempotency_key=idempotency_key,
    )
    session.add(task)
    await session.flush()
    return task


async def create_command_task(
    session: AsyncSession,
    *,
    vm: VM,
    command: str,
    created_by: str,
    timeout: int | None = None,
    idempotency_key: str | None = None,
) -> Task:
    _require_active(vm)
    # Free-form commands are only allowed when the VM is explicitly in
    # unrestricted mode (opt-in, audited elsewhere).
    if vm.exec_mode is not ExecMode.unrestricted:
        raise ExecForbidden("VM is not in unrestricted mode")
    settings = get_settings()
    if not command or len(command.encode()) > settings.max_body_bytes:
        raise TaskInputError("command is empty or too large")
    existing = await _find_idempotent(session, vm.id, idempotency_key)
    if existing:
        return existing
    task = Task(
        vm_id=vm.id,
        type=TaskType.command,
        payload={
            "command": command,
            "timeout": timeout or settings.default_task_timeout_seconds,
        },
        status=TaskStatus.pending,
        created_by=created_by,
        idempotency_key=idempotency_key,
    )
    session.add(task)
    await session.flush()
    return task


async def create_update_task(
    session: AsyncSession,
    *,
    vm: VM,
    target_version: str,
    repo: str,
    allowed_domains: list[str],
    created_by: str,
) -> Task:
    _require_active(vm)
    # Raises SSRFError if the constructed URLs are not on an allowlisted host.
    urls = versioning.build_release_urls(
        repo=repo, version=target_version, arch=vm.arch, allowed_domains=allowed_domains
    )
    task = Task(
        vm_id=vm.id,
        type=TaskType.update,
        action_name="update_worker",
        payload={"target_version": target_version, **urls},
        status=TaskStatus.pending,
        created_by=created_by,
    )
    session.add(task)
    await session.flush()
    return task


async def get_task(session: AsyncSession, task_id: uuid.UUID) -> Task | None:
    return await session.get(Task, task_id)


async def claim_next_task(session: AsyncSession, vm: VM) -> Task | None:
    """Atomically hand the oldest pending task for this VM to the worker."""
    stmt = (
        select(Task)
        .where(Task.vm_id == vm.id, Task.status == TaskStatus.pending)
        .order_by(Task.created_at.asc())
        .limit(1)
    )
    # Row-level locking avoids two pollers grabbing the same task on PostgreSQL;
    # SQLite (tests) does not support it and serializes writes anyway.
    if session.bind is not None and session.bind.dialect.name != "sqlite":
        stmt = stmt.with_for_update(skip_locked=True)
    result = await session.execute(stmt)
    task = result.scalar_one_or_none()
    if task is None:
        return None
    task.status = TaskStatus.dispatched
    task.dispatched_at = utcnow()
    await session.flush()
    return task


def _truncate(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    encoded = text.encode()
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode(errors="ignore") + "\n[...truncated...]"


async def submit_result(
    session: AsyncSession,
    *,
    vm: VM,
    task_id: uuid.UUID,
    status: TaskStatus,
    exit_code: int | None,
    stdout: str | None,
    stderr: str | None,
    error: str | None,
) -> Task | None:
    task = await session.get(Task, task_id)
    if task is None or task.vm_id != vm.id:
        return None
    if TaskStatus(task.status).is_terminal:
        return task  # idempotent: ignore duplicate result
    settings = get_settings()
    cap = settings.max_output_bytes
    task.status = status
    task.exit_code = exit_code
    task.stdout = _truncate(stdout, cap)
    task.stderr = _truncate(stderr, cap)
    task.error = _truncate(error, cap)
    task.started_at = task.started_at or task.dispatched_at
    task.finished_at = utcnow()
    await session.flush()
    return task


async def sweep_timeouts(session: AsyncSession) -> int:
    """Re-queue or dead-letter tasks that were dispatched but never completed."""
    settings = get_settings()
    now = utcnow()
    grace = timedelta(seconds=settings.default_task_timeout_seconds * 2 + 30)
    result = await session.execute(
        select(Task).where(Task.status.in_([TaskStatus.dispatched, TaskStatus.running]))
    )
    swept = 0
    for task in result.scalars():
        dispatched = task.dispatched_at or task.created_at
        if as_aware_utc(dispatched) + grace > now:
            continue
        task.retries += 1
        if task.retries > settings.task_dead_letter_retries:
            task.status = TaskStatus.dead_letter
            task.finished_at = now
            task.error = "exceeded retry budget (dead-lettered)"
        else:
            task.status = TaskStatus.pending
            task.dispatched_at = None
        swept += 1
    await session.flush()
    return swept


async def sweep_offline_vms(session: AsyncSession) -> int:
    """Mark active VMs OFFLINE when their heartbeat is stale."""
    settings = get_settings()
    now = utcnow()
    cutoff = timedelta(seconds=settings.heartbeat_offline_seconds)
    result = await session.execute(select(VM).where(VM.state == VMState.active))
    count = 0
    for vm in result.scalars():
        if vm.last_heartbeat_at is None:
            continue
        if as_aware_utc(vm.last_heartbeat_at) + cutoff < now:
            vm.state = VMState.offline
            count += 1
    await session.flush()
    return count

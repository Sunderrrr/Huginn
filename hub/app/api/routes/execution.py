"""Execution endpoints: whitelisted actions, free commands, and worker updates.

These create tasks on the DB-backed queue that workers pull. With ``wait=true`` the
hub polls briefly for a terminal result (sync-style); otherwise it returns the
task immediately (async) and the caller polls ``GET /api/tasks/{id}``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    accessible_vm_ids,
    client_ip,
    enforce_body_size,
    rate_limit_exec,
    require_operator,
)
from app.core import audit
from app.core.actions import ActionError
from app.core.principal import Principal
from app.db import get_session
from app.models.task import Task
from app.schemas.task import (
    ActionRequest,
    BulkActionRequest,
    BulkActionResult,
    CommandRequest,
    TaskOut,
)
from app.services import settings_service
from app.services import tags as tags_service
from app.services import tasks as tasks_service
from app.services import vms as vms_service
from app.services.versioning import SSRFError

router = APIRouter(prefix="/api/vms", tags=["execution"])

_WAIT_MAX_SECONDS = 30.0


async def _load_active_vm(session: AsyncSession, vm_id: uuid.UUID):  # type: ignore[no-untyped-def]
    vm = await vms_service.get(session, vm_id)
    if vm is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VM not found")
    return vm


async def _maybe_wait(session: AsyncSession, task: Task, wait: bool) -> Task:
    if not wait:
        return task
    # Commit the task creation + audit first: this ends the request's transaction
    # snapshot so the worker's independently-committed result is observable, and
    # frees the connection while we block.
    await session.commit()
    # Event-driven: woken the instant the worker submits the result (no polling).
    result = await tasks_service.wait_for_terminal(session, task.id, _WAIT_MAX_SECONDS)
    return result if result is not None else task


@router.post(
    "/bulk/actions",
    response_model=list[BulkActionResult],
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_bulk_action(
    body: BulkActionRequest,
    request: Request,
    principal: Principal = Depends(rate_limit_exec),
    _size: None = Depends(enforce_body_size),
    session: AsyncSession = Depends(get_session),
) -> list[BulkActionResult]:
    """Queue the same whitelisted action on multiple VMs (async, no wait).

    Targets are the union of ``vm_ids`` and the VMs carrying any of ``tag_ids``.
    VMs the caller cannot access are silently skipped (access filtered).
    """
    allowed = await accessible_vm_ids(session, principal)
    allowed_set = set(allowed) if allowed is not None else None

    # Resolve tag targets and merge with explicit VM ids (preserve order, dedup).
    target_ids = list(body.vm_ids)
    if body.tag_ids:
        target_ids += await tags_service.vm_ids_for_tags(session, body.tag_ids)
    seen: set[uuid.UUID] = set()
    ordered_ids: list[uuid.UUID] = []
    for i in target_ids:
        if i not in seen:
            seen.add(i)
            ordered_ids.append(i)

    results: list[BulkActionResult] = []
    for vm_id in ordered_ids:
        if allowed_set is not None and vm_id not in allowed_set:
            results.append(BulkActionResult(vm_id=vm_id, status="error", error="access denied"))
            continue
        vm = await vms_service.get(session, vm_id)
        if vm is None:
            results.append(BulkActionResult(vm_id=vm_id, status="error", error="not found"))
            continue
        try:
            task = await tasks_service.create_action_task(
                session,
                vm=vm,
                action_name=body.action,
                params=body.params,
                created_by=principal.actor_id,
            )
        except (ActionError, tasks_service.ExecForbidden) as exc:
            results.append(BulkActionResult(vm_id=vm_id, status="error", error=str(exc)))
            continue
        await audit.record(
            session,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            event_type="execute_action",
            vm_id=vm.id,
            action_name=body.action,
            detail={"params": body.params, "task_id": str(task.id), "bulk": True},
            source_ip=client_ip(request),
        )
        results.append(BulkActionResult(vm_id=vm_id, task_id=task.id, status="queued"))
    await session.commit()
    return results


@router.post("/{vm_id}/actions", response_model=TaskOut, status_code=status.HTTP_202_ACCEPTED)
async def run_action(
    vm_id: uuid.UUID,
    body: ActionRequest,
    request: Request,
    principal: Principal = Depends(rate_limit_exec),
    _size: None = Depends(enforce_body_size),
    session: AsyncSession = Depends(get_session),
) -> TaskOut:
    vm = await _load_active_vm(session, vm_id)
    try:
        task = await tasks_service.create_action_task(
            session,
            vm=vm,
            action_name=body.action,
            params=body.params,
            created_by=principal.actor_id,
            idempotency_key=body.idempotency_key,
        )
    except ActionError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except tasks_service.ExecForbidden as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="execute_action",
        vm_id=vm.id,
        action_name=body.action,
        detail={"params": body.params, "task_id": str(task.id)},
        source_ip=client_ip(request),
    )
    task = await _maybe_wait(session, task, body.wait)
    return TaskOut.model_validate(task)


@router.post("/{vm_id}/commands", response_model=TaskOut, status_code=status.HTTP_202_ACCEPTED)
async def run_command(
    vm_id: uuid.UUID,
    body: CommandRequest,
    request: Request,
    principal: Principal = Depends(rate_limit_exec),
    _size: None = Depends(enforce_body_size),
    session: AsyncSession = Depends(get_session),
) -> TaskOut:
    vm = await _load_active_vm(session, vm_id)
    try:
        task = await tasks_service.create_command_task(
            session,
            vm=vm,
            command=body.command,
            created_by=principal.actor_id,
            timeout=body.timeout,
            idempotency_key=body.idempotency_key,
        )
    except tasks_service.ExecForbidden as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except tasks_service.TaskInputError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    # Free-command execution is sensitive: always audited with the command text.
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="execute_command",
        vm_id=vm.id,
        command=body.command[:4096],
        detail={"task_id": str(task.id)},
        source_ip=client_ip(request),
    )
    task = await _maybe_wait(session, task, body.wait)
    return TaskOut.model_validate(task)


@router.post("/{vm_id}/update", response_model=TaskOut, status_code=status.HTTP_202_ACCEPTED)
async def trigger_update(
    vm_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_operator),
    session: AsyncSession = Depends(get_session),
) -> TaskOut:
    vm = await _load_active_vm(session, vm_id)
    settings_row = await settings_service.get_settings_row(session)
    if settings_row is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "settings not initialized")
    try:
        task = await tasks_service.create_update_task(
            session,
            vm=vm,
            target_version=settings_row.target_worker_version,
            repo=settings_row.target_release_repo,
            allowed_domains=list(settings_row.allowed_release_domains),
            created_by=principal.actor_id,
        )
    except SSRFError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unsafe release URL: {exc}") from exc
    except tasks_service.ExecForbidden as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="trigger_update",
        vm_id=vm.id,
        detail={"target_version": settings_row.target_worker_version, "task_id": str(task.id)},
        source_ip=client_ip(request),
    )
    return TaskOut.model_validate(task)

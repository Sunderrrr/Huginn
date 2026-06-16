"""Worker-facing endpoints. Enrollment is authenticated by the enrollment token;
all other worker endpoints (added later) use the per-worker secret.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, current_worker
from app.config import Settings, get_settings
from app.core import audit
from app.db import get_session
from app.models.enums import ActorType, TaskStatus, VMState
from app.models.mixins import utcnow
from app.models.vm import VM
from app.schemas.enrollment import WorkerEnrollRequest, WorkerEnrollResponse
from app.schemas.task import (
    HeartbeatRequest,
    HeartbeatResponse,
    TaskResultSubmit,
    WorkerTask,
)
from app.services import enrollment as enrollment_service
from app.services import notifications as notifications_service
from app.services import settings_service
from app.services import tasks as tasks_service

logger = logging.getLogger("huginn.hub.worker")

router = APIRouter(prefix="/api/worker", tags=["worker"])


def _enforce_tls(request: Request, settings: Settings) -> None:
    """In prod, refuse plaintext hub<->worker traffic."""
    if not settings.require_tls:
        return
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    scheme = forwarded or request.url.scheme
    if scheme != "https":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "TLS is required for worker communication"
        )


@router.post("/enroll", response_model=WorkerEnrollResponse, status_code=status.HTTP_201_CREATED)
async def enroll(
    body: WorkerEnrollRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> WorkerEnrollResponse:
    _enforce_tls(request, settings)
    try:
        vm, secret = await enrollment_service.enroll_worker(
            session,
            token=body.token,
            name=body.name,
            hostname=body.hostname,
            ip_address=body.ip_address or client_ip(request),
            arch=body.arch,
            os_info=body.os_info,
            worker_version=body.worker_version,
        )
    except enrollment_service.EnrollmentError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    await audit.record(
        session,
        actor_type=ActorType.system,
        actor_id="worker",
        event_type="enroll",
        vm_id=vm.id,
        detail={"name": vm.name, "arch": vm.arch.value},
        source_ip=client_ip(request),
    )
    return WorkerEnrollResponse(worker_id=vm.id, worker_secret=secret, state=vm.state.value)


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    body: HeartbeatRequest,
    request: Request,
    vm: VM = Depends(current_worker),
    session: AsyncSession = Depends(get_session),
) -> HeartbeatResponse:
    """Worker liveness + version report; returns the desired target version."""
    vm.last_heartbeat_at = utcnow()
    if body.worker_version:
        vm.worker_version = body.worker_version
    if body.ip_address:
        vm.ip_address = body.ip_address
    # Recover from OFFLINE on a fresh heartbeat.
    recovered = False
    if vm.state is VMState.offline:
        vm.state = VMState.active
        recovered = True

    row = await settings_service.get_settings_row(session)
    target = row.target_worker_version if row else get_settings().target_worker_version
    allowed_domains = list(row.allowed_release_domains) if row else []

    # Auto-update: if enabled and the worker is on a different version, queue an
    # update task (unless one is already in flight). Best-effort — never blocks
    # or fails the heartbeat.
    if (
        row is not None
        and row.auto_update_enabled
        and body.worker_version
        and body.worker_version != target
    ):
        try:
            if not await tasks_service.has_inflight_update(session, vm.id):
                await tasks_service.create_update_task(
                    session,
                    vm=vm,
                    target_version=target,
                    repo=row.target_release_repo,
                    allowed_domains=allowed_domains,
                    created_by="auto-update",
                )
        except Exception as exc:  # noqa: BLE001 - auto-update must not break heartbeat
            logger.warning("auto-update for vm %s failed: %s", vm.id, exc)

    if recovered:
        await session.commit()
        await notifications_service.notify(row, "vm_recovered", vm=vm)

    return HeartbeatResponse(
        target_worker_version=target,
        exec_mode=vm.exec_mode.value,
        allowed_release_domains=allowed_domains,
    )


_POLL_INTERVAL_SECONDS = 0.5
_MAX_WAIT_SECONDS = 25.0


@router.get("/tasks/next", response_model=WorkerTask | None)
async def next_task(
    vm: VM = Depends(current_worker),
    session: AsyncSession = Depends(get_session),
    wait: float = 0.0,
) -> WorkerTask | None:
    """Hand the worker its next queued task.

    With ``wait>0`` this long-polls: if the queue is empty it re-checks every
    ``_POLL_INTERVAL_SECONDS`` until a task appears or ``wait`` (capped at
    ``_MAX_WAIT_SECONDS``) elapses, then returns null. This gives near-instant
    task pickup without the worker hammering the hub.

    To avoid holding a pooled DB connection across the whole wait, the request's
    session is committed (which records the heartbeat and releases the
    connection) and each re-check opens its own short-lived session.
    """
    vm.last_heartbeat_at = utcnow()

    task = await tasks_service.claim_next_task(session, vm)
    if task is None and wait > 0:
        deadline = min(wait, _MAX_WAIT_SECONDS)
        waited = 0.0
        while waited < deadline:
            # Commit between checks so this connection's read snapshot is dropped
            # and the next claim observes tasks committed by other connections.
            await session.commit()
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            waited += _POLL_INTERVAL_SECONDS
            task = await tasks_service.claim_next_task(session, vm)
            if task is not None:
                break

    if task is None:
        return None
    return WorkerTask(
        id=task.id,
        type=task.type,
        action_name=task.action_name,
        payload=task.payload,
    )


@router.post("/tasks/{task_id}/result", status_code=status.HTTP_204_NO_CONTENT)
async def submit_result(
    task_id: uuid.UUID,
    body: TaskResultSubmit,
    vm: VM = Depends(current_worker),
    session: AsyncSession = Depends(get_session),
) -> None:
    task = await tasks_service.submit_result(
        session,
        vm=vm,
        task_id=task_id,
        status=body.status,
        exit_code=body.exit_code,
        stdout=body.stdout,
        stderr=body.stderr,
        error=body.error,
    )
    if task is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found for this worker")

    # Notify on failure (best-effort, after commit).
    if body.status in (TaskStatus.failed, TaskStatus.timeout, TaskStatus.dead_letter):
        await session.commit()
        row = await settings_service.get_settings_row(session)
        await notifications_service.notify(row, "task_failure", vm=vm, task=task)

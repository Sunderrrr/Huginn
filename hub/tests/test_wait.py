"""The sync wait=true path returns terminal results and never holds a snapshot."""

from __future__ import annotations

from app.api.routes.execution import _maybe_wait
from app.models.enums import TaskStatus, VMState, WorkerArch
from app.models.vm import VM
from app.services import tasks as tasks_service


async def _active_vm(session) -> VM:
    vm = VM(name="vm", arch=WorkerArch.amd64, state=VMState.active)
    session.add(vm)
    await session.flush()
    return vm


async def test_wait_returns_immediately_for_terminal_task(session) -> None:
    vm = await _active_vm(session)
    task = await tasks_service.create_action_task(
        session, vm=vm, action_name="status", params=None, created_by="admin"
    )
    # Simulate the worker having already completed it.
    task.status = TaskStatus.succeeded
    task.stdout = "done"

    result = await _maybe_wait(session, task, wait=True)
    assert result.status is TaskStatus.succeeded
    assert result.stdout == "done"


async def test_wait_false_returns_without_committing(session) -> None:
    vm = await _active_vm(session)
    task = await tasks_service.create_action_task(
        session, vm=vm, action_name="status", params=None, created_by="admin"
    )
    result = await _maybe_wait(session, task, wait=False)
    assert result.status is TaskStatus.pending

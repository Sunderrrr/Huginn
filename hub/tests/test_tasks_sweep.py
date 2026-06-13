"""Task timeout sweeping and offline detection."""

from __future__ import annotations

import uuid
from datetime import timedelta

from app.models.enums import TaskStatus, TaskType, VMState, WorkerArch
from app.models.mixins import utcnow
from app.models.task import Task
from app.models.vm import VM
from app.services import tasks as tasks_service


async def _make_vm(session, **kwargs) -> VM:
    vm = VM(name="vm", arch=WorkerArch.amd64, state=VMState.active, **kwargs)
    session.add(vm)
    await session.flush()
    return vm


async def test_stale_dispatched_task_is_requeued(session) -> None:
    vm = await _make_vm(session)
    task = Task(
        vm_id=vm.id,
        type=TaskType.action,
        status=TaskStatus.dispatched,
        payload={},
        created_by="admin",
        dispatched_at=utcnow() - timedelta(hours=1),
    )
    session.add(task)
    await session.flush()

    swept = await tasks_service.sweep_timeouts(session)
    assert swept == 1
    await session.refresh(task)
    assert task.status is TaskStatus.pending
    assert task.retries == 1


async def test_task_dead_letters_after_retry_budget(session) -> None:
    vm = await _make_vm(session)
    task = Task(
        vm_id=vm.id,
        type=TaskType.action,
        status=TaskStatus.dispatched,
        payload={},
        created_by="admin",
        retries=3,  # already at the configured budget
        dispatched_at=utcnow() - timedelta(hours=1),
    )
    session.add(task)
    await session.flush()

    await tasks_service.sweep_timeouts(session)
    await session.refresh(task)
    assert task.status is TaskStatus.dead_letter


async def test_fresh_task_not_swept(session) -> None:
    vm = await _make_vm(session)
    task = Task(
        vm_id=vm.id,
        type=TaskType.action,
        status=TaskStatus.dispatched,
        payload={},
        created_by="admin",
        dispatched_at=utcnow(),
    )
    session.add(task)
    await session.flush()
    assert await tasks_service.sweep_timeouts(session) == 0


async def test_stale_heartbeat_marks_vm_offline(session) -> None:
    vm = await _make_vm(session, last_heartbeat_at=utcnow() - timedelta(hours=1))
    count = await tasks_service.sweep_offline_vms(session)
    assert count == 1
    await session.refresh(vm)
    assert vm.state is VMState.offline


async def test_recent_heartbeat_stays_active(session) -> None:
    vm = await _make_vm(session, last_heartbeat_at=utcnow())
    assert await tasks_service.sweep_offline_vms(session) == 0
    await session.refresh(vm)
    assert vm.state is VMState.active


async def test_idempotent_action_returns_same_task(session) -> None:
    vm = await _make_vm(session)
    t1 = await tasks_service.create_action_task(
        session, vm=vm, action_name="status", params=None, created_by="x", idempotency_key="k1"
    )
    t2 = await tasks_service.create_action_task(
        session, vm=vm, action_name="status", params=None, created_by="x", idempotency_key="k1"
    )
    assert t1.id == t2.id


async def test_duplicate_result_is_ignored(session) -> None:
    vm = await _make_vm(session)
    task = await tasks_service.create_action_task(
        session, vm=vm, action_name="status", params=None, created_by="x"
    )
    await tasks_service.submit_result(
        session, vm=vm, task_id=task.id, status=TaskStatus.succeeded,
        exit_code=0, stdout="first", stderr=None, error=None,
    )
    # Second submission must not overwrite the terminal result.
    await tasks_service.submit_result(
        session, vm=vm, task_id=task.id, status=TaskStatus.failed,
        exit_code=1, stdout="second", stderr=None, error=None,
    )
    await session.refresh(task)
    assert task.status is TaskStatus.succeeded
    assert task.stdout == "first"


async def test_submit_result_wrong_worker_rejected(session) -> None:
    vm_a = await _make_vm(session)
    vm_b = await _make_vm(session)
    task = await tasks_service.create_action_task(
        session, vm=vm_a, action_name="status", params=None, created_by="x"
    )
    out = await tasks_service.submit_result(
        session, vm=vm_b, task_id=task.id, status=TaskStatus.succeeded,
        exit_code=0, stdout="x", stderr=None, error=None,
    )
    assert out is None


async def test_get_unknown_task_returns_none(session) -> None:
    assert await tasks_service.get_task(session, uuid.uuid4()) is None

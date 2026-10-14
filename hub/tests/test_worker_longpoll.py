"""Event-driven worker long-poll: instant queue pickup, no DB re-polling.

Covers the wake path of ``GET /api/worker/tasks/next`` (task_events queue
wakes registered at task-creation commits) and the queue primitives of
``app.core.task_events`` themselves.
"""

from __future__ import annotations

import asyncio

from app.core import task_events
from app.models.enums import VMState, WorkerArch
from app.models.vm import VM
from app.services import tasks as tasks_service


async def _make_active_vm(session) -> VM:  # type: ignore[no-untyped-def]
    vm = VM(name="vm", arch=WorkerArch.amd64, state=VMState.active)
    session.add(vm)
    await session.flush()
    return vm


async def _queue_status_task(client, admin_headers, vm_id: str) -> str:
    resp = await client.post(
        f"/api/vms/{vm_id}/actions", json={"action": "status"}, headers=admin_headers
    )
    assert resp.status_code == 202, resp.text
    return resp.json()["id"]


async def test_long_poll_wakes_instantly_when_task_is_queued(
    client, admin_headers, enrolled_worker
) -> None:
    """A task queued while a worker is parked is handed out in < 200 ms."""
    w = await enrolled_worker()
    poll = asyncio.create_task(client.get("/api/worker/tasks/next?wait=5", headers=w["headers"]))
    await asyncio.sleep(0.05)  # let the poll park on its queue event
    queued_at = asyncio.get_running_loop().time()
    task_id = await _queue_status_task(client, admin_headers, w["vm_id"])
    handed = await poll
    picked_up_at = asyncio.get_running_loop().time()

    assert handed.status_code == 200
    assert handed.json() is not None
    assert handed.json()["id"] == task_id
    assert picked_up_at - queued_at < 0.2


async def test_long_poll_times_out_cleanly_when_queue_stays_empty(client, enrolled_worker) -> None:
    """No task ever arrives: null after the full wait, not before, not at 25s."""
    w = await enrolled_worker()
    started = asyncio.get_running_loop().time()
    poll = await client.get("/api/worker/tasks/next?wait=0.5", headers=w["headers"])
    elapsed = asyncio.get_running_loop().time() - started

    assert poll.status_code == 200
    assert poll.json() is None
    assert elapsed >= 0.45  # waited out the whole window
    assert elapsed < 5.0  # ...and respected the requested bound


async def test_queue_wake_is_targeted_to_the_worker_vm(
    client, admin_headers, enrolled_worker
) -> None:
    """A task for VM B must not wake VM A's long-poll; B's own poll gets it."""
    a = await enrolled_worker(name="vm-a")
    b = await enrolled_worker(name="vm-b")

    poll_a = asyncio.create_task(client.get("/api/worker/tasks/next?wait=1", headers=a["headers"]))
    await asyncio.sleep(0.05)
    started = asyncio.get_running_loop().time()
    task_id = await _queue_status_task(client, admin_headers, b["vm_id"])

    handed_a = await poll_a
    elapsed = asyncio.get_running_loop().time() - started
    assert handed_a.status_code == 200
    assert handed_a.json() is None  # stayed parked until its own timeout
    assert elapsed >= 0.9

    poll_b = await client.get("/api/worker/tasks/next?wait=2", headers=b["headers"])
    assert poll_b.status_code == 200
    assert poll_b.json() is not None
    assert poll_b.json()["id"] == task_id


async def test_claimed_task_is_not_handed_out_twice(client, admin_headers, enrolled_worker) -> None:
    """Each wake re-claims, but claim_next_task arbitrates: one handout per task.

    Concurrent same-VM claims are arbitrated by row-level locking on
    PostgreSQL (FOR UPDATE SKIP LOCKED); the SQLite test harness serializes
    on a single connection, so only the sequential invariant is asserted here.
    """
    w = await enrolled_worker()
    task_id = await _queue_status_task(client, admin_headers, w["vm_id"])

    first = await client.get("/api/worker/tasks/next?wait=2", headers=w["headers"])
    assert first.status_code == 200
    assert first.json() is not None
    assert first.json()["id"] == task_id

    # The dispatched task cannot be handed to another poll of the same worker.
    second = await client.get("/api/worker/tasks/next", headers=w["headers"])
    assert second.status_code == 200
    assert second.json() is None


async def test_task_events_queue_wake_fires_on_commit_targets_vm(session) -> None:
    """Creation only flushes; the wake must fire at commit, and only for that VM."""
    vm = await _make_active_vm(session)
    mine = task_events.subscribe_queue(str(vm.id))
    other = task_events.subscribe_queue("another-vm")
    try:
        await tasks_service.create_action_task(
            session, vm=vm, action_name="status", params=None, created_by="test"
        )
        assert not mine.is_set()  # nothing fires before the commit

        await session.commit()
        assert mine.is_set()
        assert not other.is_set()  # targeted: other VMs stay parked

        task_events.broadcast_queue()  # fallback reaches every parked worker
        assert other.is_set()
    finally:
        task_events.unsubscribe_queue(str(vm.id), mine)
        task_events.unsubscribe_queue("another-vm", other)


async def test_task_events_queue_wake_dropped_on_rollback(session) -> None:
    """A rolled-back creation never became claimable: no wake, now or later."""
    vm = await _make_active_vm(session)
    wake = task_events.subscribe_queue(str(vm.id))
    try:
        await tasks_service.create_action_task(
            session, vm=vm, action_name="status", params=None, created_by="test"
        )
        await session.rollback()
        await session.commit()  # a later unrelated commit must not resurrect it
        assert not wake.is_set()
    finally:
        task_events.unsubscribe_queue(str(vm.id), wake)

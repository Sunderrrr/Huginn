"""In-process task-completion and queue-availability notifier.

Two wake channels:

- Per-task completion: ``notify(task_id)`` fires on result submission and wakes
  waiters blocked in ``wait_for_terminal`` (e.g. ``GET /tasks/{id}/wait``).
- Queue availability: wherever a task becomes claimable (creation, timeout
  re-queue) a wake is registered via ``notify_queue_on_commit`` and fires when
  that session's transaction commits. Workers parked in the
  ``GET /worker/tasks/next`` long-poll subscribe per VM (``subscribe_queue``)
  and wake instantly instead of the hub re-polling the database;
  ``broadcast_queue`` is the fallback for publishers that cannot target a VM
  and wakes every parked worker.

Single-process only (asyncio Events). With multiple hub replicas a waiter on
one replica won't be woken by a result committed on another — the callers all
re-check the DB on a bounded timeout, so this degrades to polling rather than
breaking. For a multi-replica deployment, back this with PostgreSQL
LISTEN/NOTIFY or Redis pub/sub.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session as SyncSession

_waiters: dict[str, set[asyncio.Event]] = defaultdict(set)

# Queue waiters are filed under their VM id and, additionally, under the
# broadcast key so broadcast wakes reach everyone; VM ids are UUIDs, so the
# key cannot collide.
_QUEUE_BROADCAST_KEY = "*"
_queue_waiters: dict[str, set[asyncio.Event]] = defaultdict(set)

# Session.info key holding the VM ids whose queue wake is pending until the
# session's current transaction commits.
_PENDING_QUEUE_WAKES = "task_events_pending_queue_wakes"


def subscribe(task_id: str) -> asyncio.Event:
    """Register interest in a task's completion; returns an Event to await."""
    event_ = asyncio.Event()
    _waiters[task_id].add(event_)
    return event_


def unsubscribe(task_id: str, event_: asyncio.Event) -> None:
    waiters = _waiters.get(task_id)
    if waiters is not None:
        waiters.discard(event_)
        if not waiters:
            _waiters.pop(task_id, None)


def notify(task_id: str) -> None:
    """Wake everyone waiting on this task (call AFTER the result is committed)."""
    for event_ in _waiters.get(task_id, ()):
        event_.set()


def subscribe_queue(vm_id: str) -> asyncio.Event:
    """Register interest in tasks becoming claimable for ``vm_id``.

    The returned Event fires when ``notify_queue(vm_id)`` targets this VM or
    when ``broadcast_queue()`` wakes every parked waiter.
    """
    event_ = asyncio.Event()
    _queue_waiters[vm_id].add(event_)
    _queue_waiters[_QUEUE_BROADCAST_KEY].add(event_)
    return event_


def unsubscribe_queue(vm_id: str, event_: asyncio.Event) -> None:
    for key in (vm_id, _QUEUE_BROADCAST_KEY):
        waiters = _queue_waiters.get(key)
        if waiters is not None:
            waiters.discard(event_)
            if not waiters:
                _queue_waiters.pop(key, None)


def notify_queue(vm_id: str) -> None:
    """Wake workers long-polling ``vm_id``'s queue (fires on commit, see below)."""
    for event_ in _queue_waiters.get(vm_id, ()):
        event_.set()


def broadcast_queue() -> None:
    """Fallback wake for publishers that cannot target a single VM."""
    for event_ in _queue_waiters.get(_QUEUE_BROADCAST_KEY, ()):
        event_.set()


def notify_queue_on_commit(session: AsyncSession, vm_id: str) -> None:
    """Schedule a queue wake for when ``session``'s current transaction commits.

    Task-creation services only flush; the commit happens later at the request
    (or sweeper) boundary. Waking at flush time would race parked long-polls
    into re-claiming before the task is actually visible to other connections,
    wasting the wake and stalling pickup until the wait times out. Deferring
    to the commit makes the wake coincide exactly with the task becoming
    claimable.
    """
    sync_session = getattr(session, "sync_session", session)
    pending: set[str] = sync_session.info.setdefault(_PENDING_QUEUE_WAKES, set())
    pending.add(vm_id)


@event.listens_for(SyncSession, "after_commit")
def _fire_pending_queue_wakes(sync_session: SyncSession) -> None:
    vm_ids: set[str] | None = sync_session.info.pop(_PENDING_QUEUE_WAKES, None)
    if vm_ids:
        for vm_id in vm_ids:
            notify_queue(vm_id)


@event.listens_for(SyncSession, "after_rollback")
@event.listens_for(SyncSession, "after_soft_rollback")
def _discard_pending_queue_wakes(sync_session: SyncSession, *_args: object) -> None:
    # The transaction was rolled back: the task never became claimable, so its
    # wake must not fire on some later, unrelated commit.
    sync_session.info.pop(_PENDING_QUEUE_WAKES, None)

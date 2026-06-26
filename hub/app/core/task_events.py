"""In-process task-completion notifier.

Lets a request block until a specific task reaches a terminal state without
busy-polling the database: the worker's result submission fires ``notify`` and
any waiter for that task is woken immediately.

Single-process only (asyncio Events). With multiple hub replicas a waiter on
one replica won't be woken by a result committed on another — the callers all
re-check the DB on a bounded timeout, so this degrades to polling rather than
breaking. For a multi-replica deployment, back this with PostgreSQL
LISTEN/NOTIFY or Redis pub/sub.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

_waiters: dict[str, set[asyncio.Event]] = defaultdict(set)


def subscribe(task_id: str) -> asyncio.Event:
    """Register interest in a task's completion; returns an Event to await."""
    event = asyncio.Event()
    _waiters[task_id].add(event)
    return event


def unsubscribe(task_id: str, event: asyncio.Event) -> None:
    waiters = _waiters.get(task_id)
    if waiters is not None:
        waiters.discard(event)
        if not waiters:
            _waiters.pop(task_id, None)


def notify(task_id: str) -> None:
    """Wake everyone waiting on this task (call AFTER the result is committed)."""
    for event in _waiters.get(task_id, ()):
        event.set()

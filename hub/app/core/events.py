"""In-process pub/sub for the dashboard's live event stream (SSE).

Mutation points publish a tiny hint (e.g. ``{"type": "tasks"}``) and the SSE
endpoint fans it out to connected dashboards, which invalidate the matching
React Query cache — so the UI updates the instant something changes instead of
waiting for the next poll.

Single-process (asyncio queues). With multiple hub replicas a browser connected
to one replica won't see events published on another; the dashboard keeps its
periodic refetch as a fallback, so this degrades to polling rather than breaking.
"""

from __future__ import annotations

import asyncio

# Bounded so a slow/stalled consumer can't grow memory without limit; on overflow
# we drop the oldest hint (the client will still catch up via its fallback poll).
_QUEUE_MAXSIZE = 100

_subscribers: set[asyncio.Queue[dict]] = set()


def subscribe() -> asyncio.Queue[dict]:
    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
    _subscribers.add(queue)
    return queue


def unsubscribe(queue: asyncio.Queue[dict]) -> None:
    _subscribers.discard(queue)


def publish(event: dict) -> None:
    """Fan an event out to all connected dashboards (non-blocking)."""
    for queue in _subscribers:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            # Drop the oldest event to make room; the client's fallback poll covers
            # the gap.
            try:
                queue.get_nowait()
                queue.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass

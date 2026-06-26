"""The dashboard SSE stream authenticates and pushes live hints."""

from __future__ import annotations

import asyncio

from app.core import events


async def test_events_rejects_invalid_token(client) -> None:
    resp = await client.get("/api/events", headers={"Authorization": "Bearer bogus"})
    assert resp.status_code == 401


async def test_events_requires_auth(client) -> None:
    resp = await client.get("/api/events")
    assert resp.status_code == 401  # no Authorization header


async def test_event_bus_fans_out_to_all_subscribers() -> None:
    q1 = events.subscribe()
    q2 = events.subscribe()
    try:
        events.publish({"type": "tasks"})
        assert (await asyncio.wait_for(q1.get(), 1))["type"] == "tasks"
        assert (await asyncio.wait_for(q2.get(), 1))["type"] == "tasks"
    finally:
        events.unsubscribe(q1)
        events.unsubscribe(q2)


async def test_event_bus_drops_oldest_when_full() -> None:
    q = events.subscribe()
    try:
        # Fill past capacity; publish must never raise and the newest survives.
        for i in range(events._QUEUE_MAXSIZE + 5):
            events.publish({"type": "tasks", "n": i})
        assert q.qsize() == events._QUEUE_MAXSIZE
        last = events._QUEUE_MAXSIZE + 4
        drained = [q.get_nowait()["n"] for _ in range(q.qsize())]
        assert last in drained  # the most recent event was retained
    finally:
        events.unsubscribe(q)

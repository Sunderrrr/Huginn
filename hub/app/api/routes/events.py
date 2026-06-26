"""Server-Sent Events stream for the dashboard's live updates.

Connected dashboards receive tiny hints (``{"type": "tasks"}`` / ``"vms"``) and
invalidate the matching query cache, so the UI refreshes the instant something
changes instead of waiting for its periodic poll.

Authenticated with the normal ``Authorization: Bearer`` header (the dashboard
reads the stream via fetch, not EventSource), so no token ever appears in a URL
or access log. The DB connection is released before streaming, so an open stream
never holds a pooled connection.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_principal
from app.core import events
from app.core.principal import Principal
from app.db import get_session

router = APIRouter(prefix="/api", tags=["events"])

_KEEPALIVE_SECONDS = 20.0


@router.get("/events")
async def events_stream(
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    # Authenticated via the Authorization header (get_principal). Release the
    # pooled connection before the long-lived stream, which never touches the DB.
    await session.close()
    queue = events.subscribe()

    async def gen():  # type: ignore[no-untyped-def]
        try:
            yield ": connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_KEEPALIVE_SECONDS)
                    yield f"data: {json.dumps(event)}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"  # keep the connection (and proxies) warm
        finally:
            events.unsubscribe(queue)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

"""Periodic maintenance: task timeout sweeping and offline detection."""

from __future__ import annotations

import asyncio
import logging

from app.core import events
from app.db import SessionFactory
from app.services import notifications as notifications_service
from app.services import scheduled_commands as schedules_service
from app.services import settings_service
from app.services import tasks as tasks_service

logger = logging.getLogger("huginn.hub.sweeper")

SWEEP_INTERVAL_SECONDS = 30


async def run_sweeper(stop: asyncio.Event) -> None:
    """Loop until ``stop`` is set, sweeping timeouts and offline VMs each tick."""
    while not stop.is_set():
        try:
            async with SessionFactory() as session:
                timed_out = await tasks_service.sweep_timeouts(session)
                gone_offline = await tasks_service.sweep_offline_vms(session)
                scheduled = await schedules_service.run_due(session)
                await session.commit()
                # Push live hints for changes the user didn't trigger themselves.
                if gone_offline:
                    events.publish({"type": "vms"})
                if timed_out or scheduled:
                    events.publish({"type": "tasks"})
                if timed_out or gone_offline or scheduled:
                    logger.info(
                        "sweeper: %d task(s) swept, %d VM(s) offline, %d scheduled task(s)",
                        timed_out,
                        len(gone_offline),
                        scheduled,
                    )
                # Fire offline notifications (best-effort, outside the txn).
                if gone_offline:
                    row = await settings_service.get_settings_row(session)
                    for vm in gone_offline:
                        await notifications_service.notify(row, "vm_offline", vm=vm)
        except Exception:  # pragma: no cover - keep the loop alive
            logger.exception("sweeper iteration failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=SWEEP_INTERVAL_SECONDS)
        except TimeoutError:
            pass

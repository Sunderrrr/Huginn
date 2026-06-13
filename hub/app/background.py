"""Periodic maintenance: task timeout sweeping and offline detection."""

from __future__ import annotations

import asyncio
import logging

from app.db import SessionFactory
from app.services import tasks as tasks_service

logger = logging.getLogger("huginn.hub.sweeper")

SWEEP_INTERVAL_SECONDS = 30


async def run_sweeper(stop: asyncio.Event) -> None:
    """Loop until ``stop`` is set, sweeping timeouts and offline VMs each tick."""
    while not stop.is_set():
        try:
            async with SessionFactory() as session:
                timed_out = await tasks_service.sweep_timeouts(session)
                offline = await tasks_service.sweep_offline_vms(session)
                await session.commit()
                if timed_out or offline:
                    logger.info("sweeper: %d task(s) swept, %d VM(s) offline", timed_out, offline)
        except Exception:  # pragma: no cover - keep the loop alive
            logger.exception("sweeper iteration failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=SWEEP_INTERVAL_SECONDS)
        except TimeoutError:
            pass

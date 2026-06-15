"""Huginn hub application factory."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.background import run_sweeper
from app.config import Settings, get_settings
from app.db import SessionFactory
from app.services import settings_service
from app.services import users as users_service

logger = logging.getLogger("huginn.hub")


async def _bootstrap(settings: Settings) -> None:
    """Seed the settings row and the first admin user if needed."""
    async with SessionFactory() as session:
        await settings_service.ensure_settings(session, settings)
        admin = await users_service.ensure_bootstrap_admin(
            session, settings.bootstrap_admin_username, settings.bootstrap_admin_password
        )
        if admin is not None:
            logger.info("bootstrapped initial admin user %r", admin.username)
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    settings.validate_for_prod()
    await _bootstrap(settings)

    stop = asyncio.Event()
    sweeper = asyncio.create_task(run_sweeper(stop))
    try:
        yield
    finally:
        stop.set()
        sweeper.cancel()
        try:
            await sweeper
        except asyncio.CancelledError:
            pass


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Huginn Hub",
        version="0.1.0",
        summary="Central control plane for the Huginn VM fleet",
        lifespan=lifespan,
    )

    if settings.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    from app.api.routes import (
        audit,
        auth,
        enrollment,
        execution,
        tasks,
        users,
        vms,
        worker,
    )
    from app.api.routes import (
        settings as settings_routes,
    )

    app.include_router(auth.router)
    app.include_router(enrollment.router)
    app.include_router(users.router)
    app.include_router(vms.router)
    app.include_router(execution.router)
    app.include_router(tasks.router)
    app.include_router(audit.router)
    app.include_router(settings_routes.router)
    app.include_router(worker.router)

    @app.get("/healthz", tags=["meta"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "env": settings.env}

    return app


app = create_app()

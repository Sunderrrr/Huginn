"""Huginn hub application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

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
    await _bootstrap(settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Huginn Hub",
        version="0.1.0",
        summary="Central control plane for the Huginn VM fleet",
        lifespan=lifespan,
    )

    from app.api.routes import auth, enrollment, vms, worker

    app.include_router(auth.router)
    app.include_router(enrollment.router)
    app.include_router(vms.router)
    app.include_router(worker.router)

    @app.get("/healthz", tags=["meta"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "env": settings.env}

    return app


app = create_app()

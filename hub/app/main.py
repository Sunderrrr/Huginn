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

    # Hard global request-body cap (do not trust Content-Length alone). Sized to
    # the largest legitimate body: a worker result carries stdout+stderr each up
    # to max_output_bytes. Per-endpoint command-input limits stay stricter via
    # the enforce_body_size dependency.
    _global_body_cap = settings.max_output_bytes * 2 + 65_536

    @app.middleware("http")
    async def limit_body_size(request, call_next):  # type: ignore[no-untyped-def]
        from fastapi.responses import JSONResponse

        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > _global_body_cap:
                    return JSONResponse({"detail": "request body too large"}, status_code=413)
            except ValueError:
                pass
        body = await request.body()
        if len(body) > _global_body_cap:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    if settings.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-MCP-Service-Token"],
        )

    from app.api.routes import (
        audit,
        auth,
        custom_actions,
        enrollment,
        events,
        execution,
        mcp,
        mfa,
        schedules,
        tags,
        tasks,
        users,
        vms,
        worker,
    )
    from app.api.routes import (
        settings as settings_routes,
    )

    app.include_router(auth.router)
    app.include_router(mfa.router)
    app.include_router(mcp.router)
    app.include_router(enrollment.router)
    app.include_router(users.router)
    app.include_router(tags.router)
    app.include_router(schedules.router)
    app.include_router(vms.router)
    app.include_router(execution.router)
    app.include_router(custom_actions.router)
    app.include_router(tasks.router)
    app.include_router(audit.router)
    app.include_router(events.router)
    app.include_router(settings_routes.router)
    app.include_router(worker.router)

    @app.get("/healthz", tags=["meta"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()

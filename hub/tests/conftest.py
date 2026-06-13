"""Shared test fixtures.

Tests run against an in-memory SQLite database (via aiosqlite) so the suite needs
no external services. The models are written to be dialect-portable for exactly
this reason; PostgreSQL-specific behaviour (JSONB, ENUM types) is exercised by the
Alembic migration tests / CI Postgres service.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

# Deterministic secrets for the test process (set before app imports).
os.environ.setdefault("HUGINN_JWT_SECRET", "test-jwt-secret-value-32-bytes-long!")
os.environ.setdefault("HUGINN_SECRET_HASH_KEY", "test-hmac-key-value-32-bytes-long!!")
os.environ.setdefault("HUGINN_MCP_SERVICE_TOKEN", "test-mcp-service-token")
os.environ.setdefault("HUGINN_REQUIRE_TLS", "false")
os.environ.setdefault("HUGINN_ENV", "dev")

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db import Base


@pytest_asyncio.fixture
async def engine() -> AsyncIterator:
    eng = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session(engine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as s:
        yield s

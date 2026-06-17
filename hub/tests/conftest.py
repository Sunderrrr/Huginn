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
os.environ.setdefault("HUGINN_MFA_ENCRYPTION_KEY", "test-mfa-encryption-key-32-bytes!!")
# Don't force admin MFA in the shared fixtures; enforcement is tested explicitly.
os.environ.setdefault("HUGINN_REQUIRE_ADMIN_MFA", "false")
os.environ.setdefault("HUGINN_REQUIRE_TLS", "false")
os.environ.setdefault("HUGINN_ENV", "dev")

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core import security
from app.db import Base, get_session
from app.models.enums import UserRole
from app.models.user import User


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
async def session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture
async def session(session_factory) -> AsyncIterator[AsyncSession]:
    async with session_factory() as s:
        yield s


@pytest_asyncio.fixture
async def client(engine, session_factory) -> AsyncIterator[AsyncClient]:
    # Reset the per-IP login rate limiter so failed-login tests don't bleed into
    # later tests that share the ASGITransport client IP.
    from app.api.routes import auth as auth_routes
    from app.main import create_app

    auth_routes._login_limiter._buckets.clear()
    auth_routes._oidc_limiter._buckets.clear()

    from app.api.routes import mfa as mfa_routes

    mfa_routes._verify_limiter._buckets.clear()
    mfa_routes._webauthn_limiter._buckets.clear()

    app = create_app()

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[get_session] = _override_get_session

    # ASGITransport doesn't run the lifespan, so seed the settings singleton here.
    from app.config import get_settings
    from app.services import settings_service

    async with session_factory() as s:
        await settings_service.ensure_settings(s, get_settings())
        await s.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin_headers(client, make_user) -> dict[str, str]:
    """Create an admin and return Authorization headers for it."""
    _, password = await make_user(username="admin", password="admin-password-1234")
    resp = await client.post(
        "/api/auth/login", json={"username": "admin", "password": password}
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest_asyncio.fixture
async def readonly_headers(client, make_user) -> dict[str, str]:
    _, password = await make_user(
        username="viewer", password="viewer-password-1234", role=UserRole.readonly
    )
    resp = await client.post(
        "/api/auth/login", json={"username": "viewer", "password": password}
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest_asyncio.fixture
async def enrolled_worker(client, admin_headers):
    """Enroll and approve a worker; return its id, secret, and auth headers."""

    async def _make(name: str = "vm", arch: str = "amd64") -> dict:
        token_resp = await client.post("/api/enrollment-tokens", json={}, headers=admin_headers)
        token = token_resp.json()["token"]
        enroll = await client.post(
            "/api/worker/enroll", json={"token": token, "name": name, "arch": arch}
        )
        body = enroll.json()
        vm_id, secret = body["worker_id"], body["worker_secret"]
        await client.post(f"/api/vms/{vm_id}/approve", headers=admin_headers)
        return {
            "vm_id": vm_id,
            "secret": secret,
            "headers": {"X-Worker-Id": vm_id, "X-Worker-Secret": secret},
        }

    return _make


@pytest_asyncio.fixture
async def make_user(session_factory):
    """Factory fixture: create a user and return (user, plaintext_password)."""

    async def _make(
        username: str = "alice",
        password: str = "s3cret-passw0rd",
        role: UserRole = UserRole.admin,
        active: bool = True,
    ) -> tuple[User, str]:
        async with session_factory() as s:
            user = User(
                username=username,
                password_hash=security.hash_password(password),
                role=role,
                is_active=active,
            )
            s.add(user)
            await s.commit()
            await s.refresh(user)
            return user, password

    return _make

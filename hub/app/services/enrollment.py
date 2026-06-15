"""Enrollment token lifecycle and worker self-enrollment."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.models.enrollment import EnrollmentToken
from app.models.enums import VMState, WorkerArch
from app.models.mixins import utcnow
from app.models.vm import VM


class EnrollmentError(Exception):
    """Raised when an enrollment token is invalid, expired, or exhausted."""


async def create_token(
    session: AsyncSession,
    *,
    created_by: uuid.UUID,
    label: str,
    ttl_seconds: int,
    max_uses: int,
) -> tuple[EnrollmentToken, str]:
    """Create a token; returns the row and the plaintext secret (shown once)."""
    plaintext = security.generate_secret()
    # ttl_seconds=0 means never expires → set to far future
    if ttl_seconds == 0:
        expires_at = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
    else:
        expires_at = utcnow() + timedelta(seconds=ttl_seconds)
    token = EnrollmentToken(
        token_hash=security.hash_secret(plaintext),
        label=label,
        created_by=created_by,
        max_uses=max_uses,
        uses_count=0,
        expires_at=expires_at,
    )
    session.add(token)
    await session.flush()
    return token, plaintext


async def list_tokens(session: AsyncSession) -> list[EnrollmentToken]:
    result = await session.execute(
        select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc())
    )
    return list(result.scalars().all())


async def revoke_token(session: AsyncSession, token_id: uuid.UUID) -> EnrollmentToken | None:
    token = await session.get(EnrollmentToken, token_id)
    if token is None:
        return None
    if token.revoked_at is None:
        token.revoked_at = utcnow()
    return token


async def _resolve_usable_token(session: AsyncSession, plaintext: str) -> EnrollmentToken:
    token_hash = security.hash_secret(plaintext)
    result = await session.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash)
    )
    token = result.scalar_one_or_none()
    if token is None or not token.is_usable():
        raise EnrollmentError("invalid or expired enrollment token")
    return token


async def enroll_worker(
    session: AsyncSession,
    *,
    token: str,
    name: str,
    hostname: str | None,
    ip_address: str | None,
    arch: WorkerArch,
    os_info: dict,
    worker_version: str | None,
) -> tuple[VM, str]:
    """Consume one token use and register a new PENDING VM.

    Returns the VM and its plaintext per-worker secret (delivered once over TLS).
    The VM is inert until an admin approves it.
    """
    token_row = await _resolve_usable_token(session, token)
    token_row.uses_count += 1

    worker_secret = security.generate_secret()
    now = utcnow()
    vm = VM(
        name=name,
        hostname=hostname,
        ip_address=ip_address,
        arch=arch,
        os_info=os_info or {},
        worker_version=worker_version,
        state=VMState.pending,
        worker_secret_hash=security.hash_secret(worker_secret),
        enrollment_token_id=token_row.id,
        enrolled_at=now,
        last_heartbeat_at=now,
    )
    session.add(vm)
    await session.flush()
    return vm, worker_secret

"""MFA orchestration: backup codes, enable/disable TOTP, factor inventory."""

from __future__ import annotations

import secrets
import uuid

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.models.mfa_backup_code import MfaBackupCode
from app.models.mixins import utcnow
from app.models.user import User
from app.models.webauthn_credential import WebAuthnCredential

_BACKUP_CODE_COUNT = 10


def _format_code(raw: str) -> str:
    # 10 hex chars grouped as xxxxx-xxxxx for readability.
    return f"{raw[:5]}-{raw[5:]}"


def generate_backup_codes(n: int = _BACKUP_CODE_COUNT) -> list[str]:
    return [_format_code(secrets.token_hex(5)) for _ in range(n)]


async def passkey_count(session: AsyncSession, user_id: uuid.UUID) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == user_id)
        )
        or 0
    )


async def user_has_mfa(session: AsyncSession, user: User) -> bool:
    if user.totp_enabled:
        return True
    return (await passkey_count(session, user.id)) > 0


async def store_backup_codes(session: AsyncSession, user: User, codes: list[str]) -> None:
    await session.execute(
        delete(MfaBackupCode).where(MfaBackupCode.user_id == user.id)
    )
    for code in codes:
        session.add(
            MfaBackupCode(user_id=user.id, code_hash=security.hash_secret(code))
        )
    await session.flush()


async def consume_backup_code(session: AsyncSession, user: User, code: str) -> bool:
    """Single-use: returns True and marks used iff an unused code matches.

    Locks the row (Postgres) so two concurrent verifies can't both spend it.
    """
    code_hash = security.hash_secret(code.strip())
    stmt = (
        select(MfaBackupCode)
        .where(
            MfaBackupCode.user_id == user.id,
            MfaBackupCode.code_hash == code_hash,
            MfaBackupCode.used_at.is_(None),
        )
        # Row lock prevents two concurrent verifies spending the same code. The
        # SQLite dialect (tests) silently omits FOR UPDATE, so this is portable.
        .with_for_update()
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        return False
    row.used_at = utcnow()
    await session.flush()
    return True


async def claim_totp_step(session: AsyncSession, user: User, step: int) -> bool:
    """Atomically advance totp_last_step to `step`, rejecting replay.

    A single conditional UPDATE means two concurrent verifies with the same code
    can't both succeed (only one advances the step); returns True iff this call
    won the step.
    """
    result = await session.execute(
        update(User)
        .where(
            User.id == user.id,
            or_(User.totp_last_step.is_(None), User.totp_last_step < step),
        )
        .values(totp_last_step=step)
    )
    if result.rowcount == 1:  # type: ignore[attr-defined]
        user.totp_last_step = step
        return True
    return False


async def disable_totp(session: AsyncSession, user: User) -> None:
    user.totp_secret_enc = None
    user.totp_enabled = False
    user.totp_confirmed_at = None
    user.totp_last_step = None
    await session.execute(delete(MfaBackupCode).where(MfaBackupCode.user_id == user.id))
    await session.flush()


async def reset_user_mfa(session: AsyncSession, user: User, *, include_passkeys: bool) -> None:
    """Admin action: clear a user's TOTP (+ optionally passkeys)."""
    await disable_totp(session, user)
    if include_passkeys:
        await session.execute(
            delete(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
        )
        await session.flush()

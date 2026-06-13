"""User lookups, authentication, and admin bootstrap."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.core.jwt import create_access_token
from app.models.enums import UserRole
from app.models.mixins import utcnow
from app.models.user import User


async def get_by_username(session: AsyncSession, username: str) -> User | None:
    result = await session.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_by_id(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await session.get(User, user_id)


async def get_by_oidc_subject(session: AsyncSession, subject: str) -> User | None:
    result = await session.execute(select(User).where(User.oidc_subject == subject))
    return result.scalar_one_or_none()


async def authenticate(session: AsyncSession, username: str, password: str) -> User | None:
    """Verify credentials. Always spends hashing work to limit user enumeration."""
    user = await get_by_username(session, username)
    password_hash = user.password_hash if user else None
    if not security.verify_password(password, password_hash):
        return None
    if user is None or not user.is_active:
        return None
    user.last_login_at = utcnow()
    if user.password_hash and security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(password)
    return user


def issue_token(user: User) -> str:
    return create_access_token(user.id, user.role)


async def upsert_oidc_user(
    session: AsyncSession, *, subject: str, username: str, email: str | None
) -> User:
    """Find or create a user from OIDC claims."""
    user = await get_by_oidc_subject(session, subject)
    if user is None:
        user = User(
            username=username,
            email=email,
            oidc_subject=subject,
            role=UserRole.readonly,
            password_hash=None,
        )
        session.add(user)
    user.last_login_at = utcnow()
    await session.flush()
    return user


async def ensure_bootstrap_admin(
    session: AsyncSession, username: str, password: str | None
) -> User | None:
    """Create the first admin if the users table is empty.

    Returns the created user, or None if users already exist or no password was
    configured.
    """
    count = await session.scalar(select(func.count()).select_from(User))
    if count:
        return None
    if not password:
        return None
    user = User(
        username=username,
        password_hash=security.hash_password(password),
        role=UserRole.admin,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    return user

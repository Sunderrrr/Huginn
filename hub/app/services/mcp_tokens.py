"""Per-user MCP token management and resolution."""

from __future__ import annotations

import ipaddress
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.models.mcp_token import McpToken
from app.models.mixins import utcnow
from app.models.user import User
from app.services import users as users_service

logger = logging.getLogger("huginn.mcp_tokens")


def normalize_allowed_ip(value: str | None) -> str | None:
    """Validate/normalize an IP or CIDR allow-list value (or None for "any").

    Raises ValueError if the value is not a valid IP address or CIDR network.
    """
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    # A bare IP becomes a /32 (or /128) network; a CIDR is kept as given.
    return str(ipaddress.ip_network(value, strict=False))


def ip_allowed(client_ip: str | None, allowed: str | None) -> bool:
    """True if ``client_ip`` is permitted by the token's ``allowed`` rule.

    No rule (None) → always allowed. A rule with no/invalid client IP → denied.
    """
    if allowed is None:
        return True
    if not client_ip:
        return False
    try:
        return ipaddress.ip_address(client_ip) in ipaddress.ip_network(allowed, strict=False)
    except ValueError:
        return False


async def list_for_user(session: AsyncSession, user_id: uuid.UUID) -> list[McpToken]:
    result = await session.execute(
        select(McpToken)
        .where(McpToken.user_id == user_id, McpToken.revoked_at.is_(None))
        .order_by(McpToken.created_at)
    )
    return list(result.scalars())


async def create(
    session: AsyncSession, user: User, name: str, allowed_ip: str | None = None
) -> tuple[McpToken, str]:
    """Create a token for the user; return (row, plaintext) — plaintext shown once."""
    plaintext = security.generate_secret()
    token = McpToken(
        user_id=user.id,
        token_hash=security.hash_secret(plaintext),
        name=name or "token",
        allowed_ip=normalize_allowed_ip(allowed_ip),
    )
    session.add(token)
    await session.flush()
    return token, plaintext


async def revoke(session: AsyncSession, token_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    """Revoke a token the caller owns. Returns False if not found/not owned."""
    token = await session.get(McpToken, token_id)
    if token is None or token.user_id != user_id or token.revoked_at is not None:
        return False
    token.revoked_at = utcnow()
    await session.flush()
    return True


async def set_allowed_ip(
    session: AsyncSession, token_id: uuid.UUID, user_id: uuid.UUID, allowed_ip: str | None
) -> McpToken | None:
    """Update a token's IP allow-list (caller must own it). None clears it."""
    token = await session.get(McpToken, token_id)
    if token is None or token.user_id != user_id or token.revoked_at is not None:
        return None
    token.allowed_ip = normalize_allowed_ip(allowed_ip)
    await session.flush()
    return token


async def resolve(
    session: AsyncSession, presented: str, client_ip: str | None = None
) -> User | None:
    """Map a presented MCP token to its active owner, or None.

    Deterministic keyed HMAC means a single indexed lookup; enforces the token's
    optional IP allow-list against ``client_ip``; bumps last_used_at.
    """
    if not presented:
        return None
    token_hash = security.hash_secret(presented)
    token = (
        await session.execute(
            select(McpToken).where(
                McpToken.token_hash == token_hash, McpToken.revoked_at.is_(None)
            )
        )
    ).scalar_one_or_none()
    if token is None:
        return None
    if not ip_allowed(client_ip, token.allowed_ip):
        logger.warning(
            "MCP token %s rejected: client ip %s not in allow-list %s",
            token.id, client_ip, token.allowed_ip,
        )
        return None
    user = await users_service.get_by_id(session, token.user_id)
    if user is None or not user.is_active:
        return None
    token.last_used_at = utcnow()
    await session.flush()
    return user

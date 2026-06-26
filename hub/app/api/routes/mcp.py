"""Per-user MCP tokens: each user manages their own; whoami for the MCP server."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_principal
from app.core import audit
from app.core.principal import Principal
from app.db import get_session
from app.models.user import User
from app.schemas.mcp import (
    McpTokenCreate,
    McpTokenCreated,
    McpTokenOut,
    McpTokenUpdate,
    WhoAmI,
)
from app.services import mcp_tokens as mcp_tokens_service

router = APIRouter(prefix="/api/mcp", tags=["mcp"])


def _require_user(principal: Principal) -> User:
    """The user behind the request (direct session or on-behalf-of MCP token)."""
    if principal.user is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "a user session is required")
    return principal.user


@router.get("/tokens", response_model=list[McpTokenOut])
async def list_tokens(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[McpTokenOut]:
    user = _require_user(principal)
    return await mcp_tokens_service.list_for_user(session, user.id)  # type: ignore[return-value]


@router.post("/tokens", response_model=McpTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    body: McpTokenCreate,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> McpTokenCreated:
    user = _require_user(principal)
    token, plaintext = await mcp_tokens_service.create(session, user, body.name, body.allowed_ip)
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="mcp_token_created",
        detail={"name": token.name, "allowed_ip": token.allowed_ip},
        source_ip=client_ip(request),
    )
    await session.commit()
    return McpTokenCreated(
        id=token.id, name=token.name, allowed_ip=token.allowed_ip, token=plaintext
    )


@router.patch("/tokens/{token_id}", response_model=McpTokenOut)
async def update_token(
    token_id: uuid.UUID,
    body: McpTokenUpdate,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> McpTokenOut:
    user = _require_user(principal)
    token = await mcp_tokens_service.set_allowed_ip(session, token_id, user.id, body.allowed_ip)
    if token is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="mcp_token_updated",
        detail={"name": token.name, "allowed_ip": token.allowed_ip},
        source_ip=client_ip(request),
    )
    await session.commit()
    return token  # type: ignore[return-value]


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    token_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> None:
    user = _require_user(principal)
    if not await mcp_tokens_service.revoke(session, token_id, user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="mcp_token_revoked",
        detail={"token_id": str(token_id)},
        source_ip=client_ip(request),
    )
    await session.commit()


@router.get("/whoami", response_model=WhoAmI)
async def whoami(principal: Principal = Depends(get_principal)) -> WhoAmI:
    """Resolve the caller (used by the MCP server to validate an on-behalf-of token)."""
    if principal.user is not None:
        return WhoAmI(username=principal.user.username, role=principal.user.role)
    return WhoAmI(username=principal.actor_id, role=principal.role)

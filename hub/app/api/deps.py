"""FastAPI dependencies: DB session, principal/RBAC, and worker authentication."""

from __future__ import annotations

import uuid

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.core import security
from app.core.jwt import MFA_SCOPES, TokenError, decode_access_token
from app.core.principal import Principal
from app.core.ratelimit import RateLimiter
from app.db import get_session
from app.models.enums import ActorType, VMState
from app.models.user import User
from app.models.user_vm_access import UserVMAccess
from app.models.vm import VM
from app.services import users as users_service

# auto_error=False so we can fall back to the MCP service-token scheme.
_bearer = HTTPBearer(auto_error=False)

# Shared limiter for execution endpoints (per-principal).
_exec_limiter = RateLimiter(get_settings().rate_limit_exec_per_minute)


def client_ip(request: Request) -> str | None:
    """Best-effort real client IP.

    Behind the bundled Caddy reverse proxy ``request.client.host`` is Caddy's
    container IP, so when ``trust_forwarded_for`` is set we take the first hop in
    ``X-Forwarded-For`` (the original client). The header is only honoured when
    explicitly trusted, since clients could otherwise spoof it.
    """
    if get_settings().trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
    return request.client.host if request.client else None


async def get_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    mcp_service_token: str | None = Header(default=None, alias="X-MCP-Service-Token"),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Authenticate the caller as a user (JWT) or the MCP agent (service token)."""
    # MCP façade: timing-safe service-token check.
    if mcp_service_token is not None:
        if security.constant_time_equals(mcp_service_token, settings.mcp_service_token):
            return Principal.agent()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid service token")

    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(payload["sub"])
    except (TokenError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc

    # Intermediate MFA challenge/setup tokens are NOT valid for the business API:
    # they may only be presented to the dedicated /api/auth/mfa endpoints.
    if payload.get("scope") in MFA_SCOPES:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token not valid for API access")

    user: User | None = await users_service.get_by_id(session, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")
    return Principal.from_user(user)


async def require_admin(principal: Principal = Depends(get_principal)) -> Principal:
    """Human admin only (excludes the automation agent)."""
    if not principal.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    return principal


async def require_operator(principal: Principal = Depends(get_principal)) -> Principal:
    """Admin, operator, or agent; read-only users are rejected."""
    if not principal.can_execute:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "operator privileges required")
    return principal


async def principal_can_access_vm(
    session: AsyncSession, principal: Principal, vm_id: uuid.UUID
) -> bool:
    """True if the principal may access the given VM.

    Admins and the MCP agent always can; operators/readonly need an entry in
    ``user_vm_access``.
    """
    if principal.is_admin or principal.actor_type is ActorType.agent:
        return True
    if principal.user is None:
        return False
    result = await session.execute(
        select(UserVMAccess.vm_id).where(
            UserVMAccess.user_id == principal.user.id,
            UserVMAccess.vm_id == vm_id,
        )
    )
    return result.scalar_one_or_none() is not None


async def accessible_vm_ids(
    session: AsyncSession, principal: Principal
) -> list[uuid.UUID] | None:
    """VM ids the principal may see, or None when unrestricted (admin/agent)."""
    if principal.is_admin or principal.actor_type is ActorType.agent:
        return None
    if principal.user is None:
        return []
    result = await session.execute(
        select(UserVMAccess.vm_id).where(UserVMAccess.user_id == principal.user.id)
    )
    return [row[0] for row in result.all()]


async def require_vm_access(
    vm_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> Principal:
    """Ensure the authenticated principal has access to the given VM.

    - Admins: always allowed.
    - Agent (MCP): always allowed.
    - Operator/readonly: must have an entry in ``user_vm_access``.
    - No VMs assigned: sees nothing (403).
    """
    if not await principal_can_access_vm(session, principal, vm_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "access to this VM denied")
    return principal


async def rate_limit_exec(principal: Principal = Depends(require_operator)) -> Principal:
    """Authorize as operator, then throttle execution endpoints per principal."""
    if not _exec_limiter.allow(f"{principal.actor_type}:{principal.actor_id}"):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded; slow down"
        )
    return principal


async def enforce_body_size(
    request: Request, settings: Settings = Depends(get_settings)
) -> None:
    """Reject oversized request bodies on execution endpoints early."""
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > settings.max_body_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "request body too large"
        )


async def current_worker(
    worker_id: str | None = Header(default=None, alias="X-Worker-Id"),
    worker_secret: str | None = Header(default=None, alias="X-Worker-Secret"),
    session: AsyncSession = Depends(get_session),
) -> VM:
    """Authenticate a worker by its VM id + per-worker secret (timing-safe)."""
    if not worker_id or not worker_secret:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "worker credentials required")
    try:
        vm_id = uuid.UUID(worker_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid worker id") from exc

    vm: VM | None = await session.get(VM, vm_id)
    # Verify the secret even when the VM is missing to avoid leaking existence via
    # timing; verify_secret on a None hash is constant-ish and returns False.
    secret_ok = security.verify_secret(worker_secret, vm.worker_secret_hash if vm else None)
    if vm is None or not secret_ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "worker authentication failed")
    if vm.state not in (VMState.active, VMState.offline):
        # PENDING/REVOKED workers may not interact beyond enrollment.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "worker not approved")
    return vm

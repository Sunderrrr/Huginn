"""Authentication endpoints: local login, current user, and OIDC (Authentik)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_principal
from app.config import Settings, get_settings
from app.core import audit, security
from app.core.ldap import LDAPClient
from app.core.oidc import OIDCClient, OIDCError
from app.core.principal import Principal
from app.core.ratelimit import RateLimiter
from app.db import get_session
from app.models.enums import ActorType
from app.models.user_vm_access import UserVMAccess
from app.schemas.auth import LoginRequest, OIDCStartResponse, TokenResponse, UserOut
from app.services import settings_service
from app.services import users as users_service

logger = logging.getLogger("huginn.hub.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])

_OIDC_STATE_COOKIE = "huginn_oidc_state"

# Per-IP brute-force guard on login (5 attempts/minute).
_login_limiter = RateLimiter(5)


@router.get("/config")
async def auth_config(session: AsyncSession = Depends(get_session)) -> dict:
    """Public, unauthenticated: what the login page needs to render itself.

    Tells the SPA whether the SSO button should appear and what to label it.
    No secrets here — just the enabled flag and the display name.
    """
    row = await settings_service.get_settings_row(session)
    enabled = bool(row and row.oidc_enabled and row.oidc_issuer and row.oidc_client_id)
    name = (row.oidc_provider_name if row else "") or "SSO"
    return {"oidc_enabled": enabled, "oidc_provider_name": name}


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    ip = client_ip(request) or "unknown"
    # Block only when too many *failed* attempts have accumulated for this IP, so
    # legitimate logins are never throttled but brute force is.
    if not _login_limiter.check(f"login:{ip}"):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "too many failed login attempts; slow down"
        )
    # Local password first — guarantees the bootstrap admin can always log in.
    user = await users_service.authenticate(session, body.username, body.password)
    # Fall back to LDAP if enabled and local auth did not match.
    if user is None:
        settings_row = await settings_service.get_settings_row(session)
        if settings_row is not None and settings_row.ldap_enabled:
            client = LDAPClient(settings_row)
            claims = await run_in_threadpool(
                client.authenticate, body.username, body.password
            )
            if claims is not None:
                user = await users_service.upsert_ldap_user(
                    session,
                    ldap_dn=claims.dn,
                    username=claims.username,
                    email=claims.email,
                )
    if user is None:
        _login_limiter.allow(f"login:{ip}")  # count this failed attempt
        await audit.record(
            session,
            actor_type=ActorType.system,
            actor_id=body.username,
            event_type="login_failed",
            source_ip=client_ip(request),
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="login",
        source_ip=client_ip(request),
    )
    token = users_service.issue_token(user)
    return TokenResponse(access_token=token, expires_in=settings.access_token_ttl_minutes * 60)


@router.get("/me", response_model=UserOut)
async def me(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    if principal.user is None:
        # Agent principal (MCP) has no user record.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no user for this principal")
    result = await session.execute(
        select(UserVMAccess.vm_id).where(UserVMAccess.user_id == principal.user.id)
    )
    vm_ids = [row[0] for row in result.all()]
    return UserOut.model_validate(principal.user).model_copy(update={"vm_ids": vm_ids})


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Record a logout. JWTs are short-lived and `is_active` is checked per
    request, so there is no server-side blacklist; the client discards its token.
    """
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="logout",
        source_ip=client_ip(request),
    )


async def _oidc_source(session: AsyncSession, settings: Settings) -> Any:
    """Prefer the admin-configured DB settings row; fall back to env config.

    The DB row and the env Settings expose the same OIDC attribute names, so
    OIDCClient works structurally with either.
    """
    row = await settings_service.get_settings_row(session)
    return row if (row and row.oidc_enabled) else settings


@router.get("/oidc/login", response_model=OIDCStartResponse)
async def oidc_login(
    response: Response,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> OIDCStartResponse:
    client = OIDCClient(await _oidc_source(session, settings))
    if not client.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC is not enabled")
    state = client.new_state()
    url = await client.authorization_url(state)
    # Bind the state to the browser via an httponly cookie (CSRF protection).
    response.set_cookie(
        _OIDC_STATE_COOKIE,
        state,
        httponly=True,
        secure=settings.is_prod,
        samesite="lax",
        max_age=600,
    )
    return OIDCStartResponse(authorization_url=url, state=state)


@router.get("/oidc/callback", response_model=TokenResponse)
async def oidc_callback(
    code: str,
    state: str,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Response | TokenResponse:
    cookie_state = request.cookies.get(_OIDC_STATE_COOKIE)
    if not cookie_state or not security.constant_time_equals(cookie_state, state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid OIDC state")

    source = await _oidc_source(session, settings)
    client = OIDCClient(source)
    try:
        claims = await client.exchange_code(code)
    except OIDCError as exc:
        logger.warning("OIDC callback failed: %s", exc)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "OIDC authentication failed"
        ) from exc

    user = await users_service.upsert_oidc_user(
        session, subject=claims.subject, username=claims.username, email=claims.email
    )
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="login",
        detail={"method": "oidc"},
        source_ip=client_ip(request),
    )
    response.delete_cookie(_OIDC_STATE_COOKIE)
    token = users_service.issue_token(user)
    # If a SPA dashboard URL is configured, hand the token back via the URL
    # fragment (never logged by servers/proxies) and redirect the browser there.
    post_login_redirect = source.oidc_post_login_redirect or settings.oidc_post_login_redirect
    if post_login_redirect:
        redirect = RedirectResponse(
            url=f"{post_login_redirect}#access_token={token}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        redirect.delete_cookie(_OIDC_STATE_COOKIE)
        return redirect
    return TokenResponse(access_token=token, expires_in=settings.access_token_ttl_minutes * 60)

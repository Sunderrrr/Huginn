"""Authentication endpoints: local login, current user, and OIDC (Authentik)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_principal
from app.config import Settings, get_settings
from app.core import audit, security
from app.core.oidc import OIDCClient, OIDCError
from app.core.principal import Principal
from app.db import get_session
from app.models.enums import ActorType
from app.models.user_vm_access import UserVMAccess
from app.schemas.auth import LoginRequest, OIDCStartResponse, TokenResponse, UserOut
from app.services import users as users_service

router = APIRouter(prefix="/api/auth", tags=["auth"])

_OIDC_STATE_COOKIE = "huginn_oidc_state"


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    user = await users_service.authenticate(session, body.username, body.password)
    if user is None:
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


@router.get("/oidc/login", response_model=OIDCStartResponse)
async def oidc_login(
    response: Response,
    settings: Settings = Depends(get_settings),
) -> OIDCStartResponse:
    client = OIDCClient(settings)
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

    client = OIDCClient(settings)
    try:
        claims = await client.exchange_code(code)
    except OIDCError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"OIDC error: {exc}") from exc

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
    if settings.oidc_post_login_redirect:
        redirect = RedirectResponse(
            url=f"{settings.oidc_post_login_redirect}#access_token={token}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        redirect.delete_cookie(_OIDC_STATE_COOKIE)
        return redirect
    return TokenResponse(access_token=token, expires_in=settings.access_token_ttl_minutes * 60)

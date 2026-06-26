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
from app.core.jwt import MFA_SCOPE, MFA_SETUP_SCOPE, create_mfa_challenge_token
from app.core.ldap import LDAPClient
from app.core.oidc import OIDCClient, OIDCError
from app.core.principal import Principal
from app.core.ratelimit import RateLimiter
from app.db import get_session
from app.models.enums import ActorType
from app.models.user_vm_access import UserVMAccess
from app.schemas.auth import (
    LoginChallengeResponse,
    LoginRequest,
    OIDCStartResponse,
    TokenResponse,
    UpdateProfileRequest,
    UserOut,
)
from app.services import mfa as mfa_service
from app.services import settings_service
from app.services import users as users_service

logger = logging.getLogger("huginn.hub.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])

_OIDC_STATE_COOKIE = "huginn_oidc_state"
_OIDC_NONCE_COOKIE = "huginn_oidc_nonce"

# Per-IP brute-force guard on login (5 attempts/minute).
_login_limiter = RateLimiter(5)
# Per-IP guard on the OIDC start/callback endpoints (10 attempts/minute).
_oidc_limiter = RateLimiter(10)


@router.get("/config")
async def auth_config(session: AsyncSession = Depends(get_session)) -> dict:
    """Public, unauthenticated: what the login page needs to render itself.

    Tells the SPA which auth methods to show (SSO button + label, password form,
    passkey button). No secrets here — only enable flags and the display name.
    """
    row = await settings_service.get_settings_row(session)
    settings = get_settings()
    oidc_enabled = bool(row and row.oidc_enabled and row.oidc_issuer and row.oidc_client_id)
    name = (row.oidc_provider_name if row else "") or "SSO"
    # Env var force-enables (the documented "unsafe" escape hatch); the DB row
    # can also enable it. Either source counts.
    allow_pw = settings.allow_password_login or bool(row and row.allow_password_login)
    password_login_enabled = (not oidc_enabled) or allow_pw
    # Mirror webauthn.rp_config's DB→env fallback so the button shows whenever
    # passkeys are actually usable (RP id + origin configured by either source).
    rp_id = (row.webauthn_rp_id if row else "") or settings.webauthn_rp_id
    rp_origin = (row.webauthn_origin if row else "") or settings.webauthn_origin
    webauthn_enabled = bool(rp_id and rp_origin)
    return {
        "oidc_enabled": oidc_enabled,
        "oidc_provider_name": name,
        "password_login_enabled": password_login_enabled,
        "webauthn_enabled": webauthn_enabled,
    }


@router.post("/login")
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> TokenResponse | LoginChallengeResponse:
    ip = client_ip(request) or "unknown"
    # Block only when too many *failed* attempts have accumulated for this IP, so
    # legitimate logins are never throttled but brute force is.
    if not _login_limiter.check(f"login:{ip}"):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "too many failed login attempts; slow down"
        )
    settings_row = await settings_service.get_settings_row(session)
    oidc_enabled = bool(
        settings_row and settings_row.oidc_enabled and settings_row.oidc_issuer
    )
    # SSO-first: when OIDC is active, the password form is disabled unless it's
    # re-enabled — via the env "unsafe" flag OR the admin-set DB row. With OIDC
    # off, password login is always available (no lockout).
    allow_pw = settings.allow_password_login or bool(
        settings_row and settings_row.allow_password_login
    )
    if oidc_enabled and not allow_pw:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "password login is disabled; use SSO"
        )
    # Local password first — guarantees the bootstrap admin can always log in.
    user = await users_service.authenticate(session, body.username, body.password)
    # Fall back to LDAP if enabled and local auth did not match.
    if user is None and settings_row is not None and settings_row.ldap_enabled:
        client = LDAPClient(settings_row)
        claims = await run_in_threadpool(client.authenticate, body.username, body.password)
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

    # First factor OK — branch on the second factor.
    require_admin_mfa = (
        bool(settings_row.require_admin_mfa)
        if settings_row
        else settings.require_admin_mfa
    )

    if user.totp_enabled:
        await audit.record(
            session,
            actor_type=ActorType.user,
            actor_id=str(user.id),
            event_type="login_password_ok_mfa_pending",
            source_ip=client_ip(request),
        )
        return LoginChallengeResponse(
            mfa_required=True,
            challenge_token=create_mfa_challenge_token(user.id, MFA_SCOPE),
            methods=["totp", "backup"],
        )

    if user.is_admin and require_admin_mfa and not await mfa_service.user_has_mfa(session, user):
        # Admin without any factor must enrol before getting an access token.
        await audit.record(
            session,
            actor_type=ActorType.user,
            actor_id=str(user.id),
            event_type="login_password_ok_mfa_setup_required",
            source_ip=client_ip(request),
        )
        return LoginChallengeResponse(
            mfa_setup_required=True,
            challenge_token=create_mfa_challenge_token(user.id, MFA_SETUP_SCOPE),
            methods=["totp", "webauthn"],
        )

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
    passkeys = await mfa_service.passkey_count(session, principal.user.id)
    return UserOut.model_validate(principal.user).model_copy(
        update={"vm_ids": vm_ids, "passkey_count": passkeys}
    )


@router.put("/me", response_model=UserOut)
async def update_me(
    body: UpdateProfileRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    """Self-service profile update (currently just email)."""
    if principal.user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no user for this principal")
    user = principal.user
    if body.email is not None:
        user.email = body.email or None
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="profile_updated",
        detail={"fields": ["email"]},
        source_ip=client_ip(request),
    )
    await session.commit()
    result = await session.execute(
        select(UserVMAccess.vm_id).where(UserVMAccess.user_id == user.id)
    )
    vm_ids = [row[0] for row in result.all()]
    passkeys = await mfa_service.passkey_count(session, user.id)
    return UserOut.model_validate(user).model_copy(
        update={"vm_ids": vm_ids, "passkey_count": passkeys}
    )


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


def _oidc_cookie_kwargs(settings: Settings) -> dict:
    return {"httponly": True, "secure": settings.is_prod, "samesite": "lax", "max_age": 600}


@router.get("/oidc/login", response_model=OIDCStartResponse)
async def oidc_login(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> OIDCStartResponse:
    ip = client_ip(request) or "unknown"
    if not _oidc_limiter.allow(f"oidc:{ip}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many OIDC attempts; slow down")
    client = OIDCClient(await _oidc_source(session, settings))
    if not client.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC is not enabled")
    state = client.new_state()
    nonce = client.new_nonce()
    url = await client.authorization_url(state, nonce)
    # Bind state (CSRF) and nonce (id_token replay protection) to the browser
    # via httponly cookies, checked on the callback.
    response.set_cookie(_OIDC_STATE_COOKIE, state, **_oidc_cookie_kwargs(settings))
    response.set_cookie(_OIDC_NONCE_COOKIE, nonce, **_oidc_cookie_kwargs(settings))
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
    ip = client_ip(request) or "unknown"
    if not _oidc_limiter.allow(f"oidc:{ip}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many OIDC attempts; slow down")
    cookie_state = request.cookies.get(_OIDC_STATE_COOKIE)
    if not cookie_state or not security.constant_time_equals(cookie_state, state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid OIDC state")
    nonce = request.cookies.get(_OIDC_NONCE_COOKIE)

    source = await _oidc_source(session, settings)
    client = OIDCClient(source)
    try:
        claims = await client.exchange_code(code, nonce=nonce)
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
    response.delete_cookie(_OIDC_NONCE_COOKIE)
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
        redirect.delete_cookie(_OIDC_NONCE_COOKIE)
        return redirect
    return TokenResponse(access_token=token, expires_in=settings.access_token_ttl_minutes * 60)

"""Second-factor endpoints: TOTP enrollment/verification, backup codes, WebAuthn.

The two-step login works like this:
  1. ``POST /api/auth/login`` validates the password and, when a second factor is
     required, returns a short-lived *challenge token* (scope ``mfa``) instead of
     an access token. Admins without any factor get an ``mfa_setup`` token.
  2. The client presents that token here. ``get_principal`` REJECTS these scoped
     tokens for the business API, so they are only ever usable on these routes.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_principal
from app.config import get_settings
from app.core import audit
from app.core.jwt import (
    MFA_SCOPE,
    MFA_SETUP_SCOPE,
    TokenError,
    decode_access_token,
    decode_mfa_challenge_token,
)
from app.core.principal import Principal
from app.core.ratelimit import RateLimiter
from app.db import get_session
from app.models.enums import ActorType
from app.models.mixins import utcnow
from app.models.user import User
from app.models.webauthn_credential import WebAuthnCredential
from app.schemas.auth import (
    BackupCodesResponse,
    MfaVerifyRequest,
    TokenResponse,
    TotpDisableRequest,
    TotpEnrollBeginResponse,
    TotpEnrollFinishRequest,
    WebAuthnCredentialOut,
    WebAuthnLoginBeginRequest,
    WebAuthnLoginFinishRequest,
    WebAuthnRegisterFinishRequest,
    WebAuthnRenameRequest,
)
from app.services import mfa as mfa_service
from app.services import totp as totp_service
from app.services import users as users_service
from app.services import webauthn as webauthn_service

router = APIRouter(prefix="/api/auth/mfa", tags=["mfa"])

_bearer = HTTPBearer(auto_error=False)

# Per-IP / per-user guards. Cleared in tests/conftest.py.
_verify_limiter = RateLimiter(10)
_webauthn_limiter = RateLimiter(20)


def _token_response(user: User) -> TokenResponse:
    return TokenResponse(
        access_token=users_service.issue_token(user),
        expires_in=get_settings().access_token_ttl_minutes * 60,
    )


async def _challenge_user(
    credentials: HTTPAuthorizationCredentials | None,
    session: AsyncSession,
    expected_scope: str,
) -> User:
    """Resolve the user behind an MFA challenge/setup token (scope-checked)."""
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "challenge token required")
    try:
        payload = decode_mfa_challenge_token(credentials.credentials, expected_scope)
        user_id = uuid.UUID(payload["sub"])
    except (TokenError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid challenge token") from exc
    user = await users_service.get_by_id(session, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")
    return user


def enrolling_actor(
    *, allow_setup: bool
) -> Callable[..., Awaitable[tuple[User, bool]]]:
    """Build a dependency authenticating an enrollment caller.

    Accepts a normal access token (logged-in user managing their own factors)
    and, only when ``allow_setup`` is set, an ``mfa_setup`` challenge token
    (admin completing forced first-time setup). The ``mfa`` verify scope is never
    accepted. Returns ``(user, is_setup)``. Sensitive ops (disable / regenerate)
    pass ``allow_setup=False`` so a setup token can't reach them.
    """

    async def dep(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        session: AsyncSession = Depends(get_session),
    ) -> tuple[User, bool]:
        if credentials is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
        try:
            payload = decode_access_token(credentials.credentials)
            user_id = uuid.UUID(payload["sub"])
        except (TokenError, KeyError, ValueError) as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc
        scope = payload.get("scope")
        if scope == MFA_SCOPE:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token not valid for enrollment")
        is_setup = scope == MFA_SETUP_SCOPE
        if is_setup and not allow_setup:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "setup token not valid here")
        user = await users_service.get_by_id(session, user_id)
        if user is None or not user.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")
        return user, is_setup

    return dep


# --- Two-step login verification ------------------------------------------------


@router.post("/verify")
async def verify_mfa(
    body: MfaVerifyRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    ip = client_ip(request) or "unknown"
    user = await _challenge_user(credentials, session, MFA_SCOPE)
    if not _verify_limiter.allow(f"mfa:{ip}") or not _verify_limiter.allow(f"mfa:{user.id}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; slow down")
    if not user.totp_enabled or not user.totp_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "TOTP not enabled")

    ok = False
    method = None
    if body.code:
        try:
            secret = totp_service.decrypt_secret(user.totp_secret_enc)
        except ValueError:
            # Key rotated/corrupt — fail as an auth error, not a 500.
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "invalid code"
            ) from None
        step = totp_service.matched_step(secret, body.code)
        # Atomically claim the step → rejects replay even under concurrency.
        if step is not None and await mfa_service.claim_totp_step(session, user, step):
            ok = True
            method = "totp"
    elif body.backup_code:
        ok = await mfa_service.consume_backup_code(session, user, body.backup_code)
        method = "backup"

    if not ok:
        await audit.record(
            session,
            actor_type=ActorType.user,
            actor_id=str(user.id),
            event_type="mfa_verify_failed",
            source_ip=ip,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")

    user.last_login_at = utcnow()
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="mfa_verify_success",
        detail={"method": method},
        source_ip=ip,
    )
    return _token_response(user)


# --- TOTP enrollment ------------------------------------------------------------


@router.post("/totp/enroll/begin", response_model=TotpEnrollBeginResponse)
async def totp_enroll_begin(
    request: Request,
    actor: tuple[User, bool] = Depends(enrolling_actor(allow_setup=True)),
    session: AsyncSession = Depends(get_session),
) -> TotpEnrollBeginResponse:
    user, _is_setup = actor
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "TOTP already enabled")
    secret = totp_service.generate_secret()
    user.totp_secret_enc = totp_service.encrypt_secret(secret)  # pending, not enabled
    await session.flush()
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="totp_enroll_begin",
        source_ip=client_ip(request),
    )
    return TotpEnrollBeginResponse(
        secret=secret, otpauth_uri=totp_service.provisioning_uri(secret, user.username)
    )


@router.post("/totp/enroll/finish")
async def totp_enroll_finish(
    body: TotpEnrollFinishRequest,
    request: Request,
    actor: tuple[User, bool] = Depends(enrolling_actor(allow_setup=True)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    user, is_setup = actor
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "TOTP already enabled")
    if not user.totp_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no pending enrollment")
    secret = totp_service.decrypt_secret(user.totp_secret_enc)
    if not totp_service.verify(secret, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.totp_enabled = True
    user.totp_confirmed_at = utcnow()
    codes = mfa_service.generate_backup_codes()
    await mfa_service.store_backup_codes(session, user, codes)
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="totp_enroll_complete",
        source_ip=client_ip(request),
    )
    out: dict = {"backup_codes": codes}
    # Setup flow (admin first-time) came in with only a setup token → log them in.
    if is_setup:
        out["access_token"] = _token_response(user).access_token
    return out


@router.post("/totp/disable", status_code=status.HTTP_204_NO_CONTENT)
async def totp_disable(
    body: TotpDisableRequest,
    request: Request,
    actor: tuple[User, bool] = Depends(enrolling_actor(allow_setup=False)),
    session: AsyncSession = Depends(get_session),
) -> None:
    user, _ = actor
    if not user.totp_enabled or not user.totp_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "TOTP not enabled")
    # Re-authenticate with a *current second factor* — a valid TOTP code or an
    # unused backup code. A password alone is deliberately NOT sufficient: that
    # would let a stolen session + known password strip the second factor.
    reauthed = False
    if body.code:
        try:
            secret = totp_service.decrypt_secret(user.totp_secret_enc)
        except ValueError:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "valid second factor required"
            ) from None
        reauthed = totp_service.verify(secret, body.code)
    elif body.backup_code:
        reauthed = await mfa_service.consume_backup_code(session, user, body.backup_code)
    if not reauthed:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "valid second factor required")
    await mfa_service.disable_totp(session, user)
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="totp_disabled",
        source_ip=client_ip(request),
    )


@router.post("/totp/backup-codes/regenerate", response_model=BackupCodesResponse)
async def regenerate_backup_codes(
    body: TotpEnrollFinishRequest,
    request: Request,
    actor: tuple[User, bool] = Depends(enrolling_actor(allow_setup=False)),
    session: AsyncSession = Depends(get_session),
) -> BackupCodesResponse:
    user, _ = actor
    if not user.totp_enabled or not user.totp_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "TOTP not enabled")
    if not totp_service.verify(totp_service.decrypt_secret(user.totp_secret_enc), body.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    codes = mfa_service.generate_backup_codes()
    await mfa_service.store_backup_codes(session, user, codes)
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="backup_codes_regenerated",
        source_ip=client_ip(request),
    )
    return BackupCodesResponse(backup_codes=codes)


# --- WebAuthn passkeys ----------------------------------------------------------


@router.post("/webauthn/register/begin")
async def webauthn_register_begin(
    request: Request,
    actor: tuple[User, bool] = Depends(enrolling_actor(allow_setup=True)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    user, _ = actor
    if not _webauthn_limiter.allow(f"wa:{client_ip(request) or 'unknown'}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; slow down")
    try:
        return await webauthn_service.begin_registration(session, user)
    except webauthn_service.WebAuthnError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post("/webauthn/register/finish")
async def webauthn_register_finish(
    body: WebAuthnRegisterFinishRequest,
    request: Request,
    actor: tuple[User, bool] = Depends(enrolling_actor(allow_setup=True)),
    session: AsyncSession = Depends(get_session),
) -> dict:
    user, is_setup = actor
    try:
        cred = await webauthn_service.finish_registration(
            session, user, body.name, body.credential
        )
    except webauthn_service.WebAuthnError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="passkey_added",
        detail={"name": cred.name, "aaguid": cred.aaguid},
        source_ip=client_ip(request),
    )
    out: dict = {"id": str(cred.id), "name": cred.name}
    if is_setup:
        out["access_token"] = _token_response(user).access_token
    return out


@router.put("/webauthn/credentials/{cred_id}", response_model=WebAuthnCredentialOut)
async def rename_passkey(
    cred_id: uuid.UUID,
    body: WebAuthnRenameRequest,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> WebAuthnCredential:
    user = principal.user
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no user for this principal")
    cred = await session.get(WebAuthnCredential, cred_id)
    if cred is None or cred.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "passkey not found")
    cred.name = body.name
    await session.flush()
    return cred


@router.get("/webauthn/credentials", response_model=list[WebAuthnCredentialOut])
async def list_passkeys(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[WebAuthnCredential]:
    if principal.user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no user for this principal")
    return list(
        (
            await session.execute(
                select(WebAuthnCredential)
                .where(WebAuthnCredential.user_id == principal.user.id)
                .order_by(WebAuthnCredential.created_at)
            )
        ).scalars()
    )


@router.delete("/webauthn/credentials/{cred_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_passkey(
    cred_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> None:
    user = principal.user
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no user for this principal")
    cred = await session.get(WebAuthnCredential, cred_id)
    if cred is None or cred.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "passkey not found")
    # Lockout guard: a passwordless user with no TOTP must keep at least one key.
    if not user.password_hash and not user.totp_enabled:
        remaining = await mfa_service.passkey_count(session, user.id)
        if remaining <= 1:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "cannot delete your only passkey; set a password or add another factor first",
            )
    await session.delete(cred)
    await session.flush()
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="passkey_removed",
        detail={"name": cred.name},
        source_ip=client_ip(request),
    )


@router.post("/webauthn/login/begin")
async def webauthn_login_begin(
    body: WebAuthnLoginBeginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    if not _webauthn_limiter.allow(f"wa:{client_ip(request) or 'unknown'}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; slow down")
    try:
        return await webauthn_service.begin_login(session, body.username)
    except webauthn_service.WebAuthnError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post("/webauthn/login/finish")
async def webauthn_login_finish(
    body: WebAuthnLoginFinishRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    ip = client_ip(request) or "unknown"
    if not _webauthn_limiter.allow(f"wa:{ip}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; slow down")
    try:
        user = await webauthn_service.finish_login(session, body.credential)
    except webauthn_service.WebAuthnError as exc:
        await audit.record(
            session,
            actor_type=ActorType.system,
            actor_id="webauthn",
            event_type="webauthn_login_failed",
            detail={"reason": str(exc)},
            source_ip=ip,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "passkey authentication failed") from exc
    user.last_login_at = utcnow()
    await audit.record(
        session,
        actor_type=ActorType.user,
        actor_id=str(user.id),
        event_type="webauthn_login",
        source_ip=ip,
    )
    return _token_response(user)

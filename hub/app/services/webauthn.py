"""WebAuthn (passkey) ceremonies, wrapping py_webauthn.

Challenges are generated server-side, persisted, and consumed exactly once. The
relying-party id/origin come from settings (must be a registrable domain, never
a bare IP). Sign counters are persisted and checked to detect cloned keys.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import secrets
import uuid
from datetime import timedelta

import webauthn
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.config import get_settings
from app.models.mixins import utcnow
from app.models.user import User
from app.models.webauthn_challenge import WebAuthnChallenge
from app.models.webauthn_credential import WebAuthnCredential
from app.services import settings_service
from app.services import users as users_service

logger = logging.getLogger("huginn.hub.webauthn")

_CHALLENGE_TTL = timedelta(minutes=5)


class WebAuthnError(Exception):
    """Raised on any WebAuthn configuration or verification failure."""


def _uv() -> UserVerificationRequirement:
    raw = (get_settings().webauthn_user_verification or "preferred").lower()
    try:
        return UserVerificationRequirement(raw)
    except ValueError:
        return UserVerificationRequirement.PREFERRED


def _is_registrable_domain(rp_id: str) -> bool:
    """rp_id must be a domain (with a dot), never a bare IP or 'localhost'.

    Binding passkeys to an IP literal is invalid per spec and can't be relied on;
    we fail closed rather than register credentials against a bad RP ID.
    """
    try:
        ipaddress.ip_address(rp_id)
        return False  # bare IP
    except ValueError:
        pass
    return "." in rp_id and rp_id != "localhost"


async def rp_config(session: AsyncSession) -> tuple[str, str, str]:
    """Return (rp_id, rp_name, origin) from DB settings, falling back to env."""
    row = await settings_service.get_settings_row(session)
    settings = get_settings()
    rp_id = (row.webauthn_rp_id if row else "") or settings.webauthn_rp_id
    origin = (row.webauthn_origin if row else "") or settings.webauthn_origin
    rp_name = (row.webauthn_rp_name if row else "") or settings.webauthn_rp_name or "Huginn"
    if not rp_id or not origin:
        raise WebAuthnError("WebAuthn is not configured")
    if not _is_registrable_domain(rp_id):
        raise WebAuthnError("webauthn_rp_id must be a registrable domain, not an IP")
    return rp_id, rp_name, origin


async def _store_challenge(
    session: AsyncSession, challenge: bytes, purpose: str, user_id: uuid.UUID | None
) -> None:
    session.add(
        WebAuthnChallenge(
            challenge=bytes_to_base64url(challenge),
            user_id=user_id,
            purpose=purpose,
            expires_at=utcnow() + _CHALLENGE_TTL,
        )
    )
    await session.flush()


def _client_data_challenge(credential: dict) -> str:
    try:
        cdj = credential["response"]["clientDataJSON"]
        data = json.loads(base64url_to_bytes(cdj))
        return data["challenge"]
    except (KeyError, TypeError, ValueError) as exc:
        raise WebAuthnError("malformed credential") from exc


async def _consume_challenge(
    session: AsyncSession, challenge_b64: str, purpose: str
) -> WebAuthnChallenge:
    now = utcnow()
    # Atomic claim: a single conditional UPDATE the DB serializes, so two
    # concurrent finishes can't both consume the same challenge (replay).
    result = await session.execute(
        update(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.challenge == challenge_b64,
            WebAuthnChallenge.purpose == purpose,
            WebAuthnChallenge.consumed_at.is_(None),
            WebAuthnChallenge.expires_at > now,
        )
        .values(consumed_at=now)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise WebAuthnError("unknown, used, or expired challenge")
    row = (
        await session.execute(
            select(WebAuthnChallenge).where(WebAuthnChallenge.challenge == challenge_b64)
        )
    ).scalar_one()
    return row


async def _user_credentials(
    session: AsyncSession, user_id: uuid.UUID
) -> list[WebAuthnCredential]:
    return list(
        (
            await session.execute(
                select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id)
            )
        ).scalars()
    )


# --- Registration ---------------------------------------------------------------


async def begin_registration(session: AsyncSession, user: User) -> dict:
    rp_id, rp_name, _origin = await rp_config(session)
    existing = await _user_credentials(session, user.id)
    challenge = secrets.token_bytes(32)
    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_name=user.username,
        user_id=str(user.id).encode(),
        user_display_name=user.username,
        challenge=challenge,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
            for c in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            # Configurable: "required" makes a passkey true MFA (PIN/biometric);
            # "preferred" (default) also accepts e.g. a PIN-less security key.
            user_verification=_uv(),
        ),
    )
    await _store_challenge(session, options.challenge, "register", user.id)
    return json.loads(webauthn.options_to_json(options))


async def finish_registration(
    session: AsyncSession, user: User, name: str, credential: dict
) -> WebAuthnCredential:
    rp_id, _rp_name, origin = await rp_config(session)
    row = await _consume_challenge(session, _client_data_challenge(credential), "register")
    if row.user_id != user.id:
        raise WebAuthnError("challenge does not belong to this user")
    try:
        verification = webauthn.verify_registration_response(
            credential=json.dumps(credential),
            expected_challenge=base64url_to_bytes(row.challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=_uv() == UserVerificationRequirement.REQUIRED,
        )
    except Exception as exc:  # py_webauthn raises various subclasses
        logger.warning("WebAuthn registration verification failed: %s", exc)
        raise WebAuthnError("registration verification failed") from exc

    cred = WebAuthnCredential(
        user_id=user.id,
        name=name or "passkey",
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=(credential.get("response", {}) or {}).get("transports"),
        aaguid=getattr(verification, "aaguid", None),
    )
    session.add(cred)
    await session.flush()
    return cred


# --- Authentication (passwordless login) ----------------------------------------


async def begin_login(session: AsyncSession, username: str | None) -> dict:
    # Always usernameless/discoverable: we never disclose an allowCredentials
    # list, so the response can't be used to probe whether an account exists.
    rp_id, _rp_name, _origin = await rp_config(session)
    challenge = secrets.token_bytes(32)
    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        user_verification=_uv(),
    )
    await _store_challenge(session, options.challenge, "login", None)
    return json.loads(webauthn.options_to_json(options))


async def finish_login(session: AsyncSession, credential: dict) -> User:
    rp_id, _rp_name, origin = await rp_config(session)
    row = await _consume_challenge(session, _client_data_challenge(credential), "login")

    cred_id = credential.get("id")
    if not cred_id:
        raise WebAuthnError("missing credential id")
    stored = (
        await session.execute(
            select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cred_id)
        )
    ).scalar_one_or_none()
    if stored is None:
        raise WebAuthnError("unknown credential")
    try:
        verification = webauthn.verify_authentication_response(
            credential=json.dumps(credential),
            expected_challenge=base64url_to_bytes(row.challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=_uv() == UserVerificationRequirement.REQUIRED,
        )
    except Exception as exc:
        logger.warning("WebAuthn authentication verification failed: %s", exc)
        raise WebAuthnError("authentication verification failed") from exc

    # Clone detection: a non-zero counter that didn't advance signals a copy.
    new_count = verification.new_sign_count
    if new_count <= stored.sign_count and not (new_count == 0 and stored.sign_count == 0):
        raise WebAuthnError("sign counter regression (possible cloned authenticator)")
    stored.sign_count = new_count
    stored.last_used_at = utcnow()
    await session.flush()

    user = await users_service.get_by_id(session, stored.user_id)
    if user is None or not user.is_active:
        raise WebAuthnError("user not found or inactive")
    return user

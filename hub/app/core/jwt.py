"""JWT issue/verify for dashboard and API sessions."""

from __future__ import annotations

import uuid
from datetime import timedelta

import jwt

from app.config import get_settings
from app.models.enums import UserRole
from app.models.mixins import utcnow


class TokenError(Exception):
    """Raised when a token is missing, malformed, or expired."""


# Scopes for the short-lived intermediate tokens issued between password and
# second-factor. These tokens are NOT access tokens — get_principal rejects them.
MFA_SCOPE = "mfa"  # password OK, awaiting TOTP/backup verification
MFA_SETUP_SCOPE = "mfa_setup"  # admin must enrol a factor before proceeding
MFA_SCOPES = frozenset({MFA_SCOPE, MFA_SETUP_SCOPE})


def create_access_token(user_id: uuid.UUID, role: UserRole) -> str:
    settings = get_settings()
    now = utcnow()
    payload = {
        "sub": str(user_id),
        "role": role.value,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_ttl_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:  # pragma: no cover - thin wrapper
        raise TokenError(str(exc)) from exc


def create_mfa_challenge_token(user_id: uuid.UUID, scope: str) -> str:
    """Short-lived token proving a completed first factor (or pending setup).

    Carries no role and a distinct ``scope``; only the MFA endpoints accept it.
    """
    if scope not in MFA_SCOPES:
        raise ValueError(f"invalid mfa scope: {scope}")
    settings = get_settings()
    now = utcnow()
    payload = {
        "sub": str(user_id),
        "scope": scope,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.mfa_challenge_ttl_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_mfa_challenge_token(token: str, expected_scope: str) -> dict:
    """Decode and require the exact MFA scope; raise TokenError otherwise."""
    payload = decode_access_token(token)
    if payload.get("scope") != expected_scope:
        raise TokenError("wrong token scope")
    return payload

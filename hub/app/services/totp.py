"""TOTP second factor: encrypted-at-rest secrets, backup codes, replay guard."""

from __future__ import annotations

import base64
import hashlib
import time
from datetime import UTC, datetime

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

_TOTP_PERIOD = 30
_VALID_WINDOW = 1  # accept the adjacent ±1 step for clock skew


def _fernet() -> Fernet:
    """Fernet built from a key derived (SHA-256) from the dedicated MFA secret.

    Deriving lets operators supply any sufficiently long secret (like the other
    HUGINN_* keys) instead of a raw 32-byte urlsafe-base64 Fernet key.
    """
    raw = get_settings().mfa_encryption_key.encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(key)


def generate_secret() -> str:
    return pyotp.random_base32()


def encrypt_secret(secret_b32: str) -> str:
    return _fernet().encrypt(secret_b32.encode()).decode()


def decrypt_secret(enc: str) -> str:
    try:
        return _fernet().decrypt(enc.encode()).decode()
    except InvalidToken as exc:  # key rotated or corrupt — treat as no secret
        raise ValueError("cannot decrypt TOTP secret") from exc


def provisioning_uri(secret_b32: str, username: str, issuer: str = "Huginn") -> str:
    return pyotp.TOTP(secret_b32).provisioning_uri(name=username, issuer_name=issuer)


def current_step(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // _TOTP_PERIOD)


def verify(secret_b32: str, code: str) -> bool:
    """Constant-time TOTP check (±1 step). Does NOT enforce replay — see service."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    return pyotp.TOTP(secret_b32).verify(code, valid_window=_VALID_WINDOW)


def matched_step(secret_b32: str, code: str) -> int | None:
    """Return the time-step a code matches (for replay tracking), else None."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return None
    totp = pyotp.TOTP(secret_b32)
    now = time.time()
    for offset in range(-_VALID_WINDOW, _VALID_WINDOW + 1):
        at = now + offset * _TOTP_PERIOD
        if totp.verify(code, for_time=datetime.fromtimestamp(at, tz=UTC)):
            return int(at // _TOTP_PERIOD)
    return None

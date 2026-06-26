"""Cryptographic primitives: password hashing, token hashing, timing-safe compare.

Secrets (enrollment tokens, per-worker secrets) are high-entropy random values, so
we store a keyed HMAC-SHA256 of them rather than a slow KDF — fast to verify, and
the server-side key means a DB leak alone does not reveal usable hashes. User
passwords are low-entropy and therefore go through Argon2id.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

from app.config import get_settings

_ph = PasswordHasher()

# Number of random bytes for generated secrets (256-bit).
_TOKEN_BYTES = 32


# --- User passwords (Argon2id) -------------------------------------------------

def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Constant-time-ish verify. Returns False for missing hashes."""
    if not password_hash:
        # Still spend some work to reduce user-enumeration timing signal.
        _ph.hash(password)
        return False
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _ph.check_needs_rehash(password_hash)


# --- High-entropy secrets (enrollment tokens, worker secrets) ------------------

def generate_secret() -> str:
    """Return a new URL-safe random secret."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_secret(secret: str) -> str:
    """Keyed HMAC-SHA256 of a high-entropy secret, hex-encoded."""
    key = get_settings().secret_hash_key.encode()
    return hmac.new(key, secret.encode(), hashlib.sha256).hexdigest()


def verify_secret(secret: str, expected_hash: str | None) -> bool:
    """Timing-safe comparison of a secret against its stored HMAC.

    Always computes the HMAC, even when ``expected_hash`` is None, so the timing
    does not reveal whether a worker/VM exists (mitigates enumeration).
    """
    candidate = hash_secret(secret)
    if not expected_hash:
        # Compare against a dummy of equal length to keep timing constant.
        hmac.compare_digest(candidate, candidate)
        return False
    return hmac.compare_digest(candidate, expected_hash)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)

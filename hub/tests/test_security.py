"""Password hashing, secret hashing, and timing-safe comparison."""

from __future__ import annotations

from app.core import security


def test_password_roundtrip() -> None:
    h = security.hash_password("correct horse battery staple")
    assert h != "correct horse battery staple"
    assert security.verify_password("correct horse battery staple", h)
    assert not security.verify_password("wrong", h)


def test_verify_password_missing_hash_is_false() -> None:
    assert security.verify_password("anything", None) is False
    assert security.verify_password("anything", "") is False


def test_secret_hash_is_keyed_hmac_and_verifies() -> None:
    secret = security.generate_secret()
    digest = security.hash_secret(secret)
    # Hex-encoded SHA256.
    assert len(digest) == 64
    assert digest != secret
    assert security.verify_secret(secret, digest)
    assert not security.verify_secret("other", digest)
    assert not security.verify_secret(secret, None)


def test_generate_secret_is_unique_and_high_entropy() -> None:
    secrets_seen = {security.generate_secret() for _ in range(100)}
    assert len(secrets_seen) == 100
    assert all(len(s) >= 32 for s in secrets_seen)

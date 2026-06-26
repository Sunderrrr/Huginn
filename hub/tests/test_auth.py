"""Local login, JWT sessions, RBAC, and the MCP service-token principal."""

from __future__ import annotations

import pytest

from app.config import get_settings
from app.core.jwt import create_access_token, decode_access_token
from app.models.enums import UserRole


async def test_login_success_returns_token(client, make_user) -> None:
    user, password = await make_user(username="bob", password="hunter2hunter2")
    resp = await client.post("/api/auth/login", json={"username": "bob", "password": password})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    claims = decode_access_token(body["access_token"])
    assert claims["sub"] == str(user.id)
    assert claims["role"] == "admin"


async def test_login_wrong_password_rejected(client, make_user) -> None:
    await make_user(username="bob", password="hunter2hunter2")
    resp = await client.post("/api/auth/login", json={"username": "bob", "password": "nope"})
    assert resp.status_code == 401


async def test_login_unknown_user_rejected(client) -> None:
    resp = await client.post("/api/auth/login", json={"username": "ghost", "password": "x"})
    assert resp.status_code == 401


async def test_inactive_user_cannot_login(client, make_user) -> None:
    await make_user(username="ina", password="password1234", active=False)
    resp = await client.post(
        "/api/auth/login", json={"username": "ina", "password": "password1234"}
    )
    assert resp.status_code == 401


async def test_me_requires_auth(client) -> None:
    resp = await client.get("/api/auth/me")
    assert resp.status_code == 401


async def test_me_returns_current_user(client, make_user) -> None:
    user, password = await make_user(username="carol", role=UserRole.readonly)
    login = await client.post(
        "/api/auth/login", json={"username": "carol", "password": password}
    )
    token = login.json()["access_token"]
    resp = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "carol"
    assert resp.json()["role"] == "readonly"


async def test_invalid_token_rejected(client) -> None:
    resp = await client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401


async def test_mcp_service_token_is_agent_principal(client) -> None:
    # /me has no user for an agent, but auth must succeed (404, not 401).
    token = get_settings().mcp_service_token
    resp = await client.get("/api/auth/me", headers={"X-MCP-Service-Token": token})
    assert resp.status_code == 404


async def test_wrong_mcp_service_token_rejected(client) -> None:
    resp = await client.get("/api/auth/me", headers={"X-MCP-Service-Token": "wrong"})
    assert resp.status_code == 401


async def test_oidc_disabled_returns_404(client) -> None:
    resp = await client.get("/api/auth/oidc/login")
    assert resp.status_code == 404


def test_jwt_roundtrip_carries_role() -> None:
    import uuid

    uid = uuid.uuid4()
    token = create_access_token(uid, UserRole.admin)
    claims = decode_access_token(token)
    assert claims["sub"] == str(uid)
    assert claims["role"] == "admin"


async def test_auth_config_default_sso_disabled(client) -> None:
    """Public config endpoint: no auth required, OIDC off by default."""
    resp = await client.get("/api/auth/config")
    assert resp.status_code == 200
    body = resp.json()
    assert body["oidc_enabled"] is False
    assert body["oidc_provider_name"]  # always a non-empty label


async def test_auth_config_reflects_enabled_oidc(client, admin_headers) -> None:
    await client.put(
        "/api/settings",
        json={
            "oidc_enabled": True,
            "oidc_provider_name": "Authentik",
            "oidc_issuer": "https://idp.example.com",
            "oidc_client_id": "huginn",
        },
        headers=admin_headers,
    )
    body = (await client.get("/api/auth/config")).json()
    assert body["oidc_enabled"] is True
    assert body["oidc_provider_name"] == "Authentik"


async def test_oidc_links_existing_username(session, make_user) -> None:
    """OIDC login for an existing local username adopts that account (no dup)."""
    from app.services import users as users_service

    existing, _ = await make_user(username="admin", password="local-pass-1234")
    linked = await users_service.upsert_oidc_user(
        session, subject="authentik-sub-123", username="admin", email="a@x.io"
    )
    assert linked.id == existing.id
    assert linked.oidc_subject == "authentik-sub-123"

    # A second login resolves by subject to the same user.
    again = await users_service.upsert_oidc_user(
        session, subject="authentik-sub-123", username="admin", email="a@x.io"
    )
    assert again.id == existing.id


def _make_oidc(monkeypatch_obj=None):
    """Build an OIDCClient with a dummy settings object."""
    from app.core.oidc import OIDCClient

    class _S:
        oidc_enabled = True
        oidc_issuer = "https://idp.example.com"
        oidc_client_id = "huginn"
        oidc_client_secret = "secret"
        oidc_redirect_url = "https://hub/cb"

    return OIDCClient(_S())


def test_oidc_nonce_mismatch_rejected() -> None:
    """A verified id_token whose nonce differs from the expected one is rejected."""
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from app.core.oidc import OIDCError

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    token = jwt.encode(
        {"sub": "abc", "aud": "huginn", "iss": "https://idp.example.com", "nonce": "real-nonce"},
        key,
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(pub, as_dict=True)
    jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    jwks = {"keys": [jwk]}

    client = _make_oidc()
    # Correct nonce verifies.
    claims = client._verify_id_token(token, jwks, "https://idp.example.com", nonce="real-nonce")
    assert claims.subject == "abc"
    # Wrong nonce is rejected.
    with pytest.raises(OIDCError, match="nonce"):
        client._verify_id_token(token, jwks, "https://idp.example.com", nonce="attacker-nonce")

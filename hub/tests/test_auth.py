"""Local login, JWT sessions, RBAC, and the MCP service-token principal."""

from __future__ import annotations

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

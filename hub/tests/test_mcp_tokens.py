"""Per-user MCP tokens: CRUD, on-behalf-of resolution, role, audit attribution."""

from __future__ import annotations

from app.config import get_settings
from app.models.enums import UserRole


def _svc() -> dict[str, str]:
    return {"X-MCP-Service-Token": get_settings().mcp_service_token}


async def _make_token(client, headers, name="laptop") -> dict:
    r = await client.post("/api/mcp/tokens", json={"name": name}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


async def test_create_list_revoke(client, admin_headers) -> None:
    tok = await _make_token(client, admin_headers)
    assert tok["token"] and tok["name"] == "laptop"

    listing = await client.get("/api/mcp/tokens", headers=admin_headers)
    assert any(t["id"] == tok["id"] for t in listing.json())

    deleted = await client.delete(f"/api/mcp/tokens/{tok['id']}", headers=admin_headers)
    assert deleted.status_code == 204
    after = await client.get("/api/mcp/tokens", headers=admin_headers)
    assert all(t["id"] != tok["id"] for t in after.json())


async def test_on_behalf_of_resolves_to_user(client, admin_headers) -> None:
    token = (await _make_token(client, admin_headers))["token"]
    r = await client.get("/api/mcp/whoami", headers={**_svc(), "X-MCP-On-Behalf-Of": token})
    assert r.status_code == 200
    assert r.json() == {"username": "admin", "role": "admin"}


async def test_full_role_via_mcp(client, admin_headers) -> None:
    # An admin's MCP token grants admin through MCP (require_admin endpoint).
    token = (await _make_token(client, admin_headers))["token"]
    r = await client.get("/api/users", headers={**_svc(), "X-MCP-On-Behalf-Of": token})
    assert r.status_code == 200


async def test_invalid_or_revoked_obo_rejected(client, admin_headers) -> None:
    bad = await client.get("/api/mcp/whoami", headers={**_svc(), "X-MCP-On-Behalf-Of": "bogus"})
    assert bad.status_code == 401
    tok = await _make_token(client, admin_headers)
    await client.delete(f"/api/mcp/tokens/{tok['id']}", headers=admin_headers)
    # Revoked token no longer resolves.
    r = await client.get("/api/mcp/whoami", headers={**_svc(), "X-MCP-On-Behalf-Of": tok["token"]})
    assert r.status_code == 401


async def test_service_token_only_is_operator_not_admin(client) -> None:
    # No on-behalf-of → anonymous agent: operator (can read audit) but not admin.
    assert (await client.get("/api/audit", headers=_svc())).status_code == 200
    assert (await client.get("/api/users", headers=_svc())).status_code == 403


async def test_mcp_action_attributed_to_user_in_audit(
    client, admin_headers, enrolled_worker
) -> None:
    w = await enrolled_worker()
    token = (await _make_token(client, admin_headers))["token"]
    obo = {**_svc(), "X-MCP-On-Behalf-Of": token}
    r = await client.post(f"/api/vms/{w['vm_id']}/actions", json={"action": "status"}, headers=obo)
    assert r.status_code == 202, r.text
    params = {"event_type": "execute_action"}
    audit = (await client.get("/api/audit", params=params, headers=admin_headers)).json()
    assert audit and audit[0]["actor_label"] == "mcp · admin"


async def test_readonly_token_cannot_execute(
    client, readonly_headers, enrolled_worker
) -> None:
    # A readonly user's MCP token must NOT gain operator capability via MCP.
    w = await enrolled_worker()
    token = (await _make_token(client, readonly_headers))["token"]
    obo = {**_svc(), "X-MCP-On-Behalf-Of": token}
    r = await client.post(f"/api/vms/{w['vm_id']}/actions", json={"action": "status"}, headers=obo)
    assert r.status_code == 403
    # ...but it can still read (whoami resolves the readonly user).
    who = await client.get("/api/mcp/whoami", headers=obo)
    assert who.json()["role"] == "readonly"


async def test_token_ip_binding_enforced(client, admin_headers) -> None:
    r = await client.post(
        "/api/mcp/tokens",
        json={"name": "pinned", "allowed_ip": "203.0.113.7"},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["allowed_ip"] == "203.0.113.7/32"
    token = r.json()["token"]
    obo = {**_svc(), "X-MCP-On-Behalf-Of": token}

    # Right IP → allowed.
    ok = await client.get("/api/mcp/whoami", headers={**obo, "X-Forwarded-For": "203.0.113.7"})
    assert ok.status_code == 200
    # Wrong IP → blocked.
    bad = await client.get("/api/mcp/whoami", headers={**obo, "X-Forwarded-For": "198.51.100.9"})
    assert bad.status_code == 401
    # No IP at all → blocked (restriction set).
    none = await client.get("/api/mcp/whoami", headers=obo)
    assert none.status_code == 401


async def test_token_ip_binding_cidr_and_editable(client, admin_headers) -> None:
    tok = await _make_token(client, admin_headers)
    obo = {**_svc(), "X-MCP-On-Behalf-Of": tok["token"]}
    # No restriction yet → any IP works.
    r = await client.get("/api/mcp/whoami", headers={**obo, "X-Forwarded-For": "1.2.3.4"})
    assert r.status_code == 200

    # Restrict to a subnet via PATCH.
    upd = await client.patch(
        f"/api/mcp/tokens/{tok['id']}", json={"allowed_ip": "10.0.0.0/24"}, headers=admin_headers
    )
    assert upd.status_code == 200 and upd.json()["allowed_ip"] == "10.0.0.0/24"
    inside = await client.get("/api/mcp/whoami", headers={**obo, "X-Forwarded-For": "10.0.0.55"})
    assert inside.status_code == 200
    outside = await client.get("/api/mcp/whoami", headers={**obo, "X-Forwarded-For": "10.0.1.1"})
    assert outside.status_code == 401

    # Clear it again → any IP works.
    cleared = await client.patch(
        f"/api/mcp/tokens/{tok['id']}", json={"allowed_ip": None}, headers=admin_headers
    )
    assert cleared.status_code == 200 and cleared.json()["allowed_ip"] is None
    r = await client.get("/api/mcp/whoami", headers={**obo, "X-Forwarded-For": "9.9.9.9"})
    assert r.status_code == 200


async def test_invalid_allowed_ip_rejected(client, admin_headers) -> None:
    r = await client.post(
        "/api/mcp/tokens", json={"name": "x", "allowed_ip": "not-an-ip"}, headers=admin_headers
    )
    assert r.status_code == 422


async def test_cannot_revoke_another_users_token(client, admin_headers, make_user) -> None:
    tok = await _make_token(client, admin_headers)
    _, pw = await make_user(username="bob", password="bob-password-1234", role=UserRole.operator)
    login = await client.post("/api/auth/login", json={"username": "bob", "password": pw})
    bob = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.delete(f"/api/mcp/tokens/{tok['id']}", headers=bob)).status_code == 404

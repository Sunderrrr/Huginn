"""RBAC: the MCP agent is an operator, not an admin; read-only users can't exec."""

from __future__ import annotations

import pytest

from app.config import Settings, get_settings


def _agent_headers() -> dict[str, str]:
    return {"X-MCP-Service-Token": get_settings().mcp_service_token}


async def test_agent_can_execute_action(client, enrolled_worker) -> None:
    w = await enrolled_worker()
    resp = await client.post(
        f"/api/vms/{w['vm_id']}/actions", json={"action": "status"}, headers=_agent_headers()
    )
    assert resp.status_code == 202


async def test_agent_can_read_audit_log(client) -> None:
    resp = await client.get("/api/audit", headers=_agent_headers())
    assert resp.status_code == 200


async def test_agent_cannot_approve_vm(client, admin_headers) -> None:
    # Enroll a VM (admin), then the agent must NOT be able to approve it.
    token = (await client.post("/api/enrollment-tokens", json={}, headers=admin_headers)).json()[
        "token"
    ]
    enroll = await client.post(
        "/api/worker/enroll", json={"token": token, "name": "vm", "arch": "amd64"}
    )
    vm_id = enroll.json()["worker_id"]
    resp = await client.post(f"/api/vms/{vm_id}/approve", headers=_agent_headers())
    assert resp.status_code == 403


async def test_agent_cannot_toggle_unrestricted(client, admin_headers, enrolled_worker) -> None:
    w = await enrolled_worker()
    resp = await client.put(
        f"/api/vms/{w['vm_id']}/exec-mode",
        json={"exec_mode": "unrestricted"},
        headers=_agent_headers(),
    )
    assert resp.status_code == 403


async def test_agent_cannot_create_enrollment_token(client) -> None:
    resp = await client.post("/api/enrollment-tokens", json={}, headers=_agent_headers())
    assert resp.status_code == 403


async def test_readonly_user_cannot_execute(client, readonly_headers, enrolled_worker) -> None:
    w = await enrolled_worker()
    resp = await client.post(
        f"/api/vms/{w['vm_id']}/actions", json={"action": "status"}, headers=readonly_headers
    )
    assert resp.status_code == 403


async def test_readonly_user_can_list_vms(client, readonly_headers) -> None:
    resp = await client.get("/api/vms", headers=readonly_headers)
    assert resp.status_code == 200


# --- Production secret guard (C2) ---


def test_validate_for_prod_rejects_placeholder_secrets() -> None:
    s = Settings(
        env="prod",
        jwt_secret="change-me-please-generate-a-real-secret",
        secret_hash_key="short",
        mcp_service_token="change-me-mcp-service-token",
    )
    with pytest.raises(RuntimeError) as exc:
        s.validate_for_prod()
    msg = str(exc.value)
    assert "HUGINN_JWT_SECRET" in msg
    assert "HUGINN_SECRET_HASH_KEY" in msg
    assert "HUGINN_MCP_SERVICE_TOKEN" in msg


def test_validate_for_prod_accepts_strong_secrets() -> None:
    strong = "a" * 48
    s = Settings(
        env="prod",
        jwt_secret=strong,
        secret_hash_key=strong,
        mcp_service_token=strong,
        mfa_encryption_key=strong,
    )
    s.validate_for_prod()  # must not raise


def test_validate_for_prod_rejects_weak_mfa_key() -> None:
    strong = "a" * 48
    s = Settings(
        env="prod",
        jwt_secret=strong,
        secret_hash_key=strong,
        mcp_service_token=strong,
        mfa_encryption_key="change-me-mfa-encryption-key-32b",
    )
    with pytest.raises(RuntimeError) as exc:
        s.validate_for_prod()
    assert "HUGINN_MFA_ENCRYPTION_KEY" in str(exc.value)


def test_validate_for_prod_noop_in_dev() -> None:
    Settings(env="dev").validate_for_prod()  # placeholders allowed in dev

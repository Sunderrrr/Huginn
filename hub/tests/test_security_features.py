"""Tests for the security hardening and new features added in this change set."""

from __future__ import annotations

import pytest

from app.models.enums import WorkerArch
from app.services import versioning

# --- SSRF: private/LAN IPs allowed, loopback/link-local rejected ---------------

def test_release_domain_allows_lan_ip() -> None:
    versioning.validate_release_domain("192.0.2.13")
    versioning.validate_release_domain("10.0.0.5")
    versioning.validate_release_domain("192.168.1.10")


def test_release_domain_rejects_loopback_and_metadata() -> None:
    for bad in ["127.0.0.1", "169.254.169.254", "0.0.0.0", "localhost", "x.internal"]:  # noqa: S104
        with pytest.raises(versioning.SSRFError):
            versioning.validate_release_domain(bad)


def test_self_hosted_release_urls_over_http() -> None:
    urls = versioning.build_release_urls(
        repo="http://192.0.2.13/dist",
        version="v0.1.0",
        arch=WorkerArch.amd64,
        allowed_domains=["192.0.2.13"],
    )
    assert urls["binary_url"] == "http://192.0.2.13/dist/huginn-worker-linux-amd64"


# --- IDOR: VM listing filtered by access ---------------------------------------

@pytest.mark.asyncio
async def test_readonly_sees_only_assigned_vms(
    client, admin_headers, enrolled_worker, make_user, session_factory
) -> None:
    from app.models.user_vm_access import UserVMAccess

    w1 = await enrolled_worker(name="vm-a")
    w2 = await enrolled_worker(name="vm-b")

    # Operator user with access to only vm-a.
    from app.models.enums import UserRole

    user, password = await make_user(
        username="op1", password="operator-pass-1234", role=UserRole.operator
    )
    import uuid as _uuid

    async with session_factory() as s:
        s.add(UserVMAccess(user_id=user.id, vm_id=_uuid.UUID(w1["vm_id"])))
        await s.commit()

    login = await client.post(
        "/api/auth/login", json={"username": "op1", "password": password}
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    resp = await client.get("/api/vms", headers=headers)
    assert resp.status_code == 200
    ids = {v["id"] for v in resp.json()}
    assert w1["vm_id"] in ids
    assert w2["vm_id"] not in ids

    # Direct access to the unassigned VM is forbidden.
    forbidden = await client.get(f"/api/vms/{w2['vm_id']}", headers=headers)
    assert forbidden.status_code == 403


# --- Bulk actions ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_bulk_action_queues_per_vm(client, admin_headers, enrolled_worker) -> None:
    w1 = await enrolled_worker(name="bulk-a")
    w2 = await enrolled_worker(name="bulk-b")

    resp = await client.post(
        "/api/vms/bulk/actions",
        json={"vm_ids": [w1["vm_id"], w2["vm_id"]], "action": "status"},
        headers=admin_headers,
    )
    assert resp.status_code == 202
    results = resp.json()
    assert len(results) == 2
    assert all(r["status"] == "queued" for r in results)


# --- ip_address validation (blocks stored XSS) ---------------------------------

@pytest.mark.asyncio
async def test_enroll_rejects_non_ip_address(client, admin_headers) -> None:
    token_resp = await client.post("/api/enrollment-tokens", json={}, headers=admin_headers)
    token = token_resp.json()["token"]
    resp = await client.post(
        "/api/worker/enroll",
        json={
            "token": token,
            "name": "evil",
            "arch": "amd64",
            "ip_address": "<script>alert(1)</script>",
        },
    )
    assert resp.status_code == 422


# --- login rate limit (failed attempts) ----------------------------------------

@pytest.mark.asyncio
async def test_login_rate_limit_after_failures(client, make_user) -> None:
    await make_user(username="rl", password="correct-horse-1234")
    # 5 failed attempts allowed, then 429.
    codes = []
    for _ in range(7):
        r = await client.post(
            "/api/auth/login", json={"username": "rl", "password": "wrong"}
        )
        codes.append(r.status_code)
    assert 429 in codes

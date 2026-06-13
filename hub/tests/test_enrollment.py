"""Enrollment token lifecycle and worker enrollment + approval flow."""

from __future__ import annotations

import pytest

from app.models.enums import WorkerArch
from app.services import enrollment as enrollment_service


async def _create_token(client, admin_headers, **kwargs) -> str:
    resp = await client.post("/api/enrollment-tokens", json=kwargs or {}, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["token"]


async def test_create_token_requires_admin(client, readonly_headers) -> None:
    resp = await client.post("/api/enrollment-tokens", json={}, headers=readonly_headers)
    assert resp.status_code == 403


async def test_create_token_requires_auth(client) -> None:
    resp = await client.post("/api/enrollment-tokens", json={})
    assert resp.status_code == 401


async def test_enroll_creates_pending_vm(client, admin_headers) -> None:
    token = await _create_token(client, admin_headers)
    resp = await client.post(
        "/api/worker/enroll",
        json={"token": token, "name": "vm-1", "arch": "amd64"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["state"] == "pending"
    assert body["worker_secret"]
    assert body["worker_id"]


async def test_enroll_with_bad_token_rejected(client) -> None:
    resp = await client.post(
        "/api/worker/enroll",
        json={"token": "not-a-real-token", "name": "vm-x", "arch": "amd64"},
    )
    assert resp.status_code == 401


async def test_pending_worker_cannot_be_approved_by_readonly(
    client, admin_headers, readonly_headers
) -> None:
    token = await _create_token(client, admin_headers)
    enroll = await client.post(
        "/api/worker/enroll", json={"token": token, "name": "vm-2", "arch": "arm64"}
    )
    vm_id = enroll.json()["worker_id"]
    resp = await client.post(f"/api/vms/{vm_id}/approve", headers=readonly_headers)
    assert resp.status_code == 403


async def test_full_approve_flow(client, admin_headers) -> None:
    token = await _create_token(client, admin_headers)
    enroll = await client.post(
        "/api/worker/enroll", json={"token": token, "name": "vm-3", "arch": "amd64"}
    )
    vm_id = enroll.json()["worker_id"]

    approve = await client.post(f"/api/vms/{vm_id}/approve", headers=admin_headers)
    assert approve.status_code == 200
    assert approve.json()["state"] == "active"


async def test_token_max_uses_enforced(session, monkeypatch) -> None:
    import uuid

    token_row, plaintext = await enrollment_service.create_token(
        session, created_by=uuid.uuid4(), label="t", ttl_seconds=3600, max_uses=1
    )
    await session.flush()

    # First use succeeds.
    await enrollment_service.enroll_worker(
        session,
        token=plaintext,
        name="a",
        hostname=None,
        ip_address=None,
        arch=WorkerArch.amd64,
        os_info={},
        worker_version=None,
    )
    # Second use is rejected (exhausted).
    with pytest.raises(enrollment_service.EnrollmentError):
        await enrollment_service.enroll_worker(
            session,
            token=plaintext,
            name="b",
            hostname=None,
            ip_address=None,
            arch=WorkerArch.amd64,
            os_info={},
            worker_version=None,
        )


async def test_revoked_token_unusable(session) -> None:
    import uuid

    token_row, plaintext = await enrollment_service.create_token(
        session, created_by=uuid.uuid4(), label="t", ttl_seconds=3600, max_uses=5
    )
    await session.flush()
    await enrollment_service.revoke_token(session, token_row.id)
    with pytest.raises(enrollment_service.EnrollmentError):
        await enrollment_service.enroll_worker(
            session,
            token=plaintext,
            name="c",
            hostname=None,
            ip_address=None,
            arch=WorkerArch.amd64,
            os_info={},
            worker_version=None,
        )


async def test_revoke_vm_clears_secret(client, admin_headers, session) -> None:
    from app.models.vm import VM

    token = await _create_token(client, admin_headers)
    enroll = await client.post(
        "/api/worker/enroll", json={"token": token, "name": "vm-4", "arch": "amd64"}
    )
    vm_id = enroll.json()["worker_id"]
    await client.post(f"/api/vms/{vm_id}/approve", headers=admin_headers)
    resp = await client.post(f"/api/vms/{vm_id}/revoke", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["state"] == "revoked"

    import uuid as _uuid

    vm = await session.get(VM, _uuid.UUID(vm_id))
    await session.refresh(vm)
    assert vm.worker_secret_hash is None

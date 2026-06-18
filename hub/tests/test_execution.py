"""End-to-end execution flow: actions, commands, updates, worker polling."""

from __future__ import annotations


async def test_whitelist_action_full_cycle(client, admin_headers, enrolled_worker) -> None:
    w = await enrolled_worker()
    # Create an action task (async).
    resp = await client.post(
        f"/api/vms/{w['vm_id']}/actions",
        json={"action": "status"},
        headers=admin_headers,
    )
    assert resp.status_code == 202, resp.text
    task_id = resp.json()["id"]
    assert resp.json()["status"] == "pending"

    # Worker polls and receives the task.
    poll = await client.get("/api/worker/tasks/next", headers=w["headers"])
    assert poll.status_code == 200
    handed = poll.json()
    assert handed["id"] == task_id
    assert handed["payload"]["action"] == "status"

    # Worker submits the result.
    result = await client.post(
        f"/api/worker/tasks/{task_id}/result",
        json={"status": "succeeded", "exit_code": 0, "stdout": "ok"},
        headers=w["headers"],
    )
    assert result.status_code == 204

    # Caller polls the task and sees the result.
    final = await client.get(f"/api/tasks/{task_id}", headers=admin_headers)
    assert final.json()["status"] == "succeeded"
    assert final.json()["stdout"] == "ok"


async def test_long_poll_returns_empty_when_idle(client, enrolled_worker) -> None:
    w = await enrolled_worker()
    # With a tiny wait and no queued task, returns null after the wait (not 30s).
    poll = await client.get("/api/worker/tasks/next?wait=1", headers=w["headers"])
    assert poll.status_code == 200
    assert poll.json() is None


async def test_long_poll_picks_up_queued_task(
    client, admin_headers, enrolled_worker
) -> None:
    import asyncio

    w = await enrolled_worker()

    async def queue_after_delay() -> str:
        await asyncio.sleep(0.6)
        resp = await client.post(
            f"/api/vms/{w['vm_id']}/actions",
            json={"action": "status"},
            headers=admin_headers,
        )
        return resp.json()["id"]

    # Start the long-poll and the delayed enqueue concurrently.
    poll_task = asyncio.create_task(
        client.get("/api/worker/tasks/next?wait=5", headers=w["headers"])
    )
    task_id = await queue_after_delay()
    poll = await poll_task
    assert poll.status_code == 200
    assert poll.json() is not None
    assert poll.json()["id"] == task_id


async def test_auto_update_queues_task_on_version_mismatch(
    client, admin_headers, enrolled_worker
) -> None:
    w = await enrolled_worker()

    # Enable auto-update and set a target the worker won't match.
    await client.put(
        "/api/settings",
        json={"target_worker_version": "v9.9.9", "auto_update_enabled": True},
        headers=admin_headers,
    )

    # Worker heartbeats reporting an older version → hub queues an update.
    hb = await client.post(
        "/api/worker/heartbeat",
        json={"worker_version": "v0.1.0"},
        headers=w["headers"],
    )
    assert hb.status_code == 200
    assert hb.json()["target_worker_version"] == "v9.9.9"

    # The worker now finds an update task waiting.
    poll = await client.get("/api/worker/tasks/next", headers=w["headers"])
    handed = poll.json()
    assert handed is not None
    assert handed["type"] == "update"

    # A second heartbeat must NOT queue a duplicate while one is in flight.
    await client.post(
        "/api/worker/heartbeat",
        json={"worker_version": "v0.1.0"},
        headers=w["headers"],
    )
    poll2 = await client.get("/api/worker/tasks/next", headers=w["headers"])
    assert poll2.json() is None


async def test_auto_update_disabled_queues_nothing(
    client, admin_headers, enrolled_worker
) -> None:
    w = await enrolled_worker()
    await client.put(
        "/api/settings",
        json={"target_worker_version": "v9.9.9", "auto_update_enabled": False},
        headers=admin_headers,
    )
    await client.post(
        "/api/worker/heartbeat",
        json={"worker_version": "v0.1.0"},
        headers=w["headers"],
    )
    poll = await client.get("/api/worker/tasks/next", headers=w["headers"])
    assert poll.json() is None


async def test_unknown_action_rejected(client, admin_headers, enrolled_worker) -> None:
    w = await enrolled_worker()
    resp = await client.post(
        f"/api/vms/{w['vm_id']}/actions",
        json={"action": "rm_rf_root"},
        headers=admin_headers,
    )
    assert resp.status_code == 400


async def test_action_param_injection_rejected(client, admin_headers, enrolled_worker) -> None:
    w = await enrolled_worker()
    resp = await client.post(
        f"/api/vms/{w['vm_id']}/actions",
        json={"action": "restart_service", "params": {"service": "nginx; reboot"}},
        headers=admin_headers,
    )
    assert resp.status_code == 400


async def test_free_command_blocked_in_whitelist_mode(
    client, admin_headers, enrolled_worker
) -> None:
    w = await enrolled_worker()
    resp = await client.post(
        f"/api/vms/{w['vm_id']}/commands",
        json={"command": "echo hi"},
        headers=admin_headers,
    )
    assert resp.status_code == 403


async def test_free_command_allowed_after_enabling_unrestricted(
    client, admin_headers, enrolled_worker
) -> None:
    w = await enrolled_worker()
    toggle = await client.put(
        f"/api/vms/{w['vm_id']}/exec-mode",
        json={"exec_mode": "unrestricted"},
        headers=admin_headers,
    )
    assert toggle.status_code == 200
    resp = await client.post(
        f"/api/vms/{w['vm_id']}/commands",
        json={"command": "echo hi"},
        headers=admin_headers,
    )
    assert resp.status_code == 202


async def test_toggle_unrestricted_is_audited(client, admin_headers, enrolled_worker) -> None:
    w = await enrolled_worker()
    await client.put(
        f"/api/vms/{w['vm_id']}/exec-mode",
        json={"exec_mode": "unrestricted"},
        headers=admin_headers,
    )
    audit = await client.get(
        "/api/audit", params={"event_type": "toggle_unrestricted"}, headers=admin_headers
    )
    assert audit.status_code == 200
    entries = audit.json()
    assert entries and entries[0]["detail"]["unrestricted"] is True


async def test_trigger_update_creates_update_task(client, admin_headers, enrolled_worker) -> None:
    w = await enrolled_worker()
    resp = await client.post(f"/api/vms/{w['vm_id']}/update", headers=admin_headers)
    assert resp.status_code == 202, resp.text
    assert resp.json()["type"] == "update"
    assert resp.json()["action_name"] == "update_worker"


async def test_worker_poll_requires_valid_secret(client, enrolled_worker) -> None:
    w = await enrolled_worker()
    bad = {"X-Worker-Id": w["vm_id"], "X-Worker-Secret": "wrong"}
    resp = await client.get("/api/worker/tasks/next", headers=bad)
    assert resp.status_code == 401


async def test_pending_worker_cannot_poll(client, admin_headers) -> None:
    token_resp = await client.post("/api/enrollment-tokens", json={}, headers=admin_headers)
    token = token_resp.json()["token"]
    enroll = await client.post(
        "/api/worker/enroll", json={"token": token, "name": "pend", "arch": "amd64"}
    )
    body = enroll.json()
    headers = {"X-Worker-Id": body["worker_id"], "X-Worker-Secret": body["worker_secret"]}
    # Not approved yet -> 403.
    resp = await client.get("/api/worker/tasks/next", headers=headers)
    assert resp.status_code == 403


async def test_heartbeat_reports_target_version(client, enrolled_worker) -> None:
    w = await enrolled_worker()
    resp = await client.post(
        "/api/worker/heartbeat",
        json={"worker_version": "v0.0.9"},
        headers=w["headers"],
    )
    assert resp.status_code == 200
    assert resp.json()["target_worker_version"]
    assert resp.json()["exec_mode"] == "whitelist"


async def test_execute_action_requires_auth(client, enrolled_worker) -> None:
    w = await enrolled_worker()
    resp = await client.post(f"/api/vms/{w['vm_id']}/actions", json={"action": "status"})
    assert resp.status_code == 401

async def test_result_large_output_is_truncated_not_rejected(
    client, admin_headers, enrolled_worker
) -> None:
    """Output above the 1 MB cap is stored truncated (graceful), not rejected."""
    w = await enrolled_worker()
    task_id = (
        await client.post(
            f"/api/vms/{w['vm_id']}/actions", json={"action": "status"}, headers=admin_headers
        )
    ).json()["id"]
    big = "A" * 1_500_000  # 1.5 MB: over the 1 MB cap, under the 2 MiB schema bound
    result = await client.post(
        f"/api/worker/tasks/{task_id}/result",
        json={"status": "succeeded", "exit_code": 0, "stdout": big},
        headers=w["headers"],
    )
    assert result.status_code == 204, result.text
    stored = (await client.get(f"/api/tasks/{task_id}", headers=admin_headers)).json()["stdout"]
    assert len(stored) < len(big)
    assert stored.endswith("[...truncated...]")


async def test_result_oversized_field_rejected(
    client, admin_headers, enrolled_worker
) -> None:
    """A single result field beyond the schema bound is rejected at validation."""
    w = await enrolled_worker()
    task_id = (
        await client.post(
            f"/api/vms/{w['vm_id']}/actions", json={"action": "status"}, headers=admin_headers
        )
    ).json()["id"]
    abusive = "A" * (2_097_152 + 1)  # one over max_length, still under the body cap
    result = await client.post(
        f"/api/worker/tasks/{task_id}/result",
        json={"status": "succeeded", "exit_code": 0, "stdout": abusive},
        headers=w["headers"],
    )
    assert result.status_code == 422

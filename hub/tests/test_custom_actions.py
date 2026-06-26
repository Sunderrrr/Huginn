"""Custom commands: admin CRUD + the mode-AND-tag execution gates."""

from __future__ import annotations


async def _tag(client, admin_headers, name="web") -> str:
    r = await client.post(
        "/api/tags", json={"name": name, "color": "#46d39a"}, headers=admin_headers
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _make_action(client, admin_headers, tag_id, name="restart-nginx") -> dict:
    r = await client.post(
        "/api/actions",
        json={"name": name, "description": "restart nginx",
              "commands": ["systemctl restart nginx"], "tag_ids": [tag_id]},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


async def test_admin_crud_and_operator_read(client, admin_headers, readonly_headers) -> None:
    tag = await _tag(client, admin_headers)
    action = await _make_action(client, admin_headers, tag)
    assert action["argv"] == [["systemctl", "restart", "nginx"]]
    assert action["commands"] == ["systemctl restart nginx"]
    assert action["tag_ids"] == [tag]

    listing = await client.get("/api/actions", headers=admin_headers)
    assert any(a["id"] == action["id"] for a in listing.json())

    # operator/readonly can list but not create
    assert (await client.get("/api/actions", headers=readonly_headers)).status_code == 200
    bad = await client.post(
        "/api/actions",
        json={"name": "x-cmd", "commands": ["echo hi"], "tag_ids": [tag]},
        headers=readonly_headers,
    )
    assert bad.status_code == 403


async def test_multiple_commands_and_quoting(client, admin_headers) -> None:
    tag = await _tag(client, admin_headers)
    r = await client.post(
        "/api/actions",
        json={"name": "multi", "commands": ["systemctl restart nginx", 'echo "hello world"'],
              "tag_ids": [tag]},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    # Each line → one argv vector; quoting is honoured (no shell).
    assert r.json()["argv"] == [["systemctl", "restart", "nginx"], ["echo", "hello world"]]


async def test_malformed_command_line_rejected(client, admin_headers) -> None:
    tag = await _tag(client, admin_headers)
    r = await client.post(
        "/api/actions",
        json={"name": "bad", "commands": ['echo "unbalanced'], "tag_ids": [tag]},
        headers=admin_headers,
    )
    assert r.status_code == 400  # shlex parse error


async def test_name_cannot_shadow_builtin(client, admin_headers) -> None:
    tag = await _tag(client, admin_headers)
    r = await client.post(
        "/api/actions",
        json={"name": "status", "commands": ["echo x"], "tag_ids": [tag]},
        headers=admin_headers,
    )
    assert r.status_code == 422  # rejected by the schema validator


async def test_empty_commands_rejected(client, admin_headers) -> None:
    tag = await _tag(client, admin_headers)
    r = await client.post(
        "/api/actions",
        json={"name": "noop", "commands": [], "tag_ids": [tag]},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def _set_mode(client, admin_headers, vm_id, mode) -> None:
    r = await client.put(
        f"/api/vms/{vm_id}/exec-mode", json={"exec_mode": mode}, headers=admin_headers
    )
    assert r.status_code == 200, r.text


async def test_custom_action_requires_custom_mode(client, admin_headers, enrolled_worker) -> None:
    tag = await _tag(client, admin_headers)
    action = await _make_action(client, admin_headers, tag)
    w = await enrolled_worker()
    await client.put(f"/api/vms/{w['vm_id']}/tags", json={"tag_ids": [tag]}, headers=admin_headers)

    # whitelist mode (default) → blocked
    r = await client.post(
        f"/api/vms/{w['vm_id']}/actions", json={"action": action["name"]}, headers=admin_headers
    )
    assert r.status_code == 409

    # switch to custom mode → now allowed, and the task carries the fixed argv
    await _set_mode(client, admin_headers, w["vm_id"], "custom")
    r2 = await client.post(
        f"/api/vms/{w['vm_id']}/actions", json={"action": action["name"]}, headers=admin_headers
    )
    assert r2.status_code == 202, r2.text
    handed = (await client.get("/api/worker/tasks/next", headers=w["headers"])).json()
    assert handed["payload"]["commands"] == [["systemctl", "restart", "nginx"]]


async def test_custom_action_requires_matching_tag(client, admin_headers, enrolled_worker) -> None:
    tag = await _tag(client, admin_headers, name="web")
    other = await _tag(client, admin_headers, name="db")
    action = await _make_action(client, admin_headers, tag)  # allowed for 'web' only
    w = await enrolled_worker()
    await _set_mode(client, admin_headers, w["vm_id"], "custom")
    # VM has the WRONG tag → tag gate blocks even in custom mode
    await client.put(
        f"/api/vms/{w['vm_id']}/tags", json={"tag_ids": [other]}, headers=admin_headers
    )
    r = await client.post(
        f"/api/vms/{w['vm_id']}/actions", json={"action": action["name"]}, headers=admin_headers
    )
    assert r.status_code == 409


async def test_unknown_action_still_400(client, admin_headers, enrolled_worker) -> None:
    w = await enrolled_worker()
    await _set_mode(client, admin_headers, w["vm_id"], "custom")
    r = await client.post(
        f"/api/vms/{w['vm_id']}/actions", json={"action": "totally-unknown"}, headers=admin_headers
    )
    assert r.status_code == 400

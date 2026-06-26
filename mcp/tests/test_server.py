"""The MCP tools delegate to the hub client and shape errors cleanly."""

from __future__ import annotations

import os

os.environ.setdefault("HUGINN_MCP_SERVICE_TOKEN", "test-token")

import pytest

import app.server as server
from app.hub_client import HubError


class FakeHub:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    vms: list = [
        {"id": "11111111-1111-1111-1111-111111111111", "name": "web-01",
         "state": "active", "exec_mode": "restricted", "worker_version": "v1.1.0"},
    ]

    async def list_vms(self, state=None):
        self.calls.append(("list_vms", state))
        return list(self.vms)

    async def get_vm(self, vm_id):
        self.calls.append(("get_vm", vm_id))
        return {"id": vm_id, "exec_mode": "custom", "tags": [{"id": "tag-web"}]}

    async def execute_action(self, vm_id, action, params, wait):
        self.calls.append(("execute_action", vm_id, action))
        return {"id": "t9", "vm_id": vm_id}

    async def execute_command(self, vm_id, command, wait):
        raise HubError(403, "VM is not in unrestricted mode")

    async def trigger_update(self, vm_id):
        self.calls.append(("trigger_update", vm_id))
        return {"id": "t1", "type": "update"}

    async def wait_task(self, task_id, timeout):
        self.calls.append(("wait_task", task_id, timeout))
        return {"id": task_id, "status": "succeeded"}

    async def list_actions(self):
        self.calls.append(("list_actions",))
        return [
            {"name": "restart-nginx", "description": "", "commands": ["systemctl restart nginx"],
             "argv": [["systemctl", "restart", "nginx"]], "enabled": True, "tag_ids": ["tag-web"]},
            {"name": "disabled-one", "description": "", "commands": ["true"],
             "argv": [["true"]], "enabled": False, "tag_ids": ["tag-web"]},
        ]


_VM_ID = "11111111-1111-1111-1111-111111111111"


@pytest.mark.asyncio
async def test_list_vms_tool_delegates(monkeypatch) -> None:
    fake = FakeHub()
    monkeypatch.setattr(server, "hub", fake)
    result = await server.list_vms(state="active")
    assert result[0]["id"] == _VM_ID and result[0]["worker_version"] == "v1.1.0"
    assert fake.calls == [("list_vms", "active")]


@pytest.mark.asyncio
async def test_vm_tool_resolves_name_to_id(monkeypatch) -> None:
    fake = FakeHub()
    monkeypatch.setattr(server, "hub", fake)
    # Pass the stable name instead of the (possibly stale) id.
    await server.execute_action("web-01", "status")
    assert ("execute_action", _VM_ID, "status") in fake.calls


@pytest.mark.asyncio
async def test_vm_tool_resolves_name_case_insensitively(monkeypatch) -> None:
    fake = FakeHub()
    monkeypatch.setattr(server, "hub", fake)
    await server.execute_action("WEB-01", "status")  # stored as "web-01"
    assert ("execute_action", _VM_ID, "status") in fake.calls


@pytest.mark.asyncio
async def test_vm_tool_uuid_passes_through_without_listing(monkeypatch) -> None:
    fake = FakeHub()
    monkeypatch.setattr(server, "hub", fake)
    await server.get_vm_status(_VM_ID)
    # A real id is used directly — no list_vms lookup needed.
    assert fake.calls == [("get_vm", _VM_ID)]


@pytest.mark.asyncio
async def test_vm_tool_unknown_name_errors(monkeypatch) -> None:
    monkeypatch.setattr(server, "hub", FakeHub())
    result = await server.get_vm_status("does-not-exist")
    assert result["error"]["status"] == 404


@pytest.mark.asyncio
async def test_list_actions_excludes_disabled(monkeypatch) -> None:
    monkeypatch.setattr(server, "hub", FakeHub())
    result = await server.list_actions()
    assert [a["name"] for a in result] == ["restart-nginx"]
    assert result[0]["commands"] == ["systemctl restart nginx"]


@pytest.mark.asyncio
async def test_list_actions_filtered_to_eligible_vm(monkeypatch) -> None:
    # VM is in custom mode and carries tag-web → restart-nginx is runnable.
    monkeypatch.setattr(server, "hub", FakeHub())
    result = await server.list_actions(_VM_ID)
    assert [a["name"] for a in result] == ["restart-nginx"]


@pytest.mark.asyncio
async def test_list_actions_empty_when_vm_not_custom(monkeypatch) -> None:
    fake = FakeHub()

    async def gv(vm_id):
        return {"id": vm_id, "exec_mode": "whitelist", "tags": [{"id": "tag-web"}]}

    fake.get_vm = gv  # type: ignore[method-assign]
    monkeypatch.setattr(server, "hub", fake)
    assert await server.list_actions(_VM_ID) == []


@pytest.mark.asyncio
async def test_wait_for_task_tool_delegates(monkeypatch) -> None:
    fake = FakeHub()
    monkeypatch.setattr(server, "hub", fake)
    result = await server.wait_for_task("task-1", timeout=42)
    assert result == {"id": "task-1", "status": "succeeded"}
    assert fake.calls == [("wait_task", "task-1", 42)]


@pytest.mark.asyncio
async def test_list_vms_brief_projects_essentials(monkeypatch) -> None:
    monkeypatch.setattr(server, "hub", FakeHub())
    result = await server.list_vms(brief=True)
    assert result == [{"id": _VM_ID, "name": "web-01", "state": "active", "mode": "restricted"}]


@pytest.mark.asyncio
async def test_tool_converts_huberror_to_structured_error(monkeypatch) -> None:
    monkeypatch.setattr(server, "hub", FakeHub())
    result = await server.execute_command(_VM_ID, "echo hi")
    assert result["error"]["status"] == 403
    assert "unrestricted" in result["error"]["detail"]


@pytest.mark.asyncio
async def test_trigger_update_tool_delegates(monkeypatch) -> None:
    fake = FakeHub()
    monkeypatch.setattr(server, "hub", fake)
    result = await server.trigger_update(_VM_ID)
    assert result["type"] == "update"
    assert ("trigger_update", _VM_ID) in fake.calls

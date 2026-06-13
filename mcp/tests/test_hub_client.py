"""The MCP hub client faithfully proxies to the hub REST API."""

from __future__ import annotations

import os

os.environ.setdefault("HUGINN_MCP_HUB_URL", "http://hub.test")
os.environ.setdefault("HUGINN_MCP_SERVICE_TOKEN", "test-token")

import httpx
import pytest
import respx

from app.config import Settings
from app.hub_client import HubClient, HubError


def _settings() -> Settings:
    return Settings(hub_url="http://hub.test", service_token="test-token")


@pytest.mark.asyncio
@respx.mock
async def test_list_vms_sends_service_token() -> None:
    route = respx.get("http://hub.test/api/vms").mock(
        return_value=httpx.Response(200, json=[{"id": "vm1"}])
    )
    client = HubClient(_settings())
    try:
        result = await client.list_vms()
        assert result == [{"id": "vm1"}]
        assert route.calls.last.request.headers["X-MCP-Service-Token"] == "test-token"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_execute_action_posts_body() -> None:
    route = respx.post("http://hub.test/api/vms/vm1/actions").mock(
        return_value=httpx.Response(202, json={"id": "task1", "status": "pending"})
    )
    client = HubClient(_settings())
    try:
        result = await client.execute_action("vm1", "status", {}, wait=False)
        assert result["id"] == "task1"
        import json

        body = json.loads(route.calls.last.request.content)
        assert body["action"] == "status"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_error_response_raises_huberror() -> None:
    respx.post("http://hub.test/api/vms/vm1/commands").mock(
        return_value=httpx.Response(403, json={"detail": "VM is not in unrestricted mode"})
    )
    client = HubClient(_settings())
    try:
        with pytest.raises(HubError) as exc:
            await client.execute_command("vm1", "echo hi", wait=False)
        assert exc.value.status_code == 403
        assert "unrestricted" in exc.value.detail
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_trigger_update_calls_update_endpoint() -> None:
    route = respx.post("http://hub.test/api/vms/vm1/update").mock(
        return_value=httpx.Response(202, json={"id": "t", "type": "update"})
    )
    client = HubClient(_settings())
    try:
        result = await client.trigger_update("vm1")
        assert result["type"] == "update"
        assert route.called
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_audit_log_passes_filters() -> None:
    route = respx.get("http://hub.test/api/audit").mock(
        return_value=httpx.Response(200, json=[])
    )
    client = HubClient(_settings())
    try:
        await client.get_audit_log(vm_id="vm1", event_type="execute_command", limit=50)
        request = route.calls.last.request
        assert request.url.params["vm_id"] == "vm1"
        assert request.url.params["event_type"] == "execute_command"
        assert request.url.params["limit"] == "50"
    finally:
        await client.aclose()

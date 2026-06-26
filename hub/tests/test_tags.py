"""Tags: CRUD, VM assignment, fleet filter, bulk-by-tag."""

from __future__ import annotations


async def test_create_and_list_tag(client, admin_headers) -> None:
    resp = await client.post(
        "/api/tags", json={"name": "prod", "color": "#46d39a"}, headers=admin_headers
    )
    assert resp.status_code == 201, resp.text
    tag = resp.json()
    assert tag["name"] == "prod"

    listing = await client.get("/api/tags", headers=admin_headers)
    assert any(t["id"] == tag["id"] for t in listing.json())


async def test_duplicate_tag_rejected(client, admin_headers) -> None:
    await client.post("/api/tags", json={"name": "dup", "color": "#ffffff"}, headers=admin_headers)
    resp = await client.post(
        "/api/tags", json={"name": "dup", "color": "#000000"}, headers=admin_headers
    )
    assert resp.status_code == 409


async def test_readonly_cannot_create_tag(client, readonly_headers) -> None:
    resp = await client.post(
        "/api/tags", json={"name": "x", "color": "#ffffff"}, headers=readonly_headers
    )
    assert resp.status_code == 403


async def test_assign_tag_and_filter_fleet(client, admin_headers, enrolled_worker) -> None:
    w1 = await enrolled_worker(name="vm-a")
    w2 = await enrolled_worker(name="vm-b")
    tag = (await client.post(
        "/api/tags", json={"name": "web", "color": "#6db3f2"}, headers=admin_headers
    )).json()

    # Assign tag to vm-a.
    r = await client.put(
        f"/api/vms/{w1['vm_id']}/tags", json={"tag_ids": [tag["id"]]}, headers=admin_headers
    )
    assert r.status_code == 200
    assert any(t["id"] == tag["id"] for t in r.json()["tags"])

    # Fleet filtered by tag returns only vm-a.
    filtered = await client.get(f"/api/vms?tag_id={tag['id']}", headers=admin_headers)
    ids = {v["id"] for v in filtered.json()}
    assert w1["vm_id"] in ids
    assert w2["vm_id"] not in ids


async def test_bulk_action_by_tag(client, admin_headers, enrolled_worker) -> None:
    w1 = await enrolled_worker(name="t1")
    w2 = await enrolled_worker(name="t2")  # no tag
    tag = (await client.post(
        "/api/tags", json={"name": "batch", "color": "#ff6a1a"}, headers=admin_headers
    )).json()
    await client.put(
        f"/api/vms/{w1['vm_id']}/tags", json={"tag_ids": [tag["id"]]}, headers=admin_headers
    )

    resp = await client.post(
        "/api/vms/bulk/actions",
        json={"tag_ids": [tag["id"]], "action": "status"},
        headers=admin_headers,
    )
    assert resp.status_code == 202
    results = resp.json()
    assert len(results) == 1
    assert results[0]["vm_id"] == w1["vm_id"]
    assert results[0]["status"] == "queued"
    _ = w2

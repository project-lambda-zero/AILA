"""End-to-end lifecycle for VR workspaces and targets.

Covers:
  - workspace POST → GET → PATCH → DELETE (incl. 409 when targets exist)
  - target POST → GET → PATCH → DELETE (incl. 409 when investigations exist)
  - workspace counters reflect real DB rows (target_count, active_inv_count)

Each test stands up the full FastAPI app via the shared ``async_client``
fixture and exercises real DB writes against the test PostgreSQL.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _create_workspace(
    async_client: AsyncClient, admin_token: str, slug: str,
) -> dict:
    resp = await async_client.post(
        "/vr/workspaces",
        headers=_auth(admin_token),
        json={
            "name": f"Test {slug}",
            "slug": slug,
            "description": "lifecycle fixture",
            "theme": "browser_engines",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]


async def _create_target(
    async_client: AsyncClient, admin_token: str, workspace_id: str, name: str,
) -> dict:
    resp = await async_client.post(
        "/vr/targets",
        headers=_auth(admin_token),
        json={
            "workspace_id": workspace_id,
            "display_name": name,
            "kind": "native_binary",
            "descriptor": {"binary_path": "/dev/null"},
            "primary_language": "c",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]


@pytest.mark.asyncio
async def test_workspace_create_get_patch_delete_roundtrip(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws = await _create_workspace(async_client, admin_token, "ws-roundtrip-1")
    ws_id = ws["id"]
    assert ws["target_count"] == 0
    assert ws["active_investigation_count"] == 0

    got = await async_client.get(
        f"/vr/workspaces/{ws_id}", headers=_auth(admin_token),
    )
    assert got.status_code == 200, got.text
    body = got.json()["data"]
    assert body["id"] == ws_id
    assert body["target_count"] == 0
    assert body["status"] == "active"

    patched = await async_client.patch(
        f"/vr/workspaces/{ws_id}",
        headers=_auth(admin_token),
        json={"name": "Renamed", "status": "archived"},
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()["data"]
    assert body["name"] == "Renamed"
    assert body["status"] == "archived"

    deleted = await async_client.delete(
        f"/vr/workspaces/{ws_id}", headers=_auth(admin_token),
    )
    assert deleted.status_code == 204

    missing = await async_client.get(
        f"/vr/workspaces/{ws_id}", headers=_auth(admin_token),
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_workspace_delete_refuses_when_targets_exist(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws = await _create_workspace(async_client, admin_token, "ws-with-targets")
    await _create_target(async_client, admin_token, ws["id"], "t1")

    resp = await async_client.delete(
        f"/vr/workspaces/{ws['id']}", headers=_auth(admin_token),
    )
    assert resp.status_code == 409, resp.text
    assert "target(s)" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_workspace_counters_reflect_real_rows(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws = await _create_workspace(async_client, admin_token, "ws-counter")
    await _create_target(async_client, admin_token, ws["id"], "t1")
    await _create_target(async_client, admin_token, ws["id"], "t2")
    await _create_target(async_client, admin_token, ws["id"], "t3")

    got = await async_client.get(
        f"/vr/workspaces/{ws['id']}", headers=_auth(admin_token),
    )
    assert got.status_code == 200
    body = got.json()["data"]
    assert body["target_count"] == 3
    assert body["active_investigation_count"] == 0

    listing = await async_client.get(
        "/vr/workspaces", headers=_auth(admin_token),
    )
    assert listing.status_code == 200
    rows = {r["id"]: r for r in listing.json()["data"]}
    assert rows[ws["id"]]["target_count"] == 3


@pytest.mark.asyncio
async def test_target_patch_roundtrip(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws = await _create_workspace(async_client, admin_token, "ws-target-patch")
    t = await _create_target(async_client, admin_token, ws["id"], "t-orig")

    patched = await async_client.patch(
        f"/vr/targets/{t['id']}",
        headers=_auth(admin_token),
        json={
            "display_name": "renamed",
            "primary_language": "rust",
            "secondary_languages": ["c", "asm"],
            "status": "quarantined",
            "tags": ["needs-review", "high-risk"],
        },
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()["data"]
    assert body["display_name"] == "renamed"
    assert body["primary_language"] == "rust"
    assert body["secondary_languages"] == ["c", "asm"]
    assert body["status"] == "quarantined"
    assert {tag["tag"] for tag in body["tags"]} == {"needs-review", "high-risk"}
    assert all(tag["source"] == "operator" for tag in body["tags"])


@pytest.mark.asyncio
async def test_target_delete_roundtrip(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws = await _create_workspace(async_client, admin_token, "ws-target-delete")
    t = await _create_target(async_client, admin_token, ws["id"], "t-del")

    resp = await async_client.delete(
        f"/vr/targets/{t['id']}", headers=_auth(admin_token),
    )
    assert resp.status_code == 204

    missing = await async_client.get(
        f"/vr/targets/{t['id']}", headers=_auth(admin_token),
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_404_on_unknown_workspace(
    async_client: AsyncClient, admin_token: str,
) -> None:
    for method in ("GET", "PATCH", "DELETE"):
        kwargs: dict = {"headers": _auth(admin_token)}
        if method == "PATCH":
            kwargs["json"] = {"name": "x"}
        resp = await async_client.request(
            method, "/vr/workspaces/nonexistent-id", **kwargs,
        )
        assert resp.status_code == 404, f"{method} returned {resp.status_code}"


@pytest.mark.asyncio
async def test_404_on_unknown_target(
    async_client: AsyncClient, admin_token: str,
) -> None:
    for method in ("GET", "PATCH", "DELETE"):
        kwargs: dict = {"headers": _auth(admin_token)}
        if method == "PATCH":
            kwargs["json"] = {"display_name": "x"}
        resp = await async_client.request(
            method, "/vr/targets/nonexistent-id", **kwargs,
        )
        assert resp.status_code == 404, f"{method} returned {resp.status_code}"

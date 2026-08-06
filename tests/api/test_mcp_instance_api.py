"""API tests for the RFC-11 admin MCP instance catalog router.

Covers the operator CRUD loop: create an instance, list it back, patch
the endpoint / enabled flag / capability_tags, delete it, plus the
non-admin refusal guard. Mirrors :mod:`tests.api.test_admin_prompts`.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient

# Top-level import ensures SQLModel.metadata includes the table when
# the session-scoped test_db fixture runs create_all.
from aila.platform.mcp.instance_catalog import McpServerInstance

__all__: list[str] = []


def _scope() -> str:
    return f"rfc11api-{uuid4().hex[:8]}"


def _payload(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": "audit_mcp",
        "transport": "http",
        "endpoint": "http://10.0.0.10:18822",
        "capability_tags": ["source_audit", "graph"],
        "enabled": True,
        "module_scope": _scope(),
    }
    body.update(overrides)
    return body


@pytest.mark.asyncio
async def test_create_and_list(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """POST creates a row; GET returns it inside the DataEnvelope."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    body = _payload(module_scope=scope)

    created = await async_client.post(
        "/platform/mcp/instances", json=body, headers=hdr,
    )
    assert created.status_code == 201, created.text
    row = created.json()["data"]
    assert row["name"] == "audit_mcp"
    assert row["transport"] == "http"
    assert row["endpoint"] == "http://10.0.0.10:18822"
    assert row["capability_tags"] == ["source_audit", "graph"]
    assert row["enabled"] is True
    assert row["module_scope"] == scope
    assert row["created_at"] is not None
    assert row["updated_at"] is None
    assert isinstance(row["id"], str) and row["id"]

    listing = await async_client.get(
        "/platform/mcp/instances",
        params={"module_scope": scope},
        headers=hdr,
    )
    assert listing.status_code == 200
    rows = listing.json()["data"]
    assert [r["id"] for r in rows] == [row["id"]]
    assert rows[0]["capability_tags"] == ["source_audit", "graph"]


@pytest.mark.asyncio
async def test_patch_endpoint(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """PATCH replaces the endpoint and stamps updated_at."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    created = await async_client.post(
        "/platform/mcp/instances", json=_payload(module_scope=scope), headers=hdr,
    )
    instance_id = created.json()["data"]["id"]

    patched = await async_client.patch(
        f"/platform/mcp/instances/{instance_id}",
        json={"endpoint": "http://10.0.0.99:18822"},
        headers=hdr,
    )
    assert patched.status_code == 200
    row = patched.json()["data"]
    assert row["endpoint"] == "http://10.0.0.99:18822"
    assert row["updated_at"] is not None


@pytest.mark.asyncio
async def test_patch_enabled_flag(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """PATCH flips the enabled bit without touching the endpoint."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    created = await async_client.post(
        "/platform/mcp/instances", json=_payload(module_scope=scope), headers=hdr,
    )
    instance_id = created.json()["data"]["id"]

    disabled = await async_client.patch(
        f"/platform/mcp/instances/{instance_id}",
        json={"enabled": False},
        headers=hdr,
    )
    assert disabled.status_code == 200
    assert disabled.json()["data"]["enabled"] is False

    re_enabled = await async_client.patch(
        f"/platform/mcp/instances/{instance_id}",
        json={"enabled": True},
        headers=hdr,
    )
    assert re_enabled.json()["data"]["enabled"] is True


@pytest.mark.asyncio
async def test_patch_capability_tags(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """PATCH replaces the JSON-encoded tag list."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    created = await async_client.post(
        "/platform/mcp/instances", json=_payload(module_scope=scope), headers=hdr,
    )
    instance_id = created.json()["data"]["id"]

    patched = await async_client.patch(
        f"/platform/mcp/instances/{instance_id}",
        json={"capability_tags": ["binary_audit", "decompile"]},
        headers=hdr,
    )
    assert patched.status_code == 200
    assert patched.json()["data"]["capability_tags"] == ["binary_audit", "decompile"]


@pytest.mark.asyncio
async def test_patch_empty_body_rejected(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """A PATCH with no mutable fields returns 400."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    created = await async_client.post(
        "/platform/mcp/instances", json=_payload(module_scope=scope), headers=hdr,
    )
    instance_id = created.json()["data"]["id"]

    resp = await async_client.patch(
        f"/platform/mcp/instances/{instance_id}",
        json={},
        headers=hdr,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_patch_unknown_id_404(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """PATCH against an unknown id returns 404."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    resp = await async_client.patch(
        "/platform/mcp/instances/does-not-exist",
        json={"endpoint": "http://nope:1"},
        headers=hdr,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_removes(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """DELETE returns 204 and removes the row from the listing."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    created = await async_client.post(
        "/platform/mcp/instances", json=_payload(module_scope=scope), headers=hdr,
    )
    instance_id = created.json()["data"]["id"]

    deleted = await async_client.delete(
        f"/platform/mcp/instances/{instance_id}", headers=hdr,
    )
    assert deleted.status_code == 204

    listing = await async_client.get(
        "/platform/mcp/instances",
        params={"module_scope": scope},
        headers=hdr,
    )
    assert listing.json()["data"] == []


@pytest.mark.asyncio
async def test_delete_unknown_id_404(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """DELETE against an unknown id returns 404."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    resp = await async_client.delete(
        "/platform/mcp/instances/does-not-exist", headers=hdr,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_unknown_transport_rejected(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """POST with an unsupported transport returns 400."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    resp = await async_client.post(
        "/platform/mcp/instances",
        json=_payload(transport="grpc", module_scope=scope),
        headers=hdr,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_duplicate_scope_name_conflict(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """POST twice with the same (module_scope, name) returns 409."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    first = await async_client.post(
        "/platform/mcp/instances", json=_payload(module_scope=scope), headers=hdr,
    )
    assert first.status_code == 201
    dup = await async_client.post(
        "/platform/mcp/instances",
        json=_payload(module_scope=scope, endpoint="http://other:1"),
        headers=hdr,
    )
    assert dup.status_code == 409


@pytest.mark.asyncio
async def test_requires_admin(
    async_client: AsyncClient, reader_token: str, test_db,
) -> None:
    """A non-admin token is refused on every method."""
    del test_db
    hdr = {"Authorization": f"Bearer {reader_token}"}
    listing = await async_client.get("/platform/mcp/instances", headers=hdr)
    assert listing.status_code == 403

    posting = await async_client.post(
        "/platform/mcp/instances", json=_payload(), headers=hdr,
    )
    assert posting.status_code == 403


@pytest.mark.asyncio
async def test_row_survives_full_lifecycle(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """Confirm the model round-trip end to end via the HTTP surface."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    scope = _scope()
    body = _payload(
        module_scope=scope,
        capability_tags=["binary_audit", "decompile", "exploit"],
    )
    created = await async_client.post(
        "/platform/mcp/instances", json=body, headers=hdr,
    )
    assert created.status_code == 201
    instance_id = created.json()["data"]["id"]

    # PATCH endpoint + capability_tags in a single call.
    patched = await async_client.patch(
        f"/platform/mcp/instances/{instance_id}",
        json={
            "endpoint": "http://10.0.0.42:18822",
            "capability_tags": ["source_audit"],
        },
        headers=hdr,
    )
    assert patched.status_code == 200
    payload = patched.json()["data"]
    assert payload["endpoint"] == "http://10.0.0.42:18822"
    assert payload["capability_tags"] == ["source_audit"]

    # Ensure the SQLModel class import above is real (silences lint).
    assert McpServerInstance.__tablename__ == "mcp_server_instances"

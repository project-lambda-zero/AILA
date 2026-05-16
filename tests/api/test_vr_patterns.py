"""End-to-end tests for the pattern catalog endpoints.

Exercises POST/GET/PATCH + applicable retrieval against the real test DB.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _create_workspace(
    async_client: AsyncClient, admin_token: str, slug: str,
) -> str:
    resp = await async_client.post(
        "/vr/workspaces",
        headers=_auth(admin_token),
        json={
            "name": f"Test {slug}",
            "slug": slug,
            "theme": "browser_engines",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]["id"]


async def _create_pattern(
    async_client: AsyncClient,
    admin_token: str,
    *,
    workspace_id: str,
    kind: str = "exploitation_technique",
    summary: str = "Example pattern summary",
    body: str = "Full description with example code",
    applicability: dict | None = None,
) -> dict:
    payload = {
        "workspace_id": workspace_id,
        "kind": kind,
        "summary": summary,
        "body": body,
        "applicability": applicability or {},
        "confidence": "medium",
    }
    resp = await async_client.post(
        "/vr/patterns", headers=_auth(admin_token), json=payload,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]


@pytest.mark.asyncio
async def test_create_returns_draft_local_pattern(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id = await _create_workspace(async_client, admin_token, "ws-pat-1")
    data = await _create_pattern(
        async_client, admin_token,
        workspace_id=ws_id,
        summary="V8 type confusion via aliased descriptors",
        body="Pass aliased descriptors after warmup; triggers JIT type confusion.",
    )
    assert data["status"] == "draft"
    assert data["scope"] == "local"
    assert data["kind"] == "exploitation_technique"
    assert data["workspace_id"] == ws_id
    assert data["times_retrieved"] == 0
    assert data["knowledge_entry_id"] is not None  # mirror entry created


@pytest.mark.asyncio
async def test_get_and_list_patterns(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id = await _create_workspace(async_client, admin_token, "ws-pat-list")
    p1 = await _create_pattern(
        async_client, admin_token, workspace_id=ws_id,
        kind="fuzzing_strategy", summary="afl++ qemu mode for opaque binaries",
    )
    p2 = await _create_pattern(
        async_client, admin_token, workspace_id=ws_id,
        kind="search_heuristic", summary="grep InferMaps callsites for alias bugs",
    )

    # Get by id
    got = await async_client.get(
        f"/vr/patterns/{p1['id']}", headers=_auth(admin_token),
    )
    assert got.status_code == 200
    assert got.json()["data"]["id"] == p1["id"]

    # List all
    listing = await async_client.get(
        "/vr/patterns", headers=_auth(admin_token),
        params={"workspace_id": ws_id},
    )
    assert listing.status_code == 200
    rows = {r["id"] for r in listing.json()["data"]}
    assert p1["id"] in rows
    assert p2["id"] in rows

    # Filter by kind
    only_fuzz = await async_client.get(
        "/vr/patterns", headers=_auth(admin_token),
        params={"workspace_id": ws_id, "kind": "fuzzing_strategy"},
    )
    assert only_fuzz.status_code == 200
    kinds = {r["kind"] for r in only_fuzz.json()["data"]}
    assert kinds == {"fuzzing_strategy"}


@pytest.mark.asyncio
async def test_patch_promotes_status_then_scope(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id = await _create_workspace(async_client, admin_token, "ws-pat-patch")
    p = await _create_pattern(
        async_client, admin_token, workspace_id=ws_id,
        summary="Initial draft pattern", body="Initial body",
    )
    pid = p["id"]

    # Operator approves: draft → active, local → workspace
    approved = await async_client.patch(
        f"/vr/patterns/{pid}", headers=_auth(admin_token),
        json={"status": "active", "scope": "workspace"},
    )
    assert approved.status_code == 200, approved.text
    data = approved.json()["data"]
    assert data["status"] == "active"
    assert data["scope"] == "workspace"

    # Demotion forbidden
    demoted = await async_client.patch(
        f"/vr/patterns/{pid}", headers=_auth(admin_token),
        json={"scope": "local"},
    )
    assert demoted.status_code == 409, demoted.text
    assert "demotion forbidden" in demoted.json()["detail"]

    # Archive instead
    archived = await async_client.patch(
        f"/vr/patterns/{pid}", headers=_auth(admin_token),
        json={"status": "archived"},
    )
    assert archived.status_code == 200
    assert archived.json()["data"]["status"] == "archived"


@pytest.mark.asyncio
async def test_applicable_returns_matching_active_patterns(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id = await _create_workspace(async_client, admin_token, "ws-pat-app")

    # Two patterns: one matches target_kind=native_binary, one doesn't
    p_v8 = await _create_pattern(
        async_client, admin_token, workspace_id=ws_id,
        kind="exploitation_technique",
        summary="V8 InferMaps alias check missing",
        body="V8 JIT TurboFan misses alias check on map inference",
        applicability={
            "target_kinds": ["native_binary"],
            "languages": ["javascript"],
        },
    )
    p_kotlin = await _create_pattern(
        async_client, admin_token, workspace_id=ws_id,
        kind="exploitation_technique",
        summary="Kotlin DI exploit",
        body="Kotlin DI exploit body",
        applicability={
            "target_kinds": ["apk"],
            "languages": ["kotlin"],
        },
    )

    # Promote both to active + workspace scope
    for pid in (p_v8["id"], p_kotlin["id"]):
        promote = await async_client.patch(
            f"/vr/patterns/{pid}", headers=_auth(admin_token),
            json={"status": "active", "scope": "workspace"},
        )
        assert promote.status_code == 200, promote.text

    # Query for V8-style audit
    resp = await async_client.get(
        "/vr/patterns/applicable", headers=_auth(admin_token),
        params={
            "workspace_id": ws_id,
            "query": "V8 InferMaps alias check missing on aliased descriptors",
            "target_kind": "native_binary",
            "primary_language": "javascript",
            "k": 5,
        },
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()["data"]
    pids = {r["pattern"]["id"] for r in rows}
    assert p_v8["id"] in pids
    # Kotlin pattern's applicability excludes native_binary → filtered out
    assert p_kotlin["id"] not in pids

    # Usage counter incremented
    after = await async_client.get(
        f"/vr/patterns/{p_v8['id']}", headers=_auth(admin_token),
    )
    assert after.json()["data"]["times_retrieved"] >= 1


@pytest.mark.asyncio
async def test_404_on_unknown_pattern(
    async_client: AsyncClient, admin_token: str,
) -> None:
    for method, json_body in (
        ("GET", None),
        ("PATCH", {"summary": "x"}),
    ):
        kwargs: dict = {"headers": _auth(admin_token)}
        if json_body:
            kwargs["json"] = json_body
        resp = await async_client.request(
            method, "/vr/patterns/nonexistent", **kwargs,
        )
        assert resp.status_code == 404, f"{method} returned {resp.status_code}"

"""End-to-end tests for v0.4 multi-target investigation attachments."""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlmodel import select  # noqa: F401  (re-exported for downstream test reuse)

from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.uow import UnitOfWork


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _setup(
    async_client: AsyncClient, admin_token: str, slug: str,
) -> tuple[str, str, str]:
    """Workspace + target via API; investigation via direct DB insert
    (the POST /vr/investigations route needs the platform task queue
    which is unavailable in test fixtures)."""
    ws = await async_client.post(
        "/vr/workspaces", headers=_auth(admin_token),
        json={"name": f"MT {slug}", "slug": slug, "theme": "browser_engines"},
    )
    assert ws.status_code == 201, ws.text
    ws_id = ws.json()["data"]["id"]

    primary = await async_client.post(
        "/vr/targets", headers=_auth(admin_token),
        json={
            "workspace_id": ws_id,
            "display_name": "primary",
            "kind": "native_binary",
            "descriptor": {"binary_path": "/dev/null"},
            "primary_language": "c",
        },
    )
    assert primary.status_code == 201, primary.text
    primary_id = primary.json()["data"]["id"]

    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=primary_id,
            team_id="admin",
            kind=InvestigationKind.AUDIT.value,
            title=f"investigation for {slug}",
            initial_question="compare with sibling codebase",
            status=InvestigationStatus.CREATED.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.audit",
            cost_budget_usd=10.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        branch = VRInvestigationBranchRecord(
            investigation_id=inv.id,
            status="active",
            fork_reason="primary",
        )
        uow.session.add(branch)
        await uow.session.commit()
        await uow.session.refresh(inv)
        inv_id = inv.id

    return ws_id, primary_id, inv_id


async def _create_target(
    async_client: AsyncClient, admin_token: str, ws_id: str, name: str,
) -> str:
    resp = await async_client.post(
        "/vr/targets", headers=_auth(admin_token),
        json={
            "workspace_id": ws_id,
            "display_name": name,
            "kind": "source_repo",
            "descriptor": {"repo_url": f"https://example.com/{name}"},
            "primary_language": "c",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]["id"]


@pytest.mark.asyncio
async def test_attach_secondary_target(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id, _primary, inv_id = await _setup(async_client, admin_token, "mt-attach")
    secondary = await _create_target(async_client, admin_token, ws_id, "secondary")

    attach = await async_client.post(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
        json={
            "target_id": secondary,
            "role": "comparison",
            "rationale": "compare nginx vs apache chunked parsing",
        },
    )
    assert attach.status_code == 201, attach.text
    data = attach.json()["data"]
    assert data["target_id"] == secondary
    assert data["role"] == "comparison"
    assert "nginx vs apache" in data["rationale"]


@pytest.mark.asyncio
async def test_list_attached_targets(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id, _primary, inv_id = await _setup(async_client, admin_token, "mt-list")
    t1 = await _create_target(async_client, admin_token, ws_id, "t1")
    t2 = await _create_target(async_client, admin_token, ws_id, "t2")

    for tid, role in ((t1, "comparison"), (t2, "parallel_codebase")):
        resp = await async_client.post(
            f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
            json={"target_id": tid, "role": role},
        )
        assert resp.status_code == 201

    listing = await async_client.get(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
    )
    assert listing.status_code == 200
    rows = listing.json()["data"]
    assert len(rows) == 2
    by_target = {r["target_id"]: r for r in rows}
    assert by_target[t1]["role"] == "comparison"
    assert by_target[t2]["role"] == "parallel_codebase"


@pytest.mark.asyncio
async def test_detach_secondary_target(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id, _primary, inv_id = await _setup(async_client, admin_token, "mt-detach")
    secondary = await _create_target(async_client, admin_token, ws_id, "secondary-det")

    attach = await async_client.post(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
        json={"target_id": secondary, "role": "parent_library"},
    )
    assert attach.status_code == 201

    detach = await async_client.delete(
        f"/vr/investigations/{inv_id}/targets/{secondary}",
        headers=_auth(admin_token),
    )
    assert detach.status_code == 204

    listing = await async_client.get(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
    )
    assert listing.status_code == 200
    assert listing.json()["data"] == []


@pytest.mark.asyncio
async def test_cannot_attach_primary_as_secondary(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id, primary, inv_id = await _setup(async_client, admin_token, "mt-primary")
    resp = await async_client.post(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
        json={"target_id": primary, "role": "comparison"},
    )
    assert resp.status_code == 409
    assert "primary target" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_cannot_attach_with_primary_role(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id, _primary, inv_id = await _setup(
        async_client, admin_token, "mt-primary-role",
    )
    secondary = await _create_target(async_client, admin_token, ws_id, "x")
    resp = await async_client.post(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
        json={"target_id": secondary, "role": "primary"},
    )
    assert resp.status_code == 409
    assert "PRIMARY role is reserved" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_cannot_detach_primary(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id, primary, inv_id = await _setup(
        async_client, admin_token, "mt-detach-primary",
    )
    resp = await async_client.delete(
        f"/vr/investigations/{inv_id}/targets/{primary}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 409
    assert "primary target" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_attach_idempotent_updates_role(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id, _primary, inv_id = await _setup(
        async_client, admin_token, "mt-idem",
    )
    secondary = await _create_target(async_client, admin_token, ws_id, "y")

    # First attach as comparison
    r1 = await async_client.post(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
        json={"target_id": secondary, "role": "comparison", "rationale": "first"},
    )
    assert r1.status_code == 201
    id1 = r1.json()["data"]["id"]

    # Re-attach with different role — should update, not duplicate
    r2 = await async_client.post(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
        json={"target_id": secondary, "role": "derived_fork", "rationale": "second"},
    )
    assert r2.status_code == 201
    assert r2.json()["data"]["id"] == id1
    assert r2.json()["data"]["role"] == "derived_fork"
    assert r2.json()["data"]["rationale"] == "second"

    # Only one row in listing
    listing = await async_client.get(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
    )
    assert len(listing.json()["data"]) == 1


@pytest.mark.asyncio
async def test_404_on_unknown_investigation(
    async_client: AsyncClient, admin_token: str,
) -> None:
    resp = await async_client.post(
        "/vr/investigations/nonexistent/targets", headers=_auth(admin_token),
        json={"target_id": "bogus", "role": "comparison"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_404_on_unknown_target(
    async_client: AsyncClient, admin_token: str,
) -> None:
    _ws, _primary, inv_id = await _setup(
        async_client, admin_token, "mt-unkn-tgt",
    )
    resp = await async_client.post(
        f"/vr/investigations/{inv_id}/targets", headers=_auth(admin_token),
        json={"target_id": "bogus", "role": "comparison"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_detach_not_attached_returns_404(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ws_id, _primary, inv_id = await _setup(
        async_client, admin_token, "mt-detach-404",
    )
    other = await _create_target(async_client, admin_token, ws_id, "never-attached")
    resp = await async_client.delete(
        f"/vr/investigations/{inv_id}/targets/{other}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404
    assert "not attached" in resp.json()["detail"]

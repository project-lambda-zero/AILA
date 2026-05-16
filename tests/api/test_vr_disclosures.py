"""End-to-end tests for the disclosure submission endpoints.

Exercises the full operator flow: list tracks → create submission for a
finding → render → patch state → re-render → 404 handling.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.modules.vr.contracts.finding import CrashType, DisclosureStatus
from aila.modules.vr.db_models import (
    VRFindingRecord,
    VRProjectRecord,
)
from aila.platform.uow import UnitOfWork


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _setup_workspace_target_project_finding(
    async_client: AsyncClient, admin_token: str, slug: str,
) -> tuple[str, str]:
    """Create workspace + target + project + finding; return (workspace_id, finding_id)."""
    ws = await async_client.post(
        "/vr/workspaces", headers=_auth(admin_token),
        json={"name": f"D {slug}", "slug": slug, "theme": "browser_engines"},
    )
    assert ws.status_code == 201, ws.text
    workspace_id = ws.json()["data"]["id"]

    target = await async_client.post(
        "/vr/targets", headers=_auth(admin_token),
        json={
            "workspace_id": workspace_id,
            "display_name": "d8",
            "kind": "native_binary",
            "descriptor": {"binary_path": "/dev/null"},
            "primary_language": "c++",
        },
    )
    assert target.status_code == 201, target.text
    target_id = target.json()["data"]["id"]

    # Insert a finding directly via the storage layer because the public
    # API doesn't yet have a finding-create endpoint independent of
    # outcome dispatch.
    async with UnitOfWork() as uow:
        existing_project = (await uow.session.exec(
            select(VRProjectRecord).where(VRProjectRecord.target_id == target_id),
        )).first()
        if existing_project is None:
            project = VRProjectRecord(
                target_id=target_id,
                team_id="admin",
                name="DisclosureTestProject",
                status="active",
            )
            uow.session.add(project)
            await uow.session.commit()
            await uow.session.refresh(project)
        else:
            project = existing_project
        finding = VRFindingRecord(
            project_id=project.id,
            target_id=target_id,
            team_id="admin",
            crash_type=CrashType.OVERFLOW_HEAP.value,
            crash_signature="JIT-OOB-001",
            root_cause="Missing alias check on InferMaps",
            vulnerable_function="JSCallReducer::ReduceJSCall",
            disclosure_status=DisclosureStatus.UNDISCLOSED.value,
        )
        uow.session.add(finding)
        await uow.session.commit()
        await uow.session.refresh(finding)
        finding_id = finding.id

    return workspace_id, finding_id


@pytest.mark.asyncio
async def test_list_tracks_returns_all_eleven_builtins(
    async_client: AsyncClient, admin_token: str,
) -> None:
    resp = await async_client.get(
        "/vr/disclosure-tracks", headers=_auth(admin_token),
    )
    assert resp.status_code == 200
    rows = resp.json()["data"]
    track_ids = {r["track_id"] for r in rows}
    assert track_ids == {
        "chrome_vrp", "blog_post", "vendor_direct", "cna_github_gsa",
        "msrc", "mozilla_bb", "apple_security", "github_bb",
        "zdi", "cert_cc", "conference_cfp",
    }
    # Spot-check shape
    chrome = next(r for r in rows if r["track_id"] == "chrome_vrp")
    assert chrome["kind"] == "bounty"
    assert chrome["embargo_default_days"] == 90
    assert "working_poc" in chrome["accepted_poc_tiers"]


@pytest.mark.asyncio
async def test_create_disclosure_drafts_with_rendered_body(
    async_client: AsyncClient, admin_token: str,
) -> None:
    workspace_id, finding_id = await _setup_workspace_target_project_finding(
        async_client, admin_token, "d-create",
    )
    resp = await async_client.post(
        "/vr/disclosures", headers=_auth(admin_token),
        json={
            "finding_id": finding_id,
            "track_id": "chrome_vrp",
            "workspace_id": workspace_id,
            "poc_tier": "working_poc",
            "severity_rating": "high",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()["data"]
    assert data["status"] == "drafted"
    assert data["track_id"] == "chrome_vrp"
    assert data["kind"] == "bounty"
    assert data["poc_tier"] == "working_poc"
    assert data["embargo_days_used"] == 90
    assert data["embargo_until"] is not None
    # track_info embedded
    assert data["track_info"]["display_name"] == "Chrome Vulnerability Reward Program"


@pytest.mark.asyncio
async def test_render_returns_markdown_body_and_validation(
    async_client: AsyncClient, admin_token: str,
) -> None:
    workspace_id, finding_id = await _setup_workspace_target_project_finding(
        async_client, admin_token, "d-render",
    )
    create_resp = await async_client.post(
        "/vr/disclosures", headers=_auth(admin_token),
        json={
            "finding_id": finding_id,
            "track_id": "blog_post",
            "workspace_id": workspace_id,
            "poc_tier": "sanitized_poc",
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    submission_id = create_resp.json()["data"]["id"]

    render_resp = await async_client.post(
        f"/vr/disclosures/{submission_id}/render",
        headers=_auth(admin_token),
    )
    assert render_resp.status_code == 200, render_resp.text
    payload = render_resp.json()["data"]
    assert payload["body_format"] == "markdown"
    assert "Background" in payload["body"]
    assert "JSCallReducer::ReduceJSCall" in payload["body"]
    # blog_post requires title + summary — finding has neither directly,
    # so validation_errors will list them.
    assert isinstance(payload["validation_errors"], list)


@pytest.mark.asyncio
async def test_patch_advances_state_and_records_vendor_reference(
    async_client: AsyncClient, admin_token: str,
) -> None:
    workspace_id, finding_id = await _setup_workspace_target_project_finding(
        async_client, admin_token, "d-patch",
    )
    create_resp = await async_client.post(
        "/vr/disclosures", headers=_auth(admin_token),
        json={
            "finding_id": finding_id,
            "track_id": "vendor_direct",
            "workspace_id": workspace_id,
            "poc_tier": "no_poc",
        },
    )
    sid = create_resp.json()["data"]["id"]

    # drafted → submitted → acknowledged (with vendor ref)
    r1 = await async_client.patch(
        f"/vr/disclosures/{sid}", headers=_auth(admin_token),
        json={"status": "submitted"},
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["data"]["status"] == "submitted"

    r2 = await async_client.patch(
        f"/vr/disclosures/{sid}", headers=_auth(admin_token),
        json={"status": "acknowledged", "vendor_reference": "VENDOR-2026-001"},
    )
    assert r2.status_code == 200
    data = r2.json()["data"]
    assert data["status"] == "acknowledged"
    assert data["vendor_reference"] == "VENDOR-2026-001"


@pytest.mark.asyncio
async def test_terminal_state_blocks_further_transitions(
    async_client: AsyncClient, admin_token: str,
) -> None:
    workspace_id, finding_id = await _setup_workspace_target_project_finding(
        async_client, admin_token, "d-terminal",
    )
    create_resp = await async_client.post(
        "/vr/disclosures", headers=_auth(admin_token),
        json={
            "finding_id": finding_id,
            "track_id": "cna_github_gsa",
            "workspace_id": workspace_id,
            "poc_tier": "no_poc",
        },
    )
    sid = create_resp.json()["data"]["id"]

    closed = await async_client.patch(
        f"/vr/disclosures/{sid}", headers=_auth(admin_token),
        json={"status": "closed"},
    )
    assert closed.status_code == 200

    # Attempting to leave closed → 409
    reopen = await async_client.patch(
        f"/vr/disclosures/{sid}", headers=_auth(admin_token),
        json={"status": "submitted"},
    )
    assert reopen.status_code == 409
    assert "terminal" in reopen.json()["detail"]


@pytest.mark.asyncio
async def test_list_disclosures_filtered_by_finding(
    async_client: AsyncClient, admin_token: str,
) -> None:
    workspace_id, finding_id = await _setup_workspace_target_project_finding(
        async_client, admin_token, "d-list",
    )

    # Create 3 submissions on the same finding via different tracks
    for track in ("chrome_vrp", "blog_post", "vendor_direct"):
        body = {
            "finding_id": finding_id,
            "track_id": track,
            "workspace_id": workspace_id,
            "poc_tier": "working_poc" if track == "chrome_vrp"
                       else "sanitized_poc" if track == "blog_post"
                       else "no_poc",
        }
        resp = await async_client.post(
            "/vr/disclosures", headers=_auth(admin_token), json=body,
        )
        assert resp.status_code == 201, resp.text

    listing = await async_client.get(
        "/vr/disclosures", headers=_auth(admin_token),
        params={"finding_id": finding_id},
    )
    assert listing.status_code == 200
    rows = listing.json()["data"]
    assert len(rows) >= 3
    assert all(r["finding_id"] == finding_id for r in rows)


@pytest.mark.asyncio
async def test_create_with_unknown_track_returns_404(
    async_client: AsyncClient, admin_token: str,
) -> None:
    workspace_id, finding_id = await _setup_workspace_target_project_finding(
        async_client, admin_token, "d-unkn",
    )
    resp = await async_client.post(
        "/vr/disclosures", headers=_auth(admin_token),
        json={
            "finding_id": finding_id,
            "track_id": "does_not_exist",
            "workspace_id": workspace_id,
            "poc_tier": "no_poc",
        },
    )
    assert resp.status_code == 404
    assert "unknown track" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_404_on_unknown_disclosure(
    async_client: AsyncClient, admin_token: str,
) -> None:
    for method, json_body in (
        ("GET", None),
        ("PATCH", {"status": "submitted"}),
        ("POST", None),  # render endpoint
    ):
        path = "/vr/disclosures/nonexistent"
        if method == "POST":
            path += "/render"
        kwargs: dict = {"headers": _auth(admin_token)}
        if json_body:
            kwargs["json"] = json_body
        resp = await async_client.request(method, path, **kwargs)
        assert resp.status_code == 404, f"{method} returned {resp.status_code}"

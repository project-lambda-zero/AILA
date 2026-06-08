"""D-1 — ``POST /vr/targets/{target_id}/masvs-audit`` materializes records.

Smoke coverage for the batch dispatcher endpoint added by D-1. The test
asserts the invariants the downstream tasks D-2 / D-3 / R-1 rely on:

1. **Parent invariant** — exactly one ``VRInvestigationRecord`` with
   ``kind=masvs_audit`` is created per call. ``parent_investigation_id``
   on the parent is ``None`` (it is the batch root); the parent's
   ``secondary_target_refs_json`` records the catalog spec version so
   D-3 idempotency can compare same-target / same-version dispatches
   without re-reading the catalog.

2. **Children invariants** — one ``VRInvestigationRecord`` per L1
   control. Every child carries ``kind=audit`` (the existing kind so
   the standard vuln_researcher dispatch handles it unchanged),
   ``parent_investigation_id`` pointing at the parent, the catalog's
   ``control.id`` on ``secondary_target_refs_json``, an
   ``initial_question`` produced by :class:`MasvsSeedBuilder` (verified
   by spot-checking that the control id appears verbatim in the
   question body), and one ``ACTIVE`` primary branch row.

3. **Response invariants** — the JSON envelope carries the parent id,
   one child id per L1 control in catalog order, the catalog version,
   and the summed child budget. No ARQ submission happens in D-1 —
   that lands in D-2 — so child rows sit in ``CREATED`` status.

4. **Refusal invariants** — non-android_apk targets and android_apk
   targets without a populated ``static_summary`` are rejected with
   409 (not 500, not a silent half-dispatch).
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.masvs import (
    CATALOG_VERSION,
    MASVS_CONTROLS,
    MasvsLevel,
)
from aila.platform.uow import UnitOfWork


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


_APK_STATIC_SUMMARY: dict[str, Any] = {
    "package": "com.vodafone.selfservis",
    "version_name": "19.4.0",
    "version_code": "19400",
    "permissions": ["android.permission.INTERNET"],
    "native_libs": {"arm64-v8a": ["libfoo.so"]},
    "exported_components": [],
    "certificates": [],
}

_APK_HANDLES: dict[str, Any] = {
    "android_mcp_apk_sha256": "9228be90bf0bc3c4248431d2f2acb96e222a5b85",
    "android_mcp_decoded_dir": "/tmp/decoded",  # noqa: S108  (test fixture path)
    "android_mcp_decompiled_dir": "/tmp/jadx",  # noqa: S108
    "android_mcp_jadx_class_count": 1234,
    "audit_mcp_decompiled_index_id": "vodafone_selfservis@9228be90",
    "android_mcp_static_summary": _APK_STATIC_SUMMARY,
}


async def _insert_android_apk_target(
    *, slug: str, with_static_summary: bool, kind: str = "android_apk",
) -> str:
    """Insert a workspace + target row pair directly via UnitOfWork.

    The MASVS dispatcher cares about ``kind``, ``team_id``, and
    ``mcp_handles_json`` only — no need to spin up the full
    POST /vr/workspaces + POST /vr/targets dance, and bypassing the
    ingestion machinery keeps this an endpoint test, not an integration
    test of the C-19 upload pipeline.
    """
    handles = dict(_APK_HANDLES)
    if not with_static_summary:
        handles.pop("android_mcp_static_summary", None)

    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"MASVS dispatch {slug}",
            slug=f"masvs-dispatch-{slug}",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name=f"Vodafone Yanımda {slug}",
            kind=kind,
            descriptor_json=json.dumps({"apk_path": "/tmp/example.apk"}),  # noqa: S108
            primary_language=None,
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json=json.dumps(handles),
            status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


def _l1_control_ids() -> tuple[str, ...]:
    return tuple(c.id for c in MASVS_CONTROLS if c.level == MasvsLevel.L1)


@pytest.mark.asyncio
async def test_dispatch_creates_parent_and_one_child_per_l1_control(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """End-to-end happy path: every L1 control gets one child investigation."""
    del test_db
    target_id = await _insert_android_apk_target(
        slug="happy", with_static_summary=True,
    )

    resp = await async_client.post(
        f"/vr/targets/{target_id}/masvs-audit",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 201, resp.text
    payload = resp.json()["data"]

    expected_ids = _l1_control_ids()
    assert payload["total_controls"] == len(expected_ids)
    assert len(payload["child_investigation_ids"]) == len(expected_ids)
    assert payload["masvs_spec_version"] == CATALOG_VERSION
    assert payload["cost_budget_total_usd"] == pytest.approx(50.0 * len(expected_ids))

    parent_id = payload["parent_investigation_id"]
    child_ids = payload["child_investigation_ids"]

    async with UnitOfWork() as uow:
        parent = (await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id == parent_id),
        )).one()
        assert parent.kind == InvestigationKind.MASVS_AUDIT.value
        assert parent.parent_investigation_id is None
        assert parent.target_id == target_id
        assert parent.status == InvestigationStatus.CREATED.value
        assert parent.auto_pilot is False
        assert parent.strategy_family == "vulnerability_research.masvs_audit"
        assert parent.cost_budget_usd == pytest.approx(50.0 * len(expected_ids))
        assert parent.title.startswith("MASVS audit: com.vodafone.selfservis")
        parent_refs = json.loads(parent.secondary_target_refs_json)
        assert parent_refs == [{"masvs_spec_version": CATALOG_VERSION}]

        children = (await uow.session.exec(
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.parent_investigation_id == parent_id),
        )).all()
        assert len(children) == len(expected_ids)
        children_by_id = {c.id: c for c in children}
        assert set(children_by_id) == set(child_ids)

        seen_control_ids: set[str] = set()
        for cid, control_id in zip(child_ids, expected_ids, strict=True):
            child = children_by_id[cid]
            assert child.kind == InvestigationKind.AUDIT.value, (
                f"Child {cid} (control {control_id}) has wrong kind: "
                f"{child.kind!r}; D-1 mandates kind=audit on every child."
            )
            assert child.parent_investigation_id == parent_id
            assert child.target_id == target_id
            assert child.status == InvestigationStatus.CREATED.value
            assert child.auto_pilot is True
            assert child.strategy_family == "vulnerability_research.audit"
            assert child.cost_budget_usd == pytest.approx(50.0)

            refs = json.loads(child.secondary_target_refs_json)
            assert len(refs) == 1
            assert refs[0]["masvs_control_id"] == control_id
            assert refs[0]["masvs_spec_version"] == CATALOG_VERSION
            seen_control_ids.add(refs[0]["masvs_control_id"])

            assert control_id in child.initial_question, (
                f"Child question for {control_id} did not embed the control "
                "id verbatim; MasvsSeedBuilder regressed."
            )
            assert control_id in child.title

            primary_branch = (await uow.session.exec(
                select(VRInvestigationBranchRecord)
                .where(VRInvestigationBranchRecord.investigation_id == cid),
            )).one()
            assert primary_branch.status == "active"
            assert primary_branch.fork_reason == "primary"

        assert seen_control_ids == set(expected_ids)


@pytest.mark.asyncio
async def test_dispatch_refuses_non_android_apk_target(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Refuse a target whose kind is not ``android_apk`` (409, not 500)."""
    del test_db
    target_id = await _insert_android_apk_target(
        slug="native", with_static_summary=True, kind=TargetKind.NATIVE_BINARY.value,
    )

    resp = await async_client.post(
        f"/vr/targets/{target_id}/masvs-audit",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 409, resp.text
    assert "android_apk" in resp.text


@pytest.mark.asyncio
async def test_dispatch_refuses_when_static_summary_missing(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Refuse when STATIC_SUMMARY has not populated ``mcp_handles_json``."""
    del test_db
    target_id = await _insert_android_apk_target(
        slug="no-static", with_static_summary=False,
    )

    resp = await async_client.post(
        f"/vr/targets/{target_id}/masvs-audit",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 409, resp.text
    assert "STATIC_SUMMARY" in resp.text


@pytest.mark.asyncio
async def test_dispatch_returns_404_for_unknown_target(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Unknown target id surfaces as 404, not 500 or a silent dispatch."""
    del test_db

    resp = await async_client.post(
        "/vr/targets/does-not-exist/masvs-audit",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404, resp.text

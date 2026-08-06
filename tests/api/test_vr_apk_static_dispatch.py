"""``POST /vr/targets/{target_id}/apk-static-audit`` materializes records.

Mirrors the MASVS dispatch smoke: asserts the parent + per-check children
invariants, the idempotency branch, and the refusal branches. The
endpoint clones the MASVS dispatcher's structure, so these tests focus on
what differs -- parent ``kind=apk_static_audit``, one child per STATIC
catalog check, and the ``apk_static_check_id`` / ``apk_static_spec_version``
refs.

``async_client`` sets ``app.state.platform = None`` (see
``tests/api/conftest.py``), so the ARQ submission fails for every child
with a 503; records still commit and each child id surfaces in
``enqueue_errors``. That is the same baseline the MASVS dispatch test
relies on.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.modules.vr.apk_static import (
    APK_STATIC_CATALOG_VERSION,
    APK_STATIC_CHECKS,
    ApkStaticMode,
)
from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.uow import UnitOfWork

_CHILD_BUDGET = 30.0


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


_APK_STATIC_SUMMARY: dict[str, Any] = {
    "package": "com.example.sampleapp",
    "version_name": "3.2.1",
    "version_code": "3210",
    "permissions": ["android.permission.INTERNET"],
    "native_libs": {"arm64-v8a": ["libfoo.so"]},
    "exported_components": [],
    "certificates": [],
}

_APK_HANDLES: dict[str, Any] = {
    "android_mcp_apk_sha256": "9228be90bf0bc3c4248431d2f2acb96e222a5b85",
    "android_mcp_decoded_dir": "/tmp/decoded",  # noqa: S108
    "android_mcp_decompiled_dir": "/tmp/jadx",  # noqa: S108
    "android_mcp_jadx_class_count": 1234,
    "audit_mcp_decompiled_index_id": "sampleapp@9228be90",
    "android_mcp_static_summary": _APK_STATIC_SUMMARY,
}


async def _insert_android_apk_target(
    *, slug: str, with_static_summary: bool, kind: str = "android_apk",
) -> str:
    handles = dict(_APK_HANDLES)
    if not with_static_summary:
        handles.pop("android_mcp_static_summary", None)

    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"APK static dispatch {slug}",
            slug=f"apk-static-dispatch-{slug}",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name=f"SampleApp {slug}",
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


def _static_check_ids() -> tuple[str, ...]:
    return tuple(
        c.id for c in APK_STATIC_CHECKS if c.mode == ApkStaticMode.STATIC
    )


@pytest.mark.asyncio
async def test_dispatch_creates_parent_and_one_child_per_static_check(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Happy path: every STATIC check gets exactly one child investigation."""
    del test_db
    target_id = await _insert_android_apk_target(
        slug="happy", with_static_summary=True,
    )

    resp = await async_client.post(
        f"/vr/targets/{target_id}/apk-static-audit",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 201, resp.text
    payload = resp.json()["data"]

    expected_ids = _static_check_ids()
    assert payload["total_checks"] == len(expected_ids)
    assert len(payload["child_investigation_ids"]) == len(expected_ids)
    assert payload["apk_static_spec_version"] == APK_STATIC_CATALOG_VERSION
    assert payload["cost_budget_total_usd"] == pytest.approx(
        _CHILD_BUDGET * len(expected_ids),
    )
    assert payload["idempotent_reuse"] is False

    # platform=None -> get_task_queue raises -> every child in errors.
    enqueue_errors = payload["enqueue_errors"]
    assert set(enqueue_errors) == set(payload["child_investigation_ids"])

    parent_id = payload["parent_investigation_id"]
    child_ids = payload["child_investigation_ids"]

    async with UnitOfWork() as uow:
        parent = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == parent_id,
            ),
        )).one()
        assert parent.kind == InvestigationKind.APK_STATIC_AUDIT.value
        assert parent.parent_investigation_id is None
        assert parent.status == InvestigationStatus.CREATED.value
        assert parent.strategy_family == (
            "vulnerability_research.apk_static_audit"
        )
        parent_refs = json.loads(parent.secondary_target_refs_json)
        assert parent_refs == [
            {"apk_static_spec_version": APK_STATIC_CATALOG_VERSION},
        ]

        children = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.parent_investigation_id == parent_id,
            ),
        )).all()
        assert len(children) == len(expected_ids)
        children_by_id = {c.id: c for c in children}

        seen_ids: set[str] = set()
        for cid, check_id in zip(child_ids, expected_ids, strict=True):
            child = children_by_id[cid]
            assert child.kind == InvestigationKind.AUDIT.value
            assert child.parent_investigation_id == parent_id
            assert child.cost_budget_usd == pytest.approx(_CHILD_BUDGET)
            refs = json.loads(child.secondary_target_refs_json)
            assert refs[0]["apk_static_check_id"] == check_id
            assert refs[0]["apk_static_spec_version"] == (
                APK_STATIC_CATALOG_VERSION
            )
            assert check_id in child.initial_question, (
                f"child for {check_id} did not embed the check id verbatim"
            )
            seen_ids.add(refs[0]["apk_static_check_id"])
        assert seen_ids == set(expected_ids)


@pytest.mark.asyncio
async def test_dispatch_is_idempotent_on_same_catalog_version(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """A second dispatch on the same target + version reuses the parent."""
    del test_db
    target_id = await _insert_android_apk_target(
        slug="idem", with_static_summary=True,
    )
    first = await async_client.post(
        f"/vr/targets/{target_id}/apk-static-audit",
        headers=_auth(admin_token),
    )
    assert first.status_code == 201, first.text
    first_parent = first.json()["data"]["parent_investigation_id"]

    second = await async_client.post(
        f"/vr/targets/{target_id}/apk-static-audit",
        headers=_auth(admin_token),
    )
    assert second.status_code == 200, second.text
    second_data = second.json()["data"]
    assert second_data["idempotent_reuse"] is True
    assert second_data["parent_investigation_id"] == first_parent
    assert second_data["enqueue_errors"] == {}


@pytest.mark.asyncio
async def test_dispatch_refuses_non_android_apk_target(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    del test_db
    target_id = await _insert_android_apk_target(
        slug="wrongkind", with_static_summary=True, kind="source_repo",
    )
    resp = await async_client.post(
        f"/vr/targets/{target_id}/apk-static-audit",
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
    del test_db
    target_id = await _insert_android_apk_target(
        slug="nostatic", with_static_summary=False,
    )
    resp = await async_client.post(
        f"/vr/targets/{target_id}/apk-static-audit",
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
    del test_db
    resp = await async_client.post(
        "/vr/targets/does-not-exist/apk-static-audit",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404, resp.text

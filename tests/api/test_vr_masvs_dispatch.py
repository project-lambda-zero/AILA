"""D-1 + D-2 — ``POST /vr/targets/{target_id}/masvs-audit`` materializes
records and submits each child to the ``vr`` ARQ queue.

Smoke coverage for the batch dispatcher endpoint that D-1 stood up and
D-2 wired to ``run_vr_investigate``. The test asserts the invariants
the downstream tasks D-3 / R-1 rely on:

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
   the summed child budget, and ``enqueue_errors`` (D-2). Child rows
   stay in ``CREATED`` status until the worker picks the task up.

4. **D-2 success path** — when the task queue is reachable, every
   child id lands in the ``vr`` queue via ``run_vr_investigate`` with
   ``kwargs={"investigation_id": <child_id>}`` and ``enqueue_errors``
   is empty.

5. **D-2 failure path** — when the task queue is unavailable (the
   ``app.state.platform = None`` baseline the test fixture sets),
   every child id surfaces in ``enqueue_errors`` with the
   service-unavailable detail. The records are still committed so the
   operator can retry via ``POST /vr/investigations/{id}/re-enqueue``.

6. **Refusal invariants** — non-android_apk targets and android_apk
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
    "package": "com.examplecorp.selfservis",
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
    "audit_mcp_decompiled_index_id": "examplecorp_selfservis@9228be90",
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
            display_name=f"ExampleCorp SampleApp {slug}",
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
    # async_client sets app.state.platform = None (see tests/api/conftest.py)
    # which makes the D-2 ARQ submission step fail with 503 for every
    # child. Records still commit, errors surface in the response, and
    # the operator can /re-enqueue any child. The D-2 success path is
    # exercised by test_dispatch_submits_each_child_to_vr_queue below.
    enqueue_errors = payload["enqueue_errors"]
    assert isinstance(enqueue_errors, dict)
    assert set(enqueue_errors) == set(payload["child_investigation_ids"]), (
        "D-2 should record one enqueue_errors entry per failed child; "
        "found a mismatch between child_investigation_ids and the "
        "enqueue_errors keyset."
    )
    for cid, err in enqueue_errors.items():
        assert "task queue unavailable" in err, (
            f"Child {cid}: expected the 503 platform-unavailable "
            f"message, got {err!r}. If get_task_queue's failure "
            "wording changed, update this assertion together with the "
            "endpoint's error string."
        )

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
        assert parent.title.startswith("MASVS audit: com.examplecorp.selfservis")
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
async def test_dispatch_submits_each_child_to_vr_queue(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D-2 success path: every child id is submitted to the ``vr`` queue.

    Monkey-patches :func:`aila.api.deps.get_task_queue` to return an
    :class:`AsyncMock` so the endpoint runs the full submit loop without
    needing a live platform. Asserts:

    1. ``enqueue_errors`` is empty (no submit failed).
    2. ``task_queue.submit`` was awaited exactly once per L1 control.
    3. Every submit call carries ``track="vr"``, ``fn=run_vr_investigate``,
       and ``kwargs={"investigation_id": <one of the child ids>}``.
    4. The set of investigation ids the dispatcher submitted equals
       the set returned in the response — no child is silently dropped.
    """
    del test_db

    import aila.api.deps as deps_module
    from aila.modules.vr.workflow.task import run_vr_investigate

    submit_calls: list[dict[str, Any]] = []

    class _StubQueue:
        async def submit(self, **kwargs: Any) -> None:
            submit_calls.append(kwargs)

    stub_queue = _StubQueue()

    def _stub_get_task_queue(module_id: str, request: Any) -> Any:
        del request
        assert module_id == "vr", (
            f"MASVS dispatcher should request the 'vr' queue, "
            f"got {module_id!r}"
        )
        return stub_queue

    monkeypatch.setattr(deps_module, "get_task_queue", _stub_get_task_queue)

    target_id = await _insert_android_apk_target(
        slug="d2-submits", with_static_summary=True,
    )
    resp = await async_client.post(
        f"/vr/targets/{target_id}/masvs-audit",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 201, resp.text
    payload = resp.json()["data"]

    child_ids = payload["child_investigation_ids"]
    assert payload["enqueue_errors"] == {}, (
        f"D-2 should report zero submit failures when the queue is "
        f"reachable; got {payload['enqueue_errors']!r}"
    )

    assert len(submit_calls) == len(child_ids), (
        f"D-2 should submit one ARQ task per L1 control "
        f"({len(child_ids)} expected); saw {len(submit_calls)} submit "
        f"calls"
    )

    submitted_inv_ids: list[str] = []
    for call in submit_calls:
        assert call["track"] == "vr"
        assert call["fn"] is run_vr_investigate, (
            f"D-2 must submit run_vr_investigate (same code path as a "
            f"one-off /vr/investigations dispatch); saw {call['fn']!r}"
        )
        assert set(call["kwargs"]) == {"investigation_id"}, (
            f"D-2 kwargs must be {{'investigation_id': <id>}} only; "
            f"saw {call['kwargs']!r}"
        )
        submitted_inv_ids.append(call["kwargs"]["investigation_id"])

    assert set(submitted_inv_ids) == set(child_ids), (
        "Set of investigation ids submitted to the queue diverged from "
        "the response's child_investigation_ids — D-2 dropped or "
        "duplicated a child."
    )


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

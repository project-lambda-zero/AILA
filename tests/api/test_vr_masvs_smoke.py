"""A-1 — End-to-end smoke test for the MASVS audit dispatcher.

Phase 6 acceptance gate from ``.run/ralph/apk-masvs/IMPLEMENTATION_PLAN.md``
task A-1. A single happy-path test that proves the operator's
headline flow works: a populated ``android_apk`` target dispatches
into one parent investigation plus one child investigation per L1
control, with the catalog version pinned on the parent and every
child running the existing ``audit`` kind so the standard
vuln_researcher dispatch handles them unchanged.

The four A-1 invariants enforced here:

1. **Per-control fanout** — exactly one child investigation per L1
   control entry in :data:`MASVS_CONTROLS`. The PRD's headline
   guarantee ("one independent VR investigation per OWASP MASVS L1
   control") collapses if this count is off by even one entry.
2. **Catalog version pinned on the parent** — the parent's
   ``secondary_target_refs_json`` carries
   ``[{"masvs_spec_version": CATALOG_VERSION}]``. R-2's PDF report
   and D-3's idempotency handshake both read this back; missing it
   would invalidate both surfaces.
3. **Children keep the existing ``audit`` kind** — every child
   carries ``kind=audit`` so the standard vuln_researcher dispatch
   routes them unchanged. The new ``masvs_audit`` kind is a
   parent-only batch tag; if it leaked onto a child, the standard
   dispatch would drop it.
4. **Dispatch response envelope is complete** —
   ``parent_investigation_id``, ``masvs_spec_version``, and
   ``total_controls`` all populate so the frontend can render the
   new parent row from the dispatch response alone, without a
   follow-up fetch.

Scoping note: this is the acceptance smoke test, NOT the dispatcher
unit test. Per-branch coverage (idempotency, refusal cases,
queue-submit semantics, primary branch row creation, per-child
budget plumbing) lives in ``tests/api/test_vr_masvs_dispatch.py``.
Duplicating one or two assertions across the two files is
intentional — the smoke test is the headline checkbox that proves
the feature works end to end; the unit test catches per-branch
regressions.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
)
from aila.modules.vr.db_models import (
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


# Hand-crafted ``apk_overview`` snapshot — mirrors the post-STATIC_SUMMARY
# shape the dispatcher reads. Package + version match the operator's
# ExampleCorp SampleApp fixture so the parent investigation title surfaces a
# realistic identifier in the response envelope.
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


async def _insert_android_apk_target() -> str:
    """Insert a workspace + ``android_apk`` target row pair via UnitOfWork.

    Bypasses the full POST /vr/workspaces + POST /vr/targets dance —
    the dispatcher cares about ``kind``, ``team_id``, and
    ``mcp_handles_json`` only, and the C-19 ingestion pipeline is out
    of scope for this acceptance smoke test.
    """
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="MASVS smoke A-1",
            slug="masvs-smoke-a1",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name="ExampleCorp SampleApp smoke",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/example.apk"}),  # noqa: S108
            primary_language=None,
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json=json.dumps(_APK_HANDLES),
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
async def test_a1_smoke_masvs_audit_fans_one_child_per_l1_control(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """A-1 acceptance smoke test — happy path of the MASVS dispatcher.

    Sets up one ``android_apk`` target with a hand-crafted
    ``apk_overview``, fires ``POST /vr/targets/{id}/masvs-audit``,
    and asserts the four A-1 invariants verbatim:

    1. Response envelope returns ``total_controls`` and
       ``child_investigation_ids`` matching the L1 catalog floor.
    2. Parent record (``kind=masvs_audit``) has the catalog version
       pinned on ``secondary_target_refs_json``.
    3. Every child record sits under the parent with the existing
       ``audit`` kind — never the new ``masvs_audit`` tag, which is
       parent-only.
    4. Every L1 control id appears exactly once across the child
       set (no duplicates, no omissions).
    """
    del test_db  # fixture side effect only; consumed via dependency

    target_id = await _insert_android_apk_target()
    expected_control_ids = _l1_control_ids()
    expected_total = len(expected_control_ids)

    resp = await async_client.post(
        f"/vr/targets/{target_id}/masvs-audit",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 201, resp.text
    payload = resp.json()["data"]

    # --- Invariant 4 — response envelope shape ---
    parent_id: str = payload["parent_investigation_id"]
    child_ids: list[str] = payload["child_investigation_ids"]
    assert parent_id, "A-1: dispatcher returned an empty parent_investigation_id."
    assert payload["masvs_spec_version"] == CATALOG_VERSION, (
        "A-1: dispatch response must carry the current "
        f"CATALOG_VERSION={CATALOG_VERSION!r}; got "
        f"{payload['masvs_spec_version']!r}."
    )
    assert payload["total_controls"] == expected_total, (
        f"A-1: total_controls must equal the L1 catalog floor "
        f"({expected_total}); got {payload['total_controls']}."
    )

    # --- Invariant 1 — per-control fanout ---
    assert len(child_ids) == expected_total, (
        f"A-1: dispatcher must return exactly one child id per L1 "
        f"control ({expected_total} expected); got {len(child_ids)}."
    )
    assert len(set(child_ids)) == expected_total, (
        "A-1: child_investigation_ids contained duplicates — the "
        "dispatcher must mint one fresh investigation per L1 control."
    )

    async with UnitOfWork() as uow:
        # --- Invariant 2 — catalog version pinned on parent ---
        parent = (await uow.session.exec(
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.id == parent_id),
        )).one()
        assert parent.kind == InvestigationKind.MASVS_AUDIT.value, (
            "A-1: parent investigation must carry "
            f"kind=masvs_audit; got {parent.kind!r}. This is the only "
            "place the new kind is allowed — children stay on the "
            "existing audit kind."
        )
        assert parent.parent_investigation_id is None, (
            "A-1: a MASVS audit parent is itself a root — it must not "
            "have its own parent_investigation_id set."
        )
        parent_refs = json.loads(parent.secondary_target_refs_json)
        assert parent_refs == [{"masvs_spec_version": CATALOG_VERSION}], (
            "A-1: parent must pin the catalog version on "
            "secondary_target_refs_json so D-3 idempotency and R-2 "
            f"report rendering can read it back; got {parent_refs!r}."
        )

        # --- Invariants 1 + 3 — children all on the existing audit kind ---
        children = (await uow.session.exec(
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.parent_investigation_id == parent_id),
        )).all()
        assert len(children) == expected_total, (
            f"A-1: expected {expected_total} child investigations "
            f"under parent {parent_id}; found {len(children)}."
        )

        seen_control_ids: set[str] = set()
        for child in children:
            assert child.kind == InvestigationKind.AUDIT.value, (
                f"A-1: child {child.id} carries kind={child.kind!r} but "
                "every child MUST use the existing audit kind so the "
                "standard vuln_researcher dispatch handles it "
                "unchanged. The masvs_audit kind is a parent-only "
                "batch tag — leaking it onto a child would break the "
                "standard dispatch routing."
            )
            child_refs = json.loads(child.secondary_target_refs_json)
            assert len(child_refs) == 1, (
                f"A-1: child {child.id} must carry exactly one ref "
                f"naming its MASVS control; got {child_refs!r}."
            )
            control_id = child_refs[0]["masvs_control_id"]
            assert control_id not in seen_control_ids, (
                f"A-1: control id {control_id!r} appears on more than "
                "one child — the dispatcher must mint exactly one "
                "investigation per L1 control."
            )
            seen_control_ids.add(control_id)

        # Every L1 control must be represented; none omitted.
        missing = set(expected_control_ids) - seen_control_ids
        assert not missing, (
            f"A-1: {len(missing)} L1 control(s) had no child "
            f"investigation dispatched: {sorted(missing)}. This breaks "
            "the PRD's headline 'one independent VR investigation per "
            "OWASP MASVS L1 control' guarantee."
        )

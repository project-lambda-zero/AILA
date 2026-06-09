"""U-2 — ``GET /vr/targets/{target_id}/masvs-audit-aggregate`` returns JSON.

End-to-end smoke coverage for the structured-JSON sibling of the R-3
PDF report endpoint. The aggregate endpoint reuses
:func:`aila.modules.vr.reporting.masvs_report.collect_findings` and
serves the result as :class:`MasvsAuditAggregate`, so the same
target/parent/cross-target validation tree applies — the tests below
pin each refusal shape so a contract drift in the JSON endpoint can't
silently diverge from the PDF endpoint.

Tests:

1. **Happy path** — 200, the envelope's ``data`` carries the parent /
   target / spec version, and ``verdicts`` is a list (empty when the
   parent has no children — the per-control table renders the empty
   state on the client).
2. **404 unknown target** — pasted target id never returns 500.
3. **404 unknown audit** — valid target + missing audit id returns 404.
4. **409 wrong parent kind** — the parent exists but is not a MASVS
   audit batch root.
5. **404 cross-target** — defensive guard against pasted audit ids
   under the wrong target.
6. **422 missing audit_id** — FastAPI's own validation runs first.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from httpx import AsyncClient

from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.masvs import CATALOG_VERSION
from aila.platform.uow import UnitOfWork


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


_APK_PACKAGE = "com.vodafone.selfservis"
_APK_STATIC_SUMMARY: dict[str, Any] = {
    "package": _APK_PACKAGE,
    "version_name": "19.4.0",
    "version_code": "19400",
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
    "audit_mcp_decompiled_index_id": "vodafone_selfservis@9228be90",
    "android_mcp_static_summary": _APK_STATIC_SUMMARY,
    "android_mcp_package_name": _APK_PACKAGE,
}


async def _insert_target(*, slug: str, kind: str = "android_apk") -> str:
    """Insert workspace + android_apk target. Mirrors the R-3 helper."""
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"MASVS aggregate {slug}",
            slug=f"masvs-aggregate-{slug}",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name=f"Vodafone Yanımda aggregate {slug}",
            kind=kind,
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


async def _insert_masvs_parent(
    *,
    target_id: str,
    kind: str = InvestigationKind.MASVS_AUDIT.value,
    spec_version: str = CATALOG_VERSION,
) -> str:
    """Insert one parent VRInvestigationRecord (no children).

    ``kind`` parameterised so the wrong-kind test reuses the same
    helper. ``spec_version`` lands on ``secondary_target_refs_json``
    to mirror the dispatcher's pin.
    """
    async with UnitOfWork() as uow:
        parent = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            secondary_target_refs_json=json.dumps(
                [{"masvs_spec_version": spec_version}],
            ),
            kind=kind,
            title=f"MASVS audit: {_APK_PACKAGE}",
            initial_question="MASVS audit batch parent (test fixture).",
            status=InvestigationStatus.CREATED.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.masvs_audit",
            cost_budget_usd=2300.0,
        )
        uow.session.add(parent)
        await uow.session.commit()
        await uow.session.refresh(parent)
        return parent.id


@pytest.mark.asyncio
async def test_aggregate_happy_path_returns_envelope(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Valid target + valid MASVS parent → 200 + envelope-wrapped aggregate.

    The aggregate carries parent_id / target_id / masvs_spec_version /
    generated_at / verdicts / by_group / summary_counts. With zero
    children, ``verdicts`` is an empty list and ``summary_counts`` is
    an empty map — both legal partial-aggregate shapes per the
    contract docstring on :class:`MasvsAuditAggregate`.
    """
    del test_db
    target_id = await _insert_target(slug="happy")
    audit_id = await _insert_masvs_parent(target_id=target_id)

    resp = await async_client.get(
        f"/vr/targets/{target_id}/masvs-audit-aggregate",
        params={"audit_id": audit_id},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # DataEnvelope shape: ``{"data": {...}, "meta": {...}}``.
    assert "data" in body, body
    agg = body["data"]
    assert agg["parent_id"] == audit_id
    assert agg["target_id"] == target_id
    assert agg["masvs_spec_version"] == CATALOG_VERSION
    assert isinstance(agg["verdicts"], list)
    assert agg["verdicts"] == [], (
        "U-2: parent has no children, so the verdicts list must be "
        "empty — partial aggregates are valid and a non-empty list "
        "here would mean the aggregator is fabricating verdicts."
    )
    assert isinstance(agg["by_group"], dict)
    assert isinstance(agg["summary_counts"], dict)
    assert "generated_at" in agg


@pytest.mark.asyncio
async def test_aggregate_returns_404_for_unknown_target(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Unknown target id surfaces as 404, not 500."""
    del test_db

    resp = await async_client.get(
        "/vr/targets/does-not-exist/masvs-audit-aggregate",
        params={"audit_id": "anything"},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_aggregate_returns_404_for_unknown_audit(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Valid target + unknown audit id → 404 (no JSON aggregate leaks)."""
    del test_db
    target_id = await _insert_target(slug="missing-audit")

    resp = await async_client.get(
        f"/vr/targets/{target_id}/masvs-audit-aggregate",
        params={"audit_id": "audit-does-not-exist"},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 404, resp.text
    assert "audit" in resp.text.lower()


@pytest.mark.asyncio
async def test_aggregate_returns_409_when_parent_kind_not_masvs_audit(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """A non-MASVS parent investigation produces a 409.

    Matches the R-3 PDF endpoint's refusal so the JSON / PDF surfaces
    stay symmetric — a frontend can render the same error UI on either
    code path.
    """
    del test_db
    target_id = await _insert_target(slug="wrong-kind")
    audit_id = await _insert_masvs_parent(
        target_id=target_id,
        kind=InvestigationKind.AUDIT.value,
    )

    resp = await async_client.get(
        f"/vr/targets/{target_id}/masvs-audit-aggregate",
        params={"audit_id": audit_id},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 409, resp.text
    assert "masvs_audit" in resp.text, (
        "U-2: the 409 detail should name the expected kind so the "
        "operator can correct the audit id (matches R-3 PDF surface)."
    )


@pytest.mark.asyncio
async def test_aggregate_returns_404_when_parent_belongs_to_different_target(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Cross-target audit id → 404. Defensive guard against pasted ids."""
    del test_db
    target_a = await _insert_target(slug="cross-target-a")
    target_b = await _insert_target(slug="cross-target-b")
    audit_id = await _insert_masvs_parent(target_id=target_a)

    resp = await async_client.get(
        f"/vr/targets/{target_b}/masvs-audit-aggregate",
        params={"audit_id": audit_id},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 404, resp.text
    assert audit_id in resp.text
    assert "does not belong" in resp.text.lower() or target_b in resp.text


@pytest.mark.asyncio
async def test_aggregate_requires_audit_id_query_param(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """``audit_id`` is required; FastAPI returns 422 on missing param."""
    del test_db
    target_id = await _insert_target(slug="missing-param")

    resp = await async_client.get(
        f"/vr/targets/{target_id}/masvs-audit-aggregate",
        headers=_auth(admin_token),
    )

    assert resp.status_code == 422, resp.text

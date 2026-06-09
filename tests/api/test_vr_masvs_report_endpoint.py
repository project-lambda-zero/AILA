"""R-3 — ``GET /vr/targets/{target_id}/masvs-report`` streams the MASVS PDF.

End-to-end smoke coverage for the report download endpoint that R-3
wires up on top of the R-1 aggregator + R-2a/R-2b PDF renderer. Each
test inserts the minimal DB shape the endpoint requires (one
``VRTargetRecord`` + one parent ``VRInvestigationRecord`` with
``kind='masvs_audit'`` and zero children) and exercises the HTTP
contract:

1. **Happy path** — 200, ``application/pdf`` content-type, valid PDF
   byte stream (``%PDF-`` header), and a ``Content-Disposition`` header
   whose filename embeds the APK package + audit generation date.
2. **404 unknown target** — missing target id never returns 500.
3. **404 unknown audit** — valid target + missing audit id returns 404.
4. **409 wrong parent kind** — the parent exists but is not a MASVS
   audit batch root.
5. **404 cross-target** — the parent exists but belongs to a different
   target than the one in the URL path (defensive guard against
   operators pasting an audit id under the wrong target context).

Two focused unit tests at the bottom pin the filename / sanitiser
helpers without going through HTTP — they catch a regression in the
slugger faster than a full request round-trip.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pypdf
import pytest
from httpx import AsyncClient

from aila.modules.vr.api_router import (
    _masvs_report_filename,
    _sanitize_filename_part,
)
from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.contracts.target import (
    AnalysisState,
    TargetKind,
    TargetStatus,
    VRTargetSummary,
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
    "android_mcp_decoded_dir": "/tmp/decoded",  # noqa: S108  (test fixture path)
    "android_mcp_decompiled_dir": "/tmp/jadx",  # noqa: S108
    "android_mcp_jadx_class_count": 1234,
    "audit_mcp_decompiled_index_id": "vodafone_selfservis@9228be90",
    "android_mcp_static_summary": _APK_STATIC_SUMMARY,
    "android_mcp_package_name": _APK_PACKAGE,
}


async def _insert_target(*, slug: str, kind: str = "android_apk") -> str:
    """Insert a workspace + android_apk target row pair.

    Bypasses the ingestion machinery the same way the dispatch tests
    do — the report endpoint only needs ``kind`` + ``team_id`` +
    ``mcp_handles_json`` to project a target summary.
    """
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"MASVS report {slug}",
            slug=f"masvs-report-{slug}",
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

    ``kind`` is parameterised so the wrong-kind test can insert a
    non-MASVS parent through the same helper. ``spec_version`` lands
    on ``secondary_target_refs_json`` to mirror the dispatcher's pin.
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
async def test_report_happy_path_returns_pdf(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Valid target + valid MASVS parent → 200 + application/pdf body."""
    del test_db
    target_id = await _insert_target(slug="happy")
    audit_id = await _insert_masvs_parent(target_id=target_id)

    resp = await async_client.get(
        f"/vr/targets/{target_id}/masvs-report",
        params={"audit_id": audit_id},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/pdf")

    disposition = resp.headers["content-disposition"]
    assert disposition.startswith("attachment; filename="), disposition
    assert _APK_PACKAGE in disposition, (
        "R-3: the filename should embed the APK package label so the "
        f"operator can identify the report in their downloads folder; "
        f"got {disposition!r}."
    )
    assert disposition.endswith('.pdf"'), disposition
    assert resp.headers.get("cache-control") == "no-store", (
        "R-3: the report stream is per-request — operators downloading "
        "twice must hit the renderer twice, not a stale CDN copy."
    )

    body = resp.content
    assert body.startswith(b"%PDF-"), (
        "R-3: response body must begin with the PDF magic. The renderer "
        "produced something else — typically a stray write that broke "
        "the byte stream."
    )
    # Parse with pypdf to confirm the structure survived the wire.
    reader = pypdf.PdfReader(__import__("io").BytesIO(body))
    assert len(reader.pages) >= 1


@pytest.mark.asyncio
async def test_report_returns_404_for_unknown_target(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Unknown target id surfaces as 404, not 500."""
    del test_db

    resp = await async_client.get(
        "/vr/targets/does-not-exist/masvs-report",
        params={"audit_id": "anything"},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_report_returns_404_for_unknown_audit(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Valid target + unknown audit id → 404 (no PDF leaks out)."""
    del test_db
    target_id = await _insert_target(slug="missing-audit")

    resp = await async_client.get(
        f"/vr/targets/{target_id}/masvs-report",
        params={"audit_id": "audit-does-not-exist"},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 404, resp.text
    assert "audit" in resp.text.lower()


@pytest.mark.asyncio
async def test_report_returns_409_when_parent_kind_not_masvs_audit(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """A non-MASVS parent investigation produces a 409 instead of a
    silent render under the wrong kind. The one-off investigation
    report has its own endpoint — refusing here keeps the two reports
    distinguishable.
    """
    del test_db
    target_id = await _insert_target(slug="wrong-kind")
    audit_id = await _insert_masvs_parent(
        target_id=target_id,
        kind=InvestigationKind.AUDIT.value,
    )

    resp = await async_client.get(
        f"/vr/targets/{target_id}/masvs-report",
        params={"audit_id": audit_id},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 409, resp.text
    assert "masvs_audit" in resp.text, (
        "R-3: the 409 detail should name the expected kind so the "
        "operator can correct the audit id."
    )


@pytest.mark.asyncio
async def test_report_returns_404_when_parent_belongs_to_different_target(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """Cross-target audit id (parent.target_id ≠ URL target_id) → 404.

    Defensive guard: an operator with a stale URL or a copy-pasted
    audit id could otherwise download a report under the wrong target
    context, which obscures which APK the verdicts trace to.
    """
    del test_db
    target_a = await _insert_target(slug="cross-target-a")
    target_b = await _insert_target(slug="cross-target-b")
    audit_id = await _insert_masvs_parent(target_id=target_a)

    resp = await async_client.get(
        f"/vr/targets/{target_b}/masvs-report",
        params={"audit_id": audit_id},
        headers=_auth(admin_token),
    )

    assert resp.status_code == 404, resp.text
    assert audit_id in resp.text
    assert "does not belong" in resp.text.lower() or target_b in resp.text


@pytest.mark.asyncio
async def test_report_requires_audit_id_query_param(
    async_client: AsyncClient,
    admin_token: str,
    test_db: None,
) -> None:
    """``audit_id`` is required; FastAPI returns 422 on missing param."""
    del test_db
    target_id = await _insert_target(slug="missing-param")

    resp = await async_client.get(
        f"/vr/targets/{target_id}/masvs-report",
        headers=_auth(admin_token),
    )

    assert resp.status_code == 422, resp.text


# ───────────────────────────────────────────────────────────────────
# Pure unit tests for the filename helpers — fast, no HTTP, no DB.
# Catch a sanitiser regression before the slow integration tests run.
# ───────────────────────────────────────────────────────────────────


def _bare_target_summary(
    *,
    package: str | None,
    android_package_name: str | None = None,
) -> VRTargetSummary:
    """Build a minimal :class:`VRTargetSummary` for filename unit tests."""
    overview: dict[str, Any] | None
    if package is None:
        overview = None
    else:
        overview = {
            "sha256": "0" * 64,
            "static_summary": {"package": package},
        }
    return VRTargetSummary(
        id="target-x",
        workspace_id="ws-x",
        display_name="Test target",
        kind=TargetKind.ANDROID_APK,
        descriptor={},
        uploaded_filename=None,
        android_package_name=android_package_name,
        apk_overview=overview,
        primary_language=None,
        secondary_languages=[],
        status=TargetStatus.ACTIVE,
        analysis_state=AnalysisState.PENDING,
        analysis_state_message=None,
        analysis_started_at=None,
        analysis_completed_at=None,
        analysis_stages=None,
        tags=[],
        created_at=datetime.now(UTC).isoformat(),
        updated_at=datetime.now(UTC).isoformat(),
    )


def test_sanitize_filename_part_keeps_safe_chars() -> None:
    """Alnum + dot + underscore + hyphen survive unchanged."""
    assert (
        _sanitize_filename_part("com.vodafone.selfservis", fallback="fb")
        == "com.vodafone.selfservis"
    )


def test_sanitize_filename_part_folds_unsafe_chars() -> None:
    """Spaces / slashes / shell metas collapse to underscores."""
    assert (
        _sanitize_filename_part("a b/c$d", fallback="fb")
        == "a_b_c_d"
    )


def test_sanitize_filename_part_strips_leading_trailing_punctuation() -> None:
    """Leading / trailing punctuation gets stripped so the slug never
    starts with a dot (which would create a hidden file on Unix)."""
    assert (
        _sanitize_filename_part("..weird..", fallback="fb")
        == "weird"
    )


def test_sanitize_filename_part_returns_fallback_for_empty_or_pure_punctuation() -> None:
    """Empty input → fallback; punctuation-only input → fallback."""
    assert _sanitize_filename_part("", fallback="android-apk") == "android-apk"
    assert _sanitize_filename_part("....", fallback="android-apk") == "android-apk"


def test_sanitize_filename_part_caps_length_at_64() -> None:
    """Slug is capped to 64 chars so the header stays compact."""
    long = "a" * 200
    out = _sanitize_filename_part(long, fallback="fb")
    assert len(out) == 64
    assert out == "a" * 64


def test_masvs_report_filename_prefers_static_summary_package() -> None:
    """Filename takes ``apk_overview.static_summary.package`` first."""
    summary = _bare_target_summary(
        package="com.vodafone.selfservis",
        android_package_name="should.be.ignored",
    )
    assert (
        _masvs_report_filename(summary, "20260609")
        == "masvs_com.vodafone.selfservis_20260609.pdf"
    )


def test_masvs_report_filename_falls_back_to_android_package_name() -> None:
    """When ``static_summary`` is absent, fall back to the handle."""
    summary = _bare_target_summary(
        package=None,
        android_package_name="com.fallback.example",
    )
    assert (
        _masvs_report_filename(summary, "20260609")
        == "masvs_com.fallback.example_20260609.pdf"
    )


def test_masvs_report_filename_uses_sentinel_when_no_package_resolvable() -> None:
    """All sources empty → the ``android-apk`` sentinel keeps the
    filename valid for the Content-Disposition header.
    """
    summary = _bare_target_summary(package=None, android_package_name=None)
    assert (
        _masvs_report_filename(summary, "20260609")
        == "masvs_android-apk_20260609.pdf"
    )

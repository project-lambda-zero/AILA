"""A-2 — End-to-end smoke test for the MASVS PDF generation pipeline.

The A-1 smoke test (``tests/api/test_vr_masvs_smoke.py``) covers the
dispatch happy path: one parent + N children, every child carries
``kind=AUDIT`` (the existing per-investigation kind), the catalog
version is pinned on the parent. A-2 picks up where A-1 stops and
exercises the read side of the pipeline:

1. Seed one workspace + ``android_apk`` target row pair.
2. Seed one MASVS audit parent + one child whose primary outcome is a
   ``DIRECT_FINDING`` at verifier confidence 0.8 with one verbatim
   ``affected_components`` entry. The 0.8 confidence sits above the
   S-4 ``_FINDING_CONFIDENCE_FLOOR`` so the mapper resolves the verdict
   to :attr:`MasvsVerdict.FINDING` and carries the cited evidence
   through to :class:`MasvsControlVerdict.evidence_locations`.
3. Run :func:`collect_findings` against the parent id to produce a
   :class:`MasvsAuditAggregate`.
4. Hand the aggregate to :func:`build_pdf` together with a
   :class:`VRTargetSummary` mirroring the seeded target row.
5. Confirm the bytes start with the ``%PDF-`` magic prefix.
6. Parse the bytes with :mod:`pypdf`, concatenate every page's text,
   and assert the rendered document mentions both the control id and
   the evidence file path. Those are the operator's primary navigation
   handles in the rendered report — if either is missing, the PDF is
   uninterpretable as an audit artifact regardless of how the bytes
   structure.

The renderer is verified structurally elsewhere
(``tests/test_vr_masvs_pdf_report.py`` for the R-2a scaffolding,
``tests/test_vr_masvs_pdf_report_subsections.py`` for the R-2b
per-control bodies). A-2's job is the integration confidence check —
the DB-loaded path through ``collect_findings`` produces a verdict the
renderer can turn into operator-readable text.
"""
from __future__ import annotations

import io
import json

import pypdf
import pytest

from aila.modules.vr.contracts.branch import BranchStatus
from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.contracts.masvs import MasvsVerdict
from aila.modules.vr.contracts.outcome import OutcomeConfidence, OutcomeKind
from aila.modules.vr.contracts.target import (
    AnalysisState,
    TargetKind,
    TargetStatus,
    VRTargetSummary,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.masvs.catalog import CATALOG_VERSION
from aila.modules.vr.reporting.masvs_report import build_pdf, collect_findings
from aila.platform.uow import UnitOfWork

# Control id we stub a direct finding against. ``MSTG-STORAGE-1`` is an
# L1 control in the seeded catalog so the aggregator resolves it back to
# a real :class:`MasvsControl` and the renderer emits its description +
# verification steps under the subsection header.
_CONTROL_ID = "MSTG-STORAGE-1"

# Jadx-shaped path the auditor "cited" — full enough to look like a
# real fixture entry, short enough (53 chars) that the 8pt Courier
# AFFECTED COMPONENTS table cell renders it on one line. The
# renderer's file column fits ~96 chars at 8pt mono without wrapping.
_EVIDENCE_FILE = "sources/com/examplecorp/selfservis/storage/AuthCache.java"
_EVIDENCE_FUNCTION = "writePlaintextToken"

# Confidence the mapper reads off ``payload['verifier_report']``.
# 0.8 sits above the S-4 finding floor (0.6) so the verdict resolves
# to FINDING rather than INCONCLUSIVE.
_VERIFIER_CONFIDENCE = 0.8

# APK identity meta — mirrored from the operator-supplied ExampleCorp
# SampleApp fixture so the cover page surfaces a realistic identifier.
_APK_PACKAGE = "com.examplecorp.selfservis"
_APK_VERSION = "19.4.0"
_APK_SHA = "9228be90bf0bc3c4248431d2f2acb96e222a5b85c0a07ff19adf7c1e93de3bc4"


async def _seed_target() -> str:
    """Insert one workspace + one ``android_apk`` target row pair.

    Returns the target id so the parent + ``VRTargetSummary`` builders
    can pin to the same row.
    """
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="A2 PDF smoke",
            slug="masvs-pdf-smoke",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name="A2 ExampleCorp APK",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/vf.apk"}),  # noqa: S108
            primary_language=None,
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json="{}",
            status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


async def _seed_parent(target_id: str) -> str:
    """Insert one MASVS audit parent row pinned to ``target_id``.

    ``secondary_target_refs_json`` carries the catalog version so the
    aggregator's :func:`_extract_spec_version` reads it back verbatim.
    Status starts at RUNNING because the parent reconciler (D-5) is the
    component that flips MASVS audit parents to COMPLETED, and that
    transition is out of scope for the read-side smoke test.
    """
    async with UnitOfWork() as uow:
        parent = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            kind=InvestigationKind.MASVS_AUDIT.value,
            title="A2 PDF smoke parent",
            initial_question="seed",
            status=InvestigationStatus.RUNNING.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.masvs_audit",
            cost_budget_usd=50.0,
            secondary_target_refs_json=json.dumps(
                [{"masvs_spec_version": CATALOG_VERSION}],
            ),
        )
        uow.session.add(parent)
        await uow.session.commit()
        await uow.session.refresh(parent)
        return parent.id


async def _seed_child_with_direct_finding(
    parent_id: str,
    target_id: str,
) -> str:
    """Insert one child investigation with a stubbed DIRECT_FINDING outcome.

    Payload mirrors the canonical shape ``vr/agents/prompts/system_audit.md``
    instructs the claim verifier to emit:

    * ``verifier_report.verdict`` — ``"confirmed"`` (any value other
      than ``"refuted"`` / ``"inconclusive"`` flows through the
      DIRECT_FINDING branch in :func:`child_outcome_to_verdict`).
    * ``verifier_report.confidence`` — the numeric float the mapper
      compares against the 0.6 finding floor.
    * ``affected_components`` — the ``{file, function}`` list the PDF
      renderer surfaces under the AFFECTED COMPONENTS block in the
      per-control subsection.

    The child is wired through the same DB shape the
    :mod:`tests.api.test_vr_masvs_collect_findings` helpers use:
    investigation row → one ACTIVE primary branch → one
    ``DIRECT_FINDING`` outcome → ``primary_outcome_id`` pointer back to
    the outcome.
    """
    payload = {
        "verifier_report": {
            "verdict": "confirmed",
            "confidence": _VERIFIER_CONFIDENCE,
        },
        "affected_components": [
            {"file": _EVIDENCE_FILE, "function": _EVIDENCE_FUNCTION},
        ],
    }
    async with UnitOfWork() as uow:
        child = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            parent_investigation_id=parent_id,
            kind=InvestigationKind.AUDIT.value,
            title=f"child {_CONTROL_ID}",
            initial_question="seed",
            status=InvestigationStatus.COMPLETED.value,
            auto_pilot=True,
            strategy_family="vulnerability_research.audit",
            cost_budget_usd=50.0,
            secondary_target_refs_json=json.dumps([
                {
                    "masvs_control_id": _CONTROL_ID,
                    "masvs_spec_version": CATALOG_VERSION,
                },
            ]),
        )
        uow.session.add(child)
        await uow.session.flush()

        branch = VRInvestigationBranchRecord(
            investigation_id=child.id,
            status=BranchStatus.ACTIVE.value,
            fork_reason="primary",
        )
        uow.session.add(branch)
        await uow.session.flush()

        outcome = VRInvestigationOutcomeRecord(
            investigation_id=child.id,
            branch_id=branch.id,
            outcome_kind=OutcomeKind.DIRECT_FINDING.value,
            payload_json=json.dumps(payload),
            confidence=OutcomeConfidence.STRONG.value,
            state="dispatched",
        )
        uow.session.add(outcome)
        await uow.session.flush()
        child.primary_outcome_id = outcome.id
        uow.session.add(child)

        await uow.session.commit()
        return child.id


def _build_target_summary(target_id: str) -> VRTargetSummary:
    """Build a :class:`VRTargetSummary` matching the seeded target row.

    :func:`build_pdf` reads only the renderer-facing fields (display
    name, ``android_package_name``, ``apk_overview``, ``kind``). Pinning
    the summary's ``id`` to the seeded ``target_id`` keeps the cover
    page identity aligned with the aggregate's ``target_id`` even
    though the renderer does not currently print the id directly.
    """
    return VRTargetSummary(
        id=target_id,
        workspace_id="ws-stub",
        display_name="A2 ExampleCorp APK",
        kind=TargetKind.ANDROID_APK,
        android_package_name=_APK_PACKAGE,
        apk_overview={
            "sha256": _APK_SHA,
            "static_summary": {
                "package": _APK_PACKAGE,
                "version_name": _APK_VERSION,
                "version_code": "1900400",
                "min_sdk": "21",
                "target_sdk": "34",
            },
        },
        status=TargetStatus.ACTIVE,
        analysis_state=AnalysisState.READY,
    )


def _extract_all_text(pdf_bytes: bytes) -> str:
    """Concatenate text extraction across every page, fold whitespace.

    :mod:`pypdf` inserts line breaks at table cell boundaries which
    would break a literal substring match against a long jadx path.
    Folding runs of whitespace to single spaces lets the assertion
    check the path verbatim without embedding the renderer's wrap
    points — matches the helper in
    ``tests/test_vr_masvs_pdf_report.py``.
    """
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    joined = "\n".join((page.extract_text() or "") for page in reader.pages)
    return " ".join(joined.split())


@pytest.mark.asyncio
async def test_a2_smoke_collect_findings_then_build_pdf(
    test_db: None,
) -> None:
    """A-2 acceptance: aggregate → PDF render pipeline survives end-to-end.

    Asserts:

    * Aggregate carries exactly the one stubbed verdict, resolved as
      FINDING at confidence 0.8 with the cited evidence location.
    * Rendered bytes start with the ``%PDF-`` magic prefix.
    * Rendered text mentions the control id (both the per-group row
      table and the subsection title bar emit it).
    * Rendered text mentions the evidence file path verbatim (the
      AFFECTED COMPONENTS block in the subsection body emits it on one
      line at 8pt Courier, well within the 4.8-inch column width).
    """
    target_id = await _seed_target()
    parent_id = await _seed_parent(target_id)
    await _seed_child_with_direct_finding(parent_id, target_id)

    aggregate = await collect_findings(parent_id)

    # Aggregate side — confirm the mapper landed the stubbed outcome on
    # the FINDING branch with the verifier confidence the test seeded.
    assert len(aggregate.verdicts) == 1, (
        "expected one verdict from the stubbed child; "
        f"got {len(aggregate.verdicts)}"
    )
    verdict = aggregate.verdicts[0]
    assert verdict.control_id == _CONTROL_ID
    assert verdict.verdict == MasvsVerdict.FINDING
    assert verdict.confidence == pytest.approx(_VERIFIER_CONFIDENCE)
    assert [
        (loc.file, loc.function) for loc in verdict.evidence_locations
    ] == [(_EVIDENCE_FILE, _EVIDENCE_FUNCTION)]

    target = _build_target_summary(target_id)
    pdf_bytes = build_pdf(aggregate, target)

    # Byte-level smoke check — a PDF document always opens with
    # ``%PDF-`` followed by the major/minor version. A truncated or
    # empty render would fail here before :mod:`pypdf` even tries to
    # parse the document.
    assert pdf_bytes.startswith(b"%PDF-"), (
        "build_pdf output does not look like a PDF; "
        f"first bytes: {pdf_bytes[:16]!r}"
    )

    text = _extract_all_text(pdf_bytes)
    assert _CONTROL_ID in text, (
        f"rendered PDF does not mention control id {_CONTROL_ID!r}; "
        "the per-group control table and the subsection title bar "
        "should both emit it"
    )
    assert _EVIDENCE_FILE in text, (
        f"rendered PDF does not mention evidence file path "
        f"{_EVIDENCE_FILE!r}; the AFFECTED COMPONENTS block in the "
        "per-control subsection should emit it verbatim"
    )

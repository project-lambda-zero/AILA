"""R-2b — per-control subsection bodies under each MASVS group section.

The R-2a tests in :file:`tests/test_vr_masvs_pdf_report.py` exercise the
scaffolding (cover, executive summary, group sections with TOC entries
and per-group row tables). This file pins the per-control subsection
the R-2b renderer drops beneath each row table.

A subsection MUST surface, per control:

1. The control id and the control title (from
   :class:`~aila.modules.vr.masvs.models.MasvsControl`) under a verdict-
   colored title bar.
2. The verdict label and the confidence percentage on the title bar's
   badge.
3. The control's description paragraph.
4. The verbatim ``{file, function}`` evidence entries the auditor cited
   in its primary outcome's ``payload['affected_components']``.
5. The control's verification steps as a bulleted list (doubles as
   remediation guidance per the control text).
6. A footer line carrying the child investigation id, the operator-
   facing path (``/vr/investigations/<id>``), and the inconclusive
   reason when one is present.

When a verdict's ``control_id`` is not in the active catalog (the
catalog moved on after dispatch), the subsection falls back to a
minimal "(not in current catalog)" title bar + footer — partial
fidelity beats refusing to render.
"""
from __future__ import annotations

import io
from datetime import UTC, datetime

import pypdf

from aila.modules.vr.contracts.masvs import (
    MasvsAuditAggregate,
    MasvsControlVerdict,
    MasvsEvidenceLocation,
    MasvsVerdict,
)
from aila.modules.vr.contracts.target import (
    AnalysisState,
    TargetKind,
    TargetStatus,
    VRTargetSummary,
)
from aila.modules.vr.masvs.catalog import MASVS_CONTROLS
from aila.modules.vr.masvs.models import MasvsControl, MasvsGroup
from aila.modules.vr.reporting.masvs_report import build_pdf

_APK_SHA = "9228be90bf0bc3c4248431d2f2acb96e222a5b85c0a07ff19adf7c1e93de3bc4"
_APK_PACKAGE = "com.examplecorp.selfservis"
_APK_VERSION = "19.4.0"


def _catalog_control(control_id: str) -> MasvsControl:
    """Resolve ``control_id`` against the live catalog or fail loudly.

    The subsection tests pin against real catalog text so a paraphrase
    change in :file:`src/aila/modules/vr/masvs/catalog.py` flags itself
    here. If the control disappears entirely (a future iteration
    retires it) the test fails with a clear pointer rather than
    silently skipping coverage.
    """
    for control in MASVS_CONTROLS:
        if control.id == control_id:
            return control
    raise AssertionError(
        f"catalog has no control with id {control_id!r} — "
        "the catalog moved on; update the test fixture.",
    )


def _make_target() -> VRTargetSummary:
    """Build a target whose ``apk_overview`` carries the standard post-
    STATIC_SUMMARY shape. Same fixture the R-2a tests use; duplicated
    here so the new file is self-contained.
    """
    return VRTargetSummary(
        id="target-xyz",
        workspace_id="ws-1",
        display_name="ExampleCorp Self-Service",
        kind=TargetKind.ANDROID_APK,
        android_package_name=_APK_PACKAGE,
        apk_overview={
            "sha256": _APK_SHA,
            "static_summary": {
                "package": _APK_PACKAGE,
                "version_name": _APK_VERSION,
                "version_code": "1900400",
            },
        },
        status=TargetStatus.ACTIVE,
        analysis_state=AnalysisState.READY,
    )


def _make_aggregate(
    verdicts: list[MasvsControlVerdict],
    *,
    by_group: dict[MasvsGroup, list[MasvsControlVerdict]] | None = None,
) -> MasvsAuditAggregate:
    """Assemble an aggregate with summary_counts derived from ``verdicts``.

    When ``by_group`` is omitted, every verdict lands under
    :attr:`MasvsGroup.STORAGE` so the single-group rendering paths
    exercise the subsection loop without distracting cross-group
    layout interactions.
    """
    counts: dict[MasvsVerdict, int] = {}
    for verdict in verdicts:
        counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1
    if by_group is None:
        by_group = {MasvsGroup.STORAGE: list(verdicts)} if verdicts else {}
    return MasvsAuditAggregate(
        parent_id="parent-abc",
        target_id="target-xyz",
        masvs_spec_version="1.4.2-aila",
        generated_at=datetime(2026, 6, 8, 15, 12, tzinfo=UTC),
        verdicts=list(verdicts),
        by_group=by_group,
        summary_counts=counts,
    )


def _extract_all_text(pdf_bytes: bytes) -> str:
    """Concatenated text extraction across every page, whitespace-
    collapsed so assertions can use literal expected strings without
    embedding pypdf's per-cell wrap points.
    """
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    joined = "\n".join((page.extract_text() or "") for page in reader.pages)
    return " ".join(joined.split())


def test_subsection_surfaces_control_id_title_and_verdict_label() -> None:
    """Title bar must carry the control id, the catalog title, and the
    verdict label so the reader identifies the subsection without
    scrolling back to the group's row table.
    """
    control = _catalog_control("MSTG-STORAGE-1")
    verdict = MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.FINDING,
        confidence=0.82,
        child_investigation_id="child-1",
        primary_outcome_id="oc-1",
        reason=None,
        evidence_locations=[],
    )
    pdf = build_pdf(_make_aggregate([verdict]), _make_target())
    text = _extract_all_text(pdf)

    assert "MSTG-STORAGE-1" in text
    # Title text wraps over multiple cells; pin a stable phrase.
    assert "System credential storage facilities" in text
    assert "FINDING" in text
    assert "82%" in text


def test_subsection_renders_control_description_paragraph() -> None:
    """The spec description must appear so the reader sees what the
    audit ran against without opening the catalog source.
    """
    control = _catalog_control("MSTG-STORAGE-1")
    verdict = MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.FINDING,
        confidence=0.7,
        child_investigation_id="child-1",
        primary_outcome_id="oc-1",
        reason=None,
        evidence_locations=[],
    )
    pdf = build_pdf(_make_aggregate([verdict]), _make_target())
    text = _extract_all_text(pdf)

    # Phrase lifted verbatim from the catalog's MSTG-STORAGE-1 description.
    assert "Android Keystore" in text


def test_subsection_renders_verbatim_evidence_locations() -> None:
    """Each ``MasvsEvidenceLocation`` entry must render its file path
    and its function name; nothing fabricated, nothing dropped.
    """
    control = _catalog_control("MSTG-STORAGE-1")
    verdict = MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.FINDING,
        confidence=0.85,
        child_investigation_id="child-1",
        primary_outcome_id="oc-1",
        reason=None,
        evidence_locations=[
            MasvsEvidenceLocation(
                file=(
                    "sources/com/examplecorp/selfservis/login/"
                    "LoginActivity.java"
                ),
                function="onCreate",
            ),
            MasvsEvidenceLocation(
                file=(
                    "sources/com/examplecorp/selfservis/login/"
                    "CredentialStore.java"
                ),
                function="persistToken",
            ),
        ],
    )
    pdf = build_pdf(_make_aggregate([verdict]), _make_target())
    text = _extract_all_text(pdf)

    assert "AFFECTED COMPONENTS" in text
    assert "LoginActivity.java" in text
    assert "onCreate" in text
    assert "CredentialStore.java" in text
    assert "persistToken" in text


def test_subsection_omits_evidence_block_when_no_locations() -> None:
    """A verdict with empty ``evidence_locations`` must not emit the
    "AFFECTED COMPONENTS" header — an empty block is visual noise
    that suggests missing data rather than the absence of citations.
    """
    control = _catalog_control("MSTG-STORAGE-1")
    verdict = MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.NO_FINDING,
        confidence=0.55,
        child_investigation_id="child-1",
        primary_outcome_id="oc-1",
        reason=None,
        evidence_locations=[],
    )
    pdf = build_pdf(_make_aggregate([verdict]), _make_target())
    text = _extract_all_text(pdf)

    assert "AFFECTED COMPONENTS" not in text


def test_subsection_renders_verification_steps_as_bullets() -> None:
    """Each catalog verification step must appear so the operator gets
    actionable remediation guidance without leaving the PDF.
    """
    control = _catalog_control("MSTG-STORAGE-1")
    verdict = MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.FINDING,
        confidence=0.7,
        child_investigation_id="child-1",
        primary_outcome_id="oc-1",
        reason=None,
        evidence_locations=[],
    )
    pdf = build_pdf(_make_aggregate([verdict]), _make_target())
    text = _extract_all_text(pdf)

    assert "VERIFICATION" in text
    assert "REMEDIATION" in text
    # Phrase lifted verbatim from the first verification step.
    assert "SharedPreferences.Editor.put" in text


def test_subsection_footer_carries_child_id_and_investigation_path() -> None:
    """The footer must surface the child investigation id and the
    operator-facing path so the reader can jump straight to the
    underlying audit on the AILA host.
    """
    control = _catalog_control("MSTG-STORAGE-1")
    verdict = MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.FINDING,
        confidence=0.7,
        child_investigation_id="inv-aabbcc",
        primary_outcome_id="oc-1",
        reason=None,
        evidence_locations=[],
    )
    pdf = build_pdf(_make_aggregate([verdict]), _make_target())
    text = _extract_all_text(pdf)

    assert "inv-aabbcc" in text
    assert "/vr/investigations/inv-aabbcc" in text


def test_subsection_inconclusive_reason_renders_in_footer() -> None:
    """An inconclusive verdict's ``reason`` must surface so the operator
    can see why the child landed without a conclusive outcome.
    """
    control = _catalog_control("MSTG-STORAGE-1")
    verdict = MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.INCONCLUSIVE,
        confidence=0.0,
        child_investigation_id="inv-stalled",
        primary_outcome_id=None,
        reason="no_primary_outcome",
        evidence_locations=[],
    )
    pdf = build_pdf(_make_aggregate([verdict]), _make_target())
    text = _extract_all_text(pdf)

    assert "INCONCLUSIVE" in text
    assert "no_primary_outcome" in text


def test_subsection_fallback_for_control_id_not_in_catalog() -> None:
    """A verdict whose ``control_id`` is not in the live catalog must
    still render: title bar with the id + the fallback label, no
    crash. The footer's child investigation reference remains so the
    operator can trace the audit even when the catalog moved on.
    """
    verdict = MasvsControlVerdict(
        control_id="MSTG-GHOST-99",
        verdict=MasvsVerdict.INCONCLUSIVE,
        confidence=0.0,
        child_investigation_id="inv-ghost",
        primary_outcome_id=None,
        reason="catalog_drift",
        evidence_locations=[],
    )
    aggregate = _make_aggregate(
        [verdict],
        by_group={MasvsGroup.STORAGE: [verdict]},
    )
    pdf = build_pdf(aggregate, _make_target())
    text = _extract_all_text(pdf)

    assert "MSTG-GHOST-99" in text
    assert "not in current catalog" in text
    assert "inv-ghost" in text
    assert "catalog_drift" in text


def test_subsections_render_for_every_verdict_in_a_group() -> None:
    """Two verdicts in the same group produce two distinct subsections;
    both control ids and both child investigation references must
    surface in the output.
    """
    control_one = _catalog_control("MSTG-STORAGE-1")
    control_two = _catalog_control("MSTG-STORAGE-2")
    verdict_one = MasvsControlVerdict(
        control_id=control_one.id,
        verdict=MasvsVerdict.FINDING,
        confidence=0.7,
        child_investigation_id="child-one",
        primary_outcome_id="oc-1",
        reason=None,
        evidence_locations=[],
    )
    verdict_two = MasvsControlVerdict(
        control_id=control_two.id,
        verdict=MasvsVerdict.NO_FINDING,
        confidence=0.85,
        child_investigation_id="child-two",
        primary_outcome_id="oc-2",
        reason=None,
        evidence_locations=[],
    )
    pdf = build_pdf(
        _make_aggregate([verdict_one, verdict_two]),
        _make_target(),
    )
    text = _extract_all_text(pdf)

    assert "MSTG-STORAGE-1" in text
    assert "MSTG-STORAGE-2" in text
    assert "child-one" in text
    assert "child-two" in text
    assert "FINDING" in text
    assert "NO FINDING" in text

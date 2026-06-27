"""R-2a -- :func:`build_pdf` renders an aggregate as a real PDF byte string.

The renderer is the operator-facing front-end of the MASVS audit pipeline.
It must produce a self-contained PDF whose:

1. byte stream is a valid PDF document (``%PDF-`` header + ``%%EOF``
   trailer + at least one page that pypdf can parse);
2. cover page surfaces the APK identity verbatim -- display name,
   package, version, SHA-256, MASVS catalog version -- so the operator
   can identify the artifact from page 1 without opening the body;
3. executive summary names every verdict bucket (FINDING / NO FINDING
   / NOT APPLICABLE / INCONCLUSIVE) plus the total controls audited;
4. emits one section per non-empty MASVS group with a corresponding
   PDF outline entry so a viewer renders a TOC sidebar;
5. handles the partial-aggregate path (no verdicts yet) without
   raising -- children-still-in-flight is a first-class state.

The render is structural -- none of these tests pin LLM-generated prose
(R-2b will add per-control bodies and those tests will live in
``tests/test_vr_masvs_pdf_report_subsections.py``). They exercise the
scaffolding only.
"""
from __future__ import annotations

import io
from datetime import UTC, datetime

import pypdf

from aila.modules.vr.contracts.masvs import (
    MasvsAuditAggregate,
    MasvsControlVerdict,
    MasvsVerdict,
)
from aila.modules.vr.contracts.target import (
    AnalysisState,
    TargetKind,
    TargetStatus,
    VRTargetSummary,
)
from aila.modules.vr.masvs.models import MasvsGroup
from aila.modules.vr.reporting.masvs_report import build_pdf

_APK_SHA = "9228be90bf0bc3c4248431d2f2acb96e222a5b85c0a07ff19adf7c1e93de3bc4"
_APK_PACKAGE = "com.examplecorp.selfservis"
_APK_VERSION = "19.4.0"


# Sentinel used to distinguish "argument omitted → render with the default
# post-STATIC_SUMMARY apk_overview" from "explicitly absent → render with
# no apk_overview". The Pydantic model accepts ``None`` for the field,
# but a default kwarg of ``None`` would collide with that case.
_DEFAULT_OVERVIEW = object()


def _make_target(
    *,
    display_name: str = "ExampleCorp Self-Service",
    apk_overview: object = _DEFAULT_OVERVIEW,
) -> VRTargetSummary:
    """Build a minimal :class:`VRTargetSummary` for the renderer.

    Default ``apk_overview`` mirrors the post-STATIC_SUMMARY shape so
    the cover-page meta table renders package / version / sha-256.
    Tests that exercise the unknown-fields paths pass
    ``apk_overview=None`` (or any falsy mapping) to drop the overview.
    """
    overview: dict[str, object] | None
    if apk_overview is _DEFAULT_OVERVIEW:
        overview = {
            "sha256": _APK_SHA,
            "static_summary": {
                "package": _APK_PACKAGE,
                "version_name": _APK_VERSION,
                "version_code": "1900400",
                "min_sdk": "21",
                "target_sdk": "34",
            },
        }
    elif apk_overview is None:
        overview = None
    elif isinstance(apk_overview, dict):
        overview = apk_overview
    else:
        raise TypeError(f"unsupported apk_overview type {type(apk_overview)!r}")
    return VRTargetSummary(
        id="target-xyz",
        workspace_id="ws-1",
        display_name=display_name,
        kind=TargetKind.ANDROID_APK,
        android_package_name=_APK_PACKAGE,
        apk_overview=overview,
        status=TargetStatus.ACTIVE,
        analysis_state=AnalysisState.READY,
    )


def _make_aggregate(
    verdicts: list[MasvsControlVerdict],
    *,
    by_group: dict[MasvsGroup, list[MasvsControlVerdict]] | None = None,
    spec_version: str = "1.4.2-aila",
) -> MasvsAuditAggregate:
    """Assemble a :class:`MasvsAuditAggregate` from a flat verdict list.

    Computes ``summary_counts`` automatically from the verdict list so
    individual tests only declare the verdicts they care about. When
    ``by_group`` is omitted, every verdict lands under
    :attr:`MasvsGroup.STORAGE` for the single-group rendering paths.
    """
    counts: dict[MasvsVerdict, int] = {}
    for verdict in verdicts:
        counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1
    if by_group is None:
        by_group = {MasvsGroup.STORAGE: list(verdicts)} if verdicts else {}
    return MasvsAuditAggregate(
        parent_id="parent-abc",
        target_id="target-xyz",
        masvs_spec_version=spec_version,
        generated_at=datetime(2026, 6, 8, 15, 12, tzinfo=UTC),
        verdicts=list(verdicts),
        by_group=by_group,
        summary_counts=counts,
    )


def _extract_all_text(pdf_bytes: bytes) -> str:
    """Concatenated text extraction across every page.

    Whitespace runs (including line breaks injected by pypdf when a
    table cell wraps a long string) are collapsed to single spaces
    so test assertions can use literal expected strings without
    embedding pypdf's per-cell wrap points.
    """
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    joined = "\n".join((page.extract_text() or "") for page in reader.pages)
    return " ".join(joined.split())


def _outline_titles(pdf_bytes: bytes) -> list[str]:
    """Flatten the PDF outline / TOC to a list of entry titles."""
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    titles: list[str] = []

    def _walk(items: list[object]) -> None:
        for item in items:
            if isinstance(item, list):
                _walk(item)
            elif hasattr(item, "title"):
                titles.append(str(item.title))

    _walk(list(reader.outline))
    return titles


def test_build_pdf_emits_valid_pdf_document() -> None:
    """Bytes must be a syntactically valid PDF that pypdf can parse."""
    verdicts = [
        MasvsControlVerdict(
            control_id="MSTG-STORAGE-1",
            verdict=MasvsVerdict.NO_FINDING,
            confidence=0.7,
            child_investigation_id="inv-storage-1",
            primary_outcome_id="out-storage-1",
        ),
    ]
    pdf = build_pdf(_make_aggregate(verdicts), _make_target())

    assert pdf.startswith(b"%PDF-"), "missing PDF magic header"
    assert b"%%EOF" in pdf[-1024:], "missing %%EOF trailer"
    assert len(pdf) > 2000, "rendered PDF suspiciously small"

    reader = pypdf.PdfReader(io.BytesIO(pdf))
    assert len(reader.pages) >= 2, "expected cover + at least one body page"


def test_build_pdf_cover_carries_apk_identity() -> None:
    """Cover page surfaces display name, package, version, SHA-256, catalog."""
    verdicts = [
        MasvsControlVerdict(
            control_id="MSTG-STORAGE-1",
            verdict=MasvsVerdict.NO_FINDING,
            confidence=0.7,
            child_investigation_id="inv-storage-1",
            primary_outcome_id="out-storage-1",
        ),
    ]
    pdf = build_pdf(_make_aggregate(verdicts), _make_target())
    text = _extract_all_text(pdf)

    assert "OWASP MASVS Audit Report" in text, "cover title missing"
    assert "ExampleCorp Self-Service" in text, "display name missing"
    assert _APK_PACKAGE in text, "package id missing"
    assert _APK_VERSION in text, "version name missing"
    # SHA-256 is split into 8-char groups for readability -- assert a
    # prefix that survives the formatting.
    assert "9228be90" in text, "sha-256 prefix missing"
    assert "1.4.2-aila" in text, "MASVS catalog version missing"


def test_build_pdf_executive_summary_lists_every_verdict_bucket() -> None:
    """Count grid must render the FINDING / NO_FINDING / NOT_APPLICABLE
    / INCONCLUSIVE labels regardless of which verdicts are non-zero.

    The operator looking for "did anything fail this audit" reads the
    grid first; a missing column would make a zero count invisible
    instead of explicit-zero.
    """
    verdicts = [
        MasvsControlVerdict(
            control_id="MSTG-STORAGE-1",
            verdict=MasvsVerdict.FINDING,
            confidence=0.85,
            child_investigation_id="inv-storage-1",
            primary_outcome_id="out-storage-1",
        ),
    ]
    pdf = build_pdf(_make_aggregate(verdicts), _make_target())
    text = _extract_all_text(pdf)

    assert "Executive Summary" in text
    for label in ("FINDING", "NO FINDING", "NOT APPLICABLE", "INCONCLUSIVE"):
        assert label in text, f"executive grid missing label {label!r}"
    # The interpretive sentence carries the total control count.
    assert "1 controls" in text or "1 finding" in text


def test_build_pdf_emits_section_per_group_with_toc_entries() -> None:
    """Each non-empty MASVS group becomes one section + one TOC entry."""
    verdicts = [
        MasvsControlVerdict(
            control_id="MSTG-STORAGE-1",
            verdict=MasvsVerdict.FINDING,
            confidence=0.8,
            child_investigation_id="inv-storage-1",
            primary_outcome_id="out-storage-1",
        ),
        MasvsControlVerdict(
            control_id="MSTG-CRYPTO-1",
            verdict=MasvsVerdict.NOT_APPLICABLE,
            confidence=0.0,
            child_investigation_id="inv-crypto-1",
            reason="not_applicable",
        ),
        MasvsControlVerdict(
            control_id="MSTG-PLATFORM-3",
            verdict=MasvsVerdict.INCONCLUSIVE,
            confidence=0.0,
            child_investigation_id="inv-platform-3",
            reason="timeout",
        ),
    ]
    aggregate = _make_aggregate(
        verdicts,
        by_group={
            MasvsGroup.STORAGE: [verdicts[0]],
            MasvsGroup.CRYPTO: [verdicts[1]],
            MasvsGroup.PLATFORM: [verdicts[2]],
        },
    )
    pdf = build_pdf(aggregate, _make_target())
    text = _extract_all_text(pdf)

    for heading in ("MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-PLATFORM"):
        assert heading in text, f"group section heading missing: {heading}"
    for control_id in ("MSTG-STORAGE-1", "MSTG-CRYPTO-1", "MSTG-PLATFORM-3"):
        assert control_id in text, f"control row missing: {control_id}"

    titles = _outline_titles(pdf)
    assert "Cover" in titles, "cover bookmark missing from PDF outline"
    assert "Executive summary" in titles, "executive bookmark missing"
    for heading in ("MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-PLATFORM"):
        assert heading in titles, f"outline entry missing for {heading}"


def test_build_pdf_skips_empty_groups() -> None:
    """Groups with no verdicts must not render -- empty buckets carry no
    audit signal and would clutter the report with placeholder pages.
    """
    verdicts = [
        MasvsControlVerdict(
            control_id="MSTG-STORAGE-1",
            verdict=MasvsVerdict.NO_FINDING,
            confidence=0.6,
            child_investigation_id="inv-storage-1",
            primary_outcome_id="out-storage-1",
        ),
    ]
    aggregate = _make_aggregate(
        verdicts,
        by_group={MasvsGroup.STORAGE: verdicts},
    )
    pdf = build_pdf(aggregate, _make_target())
    text = _extract_all_text(pdf)

    assert "MASVS-STORAGE" in text
    for absent in ("MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK", "MASVS-CODE"):
        assert absent not in text, f"expected no section for empty group {absent}"


def test_build_pdf_handles_empty_aggregate() -> None:
    """A partial-aggregate render with zero verdicts must still produce
    a valid PDF -- the operator-visible "audit in progress" path lands
    here when every child investigation is still running.
    """
    aggregate = _make_aggregate([], by_group={})
    pdf = build_pdf(aggregate, _make_target())

    assert pdf.startswith(b"%PDF-")
    text = _extract_all_text(pdf)
    assert "OWASP MASVS Audit Report" in text
    # The posture badge falls into the "no findings + no inconclusive"
    # branch, which renders "NO COMPLIANCE GAPS DETECTED".
    assert "NO COMPLIANCE GAPS DETECTED" in text


def test_build_pdf_handles_target_without_apk_overview() -> None:
    """A target whose STATIC_SUMMARY hasn't materialised should still
    render -- the dispatcher guards this case, but the renderer must
    not raise on it either (defence in depth).
    """
    verdicts = [
        MasvsControlVerdict(
            control_id="MSTG-STORAGE-1",
            verdict=MasvsVerdict.NO_FINDING,
            confidence=0.6,
            child_investigation_id="inv-storage-1",
            primary_outcome_id="out-storage-1",
        ),
    ]
    target = _make_target(apk_overview=None)
    pdf = build_pdf(_make_aggregate(verdicts), target)
    text = _extract_all_text(pdf)

    assert "OWASP MASVS Audit Report" in text
    # Package falls back to ``android_package_name`` because the
    # apk_overview.static_summary path is empty.
    assert _APK_PACKAGE in text
    # SHA-256 cell renders as ``(unknown)`` rather than raising.
    assert "(unknown)" in text


def test_build_pdf_overall_posture_reflects_findings() -> None:
    """The cover posture badge collapses summary counts to one word:
    findings present → 'N FINDING(S)'; otherwise the clean-or-partial
    label.
    """
    finding_verdict = MasvsControlVerdict(
        control_id="MSTG-STORAGE-1",
        verdict=MasvsVerdict.FINDING,
        confidence=0.8,
        child_investigation_id="inv-storage-1",
        primary_outcome_id="out-storage-1",
    )
    pdf_with_finding = build_pdf(
        _make_aggregate([finding_verdict]),
        _make_target(),
    )
    assert "1 FINDING" in _extract_all_text(pdf_with_finding)

    clean_verdict = MasvsControlVerdict(
        control_id="MSTG-STORAGE-1",
        verdict=MasvsVerdict.NO_FINDING,
        confidence=0.7,
        child_investigation_id="inv-storage-1",
        primary_outcome_id="out-storage-1",
    )
    pdf_clean = build_pdf(
        _make_aggregate([clean_verdict]),
        _make_target(),
    )
    assert "NO COMPLIANCE GAPS DETECTED" in _extract_all_text(pdf_clean)

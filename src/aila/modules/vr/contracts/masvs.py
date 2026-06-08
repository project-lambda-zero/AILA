"""MASVS audit aggregate contracts (Phase 2 — S-3).

A MASVS audit dispatches one child VR investigation per OWASP MASVS L1
control. After every child reaches a terminal outcome, the aggregator
(:mod:`aila.modules.vr.reporting.masvs_report`) maps each child's primary
outcome to one :class:`MasvsControlVerdict` via the pure rule in
:mod:`aila.modules.vr.masvs.verdict_mapper` (S-4). The collected verdicts
plus group/summary projections become a :class:`MasvsAuditAggregate` —
the input to the ReportLab PDF generator (R-2) and the
``GET /vr/targets/{id}/masvs-report`` payload (R-3).

This module is schema-only:

- The mapping rule lives next to the catalog
  (:mod:`aila.modules.vr.masvs.verdict_mapper`).
- The aggregator lives in
  :mod:`aila.modules.vr.reporting.masvs_report`.

Verdicts are never produced from a dedicated persona — they are read
from the child investigations' primary outcomes and transformed by the
pure mapping rule. Inconclusive is a first-class value: when a child
timed out, exhausted its cost cap, or refuted hypotheses without
landing a primary finding, the verdict is :attr:`MasvsVerdict.INCONCLUSIVE`
with the underlying status carried through in
:attr:`MasvsControlVerdict.reason`.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.masvs.models import MasvsGroup

__all__ = [
    "MasvsAuditAggregate",
    "MasvsControlVerdict",
    "MasvsVerdict",
]


class MasvsVerdict(StrEnum):
    """Per-control verdict the aggregator emits.

    The four values mirror the S-4 mapping rule outputs:

    - :attr:`FINDING` — child investigation primary outcome is a
      ``direct_finding`` with verifier confidence ≥ 0.6.
    - :attr:`NOT_APPLICABLE` — the control does not apply to this APK
      (e.g. ``MSTG-CODE-3`` native-binary symbol strip on an APK that
      ships no ``.so`` files). The child explicitly tagged
      ``not_applicable``.
    - :attr:`NO_FINDING` — the child refuted the hypothesis; no
      compliance gap detected.
    - :attr:`INCONCLUSIVE` — the child reached a terminal state without
      a conclusive outcome (timeout, cost cap exhausted, refuted with
      no primary finding). :attr:`MasvsControlVerdict.reason` carries
      the underlying status.
    """

    FINDING = "finding"
    NOT_APPLICABLE = "not_applicable"
    NO_FINDING = "no_finding"
    INCONCLUSIVE = "inconclusive"


class MasvsControlVerdict(BaseModel):
    """One control's resolved verdict, derived from a child outcome.

    Produced by :func:`aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict`
    (the only writer); consumed by
    :func:`aila.modules.vr.reporting.masvs_report.collect_findings`
    (which groups them) and ``masvs_report.build_pdf`` (which renders
    them). No other path may fabricate a verdict — operator-visible
    verdicts must trace back to a real child investigation outcome.
    """

    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(
        min_length=1,
        max_length=64,
        description="MASVS control id, e.g. ``'MSTG-STORAGE-1'``.",
    )
    verdict: MasvsVerdict
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Verifier confidence forwarded from the child's primary "
            "outcome. ``0.0`` when no conclusive outcome was produced "
            "(inconclusive paths)."
        ),
    )
    child_investigation_id: str = Field(
        min_length=1,
        max_length=64,
        description="Child :class:`VRInvestigation` that produced this verdict.",
    )
    primary_outcome_id: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Child's primary outcome id when one was produced. ``None`` "
            "when the child reached a terminal state without emitting a "
            "primary outcome (timeout, cost cap, abandoned). PDF "
            "renderer (R-2b) uses this to deep-link evidence excerpts."
        ),
    )
    reason: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "Human-readable status carried through from the child for "
            ":attr:`MasvsVerdict.INCONCLUSIVE` verdicts "
            "(e.g. ``'timeout'``, ``'cost_cap_exhausted'``). ``None`` "
            "for the three conclusive verdicts."
        ),
    )


class MasvsAuditAggregate(BaseModel):
    """Aggregated audit ready to render as PDF / API payload.

    Built by :func:`aila.modules.vr.reporting.masvs_report.collect_findings`
    once one or more child VR investigations reach a terminal state.
    Partial aggregates (children still in flight) are valid — the
    aggregator emits whatever verdicts are resolvable at call time and
    the PDF renderer (R-2) reports the remaining controls as
    ``inconclusive (in_progress)``.
    """

    model_config = ConfigDict(extra="forbid")

    parent_id: str = Field(
        min_length=1,
        max_length=64,
        description="Parent :class:`VRInvestigation` id (``kind=masvs_audit``).",
    )
    target_id: str = Field(
        min_length=1,
        max_length=64,
        description="VRTarget id the audit ran against (an ``android_apk`` target).",
    )
    masvs_spec_version: str = Field(
        min_length=1,
        max_length=32,
        description=(
            "MASVS spec version the catalog used at dispatch time, "
            "e.g. ``'1.4.2'`` or ``'2.1.0'``. Pinned on the parent "
            "record so later catalog edits do not invalidate historical "
            "reports."
        ),
    )
    generated_at: datetime = Field(
        description="UTC timestamp at which the aggregate was assembled.",
    )
    verdicts: list[MasvsControlVerdict] = Field(
        default_factory=list,
        description=(
            "Flat list of every resolved verdict, one per child "
            "investigation that has reached a terminal outcome at call "
            "time."
        ),
    )
    by_group: dict[MasvsGroup, list[MasvsControlVerdict]] = Field(
        default_factory=dict,
        description=(
            "Verdicts indexed by MASVS group, in catalog order. Groups "
            "with no resolved verdicts are absent from the map "
            "(empty bucket carries no audit signal)."
        ),
    )
    summary_counts: dict[MasvsVerdict, int] = Field(
        default_factory=dict,
        description=(
            "Per-verdict counts across the full :attr:`verdicts` list. "
            "Sum equals ``len(verdicts)``; absent keys mean zero "
            "occurrences of that verdict in this aggregate."
        ),
    )

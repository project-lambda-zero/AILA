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

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.masvs.models import MasvsGroup

__all__ = [
    "MasvsAuditAggregate",
    "MasvsAuditDispatchResponse",
    "MasvsControlVerdict",
    "MasvsEvidenceLocation",
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


class MasvsEvidenceLocation(BaseModel):
    """One ``{file, function}`` reference cited by a child investigation.

    Sourced verbatim from the child outcome's
    ``payload['affected_components']`` list — the canonical evidence
    shape every DIRECT_FINDING submit carries per ``system_audit.md``.
    The PDF renderer (R-2b) prints these as the "Affected components"
    block under the per-control subsection: file path + function name,
    one row per entry. No source body is fetched here; that resolution
    lives in :func:`aila.modules.vr.reporting.pdf_report._resolve_code_excerpts`
    behind the audit-mcp bridge and is not part of this read-only
    contract.

    Both fields are required at construction; the mapper drops any
    ``affected_components`` entry that does not carry both a non-empty
    ``file`` and a non-empty ``function`` so a malformed payload never
    produces a half-populated location.
    """

    model_config = ConfigDict(extra="forbid")

    file: str = Field(
        min_length=1,
        max_length=512,
        description=(
            "Source-relative path the agent cited, e.g. "
            "``'sources/com/examplecorp/selfservis/login/LoginActivity.java'``."
        ),
    )
    function: str = Field(
        min_length=1,
        max_length=256,
        description=(
            "Function / method name within :attr:`file`, e.g. "
            "``'onCreate'`` or ``'com.example.crypto.AesHelper.encrypt'``."
        ),
    )


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
    evidence_locations: list[MasvsEvidenceLocation] = Field(
        default_factory=list,
        max_length=64,
        description=(
            "``{file, function}`` entries the child investigation cited "
            "as evidence in its primary outcome's "
            "``payload['affected_components']``. Populated by the mapper "
            "for any child whose primary outcome carries a non-empty "
            "components list (typically DIRECT_FINDING submits); empty "
            "for inconclusive paths with no primary outcome and for "
            "outcomes whose payload omits the field. The PDF renderer "
            "(R-2b) prints these under the per-control subsection as "
            "the operator-visible evidence trail."
        ),
    )
    agent_summary: str | None = Field(
        default=None,
        max_length=4000,
        description=(
            "First paragraph(s) of the child investigation's primary "
            "outcome ``payload['answer']`` — the agent's natural-"
            "language conclusion for this control on THIS APK. "
            "Truncated to keep the PDF per-control subsection bounded. "
            "PDF renderer prints this verbatim under the per-control "
            "subsection as 'AUDIT FINDINGS', replacing the catalog's "
            "generic verification_steps as the load-bearing prose. "
            "``None`` when the child reached a terminal state without "
            "an answer field (audit_memo, no_primary_outcome, etc.)."
        ),
    )
    report_section: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Structured per-control report subsection produced by the "
            "section-writer agent (reporting/section_writer.py). When "
            "present, the PDF renderer uses this in place of the raw "
            "agent_summary — fields are sized for direct rendering "
            "(headline / evidence list / risk / remediation / "
            "why_it_matters / confidence_note). Populated lazily by the "
            "PDF endpoint and cached on outcome.payload_json so the "
            "53-LLM-calls-per-PDF cost only pays out once per audit "
            "snapshot."
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


class MasvsAuditDispatchResponse(BaseModel):
    """Response body for ``POST /vr/targets/{target_id}/masvs-audit`` (D-1).

    Returned after the batch dispatcher creates one parent investigation
    (``kind=masvs_audit``) plus one child investigation per L1 control
    (``kind=audit``). The list of ``child_investigation_ids`` is ordered
    to mirror the catalog's iteration order (group-major, then
    catalog-author order within each group) so the frontend can render a
    deterministic per-control progress table without re-sorting.

    Once D-2 has wired ARQ submission, every child id in
    ``child_investigation_ids`` is either pending in the ``vr`` queue or
    listed in ``enqueue_errors`` with the underlying submit failure. In
    both cases the row exists in the database and the operator can
    ``POST /vr/investigations/{id}/re-enqueue`` to retry an individual
    child without re-running the whole dispatcher.
    """

    model_config = ConfigDict(extra="forbid")

    parent_investigation_id: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "Parent :class:`VRInvestigation` id "
            "(``kind=masvs_audit``). Carries the audit batch tag plus "
            "the catalog version pin on "
            ":attr:`VRInvestigationRecord.secondary_target_refs_json`."
        ),
    )
    child_investigation_ids: list[str] = Field(
        default_factory=list,
        description=(
            "One id per dispatched child investigation, in MASVS catalog "
            "order. ``len(child_investigation_ids) == total_controls`` "
            "always — a partial dispatch raises 500 instead of silently "
            "returning fewer ids."
        ),
    )
    total_controls: int = Field(
        ge=0,
        description=(
            "Count of L1 controls the dispatcher fanned out. Matches "
            "``len(child_investigation_ids)``. Surfaced explicitly so the "
            "frontend can render ``0 / total_controls`` progress without "
            "needing to ``len()`` the list itself."
        ),
    )
    masvs_spec_version: str = Field(
        min_length=1,
        max_length=32,
        description=(
            "Catalog version that produced this audit, pinned on the "
            "parent record so D-3 idempotency can match same-target / "
            "same-version dispatches and so the PDF report (R-2) labels "
            "the audit with the catalog snapshot in effect at dispatch "
            "time. Mirrors "
            ":data:`aila.modules.vr.masvs.CATALOG_VERSION`."
        ),
    )
    cost_budget_total_usd: float = Field(
        ge=0.0,
        description=(
            "Sum of every child investigation's ``cost_budget_usd``. "
            "Recorded on the parent so the operator sees total expected "
            "spend in one place before deciding whether to abandon the "
            "audit (D-5)."
        ),
    )
    enqueue_errors: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Per-child submit failures keyed by child investigation id "
            "(D-2). An empty dict means every child landed in the ``vr`` "
            "ARQ queue. A populated entry means the row was created but "
            "no task was enqueued — the operator can call "
            "``POST /vr/investigations/{id}/re-enqueue`` to retry that "
            "child without re-dispatching the whole audit. Failures are "
            "captured (not raised) so a transient queue outage on one "
            "child does not roll back the parent + sibling children. "
            "Always empty on an idempotent reuse "
            "(``idempotent_reuse=True``): the dispatcher does not "
            "re-submit children whose ARQ task was already queued by "
            "the original call — operators retry individual children "
            "via ``/re-enqueue`` instead."
        ),
    )
    idempotent_reuse: bool = Field(
        default=False,
        description=(
            "``True`` when the dispatcher matched an existing active "
            "parent investigation (same target, same "
            ":data:`aila.modules.vr.masvs.CATALOG_VERSION`, and parent "
            "status not yet in a terminal state) and returned that "
            "parent's ids verbatim instead of fanning out a fresh batch "
            "(D-3). The endpoint returns HTTP 200 in that branch and "
            "201 on a fresh dispatch, so clients can distinguish the "
            "two outcomes via either the response status or this field. "
            "An audit that has already reached a terminal status "
            "(COMPLETED / FAILED / ABANDONED) does NOT block a new "
            "dispatch: an operator deliberately re-running an audit "
            "expects fresh child investigations against the latest "
            "target state."
        ),
    )

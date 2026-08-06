"""Wire contracts for the APK static-analysis audit dispatcher and aggregate.

``POST /vr/targets/{target_id}/apk-static-audit`` fans one batch into one
parent :class:`VRInvestigation` (``kind=apk_static_audit``) plus one child
(``kind=audit``) per :attr:`ApkStaticMode.STATIC` check in the catalog.
Each child runs the unchanged vuln_researcher audit chain against the
decompiled APK; only the seed prompt and the parent tag differ from a
one-off audit.

Once every child reaches a terminal outcome, the collector in
:mod:`aila.modules.vr.apk_static.aggregate` projects each child's primary
outcome through the mapping rule in
:mod:`aila.modules.vr.apk_static.verdict_mapper` and returns an
:class:`ApkStaticAuditAggregate` -- the JSON payload behind
``GET /vr/targets/{target_id}/apk-static-audit-aggregate`` and the future
APK static PDF renderer. Verdict semantics are identical to MASVS, so the
aggregate reuses :class:`~aila.modules.vr.contracts.masvs.MasvsVerdict`
and :class:`~aila.modules.vr.contracts.masvs.MasvsEvidenceLocation`
verbatim; only the control-id shape (``APK-<GROUP>-<SLUG>``) and the
grouping enum (:class:`~aila.modules.vr.apk_static.models.ApkStaticGroup`)
differ from the MASVS aggregate.

Schema-only module. The dispatcher lives in
:func:`aila.modules.vr.api_router.create_vr_router`, the catalog in
:mod:`aila.modules.vr.apk_static.catalog`, and the collector in
:mod:`aila.modules.vr.apk_static.aggregate`.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.apk_static.models import ApkStaticGroup
from aila.modules.vr.contracts.masvs import MasvsEvidenceLocation, MasvsVerdict

__all__ = [
    "ApkStaticAuditAggregate",
    "ApkStaticAuditDispatchResponse",
    "ApkStaticControlVerdict",
]


class ApkStaticAuditDispatchResponse(BaseModel):
    """Response body for ``POST /vr/targets/{target_id}/apk-static-audit``.

    Returned after the dispatcher creates one parent investigation
    (``kind=apk_static_audit``) plus one child per STATIC check
    (``kind=audit``). ``child_investigation_ids`` is ordered to mirror
    the catalog's iteration order (group-major, then catalog-author order
    within each group) so the frontend renders a deterministic
    per-check progress table without re-sorting.

    Every child id is either pending in the ``vr`` queue or listed in
    ``enqueue_errors`` with its submit failure. In both cases the row
    exists in the database and the operator can
    ``POST /vr/investigations/{id}/re-enqueue`` to retry an individual
    child without re-running the whole dispatcher.
    """

    model_config = ConfigDict(extra="forbid")

    parent_investigation_id: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "Parent :class:`VRInvestigation` id "
            "(``kind=apk_static_audit``). Carries the audit batch tag "
            "plus the catalog version pin on "
            ":attr:`VRInvestigationRecord.secondary_target_refs_json`."
        ),
    )
    child_investigation_ids: list[str] = Field(
        default_factory=list,
        description=(
            "One id per dispatched child investigation, in catalog "
            "order. ``len(child_investigation_ids) == total_checks`` "
            "always -- a partial dispatch raises 500 instead of silently "
            "returning fewer ids."
        ),
    )
    total_checks: int = Field(
        ge=0,
        description=(
            "Count of STATIC checks the dispatcher fanned out. Matches "
            "``len(child_investigation_ids)``. Surfaced explicitly so the "
            "frontend can render ``0 / total_checks`` progress without "
            "needing to ``len()`` the list itself. EXTRACTOR-mode "
            "catalog entries are never counted here -- they are roadmap "
            "rows, not dispatched investigations."
        ),
    )
    apk_static_spec_version: str = Field(
        min_length=1,
        max_length=32,
        description=(
            "Catalog version that produced this audit, pinned on the "
            "parent record so idempotency can match same-target / "
            "same-version dispatches. Mirrors "
            ":data:`aila.modules.vr.apk_static.APK_STATIC_CATALOG_VERSION`."
        ),
    )
    cost_budget_total_usd: float = Field(
        ge=0.0,
        description=(
            "Sum of every child investigation's ``cost_budget_usd``. "
            "Recorded on the parent so the operator sees total expected "
            "spend in one place before deciding whether to abandon the "
            "audit."
        ),
    )
    enqueue_errors: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Per-child submit failures keyed by child investigation id. "
            "An empty dict means every enqueued child landed in the "
            "``vr`` ARQ queue. A populated entry means the row was "
            "created but no task was enqueued -- the operator can call "
            "``POST /vr/investigations/{id}/re-enqueue`` to retry that "
            "child. Failures are captured (not raised) so a transient "
            "queue outage on one child does not roll back the parent + "
            "sibling children. Always empty on an idempotent reuse."
        ),
    )
    idempotent_reuse: bool = Field(
        default=False,
        description=(
            "``True`` when the dispatcher matched an existing active "
            "parent investigation (same target, same "
            ":data:`aila.modules.vr.apk_static.APK_STATIC_CATALOG_VERSION`, "
            "and parent status not yet terminal) and returned that "
            "parent's ids verbatim instead of fanning out a fresh batch. "
            "The endpoint returns HTTP 200 in that branch and 201 on a "
            "fresh dispatch. A terminal audit (COMPLETED / FAILED / "
            "ABANDONED) does NOT block a new dispatch."
        ),
    )


class ApkStaticControlVerdict(BaseModel):
    """One check's resolved verdict, derived from a child outcome.

    Produced by :func:`aila.modules.vr.apk_static.verdict_mapper.apk_static_child_outcome_to_verdict`
    (the only writer); consumed by
    :func:`aila.modules.vr.apk_static.aggregate.collect_apk_static_findings`
    (which groups them). No other path may fabricate a verdict --
    operator-visible verdicts must trace back to a real child
    investigation outcome.

    Mirrors :class:`~aila.modules.vr.contracts.masvs.MasvsControlVerdict`
    field-for-field. The verdict enum and the evidence-location shape are
    imported from the MASVS contracts because the semantics are identical
    across the two audit surfaces; only :attr:`control_id` documents an
    :class:`~aila.modules.vr.apk_static.models.ApkStaticCheck` id (e.g.
    ``'APK-MANIFEST-1'``) rather than an OWASP MASVS control id.
    """

    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "APK static-analysis check id, e.g. "
            "``'APK-CRYPTO-WEAK-CIPHER'``. Mirrors "
            ":attr:`~aila.modules.vr.apk_static.models.ApkStaticCheck.id`."
        ),
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
            "primary outcome (timeout, cost cap, abandoned)."
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
            "components list; empty for inconclusive paths with no "
            "primary outcome. Reuses the MASVS location shape verbatim -- "
            "the file / function pair is identical across the two "
            "aggregate surfaces."
        ),
    )
    evidence_locations_total: int = Field(
        default=0,
        ge=0,
        description=(
            "Total count of validly-formed entries in the child outcome's "
            "``payload['affected_components']`` BEFORE the per-verdict "
            "cap is applied to :attr:`evidence_locations`. Renderers "
            "use this to show 'N of M shown' when a complex audit's "
            "evidence trail exceeds the display cap."
        ),
    )
    agent_summary: str | None = Field(
        default=None,
        max_length=4000,
        description=(
            "First paragraph(s) of the child investigation's primary "
            "outcome ``payload['answer']`` -- the agent's natural-"
            "language conclusion for this check on THIS APK. Truncated "
            "to keep the aggregate response bounded. ``None`` when the "
            "child reached a terminal state without an answer field "
            "(audit_memo, no_primary_outcome, etc.)."
        ),
    )
    report_section: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Structured per-check report subsection produced by the "
            "section-writer agent. Reserved for the APK static PDF "
            "renderer to consume the same lazy-rendered subsection cache "
            "the MASVS PDF uses; the JSON aggregate endpoint leaves this "
            "``None`` today."
        ),
    )
    scope: str | None = Field(
        default=None,
        max_length=1000,
        description=(
            "Scope statement read from the child investigation's "
            "synthesis ``panel_summary.scope`` -- what the panel examined "
            "before landing the verdict (check under audit, code surface "
            "inspected, evidence base). ``None`` when the child reached "
            "a terminal state without a synthesis panel_summary "
            "(historical outcomes predating the field)."
        ),
    )
    headline: str | None = Field(
        default=None,
        max_length=800,
        description=(
            "Headline verdict read from the child investigation's "
            "synthesis ``panel_summary.headline_verdict``. ``None`` when "
            "the child produced no synthesis panel_summary."
        ),
    )
    key_points: list[str] = Field(
        default_factory=list,
        max_length=12,
        description=(
            "Up to twelve points merging the child synthesis "
            "``panel_summary.points_of_agreement`` and "
            "``panel_summary.points_of_disagreement``. Disagreement "
            "entries are prefixed with ``'Disagreement: '`` so a reader "
            "can tell the two apart without opening the child."
        ),
    )


class ApkStaticAuditAggregate(BaseModel):
    """Aggregated APK static audit ready to render as JSON / PDF payload.

    Built by :func:`aila.modules.vr.apk_static.aggregate.collect_apk_static_findings`
    once one or more child VR investigations reach a terminal state.
    Partial aggregates (children still in flight) are valid -- the
    collector emits whatever verdicts are resolvable at call time and
    marks the remaining checks as :attr:`MasvsVerdict.INCONCLUSIVE`
    (``reason='no_primary_outcome'``) via the mapper.

    Mirrors :class:`~aila.modules.vr.contracts.masvs.MasvsAuditAggregate`
    field-for-field except that the by-group projection is keyed on
    :class:`~aila.modules.vr.apk_static.models.ApkStaticGroup` (the coarse
    evidence-source taxonomy the APK static catalog uses) and the
    catalog-version pin is the APK static one, not the MASVS one.
    """

    model_config = ConfigDict(extra="forbid")

    parent_id: str = Field(
        min_length=1,
        max_length=64,
        description="Parent :class:`VRInvestigation` id (``kind=apk_static_audit``).",
    )
    target_id: str = Field(
        min_length=1,
        max_length=64,
        description="VRTarget id the audit ran against (an ``android_apk`` target).",
    )
    apk_static_spec_version: str = Field(
        min_length=1,
        max_length=32,
        description=(
            "APK static catalog version the batch used at dispatch time "
            "(e.g. ``'1.0.0-aila'``). Pinned on the parent record so "
            "later catalog edits do not invalidate historical audits."
        ),
    )
    generated_at: datetime = Field(
        description="UTC timestamp at which the aggregate was assembled.",
    )
    verdicts: list[ApkStaticControlVerdict] = Field(
        default_factory=list,
        description=(
            "Flat list of every resolved verdict, one per child "
            "investigation that has reached a terminal outcome at call "
            "time."
        ),
    )
    by_group: dict[ApkStaticGroup, list[ApkStaticControlVerdict]] = Field(
        default_factory=dict,
        description=(
            "Verdicts indexed by APK static group, in first-seen order "
            "(matches catalog order since children are dispatched in "
            "catalog order). Groups with no resolved verdicts are absent "
            "from the map -- an empty bucket carries no audit signal."
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

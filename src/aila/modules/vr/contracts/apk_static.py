"""Wire contracts for the APK static-analysis audit dispatcher.

``POST /vr/targets/{target_id}/apk-static-audit`` fans one batch into one
parent :class:`VRInvestigation` (``kind=apk_static_audit``) plus one child
(``kind=audit``) per :attr:`ApkStaticMode.STATIC` check in the catalog.
Each child runs the unchanged vuln_researcher audit chain against the
decompiled APK; only the seed prompt and the parent tag differ from a
one-off audit.

Schema-only module. The dispatcher lives in
:func:`aila.modules.vr.api_router.create_vr_router` and the catalog in
:mod:`aila.modules.vr.apk_static.catalog`.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ApkStaticAuditDispatchResponse",
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

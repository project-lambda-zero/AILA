"""MASVS audit aggregation + PDF rendering for the vr module.

R-1 (this commit) — :func:`collect_findings`. Walks every child
investigation under a MASVS audit parent, projects each child's primary
outcome through the S-4 mapping rule
(:func:`aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict`),
groups verdicts by MASVS control group, and assembles the per-verdict
summary counts. The output is the
:class:`~aila.modules.vr.contracts.masvs.MasvsAuditAggregate` consumed by
the PDF renderer (R-2) and the
``GET /vr/targets/{id}/masvs-report`` payload (R-3).

R-2 / R-3 / R-4 land in later iterations.

Design notes
------------

* The aggregator is read-only. It commits no rows, never invents a
  verdict, and never imports from :mod:`aila.modules.vr.api_router`.
  Operator-visible verdicts trace through the mapper to a real child
  outcome row.
* Catalog version pinned on the parent's
  ``secondary_target_refs_json`` is preserved verbatim so a historical
  audit always reports the version it was dispatched under, even when
  the catalog has since moved on.
* Children whose ``masvs_control_id`` ref is missing or whose control id
  is not in the current catalog are skipped with a log line. The
  parent's pinned version is the audit trail — surfacing a partial
  aggregate beats fabricating a synthetic verdict from a missing
  control entry.
* Partial aggregates are valid: a child still in flight has no
  ``primary_outcome_id`` and lands as
  :attr:`MasvsVerdict.INCONCLUSIVE` with
  ``reason='no_primary_outcome'`` (the mapper's standard rendering for
  a ``None`` outcome). R-2's renderer reads child status when it needs
  to distinguish "still running" from "terminal without an outcome".
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from sqlmodel import select

from aila.modules.vr.contracts import InvestigationKind
from aila.modules.vr.contracts.masvs import (
    MasvsAuditAggregate,
    MasvsControlVerdict,
    MasvsVerdict,
)
from aila.modules.vr.contracts.outcome import (
    OutcomeConfidence,
    OutcomeDispatchStatus,
    OutcomeKind,
    VROutcomeSummary,
)
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.masvs.catalog import CATALOG_VERSION, MASVS_CONTROLS
from aila.modules.vr.masvs.models import MasvsControl, MasvsGroup
from aila.modules.vr.masvs.verdict_mapper import child_outcome_to_verdict
from aila.platform.uow import UnitOfWork

__all__ = ["collect_findings"]

_log = logging.getLogger(__name__)


def _outcome_record_to_summary(
    record: VRInvestigationOutcomeRecord,
) -> VROutcomeSummary:
    """Project a row to the read-only summary the mapper consumes.

    Mirrors the private ``_outcome_summary`` helper in
    :mod:`aila.modules.vr.api_router` so the reporting module never
    imports the FastAPI router. The shape is identical; the legacy NULL
    ``state`` fallback is preserved for outcome rows that pre-date the
    draft-outcome lifecycle (migration 062).
    """
    return VROutcomeSummary(
        id=record.id,
        investigation_id=record.investigation_id,
        branch_id=record.branch_id,
        outcome_kind=OutcomeKind(record.outcome_kind),
        payload=json.loads(record.payload_json or "{}"),
        confidence=OutcomeConfidence(record.confidence),
        evidence_refs=json.loads(record.evidence_refs_json or "[]"),
        accepted_by_operator=record.accepted_by_operator,
        accepted_at=record.accepted_at,
        dispatch_status=OutcomeDispatchStatus(record.dispatch_status),
        dispatch_target=record.dispatch_target,
        created_at=record.created_at,
        state=record.state or "dispatched",
    )


def _extract_spec_version(parent: VRInvestigationRecord) -> str:
    """Parse the catalog version pinned on the parent's secondary refs.

    Falls back to the current :data:`CATALOG_VERSION` when the parent
    row predates the version-pinning convention or carries a malformed
    refs blob. The fallback is logged at WARNING so an upstream schema
    drift surfaces without breaking the aggregate build.
    """
    try:
        refs = json.loads(parent.secondary_target_refs_json or "[]")
    except (ValueError, TypeError):
        _log.warning(
            "MASVS parent %s has unparseable secondary_target_refs_json; "
            "falling back to catalog version %s.",
            parent.id, CATALOG_VERSION,
        )
        return CATALOG_VERSION
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                version = ref.get("masvs_spec_version")
                if isinstance(version, str) and version:
                    return version
    _log.warning(
        "MASVS parent %s missing masvs_spec_version ref; falling back to "
        "catalog version %s.", parent.id, CATALOG_VERSION,
    )
    return CATALOG_VERSION


def _extract_child_control_id(child: VRInvestigationRecord) -> str | None:
    """Read ``masvs_control_id`` from the child's secondary refs JSON.

    Returns ``None`` when the column is malformed or carries no
    ``masvs_control_id`` entry. A parse failure is logged at WARNING so
    upstream schema drift (e.g. a dispatcher regression writing a list
    of strings instead of dicts) surfaces without breaking the
    aggregate build — the caller still drops the verdict for the
    affected child.
    """
    try:
        refs = json.loads(child.secondary_target_refs_json or "[]")
    except (ValueError, TypeError):
        _log.warning(
            "MASVS child %s has unparseable secondary_target_refs_json; "
            "no masvs_control_id resolvable.", child.id,
        )
        return None
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                cid = ref.get("masvs_control_id")
                if isinstance(cid, str) and cid:
                    return cid
    return None


async def collect_findings(parent_id: str) -> MasvsAuditAggregate:
    """Aggregate every child investigation under a MASVS audit parent.

    Steps:

    1. Load the parent row, validate its ``kind == masvs_audit``, and
       extract the catalog version pinned at dispatch time.
    2. Load every child ``VRInvestigationRecord`` linked via
       ``parent_investigation_id``.
    3. Fetch every referenced primary outcome row in one ``IN`` query
       (avoids N+1 SELECT on a ~46-child batch).
    4. Per child: resolve the catalog entry, build a
       :class:`VROutcomeSummary` from the primary outcome row (or
       ``None`` when the child has no ``primary_outcome_id``), and call
       :func:`child_outcome_to_verdict` with the resolved control + the
       child's id.
    5. Group verdicts by :class:`MasvsGroup` (in first-seen order, which
       matches catalog order since children are dispatched in catalog
       order) and tally per-verdict counts.

    :param parent_id: VRInvestigationRecord id of the MASVS audit parent
        (must have ``kind == 'masvs_audit'``).
    :returns: A :class:`MasvsAuditAggregate` carrying one verdict per
        catalogued child investigation, the per-group projection, and
        the per-verdict summary counters.
    :raises ValueError: when ``parent_id`` does not resolve, or the row
        exists but is not a MASVS audit batch root.
    """
    catalog_by_id: dict[str, MasvsControl] = {
        control.id: control for control in MASVS_CONTROLS
    }

    async with UnitOfWork() as uow:
        parent = (
            await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == parent_id,
                ),
            )
        ).first()
        if parent is None:
            raise ValueError(
                f"MASVS audit parent {parent_id!r} not found",
            )
        if parent.kind != InvestigationKind.MASVS_AUDIT.value:
            raise ValueError(
                f"Investigation {parent_id!r} kind={parent.kind!r}; "
                "expected 'masvs_audit'.",
            )

        spec_version = _extract_spec_version(parent)
        target_id = parent.target_id

        children: list[VRInvestigationRecord] = list((
            await uow.session.exec(
                select(VRInvestigationRecord)
                .where(
                    VRInvestigationRecord.parent_investigation_id == parent_id,
                )
                .order_by(VRInvestigationRecord.created_at.asc()),
            )
        ).all())

        primary_ids: list[str] = [
            child.primary_outcome_id
            for child in children
            if child.primary_outcome_id
        ]
        outcome_rows: dict[str, VRInvestigationOutcomeRecord] = {}
        if primary_ids:
            for outcome_record in (
                await uow.session.exec(
                    select(VRInvestigationOutcomeRecord).where(
                        VRInvestigationOutcomeRecord.id.in_(primary_ids),
                    ),
                )
            ).all():
                outcome_rows[outcome_record.id] = outcome_record

    verdicts: list[MasvsControlVerdict] = []
    by_group: dict[MasvsGroup, list[MasvsControlVerdict]] = {}

    for child in children:
        control_id = _extract_child_control_id(child)
        if control_id is None:
            _log.warning(
                "MASVS aggregate %s: child %s missing masvs_control_id "
                "ref; skipping (no verdict emitted).",
                parent_id, child.id,
            )
            continue
        control = catalog_by_id.get(control_id)
        if control is None:
            _log.warning(
                "MASVS aggregate %s: child %s references control %r not "
                "in catalog version %s; skipping (no verdict emitted).",
                parent_id, child.id, control_id, spec_version,
            )
            continue
        outcome_summary: VROutcomeSummary | None = None
        if child.primary_outcome_id:
            outcome_record = outcome_rows.get(child.primary_outcome_id)
            if outcome_record is not None:
                outcome_summary = _outcome_record_to_summary(outcome_record)
        verdict = child_outcome_to_verdict(
            outcome_summary,
            control,
            child_investigation_id=child.id,
        )
        verdicts.append(verdict)
        by_group.setdefault(control.group, []).append(verdict)

    summary_counts: dict[MasvsVerdict, int] = {}
    for verdict in verdicts:
        summary_counts[verdict.verdict] = (
            summary_counts.get(verdict.verdict, 0) + 1
        )

    return MasvsAuditAggregate(
        parent_id=parent.id,
        target_id=target_id,
        masvs_spec_version=spec_version,
        generated_at=datetime.now(UTC),
        verdicts=verdicts,
        by_group=by_group,
        summary_counts=summary_counts,
    )

"""APK static-analysis audit aggregate collector.

Mirrors :func:`aila.modules.vr.reporting.masvs_report.collect_findings`
for the APK static catalog. Walks every child investigation under an
APK static audit parent, projects each child's primary outcome through
the mapping rule in
:mod:`aila.modules.vr.apk_static.verdict_mapper`, groups the verdicts by
:class:`~aila.modules.vr.apk_static.models.ApkStaticGroup`, and tallies
the per-verdict summary counts. The output is the
:class:`~aila.modules.vr.contracts.apk_static.ApkStaticAuditAggregate`
consumed by ``GET /vr/targets/{id}/apk-static-audit-aggregate`` and the
future APK static PDF renderer.

Design notes
------------

* The collector is read-only. It commits no rows, never invents a
  verdict, and never imports from :mod:`aila.modules.vr.api_router`.
  Operator-visible verdicts trace through the mapper to a real child
  outcome row.
* Catalog version pinned on the parent's
  ``secondary_target_refs_json`` is preserved verbatim so a historical
  audit always reports the version it was dispatched under, even when
  the catalog has since moved on.
* Children whose ``apk_static_check_id`` ref is missing or whose check
  id is not in the current catalog are skipped with a log line. The
  parent's pinned version is the audit trail -- surfacing a partial
  aggregate beats fabricating a synthetic verdict from a missing check
  entry.
* Partial aggregates are valid: a child still in flight has no
  ``primary_outcome_id`` and lands as
  :attr:`MasvsVerdict.INCONCLUSIVE` with
  ``reason='no_primary_outcome'`` (the mapper's standard rendering for
  a ``None`` outcome).
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from sqlmodel import select

from aila.modules.vr.apk_static.catalog import (
    APK_STATIC_CATALOG_VERSION,
    APK_STATIC_CHECKS,
)
from aila.modules.vr.apk_static.models import ApkStaticCheck, ApkStaticGroup
from aila.modules.vr.apk_static.verdict_mapper import (
    apk_static_child_outcome_to_verdict,
)
from aila.modules.vr.contracts import InvestigationKind
from aila.modules.vr.contracts.apk_static import (
    ApkStaticAuditAggregate,
    ApkStaticControlVerdict,
)
from aila.modules.vr.contracts.masvs import MasvsVerdict
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
from aila.platform.uow import UnitOfWork

__all__ = ["collect_apk_static_findings"]

_log = logging.getLogger(__name__)


def _outcome_record_to_summary(
    record: VRInvestigationOutcomeRecord,
) -> VROutcomeSummary:
    """Project a row to the read-only summary the mapper consumes.

    Mirrors :func:`aila.modules.vr.reporting.masvs_report._outcome_record_to_summary`
    so the collector does not have to import the MASVS report module.
    The shape is identical; the legacy NULL ``state`` fallback is
    preserved for outcome rows that pre-date the draft-outcome
    lifecycle (migration 062).
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

    Falls back to the current :data:`APK_STATIC_CATALOG_VERSION` when
    the parent row predates the version-pinning convention or carries a
    malformed refs blob. The fallback is logged at WARNING so an
    upstream schema drift surfaces without breaking the aggregate build.
    """
    try:
        refs = json.loads(parent.secondary_target_refs_json or "[]")
    except (ValueError, TypeError):
        _log.warning(
            "APK static parent %s has unparseable secondary_target_refs_json; "
            "falling back to catalog version %s.",
            parent.id, APK_STATIC_CATALOG_VERSION,
        )
        return APK_STATIC_CATALOG_VERSION
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                version = ref.get("apk_static_spec_version")
                if isinstance(version, str) and version:
                    return version
    _log.warning(
        "APK static parent %s missing apk_static_spec_version ref; falling "
        "back to catalog version %s.", parent.id, APK_STATIC_CATALOG_VERSION,
    )
    return APK_STATIC_CATALOG_VERSION


def _extract_child_check_id(child: VRInvestigationRecord) -> str | None:
    """Read ``apk_static_check_id`` from the child's secondary refs JSON.

    Returns ``None`` when the column is malformed or carries no
    ``apk_static_check_id`` entry. A parse failure is logged at WARNING
    so upstream schema drift (e.g. a dispatcher regression writing a
    list of strings instead of dicts) surfaces without breaking the
    aggregate build -- the caller still drops the verdict for the
    affected child.
    """
    try:
        refs = json.loads(child.secondary_target_refs_json or "[]")
    except (ValueError, TypeError):
        _log.warning(
            "APK static child %s has unparseable secondary_target_refs_json; "
            "no apk_static_check_id resolvable.", child.id,
        )
        return None
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                cid = ref.get("apk_static_check_id")
                if isinstance(cid, str) and cid:
                    return cid
    return None


async def collect_apk_static_findings(parent_id: str) -> ApkStaticAuditAggregate:
    """Aggregate every child investigation under an APK static audit parent.

    Steps:

    1. Load the parent row, validate its ``kind == apk_static_audit``,
       and extract the catalog version pinned at dispatch time.
    2. Load every child ``VRInvestigationRecord`` linked via
       ``parent_investigation_id``.
    3. Fetch every referenced primary outcome row in one ``IN`` query
       (avoids N+1 SELECT on a large batch).
    4. Per child: resolve the catalog entry, build a
       :class:`VROutcomeSummary` from the primary outcome row (or
       ``None`` when the child has no ``primary_outcome_id``), and call
       :func:`apk_static_child_outcome_to_verdict` with the resolved
       check + the child's id.
    5. Group verdicts by :class:`ApkStaticGroup` (in first-seen order,
       which matches catalog order since children are dispatched in
       catalog order) and tally per-verdict counts.

    :param parent_id: :class:`VRInvestigationRecord` id of the APK
        static audit parent (must have ``kind == 'apk_static_audit'``).
    :returns: An :class:`ApkStaticAuditAggregate` carrying one verdict
        per catalogued child investigation, the per-group projection,
        and the per-verdict summary counters.
    :raises ValueError: when ``parent_id`` does not resolve, or the row
        exists but is not an APK static audit batch root.
    """
    catalog_by_id: dict[str, ApkStaticCheck] = {
        check.id: check for check in APK_STATIC_CHECKS
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
                f"APK static audit parent {parent_id!r} not found",
            )
        if parent.kind != InvestigationKind.APK_STATIC_AUDIT.value:
            raise ValueError(
                f"Investigation {parent_id!r} kind={parent.kind!r}; "
                "expected 'apk_static_audit'.",
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

    verdicts: list[ApkStaticControlVerdict] = []
    by_group: dict[ApkStaticGroup, list[ApkStaticControlVerdict]] = {}

    for child in children:
        check_id = _extract_child_check_id(child)
        if check_id is None:
            _log.warning(
                "APK static aggregate %s: child %s missing "
                "apk_static_check_id ref; skipping (no verdict emitted).",
                parent_id, child.id,
            )
            continue
        check = catalog_by_id.get(check_id)
        if check is None:
            _log.warning(
                "APK static aggregate %s: child %s references check %r not "
                "in catalog version %s; skipping (no verdict emitted).",
                parent_id, child.id, check_id, spec_version,
            )
            continue
        outcome_summary: VROutcomeSummary | None = None
        if child.primary_outcome_id:
            outcome_record = outcome_rows.get(child.primary_outcome_id)
            if outcome_record is not None:
                outcome_summary = _outcome_record_to_summary(outcome_record)
        verdict = apk_static_child_outcome_to_verdict(
            outcome_summary,
            check,
            child_investigation_id=child.id,
        )
        verdicts.append(verdict)
        by_group.setdefault(check.group, []).append(verdict)

    summary_counts: dict[MasvsVerdict, int] = {}
    for verdict in verdicts:
        summary_counts[verdict.verdict] = (
            summary_counts.get(verdict.verdict, 0) + 1
        )

    return ApkStaticAuditAggregate(
        parent_id=parent.id,
        target_id=target_id,
        apk_static_spec_version=spec_version,
        generated_at=datetime.now(UTC),
        verdicts=verdicts,
        by_group=by_group,
        summary_counts=summary_counts,
    )

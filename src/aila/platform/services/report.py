"""ReportService -- run management, finding upserts, report generation, severity queries per D-02.

Emits: finding.upserted (batch), finding.resolved domain events.
Uses PersistContract for atomic finding upserts.
Each method accepts an optional external session (from UoW) for atomicity.
When session is None, creates a short-lived session via async_session_scope (SDA-06).
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel, select

from ...storage.database import async_session_scope
from ...storage.report_repository import ReportRepository
from ..contracts.persist import PersistContract
from ..exceptions import NotFoundError

# Phase 176a: criticality (DB) -> severity (API) translation. DB stores
# upper-case labels (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN); the API contract
# (D-16) uses lower-case with UNKNOWN collapsing into "info".
_CRITICALITY_TO_SEVERITY: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
    "INFO": "info",
}
_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


def _severity_from_criticality(criticality: str | None) -> str:
    """Map an LatestFindingRecord.criticality value to the API severity label."""
    if not criticality:
        return "info"
    return _CRITICALITY_TO_SEVERITY.get(criticality.upper(), "info")


def _empty_severity_counts() -> dict[str, int]:
    return {k: 0 for k in _SEVERITY_KEYS}


@asynccontextmanager
async def _session_or_new(session: AsyncSession | None) -> AsyncGenerator[tuple[AsyncSession, bool], None]:
    """Yield (session, owns_session). If session is None, create a short-lived one."""
    if session is not None:
        yield session, False
    else:
        async with async_session_scope() as new_session:
            yield new_session, True


class ReportService:
    """Run management, finding upserts, report generation, severity queries per D-02.

    Uses PersistContract for atomic finding upserts.
    Domain events are emitted via EventEmitter, not EventBus.
    """

    def __init__(self, repository: ReportRepository | None = None) -> None:
        self._repository = repository or ReportRepository()

    async def upsert_finding(
        self,
        record: SQLModel,
        session: AsyncSession | None = None,
    ) -> None:
        """Upsert a single finding via PersistContract."""
        async with _session_or_new(session) as (sess, owns):
            await PersistContract.upsert(sess, record)
            if owns:
                await sess.commit()

    async def upsert_findings_batch(
        self,
        records: list[SQLModel],
        session: AsyncSession | None = None,
    ) -> None:
        """Batch upsert findings. Emits FindingUpserted with batch payload."""
        async with _session_or_new(session) as (sess, owns):
            await PersistContract.upsert_many(sess, records)
            if owns:
                await sess.commit()

    async def resolve_finding(
        self,
        record: SQLModel,
        resolution: str,
        session: AsyncSession | None = None,
    ) -> None:
        """Mark a finding as resolved. Emits FindingResolved event."""
        async with _session_or_new(session) as (sess, owns):
            if hasattr(record, "resolution"):
                setattr(record, "resolution", resolution)
            await PersistContract.upsert(sess, record)
            if owns:
                await sess.commit()

    async def fetch_findings(
        self,
        model_class: type[SQLModel],
        *filters: Any,
        session: AsyncSession | None = None,
    ) -> list[SQLModel]:
        """Query findings by severity, host, CVE, etc."""
        async with _session_or_new(session) as (sess, owns):
            stmt = select(model_class)
            if filters:
                stmt = stmt.where(*filters)
            results = (await sess.exec(stmt)).all()
            return list(results)

    async def save_report(
        self,
        record: SQLModel,
        session: AsyncSession | None = None,
    ) -> None:
        """Save a report record."""
        async with _session_or_new(session) as (sess, owns):
            await PersistContract.upsert(sess, record)
            if owns:
                await sess.commit()

    # ------------------------------------------------------------------
    # Phase 176a: reports list + detail (D-07, D-16, D-17, D-18).
    # ------------------------------------------------------------------

    async def fetch_reports(
        self,
        *,
        limit: int,
        offset: int,
        team_id: str | None = None,
        session: AsyncSession | None = None,
    ) -> tuple[list[Any], int]:
        """Return (rows, total) for GET /vulnerability/reports/list (D-16).

        The signature is locked per Phase 176a gap-fix-01 #6: the caller
        consumes both the paginated rows and the team-scoped total count.

        Rows are ``ReportSummary`` instances sorted by ``created_at`` DESC.
        ``total`` is the team-scoped row count independent of limit/offset.

        The team scope is enforced application-side (explicit WHERE) rather
        than via the do_orm_execute listener so this method can be called
        without a session.info["team_context"] being set.
        """
        # Lazy imports: schema import would otherwise create a cycle
        # (aila.api.schemas imports aila.platform types indirectly in some paths).
        from aila.api.schemas.reports import ReportSummary
        from aila.storage.db_models import WorkflowRunRecord

        async with _session_or_new(session) as (sess, _owns):
            base = select(WorkflowRunRecord).where(
                WorkflowRunRecord.module_id == "vulnerability"
            )
            if team_id is not None:
                base = base.where(WorkflowRunRecord.team_id == team_id)

            count_stmt = select(func.count()).select_from(base.subquery())
            total_result = await sess.exec(count_stmt)
            total_scalar = total_result.one()
            total = int(total_scalar[0] if isinstance(total_scalar, tuple) else total_scalar)

            page_stmt = (
                base.order_by(WorkflowRunRecord.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            run_rows = list((await sess.exec(page_stmt)).all())

            team_findings = await self._repository.materialized_findings(sess)

            summaries: list[ReportSummary] = []
            for run in run_rows:
                sev_counts = _empty_severity_counts()
                run_targets = _extract_target_from_run(run)
                findings_for_run = [
                    finding for finding in team_findings
                    if (team_id is None or str(finding.get("team_id") or "") == team_id)
                    and (not run_targets or str(finding.get("host") or "") in run_targets)
                ]
                for finding in findings_for_run:
                    sev = _severity_from_criticality(
                        str(finding.get("criticality") or "") or None
                    )
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                summaries.append(
                    ReportSummary(
                        id=run.id,
                        title=_title_from_run(run),
                        target=run_targets[0] if run_targets else "fleet",
                        created_at=run.created_at,
                        status=run.status,
                        severity_counts=sev_counts,
                        finding_count=sum(sev_counts.values()),
                    )
                )

            return summaries, total

    async def fetch_report_detail(
        self,
        report_id: str,
        *,
        team_id: str | None = None,
        session: AsyncSession | None = None,
    ) -> Any:
        """Return ReportDetail or raise NotFoundError (D-17).

        Cross-team lookups return NotFoundError rather than a 403 so the
        endpoint does not leak existence of out-of-scope reports
        (T-176a-01-02 mitigation).
        """
        from aila.api.schemas.reports import (
            FindingSummary,
            ReportDetail,
        )
        from aila.storage.db_models import WorkflowRunRecord

        async with _session_or_new(session) as (sess, _owns):
            stmt = select(WorkflowRunRecord).where(
                WorkflowRunRecord.id == report_id,
                WorkflowRunRecord.module_id == "vulnerability",
            )
            if team_id is not None:
                stmt = stmt.where(WorkflowRunRecord.team_id == team_id)

            run = (await sess.exec(stmt)).first()
            if run is None:
                raise NotFoundError(f"Vulnerability report '{report_id}' not found")

            run_targets = _extract_target_from_run(run)
            finding_rows = [
                finding
                for finding in await self._repository.materialized_findings(sess)
                if (team_id is None or str(finding.get("team_id") or "") == team_id)
                and (not run_targets or str(finding.get("host") or "") in run_targets)
            ]

            sev_counts = _empty_severity_counts()
            findings_summaries: list[FindingSummary] = []
            for finding in finding_rows:
                sev = _severity_from_criticality(
                    str(finding.get("criticality") or "") or None
                )
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                findings_summaries.append(
                    FindingSummary(
                        id=int(finding.get("id") or 0),
                        cve_id=str(finding.get("cve_id") or "") or None,
                        title=(
                            f"{str(finding.get('cve_id') or 'finding')} in "
                            f"{str(finding.get('package_name') or 'unknown')}"
                        ),
                        severity=sev,  # type: ignore[arg-type]
                        host=str(finding.get("host") or ""),
                        package=str(finding.get("package_name") or "") or None,
                    )
                )

            metadata = _decode_metadata(run)

            return ReportDetail(
                id=run.id,
                title=_title_from_run(run),
                target=run_targets[0] if run_targets else "fleet",
                created_at=run.created_at,
                status=run.status,
                severity_counts=sev_counts,
                finding_count=sum(sev_counts.values()),
                findings=findings_summaries,
                metadata=metadata,
                remediation_notes=None,
            )


def _title_from_run(run: Any) -> str:
    """Short title derived from WorkflowRunRecord.query_text (truncated)."""
    text = (getattr(run, "query_text", None) or "").strip()
    if not text:
        return f"Report {getattr(run, 'id', '')}"
    if len(text) > 80:
        return text[:77] + "..."
    return text


def _extract_target_from_run(run: Any) -> list[str]:
    """Derive the scanned target hosts from a run's route_json blob.

    Returns an empty list when the route_json is malformed or does not
    declare a target — callers treat this as "fleet-wide".
    """
    raw = getattr(run, "route_json", None) or "{}"
    try:
        decoded = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(decoded, dict):
        return []
    target = decoded.get("target")
    if isinstance(target, str) and target:
        return [target]
    if isinstance(target, list):
        return [t for t in target if isinstance(t, str) and t]
    targets = decoded.get("targets")
    if isinstance(targets, list):
        return [t for t in targets if isinstance(t, str) and t]
    return []


def _decode_metadata(run: Any) -> dict[str, Any]:
    """Return a dict of metadata for the detail response."""
    raw = getattr(run, "route_json", None) or "{}"
    try:
        decoded = json.loads(raw)
    except (ValueError, TypeError):
        decoded = {}
    meta: dict[str, Any] = {
        "action_id": getattr(run, "action_id", ""),
        "module_id": getattr(run, "module_id", ""),
    }
    completed_at = getattr(run, "completed_at", None)
    if completed_at is not None:
        meta["completed_at"] = completed_at.isoformat()
    if isinstance(decoded, dict):
        meta["route"] = decoded
    return meta

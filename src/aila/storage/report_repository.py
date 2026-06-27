"""Report query surface for the platform's storage layer.

ReportRepository decouples the platform's report-query tools from module-specific
DB models.  The vulnerability module (and any future module that owns
LatestFindingRecord) injects a materialized query callable via
register_materialized_query() during register_tools() -- the platform never
imports module-specific models directly (Phase 41 DECOUPLE-01 fix).

Two query surfaces are provided:

latest_report() / latest_report_rows() -- artifact-file-backed queries.
    Walk completed WorkflowRunRecords in reverse chronological order and load
    report artifacts from the filesystem via ReportArtifactStore.  A single
    load_run_bundle() call per run reduces I/O (single-load optimization).

latest_materialized_findings() -- DB-backed materialized query.
    Calls the registered module callable to fetch LatestFindingRecord rows
    directly from the DB.  Returns a LatestReportRowsResult with the same
    shape as the artifact-backed surface for uniform downstream handling.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, ClassVar, Protocol

from sqlmodel import Session, select

from aila.platform.contracts.reporting import (
    LatestReportResult,
    LatestReportRowsResult,
    normalize_report_summary_payload,
)

from ..platform.contracts._common import JsonObject
from ..platform.contracts.reporting import TargetReportReference
from ..platform.exceptions import NotFoundError
from .db_models import ReportArtifactRecord, WorkflowRunRecord
from .report_store import ReportArtifactBundle, ReportArtifactStore

MAX_ROW_PAGE_SIZE = 1_000_000


class MaterializedFindingsQuery(Protocol):
    """Callable that accepts (session, target) and returns a list of row dicts.

    The vulnerability module (or any module that owns LatestFindingRecord) injects
    an implementation via ReportRepository(materialized_query=...).  The storage
    layer never imports module-specific DB models directly.
    """

    async def __call__(self, session: Session, target: str | None) -> list[dict[str, Any]]: ...


class RunFindingsQuery(Protocol):
    """Callable that accepts (session, run_id) and returns a list of row dicts.

    Queries PrioritizedFindingRecord by run_id -- returns exactly the findings
    from a specific scan run, not the latest-state materialized view.
    """

    async def __call__(self, session: Session, run_id: str) -> list[dict[str, Any]]: ...


class ReportRepository:
    """Platform query surface for report artifacts and materialized findings.

    Aggregates ReportArtifactStore (file-backed artifact queries) and optional
    module-injected query callables (DB-backed findings queries).
    The platform constructs one ReportRepository and shares it across tools;
    the vulnerability module injects its query callables via
    register_materialized_query() and register_run_findings_query() during
    register_tools().
    """

    _default_materialized_query: ClassVar[MaterializedFindingsQuery | None] = None
    _default_run_findings_query: ClassVar[RunFindingsQuery | None] = None

    def __init__(
        self,
        artifact_store: ReportArtifactStore | None = None,
        materialized_query: MaterializedFindingsQuery | None = None,
        run_findings_query: RunFindingsQuery | None = None,
    ):
        self.artifact_store = artifact_store or ReportArtifactStore()
        self._materialized_query: MaterializedFindingsQuery | None = (
            materialized_query or self.__class__._default_materialized_query
        )
        self._run_findings_query: RunFindingsQuery | None = (
            run_findings_query or self.__class__._default_run_findings_query
        )

    def register_materialized_query(self, query: MaterializedFindingsQuery) -> None:
        """Register the module-supplied callable that fetches materialized findings rows.

        Called by the vulnerability module during register_tools() so the storage layer
        never imports module-specific DB models.  Overwrites any previously registered
        callable (safe because only one module owns LatestFindingRecord).
        """
        self._materialized_query = query
        self.__class__._default_materialized_query = query

    def register_run_findings_query(self, query: RunFindingsQuery) -> None:
        """Register a callable that fetches per-run findings by run_id.

        Returns PrioritizedFindingRecord rows for a specific scan run -- honest
        per-run data, not the latest-state materialized view which may include
        findings from concurrent or later scans.
        """
        self._run_findings_query = query
        self.__class__._default_run_findings_query = query

    @classmethod
    def set_default_queries(
        cls,
        *,
        materialized_query: MaterializedFindingsQuery | None = None,
        run_findings_query: RunFindingsQuery | None = None,
    ) -> None:
        """Set shared default query callables for future repository instances."""
        if materialized_query is not None:
            cls._default_materialized_query = materialized_query
        if run_findings_query is not None:
            cls._default_run_findings_query = run_findings_query

    async def materialized_findings(
        self,
        session: Session,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return module-owned materialized findings rows from the registered query."""
        query = self._materialized_query or self.__class__._default_materialized_query
        if query is None:
            raise NotFoundError(
                "No materialized findings query registered. "
                "The vulnerability module must register a query via ReportRepository."
            )
        return list(await query(session, target))

    async def run_findings(
        self,
        session: Session,
        run_id: str,
    ) -> list[dict[str, Any]]:
        """Return honest per-run findings rows from the registered query."""
        query = self._run_findings_query or self.__class__._default_run_findings_query
        if query is None:
            raise NotFoundError(
                "No run findings query registered. "
                "The vulnerability module must register a query via ReportRepository."
            )
        return list(await query(session, run_id))

    async def latest_report(
        self,
        session,
        target: str | None = None,
        include_content: bool = False,
        module_id: str | None = None,
    ) -> LatestReportResult:
        """Return the latest completed report, optionally filtered to a target system.

        Walks WorkflowRunRecords in reverse chronological order (most recent first).
        For each completed run, calls load_run_bundle() once to load all artifact
        references in a single query (single-load optimization -- avoids N+1 artifact
        lookups).

        Args:
            session: Active SQLModel Session.
            target: Optional system name or hostname to filter to a per-target report.
                When None, returns the most recent fleet-scoped report.
            include_content: If True, reads artifact file content and populates
                report_content, summary_document, and rows_document on the result.
            module_id: If provided, skips runs that do not match this module.

        Returns:
            LatestReportResult with report metadata and optionally file content.

        Raises:
            NotFoundError: If no completed report is found for the given parameters.
        """
        runs = (await session.exec(
            select(WorkflowRunRecord)
            .where(WorkflowRunRecord.status == "completed")
            .order_by(WorkflowRunRecord.completed_at.desc())
        ))
        for run in runs:
            run_module_id = _module_id(run)
            if module_id is not None and run_module_id != module_id:
                continue
            records = await self.artifact_store.list_run_records(session, run.id)
            target_reports = self.artifact_store.target_report_references(records)
            artifact_bundle = await self.artifact_store.load_run_bundle(
                session,
                run.id,
                target=target,
                records=records,
            )

            if target is not None:
                target_report = _find_target_report(target_reports, target)
                if target_report is None or artifact_bundle is None:
                    continue
                target_summary = (
                    artifact_bundle.summary_document
                    if isinstance(artifact_bundle.summary_document, dict)
                    else target_report.summary
                )
                response = LatestReportResult(
                    message=f"Loaded latest report for target '{target}' from run {run.id}.",
                    run_id=run.id,
                    module_id=run_module_id,
                    completed_at=run.completed_at.isoformat() if run.completed_at else None,
                    report_scope="target",
                    target=target_report,
                    report_path=str(artifact_bundle.report_path or ""),
                    report_artifact_id=artifact_bundle.report_artifact_id,
                    summary_path=artifact_bundle.summary_path,
                    summary_artifact_id=artifact_bundle.summary_artifact_id,
                    rows_artifact_id=artifact_bundle.rows_artifact_id,
                    summary=normalize_report_summary_payload(target_summary),
                )
                if include_content:
                    content_payload = _artifact_payload(artifact_bundle)
                    response.artifact_storage = content_payload["artifact_storage"]
                    response.report_content = content_payload["report_content"]
                    response.summary_document = content_payload["summary_document"]
                    response.rows_document = (
                        [dict(row) for row in artifact_bundle.rows_document if isinstance(row, dict)]
                        if isinstance(artifact_bundle.rows_document, list)
                        else None
                    )
                return response

            if artifact_bundle is None or artifact_bundle.report_path is None:
                continue
            summary_payload = (
                artifact_bundle.summary_document
                if isinstance(artifact_bundle.summary_document, dict)
                else {}
            )
            response = LatestReportResult(
                message=f"Loaded latest fleet report from run {run.id}.",
                run_id=run.id,
                module_id=run_module_id,
                completed_at=run.completed_at.isoformat() if run.completed_at else None,
                report_scope="fleet",
                report_path=artifact_bundle.report_path,
                report_artifact_id=artifact_bundle.report_artifact_id,
                summary_path=artifact_bundle.summary_path,
                summary_artifact_id=artifact_bundle.summary_artifact_id,
                rows_artifact_id=artifact_bundle.rows_artifact_id,
                summary=normalize_report_summary_payload(summary_payload),
                target_reports=target_reports,
            )
            if include_content:
                content_payload = _artifact_payload(artifact_bundle)
                response.artifact_storage = content_payload["artifact_storage"]
                response.report_content = content_payload["report_content"]
                response.summary_document = content_payload["summary_document"]
                response.rows_document = (
                    [dict(row) for row in artifact_bundle.rows_document if isinstance(row, dict)]
                    if isinstance(artifact_bundle.rows_document, list)
                    else None
                )
            return response

        target_note = f" for target '{target}'" if target else ""
        raise NotFoundError(f"No completed reports are available{target_note}.")

    async def latest_report_rows(
        self,
        session,
        target: str | None = None,
        offset: int = 0,
        limit: int = 100,
        filters: JsonObject | None = None,
        row_filter: Callable[[list[JsonObject], JsonObject | None], list[JsonObject]] | None = None,
        module_id: str | None = None,
    ) -> LatestReportRowsResult:
        """Return paginated rows from the latest report's rows_json artifact file.

        Calls latest_report() with include_content=True, then applies the
        optional row_filter callable (supplied by the vulnerability module) before
        paginating.  row_filter receives the full row list and the filters dict;
        it is responsible for all domain-specific filtering logic.

        Args:
            session: Active SQLModel Session.
            target: Optional system name / hostname filter.
            offset: Zero-based row offset for pagination.
            limit: Maximum rows to return (capped at MAX_ROW_PAGE_SIZE).
            filters: Arbitrary filter dict forwarded to row_filter.
            row_filter: Optional module-supplied callable that filters and sorts rows.
            module_id: Optional module filter forwarded to latest_report().

        Returns:
            LatestReportRowsResult with total_rows, offset, limit, and the row slice.

        Raises:
            NotFoundError: If no report is found or rows_document is unavailable.
        """
        normalized_offset = max(0, int(offset))
        normalized_limit = max(1, min(int(limit), MAX_ROW_PAGE_SIZE))
        report_payload = await self.latest_report(
            session=session,
            target=target,
            include_content=True,
            module_id=module_id,
        )
        rows_doc = report_payload.rows_document
        if rows_doc is None and report_payload.run_id and self._run_findings_query is not None:
            rows_doc = await self._run_findings_query(session, report_payload.run_id)
        if rows_doc is None:
            raise NotFoundError(
                "Structured report rows are unavailable"
                + (f" for run '{report_payload.run_id}'." if report_payload.run_id else ".")
            )
        rows = rows_doc
        filtered_rows = row_filter(rows, filters) if row_filter is not None else rows
        return LatestReportRowsResult(
            message=report_payload.message,
            run_id=report_payload.run_id,
            module_id=report_payload.module_id,
            completed_at=report_payload.completed_at,
            report_scope=report_payload.report_scope,
            target=report_payload.target,
            report_path=report_payload.report_path,
            report_artifact_id=report_payload.report_artifact_id,
            summary_path=report_payload.summary_path,
            summary_artifact_id=report_payload.summary_artifact_id,
            rows_artifact_id=report_payload.rows_artifact_id,
            summary=report_payload.summary,
            artifact_storage=report_payload.artifact_storage,
            total_rows=len(filtered_rows),
            offset=normalized_offset,
            limit=normalized_limit,
            rows=filtered_rows[normalized_offset : normalized_offset + normalized_limit],
        )

    async def latest_materialized_findings(
        self,
        session,
        target: str | None = None,
        offset: int = 0,
        limit: int = 100,
        filters: JsonObject | None = None,
        row_filter: Callable[[list[JsonObject], JsonObject | None], list[JsonObject]] | None = None,
        module_id: str | None = None,
    ) -> LatestReportRowsResult:
        """Return paginated findings from the module's materialized DB query.

        Unlike latest_report_rows() which reads from filesystem artifacts, this
        method calls the module-injected materialized_query callable to fetch
        LatestFindingRecord rows directly from the database.  The result shape
        is identical to latest_report_rows() for uniform downstream handling.

        Raises NotFoundError if no materialized query is registered (module has
        not called register_materialized_query() yet) or if the query returns
        no results.

        Args:
            session: Active SQLModel Session.
            target: Optional system name / hostname filter passed to the callable.
            offset: Zero-based row offset for pagination.
            limit: Maximum rows to return (capped at MAX_ROW_PAGE_SIZE).
            filters: Arbitrary filter dict forwarded to row_filter.
            row_filter: Optional module-supplied callable that filters and sorts rows.
            module_id: Stored as module_id on the result; not used for filtering here.

        Returns:
            LatestReportRowsResult with materialized findings and summary counts.

        Raises:
            NotFoundError: If no query is registered or the query returns no rows.
        """
        normalized_offset = max(0, int(offset))
        normalized_limit = max(1, min(int(limit), MAX_ROW_PAGE_SIZE))

        records_as_dicts = await self.materialized_findings(session, target)
        if not records_as_dicts:
            raise NotFoundError(
                "No materialized findings available."
                + (f" No findings found for target '{target}'." if target else "")
            )

        rows: list[JsonObject] = list(records_as_dicts)
        filtered_rows = row_filter(rows, filters) if row_filter is not None else rows

        return LatestReportRowsResult(
            message=f"Loaded {len(filtered_rows)} materialized findings"
            + (f" for target '{target}'" if target else " across all targets")
            + ".",
            run_id=None,
            module_id=module_id,
            completed_at=str(records_as_dicts[0].get("last_scanned_at") or "") or None,
            report_scope="latest_target_reports",
            report_path=None,
            report_artifact_id=None,
            summary_path=None,
            summary_artifact_id=None,
            rows_artifact_id=None,
            summary=_build_materialized_summary(filtered_rows),
            artifact_storage="database",
            total_rows=len(filtered_rows),
            offset=normalized_offset,
            limit=normalized_limit,
            rows=filtered_rows[normalized_offset : normalized_offset + normalized_limit],
        )

    async def has_target_reports(self, session, module_id: str | None = None) -> bool:
        """Return True if any target-scoped report artifacts exist.

        Used by planning.has_cached_report() to decide whether to skip a scan.
        When module_id is provided, only runs matching that module are checked.

        Args:
            session: Active SQLModel Session.
            module_id: Optional module filter.  When None, checks across all modules.

        Returns:
            True if at least one target-scoped ReportArtifactRecord exists.
        """
        if module_id is None:
            return (
                (await session.exec(
                    select(ReportArtifactRecord.id)
                    .where(ReportArtifactRecord.scope == "target")
                    .limit(1)
                )).first()
                is not None
            )
        runs = (await session.exec(
            select(WorkflowRunRecord)
            .where(WorkflowRunRecord.status == "completed")
            .order_by(WorkflowRunRecord.completed_at.desc())
        ))
        for run in runs:
            if _module_id(run) != module_id:
                continue
            records = await self.artifact_store.list_run_records(session, run.id)
            if any(record.scope == "target" for record in records):
                return True
        return False


def _find_target_report(target_reports: list[TargetReportReference], target: str) -> TargetReportReference | None:
    normalized_target = target.strip().lower()
    for target_report in target_reports:
        candidates = {
            str(target_report.system_name).strip().lower(),
            str(target_report.host).strip().lower(),
        }
        if normalized_target in candidates:
            return target_report
    return None


def _module_id(run: WorkflowRunRecord) -> str | None:
    route_payload = _parse_json_object(run.route_json)
    if isinstance(route_payload, dict):
        selected_module = route_payload.get("selected_module")
        if isinstance(selected_module, str):
            normalized_module_id = selected_module.strip()
            if normalized_module_id:
                return normalized_module_id

    summary_payload = _parse_json_object(run.summary_json)
    if isinstance(summary_payload, dict):
        summary_module_id = summary_payload.get("module_id")
        if isinstance(summary_module_id, str):
            normalized_module_id = summary_module_id.strip()
            if normalized_module_id:
                return normalized_module_id

    action_id = str(run.action_id or "").strip()
    if "." in action_id:
        prefix = action_id.split(".", 1)[0].strip()
        if prefix:
            return prefix
    return None


def _parse_json_object(payload: str | None) -> dict[str, object]:
    try:
        loaded = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return {}
    if isinstance(loaded, dict):
        return loaded
    return {}


def _artifact_payload(artifact_bundle: ReportArtifactBundle) -> dict[str, object]:
    return {
        "artifact_storage": artifact_bundle.storage,
        "report_content": artifact_bundle.report_content,
        "summary_document": normalize_report_summary_payload(artifact_bundle.summary_document or {})
        if artifact_bundle.summary_document
        else None,
    }


def _build_materialized_summary(rows: list[JsonObject]) -> JsonObject:
    counts: dict[str, int] = {"Immediate": 0, "High": 0, "Moderate": 0, "Planned": 0}
    for row in rows:
        c = str(row.get("criticality") or "")
        if c in counts:
            counts[c] += 1
    return {
        "total_findings": len(rows),
        "immediate": counts["Immediate"],
        "high": counts["High"],
        "moderate": counts["Moderate"],
        "planned": counts["Planned"],
        "report_scope": "latest_target_reports",
    }

"""File-path-backed artifact store for workflow report artifacts.

Report content (CSV, summary JSON, rows JSON) is written to the filesystem by the
workflow and the file paths are registered in ReportArtifactRecord.  The store
never embeds file content in the DB -- only paths are persisted (SCALE-05: keeps
the database lean as report files can be megabytes).

~ (tilde) paths are rejected with an actionable ValueError pointing to the
relevant AILA_* env var.  This was fixed in Phase 46 (SRV-01): server/container
environments cannot expand home-directory paths, so a clear ValueError is
preferable to a silent OSError downstream.

Pruning: artifact records for a run are deleted and recreated on each
persist_run_bundle() call.  Old filesystem files under ``settings.report_dir``
are swept by :func:`purge_expired_report_files`, wired into the platform
reaper cron next to the idempotency-cache / confidence-drift purges. Files
older than ``retention_days`` (default 90; override via the
``AILA_REPORT_FILE_RETENTION_DAYS`` env var) are unlinked; DB records
referencing them are left alone since ``ReportArtifactStore.load_run_bundle``
already tolerates missing files by returning ``None`` for the content fields.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from sqlmodel import select

from aila.platform.contracts.reporting import normalize_report_summary_payload

from ..platform.contracts.reporting import TargetReportReference
from .db_models import ReportArtifactRecord

_log = logging.getLogger(__name__)

# Retention window default for on-disk report artifacts. Mirrors the
# module-constant style used by ``aila.platform.llm.drift`` /
# ``aila.platform.llm.idempotency_cache``: a plain module scalar that the
# reaper cron resolves once at import. The env override matches the
# platform-worker convention (worker.py reads env vars at module scope and
# falls back to the numeric default on parse failure).
try:
    _DEFAULT_REPORT_RETENTION_DAYS: int = int(
        os.environ.get("AILA_REPORT_FILE_RETENTION_DAYS", "90"),
    )
except ValueError:
    _DEFAULT_REPORT_RETENTION_DAYS = 90


@dataclass(slots=True)
class ReportArtifactBundle:
    """In-memory view of all artifacts for a single workflow run or target.

    Built by ReportArtifactStore.load_run_bundle() from the DB records and
    optional filesystem reads.  storage is always "database" (artifact paths
    are DB-registered).  Content fields (report_content, summary_document,
    rows_document) are None until load_run_bundle() reads the file content.

    Artifact IDs (report_artifact_id, summary_artifact_id, rows_artifact_id)
    are the ReportArtifactRecord primary keys assigned at persist_run_bundle()
    time -- these are the canonical artifact IDs surfaced in the API response
    (Phase 46: state_persist is the canonical ID assignment site).
    """

    storage: str
    report_content: str | None = None
    summary_document: dict | None = None
    rows_document: list[dict] | None = None
    report_artifact_id: int | None = None
    summary_artifact_id: int | None = None
    rows_artifact_id: int | None = None
    report_path: str | None = None
    summary_path: str | None = None
    rows_path: str | None = None
    scope: str | None = None
    system_id: int | None = None
    system_name: str | None = None
    host: str | None = None


class ReportArtifactStore:
    """Persist and query report artifact file-path references for workflow runs.

    Operations are split into two phases:
    - persist_run_bundle(): called during state_persist; writes DB records for
      the fleet report and each target report after files exist on disk.
    - load_run_bundle(): called during report queries; reads DB records back and
      optionally loads file content from disk.

    All methods take an explicit Session so callers control the transaction boundary.
    """

    async def persist_run_bundle(
        self,
        session,
        run_id: str,
        report_path: str | Path,
        summary_path: str | Path | None,
        target_reports: list[dict],
    ) -> list[ReportArtifactRecord]:
        """Write or replace all artifact records for a completed workflow run.

        Deletes any existing records for run_id before inserting new ones so that
        re-running persist_run_bundle() for the same run is idempotent.  Calls
        session.flush() (not commit) so callers can commit as part of a larger
        transaction.

        Args:
            session: Active AsyncSession.
            run_id: The workflow run ID these artifacts belong to.
            report_path: Absolute path to the fleet CSV report file.
            summary_path: Absolute path to the fleet summary JSON file, or None.
            target_reports: List of dicts with system_id, system_name, host,
                report_path, summary_path, and rows_path for each target system.

        Returns:
            List of created ReportArtifactRecord instances (flushed but not committed).
        """
        existing_records = list(
            await session.exec(select(ReportArtifactRecord).where(ReportArtifactRecord.run_id == run_id))
        )
        for record in existing_records:
            await session.delete(record)

        created_records: list[ReportArtifactRecord] = []
        for artifact in self._build_records(
            run_id=run_id,
            report_path=report_path,
            summary_path=summary_path,
            target_reports=target_reports,
        ):
            if artifact is None:
                continue
            session.add(artifact)
            created_records.append(artifact)
        await session.flush()
        return created_records

    async def load_run_bundle(
        self,
        session,
        run_id: str,
        target: str | None = None,
        records: list[ReportArtifactRecord] | None = None,
    ) -> ReportArtifactBundle | None:
        """Build a ReportArtifactBundle from DB records and read file content.

        If records is provided (pre-fetched by the caller), uses them directly
        to avoid an additional DB query.  This is the single-load optimization:
        ReportRepository.latest_report() pre-fetches list_run_records() once and
        passes the result here instead of triggering a second query per load.

        Reads summary_json and rows_json file content from disk if the paths exist.
        Missing or unreadable files result in None for the corresponding content
        fields -- not an error (files may have been pruned).

        Args:
            session: Active SQLModel Session (used only if records is None).
            run_id: The workflow run ID to load artifacts for.
            target: Optional system name / hostname to filter to a target bundle.
                When None, returns the fleet-scoped bundle.
            records: Pre-fetched list of ReportArtifactRecord instances.  Pass to
                avoid a redundant DB query when the caller already has them.

        Returns:
            ReportArtifactBundle if matching records exist, None otherwise.
        """
        available_records = list(records) if records is not None else await self.list_run_records(session, run_id)
        if not available_records:
            return None

        selected_records = self._select_records(available_records, target=target)
        if not selected_records:
            return None

        bundle = ReportArtifactBundle(storage="database")
        for record in selected_records:
            if record.artifact_type == "csv":
                bundle.report_artifact_id = record.id
                bundle.report_path = record.path
                bundle.scope = record.scope
                if record.scope == "target":
                    bundle.system_id = record.system_id
                    bundle.system_name = record.system_name
                    bundle.host = record.host
            elif record.artifact_type == "summary_json":
                bundle.summary_artifact_id = record.id
                bundle.summary_path = record.path
                try:
                    bundle.summary_document = normalize_report_summary_payload(
                        json.loads(Path(record.path).read_text(encoding="utf-8"))
                    )
                except (OSError, json.JSONDecodeError):
                    bundle.summary_document = None
            elif record.artifact_type == "rows_json":
                bundle.rows_artifact_id = record.id
                bundle.rows_path = record.path
                try:
                    payload = json.loads(Path(record.path).read_text(encoding="utf-8"))
                    bundle.rows_document = payload if isinstance(payload, list) else None
                except (OSError, json.JSONDecodeError):
                    bundle.rows_document = None
        return bundle

    @staticmethod
    async def list_run_records(session, run_id: str) -> list[ReportArtifactRecord]:
        """Fetch all artifact records for run_id ordered by scope then artifact_type.

        Used by ReportRepository to pre-fetch records in a single query before
        calling load_run_bundle() and target_report_references(), avoiding N+1
        artifact queries.

        Args:
            session: Active AsyncSession.
            run_id: The workflow run ID to query.

        Returns:
            List of ReportArtifactRecord ordered (scope asc, artifact_type asc).
        """
        return list(
            await session.exec(
                select(ReportArtifactRecord)
                .where(ReportArtifactRecord.run_id == run_id)
                .order_by(ReportArtifactRecord.scope.asc(), ReportArtifactRecord.artifact_type.asc())
            )
        )

    @staticmethod
    def _select_records(records: list[ReportArtifactRecord], target: str | None) -> list[ReportArtifactRecord]:
        if target:
            normalized_target = target.strip().lower()
            return [
                record
                for record in records
                if record.scope == "target"
                and normalized_target in {
                    str(record.system_name or "").strip().lower(),
                    str(record.host or "").strip().lower(),
                }
            ]
        return [record for record in records if record.scope == "fleet"]

    @staticmethod
    def target_report_references(records: list[ReportArtifactRecord]) -> list[TargetReportReference]:
        """Build a sorted list of TargetReportReference from per-target artifact records.

        Groups records by (system_id, system_name, host) and populates artifact IDs
        and the per-target summary from the summary_json file if readable.  Results
        are sorted alphabetically by (system_name, host) for stable UI display.

        Args:
            records: All artifact records for a run (from list_run_records()).

        Returns:
            List of TargetReportReference sorted by (system_name, host).
        """
        grouped: dict[tuple[int | None, str, str], dict[str, object]] = {}
        for record in records:
            if record.scope != "target":
                continue
            system_name = str(record.system_name or "")
            host = str(record.host or "")
            key = (record.system_id, system_name, host)
            payload = grouped.setdefault(
                key,
                {
                    "system_id": record.system_id,
                    "system_name": system_name,
                    "host": host,
                    "report_artifact_id": None,
                    "summary_artifact_id": None,
                    "rows_artifact_id": None,
                    "summary": {},
                },
            )
            if record.artifact_type == "csv":
                payload["report_artifact_id"] = record.id
            elif record.artifact_type == "summary_json":
                payload["summary_artifact_id"] = record.id
                try:
                    summary_payload = json.loads(Path(record.path).read_text(encoding="utf-8"))
                    payload["summary"] = normalize_report_summary_payload(summary_payload)
                except (OSError, json.JSONDecodeError):
                    payload["summary"] = {}
            elif record.artifact_type == "rows_json":
                payload["rows_artifact_id"] = record.id
        references = [TargetReportReference.model_validate(item) for item in grouped.values()]
        references.sort(key=lambda item: (item.system_name.lower(), item.host.lower()))
        return references

    @staticmethod
    def _build_records(
        run_id: str,
        report_path: str | Path,
        summary_path: str | Path | None,
        target_reports: list[dict],
    ) -> list[ReportArtifactRecord | None]:
        records: list[ReportArtifactRecord | None] = [
            ReportArtifactStore._artifact_record(
                run_id=run_id,
                scope="fleet",
                artifact_type="csv",
                path=report_path,
            ),
            ReportArtifactStore._artifact_record(
                run_id=run_id,
                scope="fleet",
                artifact_type="summary_json",
                path=summary_path,
            ),
            ReportArtifactStore._artifact_record(
                run_id=run_id,
                scope="fleet",
                artifact_type="rows_json",
                path=f"{Path(report_path).with_suffix('')}.rows.json" if report_path else None,
            ),
        ]
        for item in target_reports:
            records.append(
                ReportArtifactStore._artifact_record(
                    run_id=run_id,
                    scope="target",
                    artifact_type="csv",
                    path=item.get("report_path"),
                    system_id=item.get("system_id"),
                    system_name=item.get("system_name"),
                    host=item.get("host"),
                )
            )
            records.append(
                ReportArtifactStore._artifact_record(
                    run_id=run_id,
                    scope="target",
                    artifact_type="summary_json",
                    path=item.get("summary_path"),
                    system_id=item.get("system_id"),
                    system_name=item.get("system_name"),
                    host=item.get("host"),
                )
            )
            records.append(
                ReportArtifactStore._artifact_record(
                    run_id=run_id,
                    scope="target",
                    artifact_type="rows_json",
                    path=item.get("rows_path"),
                    system_id=item.get("system_id"),
                    system_name=item.get("system_name"),
                    host=item.get("host"),
                )
            )
        return records

    @staticmethod
    def _artifact_record(
        run_id: str,
        scope: str,
        artifact_type: str,
        path: str | Path | None,
        system_id: int | None = None,
        system_name: str | None = None,
        host: str | None = None,
    ) -> ReportArtifactRecord | None:
        """Create a ReportArtifactRecord for the given path.

        path may be synthetic (non-filesystem), e.g. a string like
        "db://run-001/csv". No filesystem existence check is performed --
        the caller is responsible for ensuring the path string is meaningful.
        Returns None only when path is falsy (None or empty string).
        """
        if not path:
            return None
        path_str = str(path)
        return ReportArtifactRecord(
            run_id=run_id,
            scope=scope,
            system_id=system_id,
            system_name=system_name,
            host=host,
            artifact_type=artifact_type,
            path=path_str,
            content=path_str,
        )


async def purge_expired_report_files(
    retention_days: int = _DEFAULT_REPORT_RETENTION_DAYS,
) -> int:
    """Unlink on-disk report files older than ``retention_days`` (by mtime).

    Report artifacts are written flat under ``settings.report_dir`` by
    :class:`aila.platform.tools.reporting.ReportWriteTool`: one CSV, one
    ``.summary.json``, one ``.rows.json`` per run plus per-target variants.
    DB rows in ``ReportArtifactRecord`` are recreated on each
    :meth:`ReportArtifactStore.persist_run_bundle` call, but the disk
    files accumulate forever without a sweep. This function walks the
    top-level of ``report_dir`` and unlinks every regular file whose
    mtime is older than the cutoff.

    The sweep is deliberately shallow (``iterdir`` -- no recursion): the
    report tool writes only into the root of ``report_dir`` and any
    subdirectories are treated as operator-owned and left alone. Symlinks
    that resolve to a directory are also skipped for the same reason.

    Best-effort in the drift / idempotency-cache style: any ``OSError``
    encountered while stat-ing or unlinking a single file is logged at
    WARNING and the walk continues so one unreadable entry cannot block
    the whole tick. Returns the count of files actually deleted (never
    negative).

    Wired into ``aila.platform.tasks.worker.reaper`` alongside
    :func:`aila.platform.llm.idempotency_cache.run_purge_expired_cron`
    and :func:`aila.platform.llm.drift.run_purge_old_records_cron`.

    Args:
        retention_days: Maximum file age in days. Files with mtime older
            than ``now - retention_days`` are removed. Callers may
            override the module default (env-driven,
            ``AILA_REPORT_FILE_RETENTION_DAYS``) per-call.

    Returns:
        Count of files unlinked. ``0`` when the directory is missing,
        when nothing is past the cutoff, or when the top-level iteration
        itself fails (logged at WARNING).
    """
    # Local import: ``aila.config`` pulls the platform settings singleton;
    # importing at module scope would force every consumer of the report
    # store to eagerly resolve settings (and mkdir the report dir) at
    # import time. Keep the surface narrow -- the purge is the only
    # settings consumer in this module.
    from aila.config import get_settings

    report_dir: Path = get_settings().report_dir
    if not report_dir.exists() or not report_dir.is_dir():
        return 0

    cutoff = time.time() - (retention_days * 86400)
    deleted = 0
    try:
        entries = list(report_dir.iterdir())
    except OSError as exc:
        _log.warning(
            "report-file purge: failed to iterate %s: %s", report_dir, exc,
        )
        return 0

    for entry in entries:
        try:
            # ``is_file`` follows symlinks; a symlink to a directory
            # returns False so directories are skipped by the same
            # check. A broken symlink also returns False -- fine, leave
            # it for the operator.
            if not entry.is_file():
                continue
            if entry.stat().st_mtime >= cutoff:
                continue
            entry.unlink()
            deleted += 1
        except OSError as exc:
            # Per-file best-effort: one unreadable / locked file must
            # not abort the sweep. Log and move on.
            _log.warning(
                "report-file purge: failed to unlink %s: %s", entry, exc,
            )
            continue
    return deleted

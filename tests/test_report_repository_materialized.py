"""
Integration tests for DATA-02: ReportRepository.latest_materialized_findings().

After DECOUPLE-01 / STD-06, the storage layer no longer imports LatestFindingRecord
directly.  Tests supply the query callable themselves, mirroring how the vulnerability
module wires it via ReportRepository(materialized_query=...).

The current storage contract is fully async: MaterializedFindingsQuery is defined as
`async def __call__(session, target) -> list[dict]` and ReportRepository awaits the
query callable + `session.exec(...)`. Tests supply an async query fn and drive the
repository through an AsyncSession from `async_session_scope()`, with seeding via
the sync `session_scope()` helper (mirrors tests/test_mttr_tool.py).

Covers:
  - test_latest_findings_replaces_artifact_rows: 2 rows returned via injected callable
  - test_filter_by_target: target= filters to matching host/system_name only
  - test_row_filter_applied: row_filter callable is applied; rows not matching are excluded
  - test_returns_correct_report_scope: result.report_scope == "latest_target_reports"
  - test_empty_table_raises: empty DB raises NotFoundError
  - test_no_query_registered_raises: missing callable raises NotFoundError with clear message
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from sqlmodel import select

from aila.modules.vulnerability.db_models import LatestFindingRecord
from aila.storage.database import async_session_scope, session_scope
from aila.storage.report_repository import ReportRepository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    host: str,
    cve_id: str,
    criticality: str = "High",
    package_name: str = "pkg",
    system_name: str | None = None,
) -> LatestFindingRecord:
    return LatestFindingRecord(
        host=host,
        package_name=package_name,
        cve_id=cve_id,
        system_id=1,
        system_name=system_name or host,
        distribution="ubuntu",
        criticality=criticality,
        score=75.0,
        rationale="test",
        nvd_url="https://nvd.nist.gov",
        last_scanned_at=datetime.now(UTC),
    )


def _seed(*records: LatestFindingRecord) -> None:
    """Seed LatestFindingRecord rows into the shared test DB via sync session_scope."""
    with session_scope() as session:
        for record in records:
            session.add(record)
        session.commit()


async def _query_latest_findings(session, target: str | None) -> list[dict]:
    """Async materialized query callable.

    Mirrors aila.modules.vulnerability.module._query_latest_findings so tests exercise
    the same async contract wired into production without importing that private helper.
    """
    query = select(LatestFindingRecord).order_by(LatestFindingRecord.last_scanned_at.desc())
    if target is not None:
        normalized = target.strip().lower()
        query = query.where(
            (LatestFindingRecord.host == normalized)
            | (LatestFindingRecord.system_name == normalized)
        )
    records = list(await session.exec(query))
    return [
        {
            "system_id": r.system_id,
            "system_name": r.system_name,
            "host": r.host,
            "package_name": r.package_name,
            "cve_id": r.cve_id,
            "criticality": r.criticality,
            "numeric_score": r.score,
            "score": r.score,
            "rationale": r.rationale,
            "fixed_version": r.fixed_version,
            "nvd_url": r.nvd_url,
            "compliance_tags": json.loads(r.compliance_tags_json or "[]"),
            "last_scanned_at": r.last_scanned_at.isoformat() if r.last_scanned_at else None,
        }
        for r in records
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_latest_findings_replaces_artifact_rows(test_db) -> None:
    """Seeding 2 LatestFindingRecord rows and calling latest_materialized_findings()
    returns 2 rows without requiring any ReportArtifactRecord to exist."""
    _seed(
        _finding("prod-01", "CVE-2024-0001"),
        _finding("prod-02", "CVE-2024-0002"),
    )

    repo = ReportRepository(materialized_query=_query_latest_findings)
    async with async_session_scope() as session:
        result = await repo.latest_materialized_findings(session)

    assert result.total_rows == 2
    assert len(result.rows) == 2


async def test_filter_by_target(test_db) -> None:
    """target= parameter limits results to rows matching the given host."""
    _seed(
        _finding("prod-01", "CVE-2024-0001"),
        _finding("prod-02", "CVE-2024-0002"),
    )

    repo = ReportRepository(materialized_query=_query_latest_findings)
    async with async_session_scope() as session:
        result = await repo.latest_materialized_findings(session, target="prod-01")

    assert result.total_rows == 1
    assert result.rows[0]["host"] == "prod-01"


async def test_row_filter_applied(test_db) -> None:
    """row_filter callable is applied: only rows matching the filter are returned."""
    _seed(
        _finding("host-01", "CVE-2024-0001", criticality="Immediate"),
        _finding("host-02", "CVE-2024-0002", criticality="High"),
        _finding("host-03", "CVE-2024-0003", criticality="Planned"),
    )

    def only_immediate(rows, filters):
        return [r for r in rows if r.get("criticality") == "Immediate"]

    repo = ReportRepository(materialized_query=_query_latest_findings)
    async with async_session_scope() as session:
        result = await repo.latest_materialized_findings(session, row_filter=only_immediate)

    assert result.total_rows == 1
    assert result.rows[0]["criticality"] == "Immediate"


async def test_returns_correct_report_scope(test_db) -> None:
    """result.report_scope must equal 'latest_target_reports'."""
    _seed(_finding("host-01", "CVE-2024-0001"))

    repo = ReportRepository(materialized_query=_query_latest_findings)
    async with async_session_scope() as session:
        result = await repo.latest_materialized_findings(session)

    assert result.report_scope == "latest_target_reports"


async def test_empty_table_raises(test_db) -> None:
    """Empty result from injected callable raises NotFoundError."""
    from aila.platform.exceptions import NotFoundError

    repo = ReportRepository(materialized_query=_query_latest_findings)
    async with async_session_scope() as session:
        with pytest.raises(NotFoundError):
            await repo.latest_materialized_findings(session)


async def test_no_query_registered_raises(test_db) -> None:
    """Calling latest_materialized_findings without a registered callable raises NotFoundError
    with a message that names the vulnerability module as the expected registrant.

    ReportRepository stores a class-level default query set by
    aila.modules.vulnerability.module import (via ReportRepository.set_default_queries).
    This test needs a truly-unregistered repository to exercise the missing-query branch,
    so patch the class default to None for the duration of the assertion.
    """
    from aila.platform.exceptions import NotFoundError

    async with async_session_scope() as session:
        with patch.object(ReportRepository, "_default_materialized_query", None):
            repo = ReportRepository()
            with pytest.raises(NotFoundError, match="No materialized findings query registered"):
                await repo.latest_materialized_findings(session)

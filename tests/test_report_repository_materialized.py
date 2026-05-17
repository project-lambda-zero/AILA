"""
Integration tests for DATA-02: ReportRepository.latest_materialized_findings().

After DECOUPLE-01 / STD-06, the storage layer no longer imports LatestFindingRecord
directly.  Tests supply the query callable themselves, mirroring how the vulnerability
module wires it via ReportRepository(materialized_query=...).

Covers:
  - test_latest_findings_replaces_artifact_rows: 2 rows returned via injected callable
  - test_filter_by_target: target= filters to matching host/system_name only
  - test_row_filter_applied: row_filter callable is applied; rows not matching are excluded
  - test_returns_correct_report_scope: result.report_scope == "latest_target_reports"
  - test_empty_table_raises: empty DB raises ValueError
  - test_no_query_registered_raises: missing callable raises ValueError with clear message
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from aila.modules.vulnerability.db_models import LatestFindingRecord
from aila.storage.report_repository import ReportRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(eng)
    yield eng
    SQLModel.metadata.drop_all(eng)


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


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


def _seed(session: Session, *records: LatestFindingRecord) -> None:
    for record in records:
        session.add(record)
    session.commit()


def _make_query_fn(engine):
    """Return a MaterializedFindingsQuery that reads LatestFindingRecord from the given engine.

    This mirrors what the vulnerability module does via _query_latest_findings — the test
    supplies it directly so the test file owns the coupling to db_models, not the storage layer.
    """
    def _query(session: Session, target: str | None) -> list[dict]:
        query = select(LatestFindingRecord).order_by(LatestFindingRecord.last_scanned_at.desc())
        if target is not None:
            normalized = target.strip().lower()
            query = query.where(
                (LatestFindingRecord.host == normalized)
                | (LatestFindingRecord.system_name == normalized)
            )
        records = list(session.exec(query).all())
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
    return _query


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_latest_findings_replaces_artifact_rows(session: Session, engine) -> None:
    """Seeding 2 LatestFindingRecord rows and calling latest_materialized_findings()
    returns 2 rows without requiring any ReportArtifactRecord to exist."""
    _seed(
        session,
        _finding("prod-01", "CVE-2024-0001"),
        _finding("prod-02", "CVE-2024-0002"),
    )

    result = ReportRepository(materialized_query=_make_query_fn(engine)).latest_materialized_findings(session)

    assert result.total_rows == 2
    assert len(result.rows) == 2


def test_filter_by_target(session: Session, engine) -> None:
    """target= parameter limits results to rows matching the given host."""
    _seed(
        session,
        _finding("prod-01", "CVE-2024-0001"),
        _finding("prod-02", "CVE-2024-0002"),
    )

    result = ReportRepository(materialized_query=_make_query_fn(engine)).latest_materialized_findings(session, target="prod-01")

    assert result.total_rows == 1
    assert result.rows[0]["host"] == "prod-01"


def test_row_filter_applied(session: Session, engine) -> None:
    """row_filter callable is applied: only rows matching the filter are returned."""
    _seed(
        session,
        _finding("host-01", "CVE-2024-0001", criticality="Immediate"),
        _finding("host-02", "CVE-2024-0002", criticality="High"),
        _finding("host-03", "CVE-2024-0003", criticality="Planned"),
    )

    def only_immediate(rows, filters):
        return [r for r in rows if r.get("criticality") == "Immediate"]

    result = ReportRepository(materialized_query=_make_query_fn(engine)).latest_materialized_findings(
        session, row_filter=only_immediate
    )

    assert result.total_rows == 1
    assert result.rows[0]["criticality"] == "Immediate"


def test_returns_correct_report_scope(session: Session, engine) -> None:
    """result.report_scope must equal 'latest_target_reports'."""
    _seed(session, _finding("host-01", "CVE-2024-0001"))

    result = ReportRepository(materialized_query=_make_query_fn(engine)).latest_materialized_findings(session)

    assert result.report_scope == "latest_target_reports"


def test_empty_table_raises(session: Session, engine) -> None:
    """Empty result from injected callable raises NotFoundError."""
    from aila.platform.exceptions import NotFoundError

    with pytest.raises(NotFoundError):
        ReportRepository(materialized_query=_make_query_fn(engine)).latest_materialized_findings(session)


def test_no_query_registered_raises(session: Session) -> None:
    """Calling latest_materialized_findings without a registered callable raises NotFoundError
    with a message that names the vulnerability module as the expected registrant."""
    from aila.platform.exceptions import NotFoundError

    with pytest.raises(NotFoundError, match="No materialized findings query registered"):
        ReportRepository().latest_materialized_findings(session)

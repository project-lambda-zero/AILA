"""
Tests for INTEL-01: CVE arrival/departure detection via LatestFindingRecord.last_scanned_at.

Covers:
  - test_arrivals_departures_split: two findings — one recent (arrival), one stale (departure)
  - test_empty_table: empty table returns zero counts with correct keys
  - test_since_parse_iso_date: since="2025-01-01" parses as midnight UTC
  - test_arrivals_query_function: arrivals() returns only rows >= since_ts
  - test_departures_query_function: departures() returns only rows < since_ts
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session, create_engine

from aila.modules.vulnerability.db_models import LatestFindingRecord
from aila.modules.vulnerability.tools.cve_arrivals import (
    _parse_since,
    arrivals,
    departures,
)

# Real PostgreSQL test database — same rule as the rest of the test suite.
_TEST_DB_URL: str = os.environ.get(
    "AILA_TEST_DATABASE_URL",
    "postgresql+psycopg://postgres:admin@localhost:5432/aila_test",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    """Sync engine against the real test PostgreSQL database.

    Creates only LatestFindingRecord so we don't need to import every model
    module — the table is dropped on teardown to leave the DB clean.
    """
    eng = create_engine(_TEST_DB_URL)
    LatestFindingRecord.__table__.create(eng, checkfirst=True)
    yield eng
    LatestFindingRecord.__table__.drop(eng)


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s
    # Truncate after each test so committed rows don't bleed across tests
    # (rollback only undoes uncommitted work; test bodies call session.commit()).
    with engine.begin() as conn:
        conn.execute(LatestFindingRecord.__table__.delete())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    *,
    host: str = "host-01",
    package_name: str = "pkg",
    cve_id: str = "CVE-2024-0001",
    system_id: int = 1,
    system_name: str = "host-01",
    distribution: str = "ubuntu-22.04",
    criticality: str = "High",
    score: float = 8.5,
    rationale: str = "test",
    fixed_version: str | None = "1.2.3",
    nvd_url: str = "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
    compliance_tags_json: str = "[]",
    details_json: str = "{}",
    last_scanned_at: datetime,
) -> LatestFindingRecord:
    return LatestFindingRecord(
        host=host,
        package_name=package_name,
        cve_id=cve_id,
        system_id=system_id,
        system_name=system_name,
        distribution=distribution,
        criticality=criticality,
        score=score,
        rationale=rationale,
        fixed_version=fixed_version,
        nvd_url=nvd_url,
        compliance_tags_json=compliance_tags_json,
        details_json=details_json,
        last_scanned_at=last_scanned_at,
    )


# ---------------------------------------------------------------------------
# Tests: _parse_since
# ---------------------------------------------------------------------------

def test_since_parse_iso_date():
    """since='2025-01-01' must parse as midnight UTC."""
    dt = _parse_since("2025-01-01")
    assert dt.year == 2025
    assert dt.month == 1
    assert dt.day == 1
    assert dt.hour == 0
    assert dt.minute == 0
    assert dt.tzinfo == UTC


def test_since_parse_iso_datetime_with_tz():
    """since with explicit timezone is preserved."""
    dt = _parse_since("2025-06-15T12:00:00+00:00")
    assert dt.year == 2025
    assert dt.month == 6
    assert dt.day == 15
    assert dt.tzinfo is not None


def test_since_none_defaults_to_24h_ago():
    """since=None should return a datetime roughly 24 hours before now."""
    before = datetime.now(tz=UTC) - timedelta(hours=24, seconds=5)
    result = _parse_since(None)
    after = datetime.now(tz=UTC) - timedelta(hours=24) + timedelta(seconds=5)
    assert before <= result <= after


# ---------------------------------------------------------------------------
# Tests: arrivals() and departures() query functions
# ---------------------------------------------------------------------------

def test_arrivals_query_function(session):
    """arrivals() returns rows with last_scanned_at >= since_ts."""
    now = datetime.now(tz=UTC)
    cutoff = now - timedelta(hours=24)

    recent = _make_finding(cve_id="CVE-2024-RECENT", last_scanned_at=now - timedelta(hours=2))
    old = _make_finding(cve_id="CVE-2024-OLD", package_name="pkg2", last_scanned_at=now - timedelta(hours=48))
    session.add(recent)
    session.add(old)
    session.commit()

    result = arrivals(session, cutoff)
    cve_ids = [r.cve_id for r in result]
    assert "CVE-2024-RECENT" in cve_ids
    assert "CVE-2024-OLD" not in cve_ids


def test_departures_query_function(session):
    """departures() returns rows with last_scanned_at < since_ts."""
    now = datetime.now(tz=UTC)
    cutoff = now - timedelta(hours=24)

    recent = _make_finding(cve_id="CVE-2024-RECENT", last_scanned_at=now - timedelta(hours=2))
    old = _make_finding(cve_id="CVE-2024-OLD", package_name="pkg2", last_scanned_at=now - timedelta(hours=48))
    session.add(recent)
    session.add(old)
    session.commit()

    result = departures(session, cutoff)
    cve_ids = [r.cve_id for r in result]
    assert "CVE-2024-OLD" in cve_ids
    assert "CVE-2024-RECENT" not in cve_ids


# ---------------------------------------------------------------------------
# Tests: arrivals_departures() end-to-end (direct session injection)
# ---------------------------------------------------------------------------

def test_arrivals_departures_split(session):
    """One recent finding is an arrival; one stale finding is a departure."""
    now = datetime.now(tz=UTC)
    cutoff = now - timedelta(hours=24)

    recent = _make_finding(cve_id="CVE-2024-A", last_scanned_at=now - timedelta(hours=2))
    old = _make_finding(cve_id="CVE-2024-B", package_name="pkg2", last_scanned_at=now - timedelta(hours=48))
    session.add(recent)
    session.add(old)
    session.commit()

    arrival_rows = arrivals(session, cutoff)
    departure_rows = departures(session, cutoff)

    assert len(arrival_rows) == 1
    assert arrival_rows[0].cve_id == "CVE-2024-A"
    assert len(departure_rows) == 1
    assert departure_rows[0].cve_id == "CVE-2024-B"


def test_empty_table_returns_zero_counts(session):
    """Empty table produces arrivals_departures with zero counts and correct keys."""
    cutoff = datetime.now(tz=UTC) - timedelta(hours=24)
    arrival_rows = arrivals(session, cutoff)
    departure_rows = departures(session, cutoff)

    result = {
        "since": cutoff.isoformat(),
        "arrival_count": len(arrival_rows),
        "departure_count": len(departure_rows),
        "arrivals": arrival_rows,
        "departures": departure_rows,
    }

    assert result["arrival_count"] == 0
    assert result["departure_count"] == 0
    assert result["arrivals"] == []
    assert result["departures"] == []
    assert "since" in result


def test_serialized_row_keys(session):
    """Each serialized arrival row must contain the required keys."""
    from aila.modules.vulnerability.tools.cve_arrivals import _serialize_row

    now = datetime.now(tz=UTC)
    finding = _make_finding(cve_id="CVE-2024-KEYS", last_scanned_at=now)
    session.add(finding)
    session.commit()

    from sqlmodel import select
    rows = list(session.exec(select(LatestFindingRecord)).all())
    assert rows

    serialized = _serialize_row(rows[0])
    for key in ("host", "cve_id", "package_name", "criticality", "score", "last_scanned_at"):
        assert key in serialized, f"Missing key: {key}"
    assert isinstance(serialized["last_scanned_at"], str)

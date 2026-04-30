"""
Tests for DATA-01: LatestFindingRecord upsert behaviour.

Covers:
  - test_upsert_latest_finding: second upsert overwrites first; one row remains
  - test_new_finding_inserted: novel triple is inserted as a single row
  - test_unique_constraint_enforced: raw duplicate INSERT raises IntegrityError
  - test_no_details_json_deserialization: materialized columns are directly readable (DATA-07 guard)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy.dialects.sqlite import insert as sa_insert
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel, create_engine, select

from aila.modules.vulnerability.db_models import LatestFindingRecord


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

def _upsert_finding(session: Session, *, host: str, package_name: str, cve_id: str,
                    system_id: int = 1, system_name: str = "host-01",
                    distribution: str = "ubuntu-22.04", criticality: str = "HIGH",
                    score: float = 8.5, rationale: str = "test rationale",
                    fixed_version: str | None = "1.2.3",
                    nvd_url: str = "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                    compliance_tags: list[str] | None = None,
                    details_json: str = "{}",
                    last_scanned_at: datetime | None = None) -> None:
    """Execute the same upsert logic as state_persist() for test purposes."""
    now = last_scanned_at or datetime.now(timezone.utc)
    stmt = (
        sa_insert(LatestFindingRecord)
        .values(
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
            compliance_tags_json=json.dumps(compliance_tags or []),
            details_json=details_json,
            last_scanned_at=now,
        )
        .on_conflict_do_update(
            index_elements=["host", "package_name", "cve_id"],
            set_={
                "system_id": system_id,
                "system_name": system_name,
                "distribution": distribution,
                "criticality": criticality,
                "score": score,
                "rationale": rationale,
                "fixed_version": fixed_version,
                "nvd_url": nvd_url,
                "compliance_tags_json": json.dumps(compliance_tags or []),
                "details_json": details_json,
                "last_scanned_at": now,
            },
        )
    )
    session.execute(stmt)
    session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_upsert_latest_finding(session: Session) -> None:
    """Running upsert twice for the same triple produces exactly one row with values from second run."""
    key = dict(host="10.0.0.1", package_name="libssl", cve_id="CVE-2024-0001")

    _upsert_finding(session, **key, criticality="MEDIUM", score=5.0,
                    last_scanned_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
    _upsert_finding(session, **key, criticality="HIGH", score=9.0,
                    last_scanned_at=datetime(2024, 6, 1, tzinfo=timezone.utc))

    rows = session.exec(select(LatestFindingRecord)).all()
    assert len(rows) == 1, f"Expected 1 row, got {len(rows)}"

    row = rows[0]
    assert row.criticality == "HIGH"
    assert row.score == 9.0
    # last_scanned_at must reflect the second run
    # SQLite returns naive datetimes; compare without tz
    assert row.last_scanned_at >= datetime(2024, 6, 1)


def test_new_finding_inserted(session: Session) -> None:
    """Upserting a triple not yet in DB inserts exactly one row."""
    _upsert_finding(session, host="10.0.0.2", package_name="curl", cve_id="CVE-2024-9999")

    rows = session.exec(
        select(LatestFindingRecord).where(
            LatestFindingRecord.package_name == "curl"
        )
    ).all()
    assert len(rows) == 1
    assert rows[0].cve_id == "CVE-2024-9999"


def test_unique_constraint_enforced(engine) -> None:
    """Direct duplicate INSERT (no upsert) raises IntegrityError."""
    key_vals = dict(
        host="10.0.0.3",
        package_name="openssl",
        cve_id="CVE-2024-1234",
        system_id=2,
        system_name="host-03",
        distribution="debian-12",
        criticality="CRITICAL",
        score=9.8,
        rationale="direct insert test",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        compliance_tags_json="[]",
        details_json="{}",
        last_scanned_at=datetime.now(timezone.utc),
    )

    with Session(engine) as s:
        s.execute(sa_insert(LatestFindingRecord).values(**key_vals))
        s.commit()

    with Session(engine) as s:
        with pytest.raises(IntegrityError):
            s.execute(sa_insert(LatestFindingRecord).values(**key_vals))
            s.commit()


# ---------------------------------------------------------------------------
# DATA-07 guard tests (Plan 03) — PrioritizedFindingRecord schema enforcement
# ---------------------------------------------------------------------------

def test_prioritized_finding_record_has_no_details_json() -> None:
    """PrioritizedFindingRecord must not have a details_json column (DATA-07)."""
    from aila.modules.vulnerability.db_models import PrioritizedFindingRecord
    assert "details_json" not in PrioritizedFindingRecord.__table__.columns


def test_latest_finding_record_still_has_details_json() -> None:
    """LatestFindingRecord must retain details_json as the sole full-context blob."""
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    assert "details_json" in LatestFindingRecord.__table__.columns


def test_prioritized_finding_no_details_json_kwarg() -> None:
    """Even if details_json= is passed to the constructor (SQLModel ignores unknown kwargs),
    the field must NOT be stored on the instance — the column does not exist (DATA-07)."""
    from aila.modules.vulnerability.db_models import PrioritizedFindingRecord
    record = PrioritizedFindingRecord(
        run_id="r1", system_id=1, host="h", package_name="pkg",
        installed_version="1.0", cve_id="CVE-1", criticality="High",
        score=70.0, rationale="test", nvd_url="https://nvd.nist.gov",
        details_json="{}",   # SQLModel ignores unknown kwargs — must not be stored
    )
    assert not hasattr(record, "details_json"), (
        "details_json must not exist as an attribute on PrioritizedFindingRecord instances"
    )


def test_no_details_json_deserialization(session: Session) -> None:
    """Materialized columns (criticality, score, nvd_url, rationale) are directly readable
    without calling json.loads() — DATA-07 guard."""
    _upsert_finding(
        session,
        host="10.0.0.4",
        package_name="zlib",
        cve_id="CVE-2024-5678",
        criticality="CRITICAL",
        score=9.1,
        rationale="heap overflow in inflate",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-5678",
    )

    row = session.exec(
        select(LatestFindingRecord).where(LatestFindingRecord.cve_id == "CVE-2024-5678")
    ).one()

    # All risk-signal fields must be accessible as plain Python values — no json.loads required
    assert isinstance(row.criticality, str)
    assert row.criticality == "CRITICAL"
    assert isinstance(row.score, float)
    assert row.score == 9.1
    assert isinstance(row.nvd_url, str)
    assert "CVE-2024-5678" in row.nvd_url
    assert isinstance(row.rationale, str)
    assert "heap overflow" in row.rationale

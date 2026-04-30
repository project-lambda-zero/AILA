"""Tests for mttr() and MttrTool (OPS-08 / plan 35-01, Task 1)."""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.dialects.sqlite import insert as sa_insert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(tmp_path):
    from aila.config import Settings
    return Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")


def _setup_db(settings):
    from aila.storage.database import init_db
    init_db(settings)


def _insert_finding(
    settings,
    *,
    host: str,
    package_name: str,
    cve_id: str,
    system_id: int = 1,
    criticality: str = "High",
    score: float = 7.5,
    created_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = created_at or datetime.now(timezone.utc)
    stmt = (
        sa_insert(LatestFindingRecord)
        .values(
            host=host,
            package_name=package_name,
            cve_id=cve_id,
            system_id=system_id,
            system_name=host,
            distribution="ubuntu-22.04",
            criticality=criticality,
            score=score,
            rationale="test",
            fixed_version="1.0.0",
            nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            compliance_tags_json="[]",
            details_json="{}",
            last_scanned_at=now,
            created_at=now,
        )
        .prefix_with("OR REPLACE")
    )
    with session_scope(settings) as session:
        session.exec(stmt)  # type: ignore[arg-type]
        session.commit()


def _insert_remediation(
    settings,
    *,
    host: str,
    package_name: str,
    cve_id: str,
    status: str = "remediated",
    updated_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import RemediationRecord
    from aila.storage.database import session_scope

    now = updated_at or datetime.now(timezone.utc)
    stmt = (
        sa_insert(RemediationRecord)
        .values(
            host=host,
            package_name=package_name,
            cve_id=cve_id,
            status=status,
            notes="",
            updated_at=now,
        )
        .prefix_with("OR REPLACE")
    )
    with session_scope(settings) as session:
        session.exec(stmt)  # type: ignore[arg-type]
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_returns_empty_by_criticality(tmp_path):
    """No RemediationRecord rows -> result['by_criticality'] == {} and result['finding_count'] == 0."""
    from aila.modules.vulnerability.tools.mttr import mttr

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = mttr(settings=settings)

    assert result["by_criticality"] == {}
    assert result["finding_count"] == 0


def test_single_remediated_finding_p50_p90_p99_equal(tmp_path):
    """One remediated record with duration 5 days -> p50=p90=p99=5 for its criticality."""
    from aila.modules.vulnerability.tools.mttr import mttr

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(timezone.utc)
    created = now - timedelta(days=5)
    remediated_at = now

    _insert_finding(
        settings,
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        criticality="High",
        created_at=created,
    )
    _insert_remediation(
        settings,
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        status="remediated",
        updated_at=remediated_at,
    )

    result = mttr(settings=settings)

    assert result["finding_count"] == 1
    assert "High" in result["by_criticality"]
    stats = result["by_criticality"]["High"]
    assert stats["count"] == 1
    assert stats["p50_days"] == pytest.approx(5.0, abs=0.1)
    assert stats["p90_days"] == pytest.approx(5.0, abs=0.1)
    assert stats["p99_days"] == pytest.approx(5.0, abs=0.1)


def test_percentile_ordering(tmp_path):
    """10 remediated High findings with durations [1..10] days -> p50=5, p90=9, p99=10."""
    from aila.modules.vulnerability.tools.mttr import mttr

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(timezone.utc)
    for i in range(1, 11):
        cve = f"CVE-2024-{i:04d}"
        created = now - timedelta(days=i)
        _insert_finding(
            settings,
            host=f"host-{i}",
            package_name="openssl",
            cve_id=cve,
            criticality="High",
            created_at=created,
        )
        _insert_remediation(
            settings,
            host=f"host-{i}",
            package_name="openssl",
            cve_id=cve,
            status="remediated",
            updated_at=now,
        )

    result = mttr(settings=settings)

    assert result["finding_count"] == 10
    stats = result["by_criticality"]["High"]
    assert stats["count"] == 10
    # p50 = durations[ceil(10 * 0.50) - 1] = durations[4] = 5 (sorted ascending: [1..10])
    assert stats["p50_days"] == pytest.approx(5.0, abs=0.1)
    # p90 = durations[ceil(10 * 0.90) - 1] = durations[8] = 9
    assert stats["p90_days"] == pytest.approx(9.0, abs=0.1)
    # p99 = durations[ceil(10 * 0.99) - 1] = durations[9] = 10
    assert stats["p99_days"] == pytest.approx(10.0, abs=0.1)


def test_multiple_criticalities_grouped(tmp_path):
    """Immediate findings and High findings reported separately under different keys."""
    from aila.modules.vulnerability.tools.mttr import mttr

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(timezone.utc)

    # Immediate finding: 1 day
    _insert_finding(
        settings,
        host="host-imm",
        package_name="pkg-a",
        cve_id="CVE-2024-I001",
        criticality="Immediate",
        created_at=now - timedelta(days=1),
    )
    _insert_remediation(
        settings,
        host="host-imm",
        package_name="pkg-a",
        cve_id="CVE-2024-I001",
        status="remediated",
        updated_at=now,
    )

    # High finding: 7 days
    _insert_finding(
        settings,
        host="host-hi",
        package_name="pkg-b",
        cve_id="CVE-2024-H001",
        criticality="High",
        created_at=now - timedelta(days=7),
    )
    _insert_remediation(
        settings,
        host="host-hi",
        package_name="pkg-b",
        cve_id="CVE-2024-H001",
        status="remediated",
        updated_at=now,
    )

    result = mttr(settings=settings)

    assert result["finding_count"] == 2
    assert "Immediate" in result["by_criticality"]
    assert "High" in result["by_criticality"]
    assert result["by_criticality"]["Immediate"]["count"] == 1
    assert result["by_criticality"]["High"]["count"] == 1


def test_unresolved_findings_excluded(tmp_path):
    """RemediationRecord with status='open' not counted in MTTR."""
    from aila.modules.vulnerability.tools.mttr import mttr

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(timezone.utc)

    _insert_finding(
        settings,
        host="host-open",
        package_name="pkg-x",
        cve_id="CVE-2024-X001",
        criticality="High",
        created_at=now - timedelta(days=3),
    )
    # status="open" — should be excluded
    _insert_remediation(
        settings,
        host="host-open",
        package_name="pkg-x",
        cve_id="CVE-2024-X001",
        status="open",
        updated_at=now,
    )

    result = mttr(settings=settings)

    assert result["finding_count"] == 0
    assert result["by_criticality"] == {}


def test_tool_action_query(tmp_path):
    """MttrTool().forward(action='query') returns dict with 'by_criticality' key."""
    from aila.modules.vulnerability.tools.mttr import MttrTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = MttrTool(settings=settings)
    result = tool.forward(action="query")

    assert isinstance(result, dict)
    assert "by_criticality" in result


def test_tool_rejects_bad_action(tmp_path):
    """MttrTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.mttr import MttrTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = MttrTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad")

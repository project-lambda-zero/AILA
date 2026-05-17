"""Tests for package_heat_map() and PackageHeatMapTool (INTEL-03 / plan 34-01, Task 1)."""
from __future__ import annotations

from datetime import UTC, datetime

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
    fixed_version: str | None = "1.0.0",
    last_scanned_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = last_scanned_at or datetime.now(UTC)
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
            fixed_version=fixed_version,
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_db_returns_empty_list(tmp_path):
    """No LatestFindingRecord rows -> result['packages'] == []."""
    from aila.modules.vulnerability.tools.heat_map import package_heat_map

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = package_heat_map(settings=settings)

    assert result["packages"] == []
    assert result["package_count"] == 0


def test_single_package_single_host(tmp_path):
    """One finding for 'openssl' on 'host-a' with criticality='High', score=8.5."""
    from aila.modules.vulnerability.tools.heat_map import package_heat_map

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(
        settings,
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        criticality="High",
        score=8.5,
    )

    result = package_heat_map(settings=settings)

    assert len(result["packages"]) == 1
    pkg = result["packages"][0]
    assert pkg["package_name"] == "openssl"
    assert pkg["host_count"] == 1
    assert pkg["finding_count"] == 1
    assert pkg["max_score"] == 8.5
    assert pkg["avg_score"] == 8.5
    assert pkg["criticality_counts"] == {"Immediate": 0, "High": 1, "Moderate": 0, "Planned": 0}
    assert pkg["has_immediate"] is False


def test_multiple_hosts_same_package(tmp_path):
    """'libssl' on host-a (Immediate, 9.0) + host-b (High, 7.0) -> host_count=2, has_immediate=True."""
    from aila.modules.vulnerability.tools.heat_map import package_heat_map

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(
        settings,
        host="host-a",
        package_name="libssl",
        cve_id="CVE-2024-0010",
        criticality="Immediate",
        score=9.0,
        system_id=1,
    )
    _insert_finding(
        settings,
        host="host-b",
        package_name="libssl",
        cve_id="CVE-2024-0010",
        criticality="High",
        score=7.0,
        system_id=2,
    )

    result = package_heat_map(settings=settings)

    assert len(result["packages"]) == 1
    pkg = result["packages"][0]
    assert pkg["package_name"] == "libssl"
    assert pkg["host_count"] == 2
    assert pkg["finding_count"] == 2
    assert pkg["max_score"] == 9.0
    assert pkg["has_immediate"] is True


def test_sort_order(tmp_path):
    """Three packages with different max_score are ordered descending by max_score."""
    from aila.modules.vulnerability.tools.heat_map import package_heat_map

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="h1", package_name="pkg-low", cve_id="CVE-2024-L01", score=3.0, criticality="Planned")
    _insert_finding(settings, host="h1", package_name="pkg-high", cve_id="CVE-2024-H01", score=9.5, criticality="Immediate")
    _insert_finding(settings, host="h1", package_name="pkg-mid", cve_id="CVE-2024-M01", score=6.0, criticality="Moderate")

    result = package_heat_map(settings=settings)

    scores = [p["max_score"] for p in result["packages"]]
    assert scores == sorted(scores, reverse=True)
    assert result["packages"][0]["package_name"] == "pkg-high"
    assert result["packages"][-1]["package_name"] == "pkg-low"


def test_multiple_cves_same_package_same_host(tmp_path):
    """Same package+host with two CVEs -> host_count=1 (distinct hosts), finding_count=2."""
    from aila.modules.vulnerability.tools.heat_map import package_heat_map

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-x", package_name="curl", cve_id="CVE-2024-C01", score=7.0, criticality="High")
    _insert_finding(settings, host="host-x", package_name="curl", cve_id="CVE-2024-C02", score=8.0, criticality="High")

    result = package_heat_map(settings=settings)

    assert len(result["packages"]) == 1
    pkg = result["packages"][0]
    assert pkg["host_count"] == 1
    assert pkg["finding_count"] == 2


def test_tool_action_query(tmp_path):
    """PackageHeatMapTool().forward(action='query') returns dict with 'packages' key."""
    from aila.modules.vulnerability.tools.heat_map import PackageHeatMapTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = PackageHeatMapTool(settings=settings)
    result = tool.forward(action="query")

    assert isinstance(result, dict)
    assert "packages" in result


def test_tool_rejects_bad_action(tmp_path):
    """PackageHeatMapTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.heat_map import PackageHeatMapTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = PackageHeatMapTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad")

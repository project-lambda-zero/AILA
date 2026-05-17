"""Tests for weekly_digest() and WeeklyDigestTool (EXEC-01 / plan 37-01, Task 1)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

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
    last_scanned_at: datetime | None = None,
    created_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = created_at or datetime.now(UTC)
    scanned = last_scanned_at or now
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
            last_scanned_at=scanned,
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


def test_empty_db_returns_all_keys_with_zero_counts(tmp_path):
    """Empty DB returns dict with required keys; all numeric counts are 0; narrative is non-empty."""
    from aila.modules.vulnerability.tools.digest import weekly_digest

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = weekly_digest(settings=settings)

    # Required top-level keys
    assert "period_days" in result
    assert "generated_at" in result
    assert "risk_posture" in result
    assert "cve_arrivals" in result
    assert "sla_summary" in result
    assert "mttr_summary" in result
    assert "top_packages" in result
    assert "narrative" in result

    # Numeric zero checks
    assert result["risk_posture"]["finding_count"] == 0
    assert result["cve_arrivals"]["arrival_count"] == 0
    assert result["sla_summary"]["breach_count"] == 0
    assert result["mttr_summary"]["tracked_remediations"] == 0

    # narrative is non-empty
    assert isinstance(result["narrative"], str)
    assert len(result["narrative"]) > 0


def test_two_findings_risk_posture_band(tmp_path):
    """With 2 findings (one Immediate, one High), finding_count==2 and band in valid set."""
    from aila.modules.vulnerability.tools.digest import weekly_digest

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(UTC)
    _insert_finding(
        settings,
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        criticality="Immediate",
        score=9.5,
        created_at=now,
    )
    _insert_finding(
        settings,
        host="host-b",
        package_name="curl",
        cve_id="CVE-2024-0002",
        criticality="High",
        score=7.5,
        created_at=now,
    )

    result = weekly_digest(settings=settings)

    assert result["risk_posture"]["finding_count"] == 2
    assert result["risk_posture"]["band"] in {"critical", "high", "moderate", "low"}


def test_recent_finding_counted_in_cve_arrivals(tmp_path):
    """A finding last_scanned_at within 7 days -> cve_arrivals arrival_count >= 1."""
    from aila.modules.vulnerability.tools.digest import weekly_digest

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(UTC)
    recent = now - timedelta(days=3)
    _insert_finding(
        settings,
        host="host-c",
        package_name="libc",
        cve_id="CVE-2024-0003",
        criticality="Moderate",
        score=5.0,
        last_scanned_at=recent,
        created_at=recent,
    )

    result = weekly_digest(settings=settings)

    assert result["cve_arrivals"]["arrival_count"] >= 1


def test_tool_forward_weekly_matches_function(tmp_path):
    """WeeklyDigestTool().forward(action='weekly') returns same shape as weekly_digest()."""
    from aila.modules.vulnerability.tools.digest import WeeklyDigestTool, weekly_digest

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool_result = WeeklyDigestTool(settings=settings).forward(action="weekly")
    func_result = weekly_digest(settings=settings)

    # Same keys
    assert set(tool_result.keys()) == set(func_result.keys())
    # Same structural shape for nested dicts
    assert set(tool_result["risk_posture"].keys()) == set(func_result["risk_posture"].keys())
    assert set(tool_result["cve_arrivals"].keys()) == set(func_result["cve_arrivals"].keys())


def test_tool_rejects_bad_action(tmp_path):
    """WeeklyDigestTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.digest import WeeklyDigestTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = WeeklyDigestTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad")


def test_tool_alias_and_capability(tmp_path):
    """TOOL_ALIAS == 'WEEKLY_DIGEST' and TOOL_CAPABILITY == 'exec.weekly_digest'."""
    from aila.modules.vulnerability.tools.digest import TOOL_ALIAS, TOOL_CAPABILITY

    assert TOOL_ALIAS == "WEEKLY_DIGEST"
    assert TOOL_CAPABILITY == "exec.weekly_digest"

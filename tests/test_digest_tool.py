"""Tests for weekly_digest() and WeeklyDigestTool (EXEC-01 / plan 37-01, Task 1)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insert_finding(
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
    with session_scope() as session:
        session.add(
            LatestFindingRecord(
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
        )
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_empty_db_returns_all_keys_with_zero_counts(test_db):
    """Empty DB returns dict with required keys; all numeric counts are 0; narrative is non-empty."""
    from aila.modules.vulnerability.tools.digest import weekly_digest

    result = await weekly_digest()

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


async def test_two_findings_risk_posture_band(test_db):
    """With 2 findings (one Immediate, one High), finding_count==2 and band in valid set."""
    from aila.modules.vulnerability.tools.digest import weekly_digest

    now = datetime.now(UTC)
    _insert_finding(
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        criticality="Immediate",
        score=9.5,
        created_at=now,
    )
    _insert_finding(
        host="host-b",
        package_name="curl",
        cve_id="CVE-2024-0002",
        criticality="High",
        score=7.5,
        created_at=now,
    )

    result = await weekly_digest()

    assert result["risk_posture"]["finding_count"] == 2
    assert result["risk_posture"]["band"] in {"critical", "high", "moderate", "low"}


async def test_recent_finding_counted_in_cve_arrivals(test_db):
    """A finding last_scanned_at within 7 days -> cve_arrivals arrival_count >= 1."""
    from aila.modules.vulnerability.tools.digest import weekly_digest

    now = datetime.now(UTC)
    recent = now - timedelta(days=3)
    _insert_finding(
        host="host-c",
        package_name="libc",
        cve_id="CVE-2024-0003",
        criticality="Moderate",
        score=5.0,
        last_scanned_at=recent,
        created_at=recent,
    )

    result = await weekly_digest()

    assert result["cve_arrivals"]["arrival_count"] >= 1


async def test_tool_forward_weekly_matches_function(test_db):
    """WeeklyDigestTool().forward(action='weekly') returns same shape as weekly_digest()."""
    from aila.modules.vulnerability.tools.digest import WeeklyDigestTool, weekly_digest

    tool_result = await WeeklyDigestTool().forward(action="weekly")
    func_result = await weekly_digest()

    # Same keys
    assert set(tool_result.keys()) == set(func_result.keys())
    # Same structural shape for nested dicts
    assert set(tool_result["risk_posture"].keys()) == set(func_result["risk_posture"].keys())
    assert set(tool_result["cve_arrivals"].keys()) == set(func_result["cve_arrivals"].keys())


async def test_tool_rejects_bad_action(test_db):
    """WeeklyDigestTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.digest import WeeklyDigestTool

    tool = WeeklyDigestTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad")


def test_tool_alias_and_capability():
    """TOOL_ALIAS == 'WEEKLY_DIGEST' and TOOL_CAPABILITY == 'exec.weekly_digest'."""
    from aila.modules.vulnerability.tools.digest import TOOL_ALIAS, TOOL_CAPABILITY

    assert TOOL_ALIAS == "WEEKLY_DIGEST"
    assert TOOL_CAPABILITY == "exec.weekly_digest"

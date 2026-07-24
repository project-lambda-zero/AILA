"""Tests for sla_breach() and SlaBreachTool (OPS-09 / plan 35-01, Task 2)."""
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
    created_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = created_at or datetime.now(UTC)
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
                last_scanned_at=now,
                created_at=now,
            )
        )
        session.commit()


def _insert_remediation(
    *,
    host: str,
    package_name: str,
    cve_id: str,
    status: str = "remediated",
    updated_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import RemediationRecord
    from aila.storage.database import session_scope

    now = updated_at or datetime.now(UTC)
    with session_scope() as session:
        session.add(
            RemediationRecord(
                host=host,
                package_name=package_name,
                cve_id=cve_id,
                status=status,
                notes="",
                updated_at=now,
            )
        )
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_empty_returns_no_breaches(test_db):
    """No LatestFindingRecord rows -> result['breaches'] == [] and result['finding_count'] == 0."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    result = await sla_breach()

    assert result["breaches"] == []
    assert result["finding_count"] == 0


async def test_within_sla_not_flagged(test_db):
    """Immediate finding created 0.5 days ago (SLA=1 day) -> 50% utilization, no breach (threshold is 80%)."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    now = datetime.now(UTC)
    # Immediate SLA = 1 day; 0.5 days = 50% utilization -- below 80% threshold
    _insert_finding(
        host="host-ok",
        package_name="pkg-ok",
        cve_id="CVE-2024-OK01",
        criticality="Immediate",
        created_at=now - timedelta(days=0.5),
    )

    result = await sla_breach()

    assert result["finding_count"] == 1
    assert result["breaches"] == []
    assert result["breach_count"] == 0


async def test_breach_at_80_percent(test_db):
    """Immediate finding created 0.81 days ago -> escalation_level='warning' (>=80%, <100%)."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    now = datetime.now(UTC)
    # Immediate SLA = 1 day; 0.81 days = 81% utilization -- warning level
    _insert_finding(
        host="host-warn",
        package_name="pkg-warn",
        cve_id="CVE-2024-W001",
        criticality="Immediate",
        created_at=now - timedelta(days=0.81),
    )

    result = await sla_breach()

    assert result["finding_count"] == 1
    assert result["breach_count"] == 1
    assert len(result["breaches"]) == 1
    breach = result["breaches"][0]
    assert breach["escalation_level"] == "warning"
    assert breach["host"] == "host-warn"
    assert breach["cve_id"] == "CVE-2024-W001"


async def test_breach_at_100_percent(test_db):
    """High finding created 7.1 days ago (SLA=7) -> escalation_level='breach' (>=100%, <150%)."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    now = datetime.now(UTC)
    # High SLA = 7 days; 7.1 days = ~101.4% -- breach level
    _insert_finding(
        host="host-breach",
        package_name="pkg-breach",
        cve_id="CVE-2024-B001",
        criticality="High",
        created_at=now - timedelta(days=7.1),
    )

    result = await sla_breach()

    assert result["breach_count"] == 1
    breach = result["breaches"][0]
    assert breach["escalation_level"] == "breach"
    assert breach["sla_days"] == 7
    assert breach["sla_ratio"] >= 1.0


async def test_breach_at_150_percent(test_db):
    """Moderate finding created 46 days ago (SLA=30) -> escalation_level='critical' (>=150%)."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    now = datetime.now(UTC)
    # Moderate SLA = 30 days; 46 days = ~153.3% -- critical level
    _insert_finding(
        host="host-critical",
        package_name="pkg-critical",
        cve_id="CVE-2024-C001",
        criticality="Moderate",
        created_at=now - timedelta(days=46),
    )

    result = await sla_breach()

    assert result["breach_count"] == 1
    breach = result["breaches"][0]
    assert breach["escalation_level"] == "critical"
    assert breach["sla_days"] == 30
    assert breach["sla_ratio"] >= 1.5


async def test_multiple_findings_multiple_levels(test_db):
    """Mix of warning/breach/critical findings in same result."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    now = datetime.now(UTC)

    # warning: Immediate, 0.81 days -> 81%
    _insert_finding(
        host="h1", package_name="pkg1", cve_id="CVE-W001",
        criticality="Immediate", created_at=now - timedelta(days=0.81),
    )
    # breach: High, 7.5 days -> 107%
    _insert_finding(
        host="h2", package_name="pkg2", cve_id="CVE-B001",
        criticality="High", created_at=now - timedelta(days=7.5),
    )
    # critical: Moderate, 50 days -> 167%
    _insert_finding(
        host="h3", package_name="pkg3", cve_id="CVE-C001",
        criticality="Moderate", created_at=now - timedelta(days=50),
    )
    # under threshold: Planned, 10 days -> 11%
    _insert_finding(
        host="h4", package_name="pkg4", cve_id="CVE-OK001",
        criticality="Planned", created_at=now - timedelta(days=10),
    )

    result = await sla_breach()

    assert result["finding_count"] == 4
    assert result["breach_count"] == 3
    levels = {b["escalation_level"] for b in result["breaches"]}
    assert "warning" in levels
    assert "breach" in levels
    assert "critical" in levels


async def test_remediated_findings_excluded(test_db):
    """Findings with a matching remediated RemediationRecord are excluded from breach check."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    now = datetime.now(UTC)
    # This would be critical if counted (46 days, Moderate SLA=30)
    _insert_finding(
        host="host-done", package_name="pkg-done", cve_id="CVE-DONE001",
        criticality="Moderate", created_at=now - timedelta(days=46),
    )
    # Mark it remediated
    _insert_remediation(
        host="host-done", package_name="pkg-done", cve_id="CVE-DONE001",
        status="remediated",
    )

    result = await sla_breach()

    assert result["breaches"] == []


async def test_tool_action_query(test_db):
    """SlaBreachTool().forward(action='query') returns dict with 'breaches' key."""
    from aila.modules.vulnerability.tools.sla_breach import SlaBreachTool

    tool = SlaBreachTool()
    result = await tool.forward(action="query")

    assert isinstance(result, dict)
    assert "breaches" in result


async def test_tool_rejects_bad_action(test_db):
    """SlaBreachTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.sla_breach import SlaBreachTool

    tool = SlaBreachTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad")

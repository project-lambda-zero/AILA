"""Tests for sla_breach() and SlaBreachTool (OPS-09 / plan 35-01, Task 2)."""
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
    created_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = created_at or datetime.now(UTC)
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

    now = updated_at or datetime.now(UTC)
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


def test_empty_returns_no_breaches(tmp_path):
    """No LatestFindingRecord rows -> result['breaches'] == [] and result['finding_count'] == 0."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = sla_breach(settings=settings)

    assert result["breaches"] == []
    assert result["finding_count"] == 0


def test_within_sla_not_flagged(tmp_path):
    """Immediate finding created 0.5 days ago (SLA=1 day) -> 50% utilization, no breach (threshold is 80%)."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(UTC)
    # Immediate SLA = 1 day; 0.5 days = 50% utilization — below 80% threshold
    _insert_finding(
        settings,
        host="host-ok",
        package_name="pkg-ok",
        cve_id="CVE-2024-OK01",
        criticality="Immediate",
        created_at=now - timedelta(days=0.5),
    )

    result = sla_breach(settings=settings)

    assert result["finding_count"] == 1
    assert result["breaches"] == []
    assert result["breach_count"] == 0


def test_breach_at_80_percent(tmp_path):
    """Immediate finding created 0.81 days ago -> escalation_level='warning' (>=80%, <100%)."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(UTC)
    # Immediate SLA = 1 day; 0.81 days = 81% utilization — warning level
    _insert_finding(
        settings,
        host="host-warn",
        package_name="pkg-warn",
        cve_id="CVE-2024-W001",
        criticality="Immediate",
        created_at=now - timedelta(days=0.81),
    )

    result = sla_breach(settings=settings)

    assert result["finding_count"] == 1
    assert result["breach_count"] == 1
    assert len(result["breaches"]) == 1
    breach = result["breaches"][0]
    assert breach["escalation_level"] == "warning"
    assert breach["host"] == "host-warn"
    assert breach["cve_id"] == "CVE-2024-W001"


def test_breach_at_100_percent(tmp_path):
    """High finding created 7.1 days ago (SLA=7) -> escalation_level='breach' (>=100%, <150%)."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(UTC)
    # High SLA = 7 days; 7.1 days = ~101.4% — breach level
    _insert_finding(
        settings,
        host="host-breach",
        package_name="pkg-breach",
        cve_id="CVE-2024-B001",
        criticality="High",
        created_at=now - timedelta(days=7.1),
    )

    result = sla_breach(settings=settings)

    assert result["breach_count"] == 1
    breach = result["breaches"][0]
    assert breach["escalation_level"] == "breach"
    assert breach["sla_days"] == 7
    assert breach["sla_ratio"] >= 1.0


def test_breach_at_150_percent(tmp_path):
    """Moderate finding created 46 days ago (SLA=30) -> escalation_level='critical' (>=150%)."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(UTC)
    # Moderate SLA = 30 days; 46 days = ~153.3% — critical level
    _insert_finding(
        settings,
        host="host-critical",
        package_name="pkg-critical",
        cve_id="CVE-2024-C001",
        criticality="Moderate",
        created_at=now - timedelta(days=46),
    )

    result = sla_breach(settings=settings)

    assert result["breach_count"] == 1
    breach = result["breaches"][0]
    assert breach["escalation_level"] == "critical"
    assert breach["sla_days"] == 30
    assert breach["sla_ratio"] >= 1.5


def test_multiple_findings_multiple_levels(tmp_path):
    """Mix of warning/breach/critical findings in same result."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(UTC)

    # warning: Immediate, 0.81 days -> 81%
    _insert_finding(
        settings, host="h1", package_name="pkg1", cve_id="CVE-W001",
        criticality="Immediate", created_at=now - timedelta(days=0.81),
    )
    # breach: High, 7.5 days -> 107%
    _insert_finding(
        settings, host="h2", package_name="pkg2", cve_id="CVE-B001",
        criticality="High", created_at=now - timedelta(days=7.5),
    )
    # critical: Moderate, 50 days -> 167%
    _insert_finding(
        settings, host="h3", package_name="pkg3", cve_id="CVE-C001",
        criticality="Moderate", created_at=now - timedelta(days=50),
    )
    # under threshold: Planned, 10 days -> 11%
    _insert_finding(
        settings, host="h4", package_name="pkg4", cve_id="CVE-OK001",
        criticality="Planned", created_at=now - timedelta(days=10),
    )

    result = sla_breach(settings=settings)

    assert result["finding_count"] == 4
    assert result["breach_count"] == 3
    levels = {b["escalation_level"] for b in result["breaches"]}
    assert "warning" in levels
    assert "breach" in levels
    assert "critical" in levels


def test_remediated_findings_excluded(tmp_path):
    """Findings with a matching remediated RemediationRecord are excluded from breach check."""
    from aila.modules.vulnerability.tools.sla_breach import sla_breach

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    now = datetime.now(UTC)
    # This would be critical if counted (46 days, Moderate SLA=30)
    _insert_finding(
        settings, host="host-done", package_name="pkg-done", cve_id="CVE-DONE001",
        criticality="Moderate", created_at=now - timedelta(days=46),
    )
    # Mark it remediated
    _insert_remediation(
        settings, host="host-done", package_name="pkg-done", cve_id="CVE-DONE001",
        status="remediated",
    )

    result = sla_breach(settings=settings)

    assert result["breaches"] == []


def test_tool_action_query(tmp_path):
    """SlaBreachTool().forward(action='query') returns dict with 'breaches' key."""
    from aila.modules.vulnerability.tools.sla_breach import SlaBreachTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = SlaBreachTool(settings=settings)
    result = tool.forward(action="query")

    assert isinstance(result, dict)
    assert "breaches" in result


def test_tool_rejects_bad_action(tmp_path):
    """SlaBreachTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.sla_breach import SlaBreachTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = SlaBreachTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad")

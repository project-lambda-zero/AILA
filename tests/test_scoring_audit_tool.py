"""Tests for scoring_audit() and ScoringAuditTool (OPS-11 / plan 35-02, Task 1)."""
from __future__ import annotations

from datetime import UTC, datetime

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
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = datetime.now(UTC)
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_empty_db_returns_no_discrepancies(test_db):
    """No data -> result['discrepancies'] == [] and result['cve_count'] == 0."""
    from aila.modules.vulnerability.tools.scoring_audit import scoring_audit

    result = await scoring_audit()

    assert result["discrepancies"] == []
    assert result["cve_count"] == 0
    assert result["discrepancy_count"] == 0


async def test_consistent_cve_not_flagged(test_db):
    """CVE-2024-0001 scored 'High' on host-a and host-b -> not in discrepancies."""
    from aila.modules.vulnerability.tools.scoring_audit import scoring_audit

    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=1, criticality="High", score=7.0)
    _insert_finding(host="host-b", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=2, criticality="High", score=7.5)

    result = await scoring_audit()

    assert result["discrepancy_count"] == 0
    assert result["discrepancies"] == []
    assert result["cve_count"] == 1


async def test_inconsistent_cve_flagged(test_db):
    """CVE-2024-0001 scored 'High' on host-a but 'Immediate' on host-b -> in discrepancies."""
    from aila.modules.vulnerability.tools.scoring_audit import scoring_audit

    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=1, criticality="High", score=7.0)
    _insert_finding(host="host-b", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=2, criticality="Immediate", score=9.0)

    result = await scoring_audit()

    assert result["discrepancy_count"] == 1
    d = result["discrepancies"][0]
    assert d["cve_id"] == "CVE-2024-0001"
    assert set(d["criticalities"]) == {"High", "Immediate"}
    assert d["criticalities"] == sorted(d["criticalities"])


async def test_discrepancy_entry_has_host_breakdown(test_db):
    """Each discrepancy entry has 'hosts' list with per-host {host, criticality, score}."""
    from aila.modules.vulnerability.tools.scoring_audit import scoring_audit

    _insert_finding(host="host-a", package_name="curl", cve_id="CVE-2024-9999",
                    system_id=1, criticality="Moderate", score=5.0)
    _insert_finding(host="host-b", package_name="curl", cve_id="CVE-2024-9999",
                    system_id=2, criticality="Immediate", score=9.0)

    result = await scoring_audit()

    d = result["discrepancies"][0]
    assert "hosts" in d
    hosts_by_host = {h["host"]: h for h in d["hosts"]}
    assert "host-a" in hosts_by_host
    assert "host-b" in hosts_by_host
    assert hosts_by_host["host-a"]["criticality"] == "Moderate"
    assert hosts_by_host["host-b"]["criticality"] == "Immediate"
    assert hosts_by_host["host-a"]["score"] == 5.0
    assert "package_name" in hosts_by_host["host-a"]


async def test_tool_rejects_bad_action(test_db):
    """ScoringAuditTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.scoring_audit import ScoringAuditTool

    tool = ScoringAuditTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad")

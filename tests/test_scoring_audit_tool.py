"""Tests for scoring_audit() and ScoringAuditTool (OPS-11 / plan 35-02, Task 1)."""
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
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = datetime.now(UTC)
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_db_returns_no_discrepancies(tmp_path):
    """No data -> result['discrepancies'] == [] and result['cve_count'] == 0."""
    from aila.modules.vulnerability.tools.scoring_audit import scoring_audit

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = scoring_audit(settings=settings)

    assert result["discrepancies"] == []
    assert result["cve_count"] == 0
    assert result["discrepancy_count"] == 0


def test_consistent_cve_not_flagged(tmp_path):
    """CVE-2024-0001 scored 'High' on host-a and host-b -> not in discrepancies."""
    from aila.modules.vulnerability.tools.scoring_audit import scoring_audit

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=1, criticality="High", score=7.0)
    _insert_finding(settings, host="host-b", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=2, criticality="High", score=7.5)

    result = scoring_audit(settings=settings)

    assert result["discrepancy_count"] == 0
    assert result["discrepancies"] == []
    assert result["cve_count"] == 1


def test_inconsistent_cve_flagged(tmp_path):
    """CVE-2024-0001 scored 'High' on host-a but 'Immediate' on host-b -> in discrepancies."""
    from aila.modules.vulnerability.tools.scoring_audit import scoring_audit

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=1, criticality="High", score=7.0)
    _insert_finding(settings, host="host-b", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=2, criticality="Immediate", score=9.0)

    result = scoring_audit(settings=settings)

    assert result["discrepancy_count"] == 1
    d = result["discrepancies"][0]
    assert d["cve_id"] == "CVE-2024-0001"
    assert set(d["criticalities"]) == {"High", "Immediate"}
    assert d["criticalities"] == sorted(d["criticalities"])


def test_discrepancy_entry_has_host_breakdown(tmp_path):
    """Each discrepancy entry has 'hosts' list with per-host {host, criticality, score}."""
    from aila.modules.vulnerability.tools.scoring_audit import scoring_audit

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="curl", cve_id="CVE-2024-9999",
                    system_id=1, criticality="Moderate", score=5.0)
    _insert_finding(settings, host="host-b", package_name="curl", cve_id="CVE-2024-9999",
                    system_id=2, criticality="Immediate", score=9.0)

    result = scoring_audit(settings=settings)

    d = result["discrepancies"][0]
    assert "hosts" in d
    hosts_by_host = {h["host"]: h for h in d["hosts"]}
    assert "host-a" in hosts_by_host
    assert "host-b" in hosts_by_host
    assert hosts_by_host["host-a"]["criticality"] == "Moderate"
    assert hosts_by_host["host-b"]["criticality"] == "Immediate"
    assert hosts_by_host["host-a"]["score"] == 5.0
    assert "package_name" in hosts_by_host["host-a"]


def test_tool_rejects_bad_action(tmp_path):
    """ScoringAuditTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.scoring_audit import ScoringAuditTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = ScoringAuditTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad")

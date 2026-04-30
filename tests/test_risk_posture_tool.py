"""Tests for RiskPostureTool (ENT-07 / plan 27-02, Task 2)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest


def _make_settings(tmp_path):
    from aila.config import Settings
    return Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")


def _make_tool(tmp_path):
    """Create RiskPostureTool — its __init__ calls init_db which sets up all tables."""
    from aila.modules.vulnerability.tools.risk_posture import RiskPostureTool
    settings = _make_settings(tmp_path)
    return RiskPostureTool(settings=settings)


def _insert_findings(tool, findings: list[dict]):
    """Insert LatestFindingRecord rows directly via session_scope."""
    from aila.storage.database import session_scope
    from aila.modules.vulnerability.db_models import LatestFindingRecord

    with session_scope(tool.settings) as session:
        for f in findings:
            record = LatestFindingRecord(
                host=f.get("host", "host-a"),
                package_name=f.get("package_name", "pkg"),
                cve_id=f["cve_id"],
                system_id=f.get("system_id", 1),
                criticality=f["criticality"],
                score=f.get("score", 5.0),
                nvd_url="https://nvd.nist.gov/vuln/detail/" + f["cve_id"],
                last_scanned_at=f.get("created_at", datetime(2024, 1, 1, tzinfo=timezone.utc)),
                created_at=f.get("created_at", datetime(2024, 1, 1, tzinfo=timezone.utc)),
            )
            session.add(record)
        session.commit()


def test_empty_db_returns_zero_score(tmp_path):
    tool = _make_tool(tmp_path)
    result = tool.forward(action="score")
    assert result["score"] == 0.0
    assert result["band"] == "low"
    assert result["finding_count"] == 0


def test_four_immediate_findings_score_100_critical(tmp_path):
    tool = _make_tool(tmp_path)
    findings = [
        {"cve_id": f"CVE-2024-000{i}", "criticality": "Immediate"}
        for i in range(4)
    ]
    _insert_findings(tool, findings)
    result = tool.forward(action="score")
    assert result["score"] == 100.0
    assert result["band"] == "critical"
    assert result["finding_count"] == 4
    assert result["criticality_counts"]["Immediate"] == 4


def test_four_planned_findings_score_25_moderate(tmp_path):
    """4 Planned findings: raw=4*1=4, max=4*4=16, score=4/16*100=25.0, band=moderate."""
    tool = _make_tool(tmp_path)
    findings = [
        {"cve_id": f"CVE-2024-000{i}", "criticality": "Planned"}
        for i in range(4)
    ]
    _insert_findings(tool, findings)
    result = tool.forward(action="score")
    assert result["score"] == 25.0
    assert result["band"] == "moderate"
    assert result["finding_count"] == 4


def test_mixed_findings_produce_correct_weighted_average(tmp_path):
    """
    1 Immediate (w=4), 1 High (w=3), 1 Moderate (w=2), 1 Planned (w=1)
    raw=10, max=16, score=round(10/16*100, 1)=62.5, band=high
    """
    tool = _make_tool(tmp_path)
    findings = [
        {"cve_id": "CVE-2024-0001", "criticality": "Immediate"},
        {"cve_id": "CVE-2024-0002", "criticality": "High"},
        {"cve_id": "CVE-2024-0003", "criticality": "Moderate"},
        {"cve_id": "CVE-2024-0004", "criticality": "Planned"},
    ]
    _insert_findings(tool, findings)
    result = tool.forward(action="score")
    assert result["score"] == 62.5
    assert result["band"] == "high"
    assert result["finding_count"] == 4
    assert result["criticality_counts"]["Immediate"] == 1
    assert result["criticality_counts"]["High"] == 1
    assert result["criticality_counts"]["Moderate"] == 1
    assert result["criticality_counts"]["Planned"] == 1


def test_all_findings_returned_regardless_of_host(tmp_path):
    """RiskPostureTool queries all LatestFindingRecord rows — not scoped by run_id.

    Insert two rows with different host+cve_id combos and verify both are counted.
    """
    tool = _make_tool(tmp_path)
    older_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
    newer_time = datetime(2024, 6, 1, tzinfo=timezone.utc)
    findings = [
        {"host": "host-a", "cve_id": "CVE-2024-0001", "criticality": "Planned", "created_at": older_time},
        {"host": "host-b", "cve_id": "CVE-2024-0002", "criticality": "Immediate", "created_at": newer_time},
    ]
    _insert_findings(tool, findings)
    result = tool.forward(action="score")
    # Both rows from LatestFindingRecord — not scoped by run_id
    assert result["finding_count"] == 2
    assert result["criticality_counts"]["Immediate"] == 1
    assert result["criticality_counts"]["Planned"] == 1

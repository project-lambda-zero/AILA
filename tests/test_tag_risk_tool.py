"""Tests for tag_risk() and TagRiskTool (OPS-10 / plan 35-02, Task 1)."""
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


def _insert_tag(*, system_id: int, tag_key: str, tag_value: str) -> None:
    from aila.modules.vulnerability.db_models import AssetTagRecord
    from aila.storage.database import session_scope

    with session_scope() as session:
        session.add(AssetTagRecord(system_id=system_id, tag_key=tag_key, tag_value=tag_value))
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_empty_db_returns_empty_segments(test_db):
    """No data -> result['segments'] == []."""
    from aila.modules.vulnerability.tools.tag_risk import tag_risk

    result = await tag_risk()

    assert result["segments"] == []
    assert result["segment_count"] == 0


async def test_single_tag_single_segment(test_db):
    """system_id=1 tagged env=production with 2 Immediate findings -> one segment with correct data."""
    from aila.modules.vulnerability.tools.tag_risk import tag_risk

    _insert_finding(host="prod-1", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=1, criticality="Immediate", score=9.0)
    _insert_finding(host="prod-1", package_name="curl", cve_id="CVE-2024-0002",
                    system_id=1, criticality="Immediate", score=9.5)
    _insert_tag(system_id=1, tag_key="environment", tag_value="production")

    result = await tag_risk()

    assert result["segment_count"] == 1
    seg = result["segments"][0]
    assert seg["tag_key"] == "environment"
    assert seg["tag_value"] == "production"
    assert seg["finding_count"] == 2
    assert seg["score"] == 100.0
    assert seg["band"] == "critical"


async def test_multiple_environments_separate_scores(test_db):
    """Production (all Immediate) and staging (all Planned) -> two separate segments with different scores."""
    from aila.modules.vulnerability.tools.tag_risk import tag_risk

    _insert_finding(host="prod-1", package_name="pkg-a", cve_id="CVE-2024-P01",
                    system_id=1, criticality="Immediate", score=9.0)
    _insert_tag(system_id=1, tag_key="environment", tag_value="production")

    _insert_finding(host="stg-1", package_name="pkg-b", cve_id="CVE-2024-S01",
                    system_id=2, criticality="Planned", score=2.0)
    _insert_tag(system_id=2, tag_key="environment", tag_value="staging")

    result = await tag_risk()

    assert result["segment_count"] == 2
    segs_by_value = {s["tag_value"]: s for s in result["segments"]}
    assert segs_by_value["production"]["score"] == 100.0
    assert segs_by_value["staging"]["score"] == 25.0
    # sorted by score descending
    assert result["segments"][0]["tag_value"] == "production"
    assert result["segments"][1]["tag_value"] == "staging"


async def test_systems_without_tags_not_in_segments(test_db):
    """Findings for system_id with no AssetTagRecord row -> excluded from segments."""
    from aila.modules.vulnerability.tools.tag_risk import tag_risk

    _insert_finding(host="untagged", package_name="pkg-z", cve_id="CVE-2024-Z01",
                    system_id=99, criticality="High", score=7.0)
    # No tag inserted for system_id=99

    result = await tag_risk()

    assert result["segments"] == []
    assert result["segment_count"] == 0


async def test_tool_rejects_bad_action(test_db):
    """TagRiskTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.tag_risk import TagRiskTool

    tool = TagRiskTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad")

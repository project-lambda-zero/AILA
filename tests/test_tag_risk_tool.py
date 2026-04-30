"""Tests for tag_risk() and TagRiskTool (OPS-10 / plan 35-02, Task 1)."""
from __future__ import annotations

from datetime import datetime, timezone

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

    now = datetime.now(timezone.utc)
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


def _insert_tag(settings, *, system_id: int, tag_key: str, tag_value: str) -> None:
    from aila.modules.vulnerability.db_models import AssetTagRecord
    from aila.storage.database import session_scope
    with session_scope(settings) as session:
        session.add(AssetTagRecord(system_id=system_id, tag_key=tag_key, tag_value=tag_value))
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_db_returns_empty_segments(tmp_path):
    """No data -> result['segments'] == []."""
    from aila.modules.vulnerability.tools.tag_risk import tag_risk

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = tag_risk(settings=settings)

    assert result["segments"] == []
    assert result["segment_count"] == 0


def test_single_tag_single_segment(tmp_path):
    """system_id=1 tagged env=production with 2 Immediate findings -> one segment with correct data."""
    from aila.modules.vulnerability.tools.tag_risk import tag_risk

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="prod-1", package_name="openssl", cve_id="CVE-2024-0001",
                    system_id=1, criticality="Immediate", score=9.0)
    _insert_finding(settings, host="prod-1", package_name="curl", cve_id="CVE-2024-0002",
                    system_id=1, criticality="Immediate", score=9.5)
    _insert_tag(settings, system_id=1, tag_key="environment", tag_value="production")

    result = tag_risk(settings=settings)

    assert result["segment_count"] == 1
    seg = result["segments"][0]
    assert seg["tag_key"] == "environment"
    assert seg["tag_value"] == "production"
    assert seg["finding_count"] == 2
    assert seg["score"] == 100.0
    assert seg["band"] == "critical"


def test_multiple_environments_separate_scores(tmp_path):
    """Production (all Immediate) and staging (all Planned) -> two separate segments with different scores."""
    from aila.modules.vulnerability.tools.tag_risk import tag_risk

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="prod-1", package_name="pkg-a", cve_id="CVE-2024-P01",
                    system_id=1, criticality="Immediate", score=9.0)
    _insert_tag(settings, system_id=1, tag_key="environment", tag_value="production")

    _insert_finding(settings, host="stg-1", package_name="pkg-b", cve_id="CVE-2024-S01",
                    system_id=2, criticality="Planned", score=2.0)
    _insert_tag(settings, system_id=2, tag_key="environment", tag_value="staging")

    result = tag_risk(settings=settings)

    assert result["segment_count"] == 2
    segs_by_value = {s["tag_value"]: s for s in result["segments"]}
    assert segs_by_value["production"]["score"] == 100.0
    assert segs_by_value["staging"]["score"] == 25.0
    # sorted by score descending
    assert result["segments"][0]["tag_value"] == "production"
    assert result["segments"][1]["tag_value"] == "staging"


def test_systems_without_tags_not_in_segments(tmp_path):
    """Findings for system_id with no AssetTagRecord row -> excluded from segments."""
    from aila.modules.vulnerability.tools.tag_risk import tag_risk

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="untagged", package_name="pkg-z", cve_id="CVE-2024-Z01",
                    system_id=99, criticality="High", score=7.0)
    # No tag inserted for system_id=99

    result = tag_risk(settings=settings)

    assert result["segments"] == []
    assert result["segment_count"] == 0


def test_tool_rejects_bad_action(tmp_path):
    """TagRiskTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.tag_risk import TagRiskTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = TagRiskTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad")

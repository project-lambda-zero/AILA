"""Tests for baseline_create() and baseline_compare() -- AUTO-04 (plan 36-02, Task 2)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest


def _insert_finding(
    *,
    host: str,
    package_name: str,
    cve_id: str,
    system_id: int = 1,
    system_name: str = "web-01",
    distribution: str = "ubuntu",
    criticality: str = "High",
    score: float = 7.5,
    fixed_version: str = "3.0.14",
    nvd_url: str = "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
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
                system_name=system_name,
                distribution=distribution,
                criticality=criticality,
                score=score,
                rationale="",
                fixed_version=fixed_version,
                nvd_url=nvd_url,
                compliance_tags_json="[]",
                details_json="{}",
                last_scanned_at=now,
                created_at=now,
            )
        )
        session.commit()


def _delete_all_findings() -> None:
    from sqlmodel import delete

    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    with session_scope() as session:
        session.exec(delete(LatestFindingRecord))  # type: ignore[arg-type]
        session.commit()


async def test_create_stores_snapshot_in_cache(test_db):
    """baseline_create inserts CacheRecord(namespace='auto_baseline', cache_key='q1-2026')."""
    from aila.modules.vulnerability.db_models import CacheRecord
    from aila.modules.vulnerability.tools.baseline import baseline_create
    from aila.storage.database import session_scope

    _insert_finding(host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")

    await baseline_create(name="q1-2026")

    with session_scope() as session:
        entry = session.get(CacheRecord, ("auto_baseline", "q1-2026"))

    assert entry is not None
    assert entry.namespace == "auto_baseline"
    assert entry.cache_key == "q1-2026"

    import json
    payload = json.loads(entry.payload_json)
    assert "finding_count" in payload
    assert payload["finding_count"] == 1


async def test_create_returns_snapshot_summary(test_db):
    """result has keys: name, finding_count, criticality_counts, created_at."""
    from aila.modules.vulnerability.tools.baseline import baseline_create

    _insert_finding(host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")

    result = await baseline_create(name="q1-2026")

    assert set(result.keys()) >= {"name", "finding_count", "criticality_counts", "created_at"}
    assert result["name"] == "q1-2026"
    assert result["finding_count"] == 1


async def test_create_overwrites_existing(test_db):
    """Calling baseline_create twice with same name overwrites first snapshot."""
    from aila.modules.vulnerability.tools.baseline import baseline_create

    _insert_finding(host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")

    result1 = await baseline_create(name="q1-2026")
    assert result1["finding_count"] == 1

    # Add a second finding and overwrite
    _insert_finding(host="10.0.0.2", package_name="curl", cve_id="CVE-2024-5678")
    result2 = await baseline_create(name="q1-2026")
    assert result2["finding_count"] == 2


async def test_compare_reports_new_findings(test_db):
    """Snapshot had 2 findings, now DB has 3 -> new_count=1, resolved_count=0."""
    from aila.modules.vulnerability.tools.baseline import baseline_compare, baseline_create

    _insert_finding(host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")
    _insert_finding(host="10.0.0.2", package_name="curl", cve_id="CVE-2024-5678")

    await baseline_create(name="snapshot-a")

    # Add a new finding after snapshot
    _insert_finding(host="10.0.0.3", package_name="bash", cve_id="CVE-2024-9999")

    result = await baseline_compare(name="snapshot-a")
    assert result["new_count"] == 1
    assert result["resolved_count"] == 0


async def test_compare_reports_resolved_findings(test_db):
    """Snapshot had 3 findings (by key), now 2 remain -> resolved_count=1, new_count=0."""
    from aila.modules.vulnerability.tools.baseline import baseline_compare, baseline_create

    _insert_finding(host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")
    _insert_finding(host="10.0.0.2", package_name="curl", cve_id="CVE-2024-5678")
    _insert_finding(host="10.0.0.3", package_name="bash", cve_id="CVE-2024-9999")

    await baseline_create(name="snapshot-b")

    # Remove one finding
    _delete_all_findings()
    _insert_finding(host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")
    _insert_finding(host="10.0.0.2", package_name="curl", cve_id="CVE-2024-5678")

    result = await baseline_compare(name="snapshot-b")
    assert result["resolved_count"] == 1
    assert result["new_count"] == 0


async def test_compare_missing_baseline_raises(test_db):
    """baseline_compare with nonexistent name raises ValueError with 'not found'."""
    from aila.modules.vulnerability.tools.baseline import baseline_compare

    with pytest.raises(ValueError, match="not found"):
        await baseline_compare(name="nonexistent")


async def test_tool_forward_create(test_db):
    """BaselineTool().forward(action='create', name='q1') returns dict with 'finding_count'."""
    from aila.modules.vulnerability.tools.baseline import BaselineTool

    tool = BaselineTool()
    result = await tool.forward(action="create", name="q1")

    assert isinstance(result, dict)
    assert "finding_count" in result


async def test_tool_forward_compare(test_db):
    """BaselineTool().forward(action='compare', name='q1') returns dict with 'new_count'."""
    from aila.modules.vulnerability.tools.baseline import BaselineTool, baseline_create

    await baseline_create(name="q1")

    tool = BaselineTool()
    result = await tool.forward(action="compare", name="q1")

    assert isinstance(result, dict)
    assert "new_count" in result


async def test_tool_rejects_bad_action(test_db):
    """BaselineTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.baseline import BaselineTool

    tool = BaselineTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad", name="q1")


async def test_tool_requires_name(test_db):
    """BaselineTool().forward(action='create', name='') raises ValueError."""
    from aila.modules.vulnerability.tools.baseline import BaselineTool

    tool = BaselineTool()
    with pytest.raises(ValueError):
        await tool.forward(action="create", name="")

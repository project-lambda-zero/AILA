"""Tests for baseline_create() and baseline_compare() -- AUTO-04 (plan 36-02, Task 2)."""
from __future__ import annotations

import pytest
from sqlalchemy.dialects.sqlite import insert as sa_insert


def _make_settings(tmp_path):
    from aila.config import Settings
    return Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")


def _setup_db(settings):
    from aila.storage.database import init_db
    init_db(settings)


def _insert_finding(settings, *, host, package_name, cve_id, system_id=1,
                    system_name="web-01", distribution="ubuntu", criticality="High",
                    score=7.5, fixed_version="3.0.14",
                    nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234"):
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope
    stmt = (
        sa_insert(LatestFindingRecord)
        .values(
            host=host, package_name=package_name, cve_id=cve_id,
            system_id=system_id, system_name=system_name, distribution=distribution,
            criticality=criticality, score=score, fixed_version=fixed_version,
            nvd_url=nvd_url,
        )
        .prefix_with("OR REPLACE")
    )
    with session_scope(settings) as session:
        session.exec(stmt)  # type: ignore[arg-type]
        session.commit()


def _delete_all_findings(settings):
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope
    from sqlmodel import delete
    with session_scope(settings) as session:
        session.exec(delete(LatestFindingRecord))  # type: ignore[arg-type]
        session.commit()


def test_create_stores_snapshot_in_cache(tmp_path):
    """baseline_create inserts CacheRecord(namespace='auto_baseline', cache_key='q1-2026')."""
    from aila.modules.vulnerability.tools.baseline import baseline_create
    from aila.modules.vulnerability.db_models import CacheRecord
    from aila.storage.database import session_scope

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_finding(settings, host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")

    baseline_create(name="q1-2026", settings=settings)

    with session_scope(settings) as session:
        entry = session.get(CacheRecord, ("auto_baseline", "q1-2026"))

    assert entry is not None
    assert entry.namespace == "auto_baseline"
    assert entry.cache_key == "q1-2026"

    import json
    payload = json.loads(entry.payload_json)
    assert "finding_count" in payload
    assert payload["finding_count"] == 1


def test_create_returns_snapshot_summary(tmp_path):
    """result has keys: name, finding_count, criticality_counts, created_at."""
    from aila.modules.vulnerability.tools.baseline import baseline_create

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_finding(settings, host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")

    result = baseline_create(name="q1-2026", settings=settings)

    assert set(result.keys()) >= {"name", "finding_count", "criticality_counts", "created_at"}
    assert result["name"] == "q1-2026"
    assert result["finding_count"] == 1


def test_create_overwrites_existing(tmp_path):
    """Calling baseline_create twice with same name overwrites first snapshot."""
    from aila.modules.vulnerability.tools.baseline import baseline_create

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_finding(settings, host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")

    result1 = baseline_create(name="q1-2026", settings=settings)
    assert result1["finding_count"] == 1

    # Add a second finding and overwrite
    _insert_finding(settings, host="10.0.0.2", package_name="curl", cve_id="CVE-2024-5678")
    result2 = baseline_create(name="q1-2026", settings=settings)
    assert result2["finding_count"] == 2


def test_compare_reports_new_findings(tmp_path):
    """Snapshot had 2 findings, now DB has 3 -> new_count=1, resolved_count=0."""
    from aila.modules.vulnerability.tools.baseline import baseline_create, baseline_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_finding(settings, host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")
    _insert_finding(settings, host="10.0.0.2", package_name="curl", cve_id="CVE-2024-5678")

    baseline_create(name="snapshot-a", settings=settings)

    # Add a new finding after snapshot
    _insert_finding(settings, host="10.0.0.3", package_name="bash", cve_id="CVE-2024-9999")

    result = baseline_compare(name="snapshot-a", settings=settings)
    assert result["new_count"] == 1
    assert result["resolved_count"] == 0


def test_compare_reports_resolved_findings(tmp_path):
    """Snapshot had 3 findings (by key), now 2 remain -> resolved_count=1, new_count=0."""
    from aila.modules.vulnerability.tools.baseline import baseline_create, baseline_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_finding(settings, host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")
    _insert_finding(settings, host="10.0.0.2", package_name="curl", cve_id="CVE-2024-5678")
    _insert_finding(settings, host="10.0.0.3", package_name="bash", cve_id="CVE-2024-9999")

    baseline_create(name="snapshot-b", settings=settings)

    # Remove one finding
    _delete_all_findings(settings)
    _insert_finding(settings, host="10.0.0.1", package_name="openssl", cve_id="CVE-2024-1234")
    _insert_finding(settings, host="10.0.0.2", package_name="curl", cve_id="CVE-2024-5678")

    result = baseline_compare(name="snapshot-b", settings=settings)
    assert result["resolved_count"] == 1
    assert result["new_count"] == 0


def test_compare_missing_baseline_raises(tmp_path):
    """baseline_compare with nonexistent name raises ValueError with 'not found'."""
    from aila.modules.vulnerability.tools.baseline import baseline_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    with pytest.raises(ValueError, match="not found"):
        baseline_compare(name="nonexistent", settings=settings)


def test_tool_forward_create(tmp_path):
    """BaselineTool().forward(action='create', name='q1') returns dict with 'finding_count'."""
    from aila.modules.vulnerability.tools.baseline import BaselineTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = BaselineTool(settings=settings)
    result = tool.forward(action="create", name="q1")

    assert isinstance(result, dict)
    assert "finding_count" in result


def test_tool_forward_compare(tmp_path):
    """BaselineTool().forward(action='compare', name='q1') returns dict with 'new_count'."""
    from aila.modules.vulnerability.tools.baseline import BaselineTool, baseline_create

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    baseline_create(name="q1", settings=settings)

    tool = BaselineTool(settings=settings)
    result = tool.forward(action="compare", name="q1")

    assert isinstance(result, dict)
    assert "new_count" in result


def test_tool_rejects_bad_action(tmp_path):
    """BaselineTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.baseline import BaselineTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    tool = BaselineTool(settings=settings)

    with pytest.raises(ValueError):
        tool.forward(action="bad", name="q1")


def test_tool_requires_name(tmp_path):
    """BaselineTool().forward(action='create', name='') raises ValueError."""
    from aila.modules.vulnerability.tools.baseline import BaselineTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    tool = BaselineTool(settings=settings)

    with pytest.raises(ValueError):
        tool.forward(action="create", name="")

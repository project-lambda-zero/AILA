"""Tests for peer_compare() query (INTEL-05 / plan 34-02, Task 1)."""
from __future__ import annotations

import json
from datetime import UTC, datetime

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
    fixed_version: str | None = "1.0.0",
    last_scanned_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = last_scanned_at or datetime.now(UTC)
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
            fixed_version=fixed_version,
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


def _insert_inventory(
    settings,
    *,
    host: str,
    packages: list[dict],
    system_id: int = 1,
    status: str = "collected",
    run_id: str = "run-1",
    collected_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import InventoryArtifactRecord
    from aila.storage.database import session_scope

    now = collected_at or datetime.now(UTC)
    payload = json.dumps({"packages": packages, "kernel": "5.15", "os_release": {}})
    stmt = (
        sa_insert(InventoryArtifactRecord)
        .values(
            run_id=run_id,
            system_id=system_id,
            host=host,
            distro="ubuntu-22.04",
            status=status,
            payload_json=payload,
            collected_at=now,
        )
        .prefix_with("OR REPLACE")
    )
    with session_scope(settings) as session:
        session.exec(stmt)  # type: ignore[arg-type]
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_identical_hosts_no_diff(tmp_path):
    """Both hosts have same packages and same CVE findings -- no diffs."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    packages = [{"name": "curl", "version": "7.88"}, {"name": "libssl", "version": "1.0"}]
    _insert_inventory(settings, host="host-a", packages=packages, system_id=1)
    _insert_inventory(settings, host="host-b", packages=packages, system_id=2)
    _insert_finding(settings, host="host-a", package_name="curl", cve_id="CVE-2024-1111", system_id=1)
    _insert_finding(settings, host="host-b", package_name="curl", cve_id="CVE-2024-1111", system_id=2)

    result = peer_compare(host_a="host-a", host_b="host-b", settings=settings)

    assert result["host_a"] == "host-a"
    assert result["host_b"] == "host-b"
    assert result["packages_only_in_a"] == []
    assert result["packages_only_in_b"] == []
    assert result["version_differences"] == []
    assert result["findings_only_in_a"] == 0
    assert result["findings_only_in_b"] == 0


def test_package_only_in_a(tmp_path):
    """host-a has 'curl:7.88', host-b does not."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_inventory(settings, host="host-a", packages=[{"name": "curl", "version": "7.88"}], system_id=1)
    _insert_inventory(settings, host="host-b", packages=[], system_id=2)

    result = peer_compare(host_a="host-a", host_b="host-b", settings=settings)

    assert result["packages_only_in_a"] == [{"name": "curl", "version": "7.88"}]
    assert result["packages_only_in_b"] == []
    assert result["version_differences"] == []


def test_package_only_in_b(tmp_path):
    """host-b has 'nginx:1.22', host-a does not."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_inventory(settings, host="host-a", packages=[], system_id=1)
    _insert_inventory(settings, host="host-b", packages=[{"name": "nginx", "version": "1.22"}], system_id=2)

    result = peer_compare(host_a="host-a", host_b="host-b", settings=settings)

    assert result["packages_only_in_a"] == []
    assert result["packages_only_in_b"] == [{"name": "nginx", "version": "1.22"}]
    assert result["version_differences"] == []


def test_version_difference(tmp_path):
    """Both hosts have 'libssl' but different versions."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_inventory(settings, host="host-a", packages=[{"name": "libssl", "version": "1.0"}], system_id=1)
    _insert_inventory(settings, host="host-b", packages=[{"name": "libssl", "version": "1.1"}], system_id=2)

    result = peer_compare(host_a="host-a", host_b="host-b", settings=settings)

    assert result["packages_only_in_a"] == []
    assert result["packages_only_in_b"] == []
    assert result["version_differences"] == [{"name": "libssl", "version_a": "1.0", "version_b": "1.1"}]


def test_finding_only_in_a(tmp_path):
    """host-a has CVE-2024-1234 finding, host-b does not."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-1234", system_id=1)

    result = peer_compare(host_a="host-a", host_b="host-b", settings=settings)

    assert result["findings_only_in_a"] == 1
    assert result["findings_only_in_b"] == 0
    assert result["finding_count_a"] == 1
    assert result["finding_count_b"] == 0


def test_no_inventory_for_host_a(tmp_path):
    """host-a has no InventoryArtifactRecord -- result includes 'warning' for host_a; finding diff still works."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_inventory(settings, host="host-b", packages=[{"name": "curl", "version": "7.88"}], system_id=2)
    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-9999", system_id=1)
    _insert_finding(settings, host="host-b", package_name="curl", cve_id="CVE-2024-0001", system_id=2)

    result = peer_compare(host_a="host-a", host_b="host-b", settings=settings)

    assert isinstance(result["warnings"], list)
    assert any("host_a" in w or "host-a" in w for w in result["warnings"])
    # Finding diff still computed
    assert result["finding_count_a"] == 1
    assert result["finding_count_b"] == 1


def test_both_hosts_unknown(tmp_path):
    """Neither host has any data -- result is valid with all empty lists and zero counts."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = peer_compare(host_a="ghost-a", host_b="ghost-b", settings=settings)

    assert result["host_a"] == "ghost-a"
    assert result["host_b"] == "ghost-b"
    assert result["packages_only_in_a"] == []
    assert result["packages_only_in_b"] == []
    assert result["version_differences"] == []
    assert result["findings_only_in_a"] == 0
    assert result["findings_only_in_b"] == 0
    assert result["finding_count_a"] == 0
    assert result["finding_count_b"] == 0
    assert isinstance(result["warnings"], list)


def test_tool_action_compare(tmp_path):
    """PeerCompareTool().forward(action='compare', host_a='x', host_b='y') returns dict with required keys."""
    from aila.modules.vulnerability.tools.peer_compare import PeerCompareTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = PeerCompareTool(settings=settings)
    result = tool.forward(action="compare", host_a="x", host_b="y")

    required_keys = {
        "host_a", "host_b",
        "packages_only_in_a", "packages_only_in_b",
        "version_differences",
        "findings_only_in_a", "findings_only_in_b",
        "finding_count_a", "finding_count_b",
        "warnings",
    }
    assert required_keys.issubset(result.keys())

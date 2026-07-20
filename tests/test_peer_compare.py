"""Tests for peer_compare() query (INTEL-05 / plan 34-02, Task 1)."""
from __future__ import annotations

import json
from datetime import UTC, datetime

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
    fixed_version: str | None = "1.0.0",
    last_scanned_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = last_scanned_at or datetime.now(UTC)
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
                fixed_version=fixed_version,
                nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                compliance_tags_json="[]",
                details_json="{}",
                last_scanned_at=now,
                created_at=now,
            )
        )
        session.commit()


def _insert_inventory(
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
    with session_scope() as session:
        session.add(
            InventoryArtifactRecord(
                run_id=run_id,
                system_id=system_id,
                host=host,
                distro="ubuntu-22.04",
                status=status,
                payload_json=payload,
                collected_at=now,
            )
        )
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_identical_hosts_no_diff(test_db):
    """Both hosts have same packages and same CVE findings -- no diffs."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    packages = [{"name": "curl", "version": "7.88"}, {"name": "libssl", "version": "1.0"}]
    _insert_inventory(host="host-a", packages=packages, system_id=1)
    _insert_inventory(host="host-b", packages=packages, system_id=2)
    _insert_finding(host="host-a", package_name="curl", cve_id="CVE-2024-1111", system_id=1)
    _insert_finding(host="host-b", package_name="curl", cve_id="CVE-2024-1111", system_id=2)

    result = await peer_compare(host_a="host-a", host_b="host-b")

    assert result["host_a"] == "host-a"
    assert result["host_b"] == "host-b"
    assert result["packages_only_in_a"] == []
    assert result["packages_only_in_b"] == []
    assert result["version_differences"] == []
    assert result["findings_only_in_a"] == 0
    assert result["findings_only_in_b"] == 0


async def test_package_only_in_a(test_db):
    """host-a has 'curl:7.88', host-b does not."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    _insert_inventory(host="host-a", packages=[{"name": "curl", "version": "7.88"}], system_id=1)
    _insert_inventory(host="host-b", packages=[], system_id=2)

    result = await peer_compare(host_a="host-a", host_b="host-b")

    assert result["packages_only_in_a"] == [{"name": "curl", "version": "7.88"}]
    assert result["packages_only_in_b"] == []
    assert result["version_differences"] == []


async def test_package_only_in_b(test_db):
    """host-b has 'nginx:1.22', host-a does not."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    _insert_inventory(host="host-a", packages=[], system_id=1)
    _insert_inventory(host="host-b", packages=[{"name": "nginx", "version": "1.22"}], system_id=2)

    result = await peer_compare(host_a="host-a", host_b="host-b")

    assert result["packages_only_in_a"] == []
    assert result["packages_only_in_b"] == [{"name": "nginx", "version": "1.22"}]
    assert result["version_differences"] == []


async def test_version_difference(test_db):
    """Both hosts have 'libssl' but different versions."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    _insert_inventory(host="host-a", packages=[{"name": "libssl", "version": "1.0"}], system_id=1)
    _insert_inventory(host="host-b", packages=[{"name": "libssl", "version": "1.1"}], system_id=2)

    result = await peer_compare(host_a="host-a", host_b="host-b")

    assert result["packages_only_in_a"] == []
    assert result["packages_only_in_b"] == []
    assert result["version_differences"] == [{"name": "libssl", "version_a": "1.0", "version_b": "1.1"}]


async def test_finding_only_in_a(test_db):
    """host-a has CVE-2024-1234 finding, host-b does not."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-1234", system_id=1)

    result = await peer_compare(host_a="host-a", host_b="host-b")

    assert result["findings_only_in_a"] == 1
    assert result["findings_only_in_b"] == 0
    assert result["finding_count_a"] == 1
    assert result["finding_count_b"] == 0


async def test_no_inventory_for_host_a(test_db):
    """host-a has no InventoryArtifactRecord -- result includes 'warning' for host_a; finding diff still works."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    _insert_inventory(host="host-b", packages=[{"name": "curl", "version": "7.88"}], system_id=2)
    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-9999", system_id=1)
    _insert_finding(host="host-b", package_name="curl", cve_id="CVE-2024-0001", system_id=2)

    result = await peer_compare(host_a="host-a", host_b="host-b")

    assert isinstance(result["warnings"], list)
    assert any("host_a" in w or "host-a" in w for w in result["warnings"])
    # Finding diff still computed
    assert result["finding_count_a"] == 1
    assert result["finding_count_b"] == 1


async def test_both_hosts_unknown(test_db):
    """Neither host has any data -- result is valid with all empty lists and zero counts."""
    from aila.modules.vulnerability.tools.peer_compare import peer_compare

    result = await peer_compare(host_a="ghost-a", host_b="ghost-b")

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


async def test_tool_action_compare(test_db):
    """PeerCompareTool().forward(action='compare', host_a='x', host_b='y') returns dict with required keys."""
    from aila.modules.vulnerability.tools.peer_compare import PeerCompareTool

    tool = PeerCompareTool()
    result = await tool.forward(action="compare", host_a="x", host_b="y")

    required_keys = {
        "host_a", "host_b",
        "packages_only_in_a", "packages_only_in_b",
        "version_differences",
        "findings_only_in_a", "findings_only_in_b",
        "finding_count_a", "finding_count_b",
        "warnings",
    }
    assert required_keys.issubset(result.keys())

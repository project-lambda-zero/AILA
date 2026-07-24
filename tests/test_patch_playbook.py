"""Tests for patch_playbook() and PatchPlaybookTool (AUTO-01 / plan 36-01, Task 1)."""
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
    distribution: str = "ubuntu-22.04",
    fixed_version: str | None = "1.0.0",
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
                distribution=distribution,
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_empty_returns_no_hosts(test_db):
    """No LatestFindingRecord rows -> result['hosts'] == [] and result['finding_count'] == 0."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    result = await patch_playbook()

    assert result["hosts"] == []
    assert result["finding_count"] == 0


async def test_single_host_sorted_by_score(test_db):
    """Two findings on same host with scores 9.0 and 5.0 -> commands list has higher-score package first."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    score=9.0, fixed_version="3.0.14")
    _insert_finding(host="host-a", package_name="curl", cve_id="CVE-2024-0002",
                    score=5.0, fixed_version="8.0.0")

    result = await patch_playbook()

    assert len(result["hosts"]) == 1
    host_entry = result["hosts"][0]
    commands = host_entry["commands"]
    assert len(commands) == 2
    assert commands[0]["score"] > commands[1]["score"]
    assert commands[0]["package_name"] == "openssl"


async def test_only_fixable_packages_included(test_db):
    """Finding with fixed_version=None is excluded from commands (no fix available)."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    score=9.0, fixed_version="3.0.14")
    _insert_finding(host="host-a", package_name="curl", cve_id="CVE-2024-0002",
                    score=5.0, fixed_version=None)  # no fix

    result = await patch_playbook()

    assert len(result["hosts"]) == 1
    commands = result["hosts"][0]["commands"]
    pkg_names = [c["package_name"] for c in commands]
    assert "openssl" in pkg_names
    assert "curl" not in pkg_names


async def test_target_filter(test_db):
    """Two hosts 'host-a' and 'host-b' in DB, patch_playbook(target='host-a') returns only host-a."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    score=9.0, fixed_version="3.0.14")
    _insert_finding(host="host-b", package_name="curl", cve_id="CVE-2024-0002",
                    score=5.0, fixed_version="8.0.0")

    result = await patch_playbook(target="host-a")

    assert len(result["hosts"]) == 1
    assert result["hosts"][0]["host"] == "host-a"


async def test_ubuntu_apt_command_format(test_db):
    """distribution='ubuntu-22.04', package_name='openssl', fixed_version='3.0.14' -> apt-get command."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    _insert_finding(host="host-ubuntu", package_name="openssl", cve_id="CVE-2024-0001",
                    distribution="ubuntu-22.04", fixed_version="3.0.14")

    result = await patch_playbook()

    commands = result["hosts"][0]["commands"]
    assert commands[0]["command"] == "apt-get install --only-upgrade openssl=3.0.14"


async def test_arch_pacman_command_format(test_db):
    """distribution='arch', package_name='openssl' -> command contains 'pacman -S openssl'."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    _insert_finding(host="host-arch", package_name="openssl", cve_id="CVE-2024-0001",
                    distribution="arch", fixed_version="3.0.14")

    result = await patch_playbook()

    commands = result["hosts"][0]["commands"]
    assert "pacman -S openssl" in commands[0]["command"]


async def test_alpine_apk_command_format(test_db):
    """distribution='alpine-3.18', package_name='curl', fixed_version='8.0.0' -> apk add command."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    _insert_finding(host="host-alpine", package_name="curl", cve_id="CVE-2024-0001",
                    distribution="alpine-3.18", fixed_version="8.0.0")

    result = await patch_playbook()

    commands = result["hosts"][0]["commands"]
    assert commands[0]["command"] == "apk add curl=8.0.0"


async def test_fallback_command_format(test_db):
    """distribution='centos-7', package_name='bash', fixed_version='5.2' -> comment fallback."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    _insert_finding(host="host-centos", package_name="bash", cve_id="CVE-2024-0001",
                    distribution="centos-7", fixed_version="5.2")

    result = await patch_playbook()

    commands = result["hosts"][0]["commands"]
    assert commands[0]["command"].startswith("# upgrade")


async def test_tool_forward_action_generate(test_db):
    """PatchPlaybookTool().forward(action='generate') returns dict with 'hosts' key."""
    from aila.modules.vulnerability.tools.patch_playbook import PatchPlaybookTool

    tool = PatchPlaybookTool()
    result = await tool.forward(action="generate")

    assert isinstance(result, dict)
    assert "hosts" in result


async def test_tool_rejects_bad_action(test_db):
    """PatchPlaybookTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.patch_playbook import PatchPlaybookTool

    tool = PatchPlaybookTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad")

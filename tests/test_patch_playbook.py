"""Tests for patch_playbook() and PatchPlaybookTool (AUTO-01 / plan 36-01, Task 1)."""
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
    distribution: str = "ubuntu-22.04",
    fixed_version: str | None = "1.0.0",
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
        .prefix_with("OR REPLACE")
    )
    with session_scope(settings) as session:
        session.exec(stmt)  # type: ignore[arg-type]
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_returns_no_hosts(tmp_path):
    """No LatestFindingRecord rows -> result['hosts'] == [] and result['finding_count'] == 0."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = patch_playbook(settings=settings)

    assert result["hosts"] == []
    assert result["finding_count"] == 0


def test_single_host_sorted_by_score(tmp_path):
    """Two findings on same host with scores 9.0 and 5.0 -> commands list has higher-score package first."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    score=9.0, fixed_version="3.0.14")
    _insert_finding(settings, host="host-a", package_name="curl", cve_id="CVE-2024-0002",
                    score=5.0, fixed_version="8.0.0")

    result = patch_playbook(settings=settings)

    assert len(result["hosts"]) == 1
    host_entry = result["hosts"][0]
    commands = host_entry["commands"]
    assert len(commands) == 2
    assert commands[0]["score"] > commands[1]["score"]
    assert commands[0]["package_name"] == "openssl"


def test_only_fixable_packages_included(tmp_path):
    """Finding with fixed_version=None is excluded from commands (no fix available)."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    score=9.0, fixed_version="3.0.14")
    _insert_finding(settings, host="host-a", package_name="curl", cve_id="CVE-2024-0002",
                    score=5.0, fixed_version=None)  # no fix

    result = patch_playbook(settings=settings)

    assert len(result["hosts"]) == 1
    commands = result["hosts"][0]["commands"]
    pkg_names = [c["package_name"] for c in commands]
    assert "openssl" in pkg_names
    assert "curl" not in pkg_names


def test_target_filter(tmp_path):
    """Two hosts 'host-a' and 'host-b' in DB, patch_playbook(target='host-a') returns only host-a."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    score=9.0, fixed_version="3.0.14")
    _insert_finding(settings, host="host-b", package_name="curl", cve_id="CVE-2024-0002",
                    score=5.0, fixed_version="8.0.0")

    result = patch_playbook(target="host-a", settings=settings)

    assert len(result["hosts"]) == 1
    assert result["hosts"][0]["host"] == "host-a"


def test_ubuntu_apt_command_format(tmp_path):
    """distribution='ubuntu-22.04', package_name='openssl', fixed_version='3.0.14' -> apt-get command."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-ubuntu", package_name="openssl", cve_id="CVE-2024-0001",
                    distribution="ubuntu-22.04", fixed_version="3.0.14")

    result = patch_playbook(settings=settings)

    commands = result["hosts"][0]["commands"]
    assert commands[0]["command"] == "apt-get install --only-upgrade openssl=3.0.14"


def test_arch_pacman_command_format(tmp_path):
    """distribution='arch', package_name='openssl' -> command contains 'pacman -S openssl'."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-arch", package_name="openssl", cve_id="CVE-2024-0001",
                    distribution="arch", fixed_version="3.0.14")

    result = patch_playbook(settings=settings)

    commands = result["hosts"][0]["commands"]
    assert "pacman -S openssl" in commands[0]["command"]


def test_alpine_apk_command_format(tmp_path):
    """distribution='alpine-3.18', package_name='curl', fixed_version='8.0.0' -> apk add command."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-alpine", package_name="curl", cve_id="CVE-2024-0001",
                    distribution="alpine-3.18", fixed_version="8.0.0")

    result = patch_playbook(settings=settings)

    commands = result["hosts"][0]["commands"]
    assert commands[0]["command"] == "apk add curl=8.0.0"


def test_fallback_command_format(tmp_path):
    """distribution='centos-7', package_name='bash', fixed_version='5.2' -> comment fallback."""
    from aila.modules.vulnerability.tools.patch_playbook import patch_playbook

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-centos", package_name="bash", cve_id="CVE-2024-0001",
                    distribution="centos-7", fixed_version="5.2")

    result = patch_playbook(settings=settings)

    commands = result["hosts"][0]["commands"]
    assert commands[0]["command"].startswith("# upgrade")


def test_tool_forward_action_generate(tmp_path):
    """PatchPlaybookTool().forward(action='generate') returns dict with 'hosts' key."""
    from aila.modules.vulnerability.tools.patch_playbook import PatchPlaybookTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = PatchPlaybookTool(settings=settings)
    result = tool.forward(action="generate")

    assert isinstance(result, dict)
    assert "hosts" in result


def test_tool_rejects_bad_action(tmp_path):
    """PatchPlaybookTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.patch_playbook import PatchPlaybookTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = PatchPlaybookTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad")

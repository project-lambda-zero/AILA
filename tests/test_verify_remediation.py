"""Tests for verify_remediation() -- AUTO-03 (plan 36-02, Task 1)."""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insert_system(*, name: str, host: str, username: str = "admin") -> None:
    from aila.storage.database import session_scope
    from aila.storage.db_models import ManagedSystemRecord

    with session_scope() as session:
        session.add(
            ManagedSystemRecord(
                name=name,
                host=host,
                username=username,
            )
        )
        session.commit()


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
    fixed_version: str | None = None,
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
                rationale="test",
                fixed_version=fixed_version,
                nvd_url=nvd_url,
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


async def test_verified_true_when_installed_gte_fixed(test_db):
    """SSH returns '3.0.14', fixed_version='3.0.14' -> verified=True."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation

    _insert_system(name="web-01", host="10.0.0.1")
    _insert_finding(host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "3.0.14\n"
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        result = await verify_remediation(target="web-01", cve_id="CVE-2024-1234")
    assert result["verified"] is True
    assert result["installed_version"] == "3.0.14"


async def test_verified_false_when_installed_lt_fixed(test_db):
    """SSH returns '3.0.1', fixed_version='3.0.14' -> verified=False (string '3.0.1' < '3.0.14')."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation

    _insert_system(name="web-01", host="10.0.0.1")
    _insert_finding(host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "3.0.1\n"
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        result = await verify_remediation(target="web-01", cve_id="CVE-2024-1234")
    assert result["verified"] is False
    assert result["installed_version"] == "3.0.1"


async def test_finding_not_found_raises(test_db):
    """LatestFindingRecord not in DB for (target, cve_id) -> raises ValueError with 'not found'."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation

    _insert_system(name="web-01", host="10.0.0.1")
    with pytest.raises(ValueError, match="not found"):
        await verify_remediation(target="web-01", cve_id="CVE-2024-9999")


async def test_no_fixed_version_raises(test_db):
    """LatestFindingRecord.fixed_version is None -> raises ValueError with 'no fixed version'."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation

    _insert_system(name="web-01", host="10.0.0.1")
    _insert_finding(host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version=None)
    with pytest.raises(ValueError, match="no fixed version"):
        await verify_remediation(target="web-01", cve_id="CVE-2024-1234")


async def test_result_keys_present(test_db):
    """result dict has keys: host, cve_id, package_name, fixed_version, installed_version, verified."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation

    _insert_system(name="web-01", host="10.0.0.1")
    _insert_finding(host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "3.0.14\n"
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        result = await verify_remediation(target="web-01", cve_id="CVE-2024-1234")
    assert set(result.keys()) >= {"host", "cve_id", "package_name", "fixed_version", "installed_version", "verified"}


async def test_ssh_error_propagates(test_db):
    """run_command raises RuntimeError -> verify_remediation re-raises RuntimeError."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation

    _insert_system(name="web-01", host="10.0.0.1")
    _insert_finding(host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    mock_ssh = MagicMock()
    mock_ssh.run_command.side_effect = RuntimeError("SSH connection refused")
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        with pytest.raises(RuntimeError):
            await verify_remediation(target="web-01", cve_id="CVE-2024-1234")


async def test_system_not_found_raises(test_db):
    """ManagedSystemRecord not in DB for target -> raises ValueError with 'not found'."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation

    with pytest.raises(ValueError, match="not found"):
        await verify_remediation(target="nonexistent-host", cve_id="CVE-2024-1234")


async def test_tool_forward_action_check(test_db):
    """VerifyRemediationTool().forward(action='check', target='h', cve_id='CVE-x') returns dict."""
    from aila.modules.vulnerability.tools.verify_remediation import VerifyRemediationTool

    _insert_system(name="web-01", host="10.0.0.1")
    _insert_finding(host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    tool = VerifyRemediationTool()
    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "3.0.14\n"
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        result = await tool.forward(action="check", target="web-01", cve_id="CVE-2024-1234")
    assert isinstance(result, dict)
    assert "verified" in result


async def test_tool_rejects_bad_action(test_db):
    """VerifyRemediationTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.verify_remediation import VerifyRemediationTool

    tool = VerifyRemediationTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad", target="web-01", cve_id="CVE-2024-1234")

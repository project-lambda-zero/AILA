"""Tests for verify_remediation() -- AUTO-03 (plan 36-02, Task 1)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.dialects.sqlite import insert as sa_insert


def _make_settings(tmp_path):
    from aila.config import Settings
    return Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")


def _setup_db(settings):
    from aila.storage.database import init_db
    init_db(settings)


def _insert_system(settings, *, name, host, username="admin"):
    from aila.storage.database import session_scope
    from aila.storage.db_models import ManagedSystemRecord
    stmt = (
        sa_insert(ManagedSystemRecord)
        .values(name=name, host=host, username=username)
        .prefix_with("OR REPLACE")
    )
    with session_scope(settings) as session:
        session.exec(stmt)  # type: ignore[arg-type]
        session.commit()


def _insert_finding(settings, *, host, package_name, cve_id, system_id=1,
                    system_name="web-01", distribution="ubuntu", criticality="High",
                    score=7.5, fixed_version=None,
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


def test_verified_true_when_installed_gte_fixed(tmp_path):
    """SSH returns '3.0.14', fixed_version='3.0.14' -> verified=True."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="web-01", host="10.0.0.1")
    _insert_finding(settings, host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "3.0.14\n"
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        result = verify_remediation(target="web-01", cve_id="CVE-2024-1234", settings=settings)
    assert result["verified"] is True
    assert result["installed_version"] == "3.0.14"


def test_verified_false_when_installed_lt_fixed(tmp_path):
    """SSH returns '3.0.1', fixed_version='3.0.14' -> verified=False (string '3.0.1' < '3.0.14')."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="web-01", host="10.0.0.1")
    _insert_finding(settings, host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "3.0.1\n"
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        result = verify_remediation(target="web-01", cve_id="CVE-2024-1234", settings=settings)
    assert result["verified"] is False
    assert result["installed_version"] == "3.0.1"


def test_finding_not_found_raises(tmp_path):
    """LatestFindingRecord not in DB for (target, cve_id) -> raises ValueError with 'not found'."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="web-01", host="10.0.0.1")
    with pytest.raises(ValueError, match="not found"):
        verify_remediation(target="web-01", cve_id="CVE-2024-9999", settings=settings)


def test_no_fixed_version_raises(tmp_path):
    """LatestFindingRecord.fixed_version is None -> raises ValueError with 'no fixed version'."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="web-01", host="10.0.0.1")
    _insert_finding(settings, host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version=None)
    with pytest.raises(ValueError, match="no fixed version"):
        verify_remediation(target="web-01", cve_id="CVE-2024-1234", settings=settings)


def test_result_keys_present(tmp_path):
    """result dict has keys: host, cve_id, package_name, fixed_version, installed_version, verified."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="web-01", host="10.0.0.1")
    _insert_finding(settings, host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "3.0.14\n"
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        result = verify_remediation(target="web-01", cve_id="CVE-2024-1234", settings=settings)
    assert set(result.keys()) >= {"host", "cve_id", "package_name", "fixed_version", "installed_version", "verified"}


def test_ssh_error_propagates(tmp_path):
    """run_command raises RuntimeError -> verify_remediation re-raises RuntimeError."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="web-01", host="10.0.0.1")
    _insert_finding(settings, host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    mock_ssh = MagicMock()
    mock_ssh.run_command.side_effect = RuntimeError("SSH connection refused")
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        with pytest.raises(RuntimeError):
            verify_remediation(target="web-01", cve_id="CVE-2024-1234", settings=settings)


def test_system_not_found_raises(tmp_path):
    """ManagedSystemRecord not in DB for target -> raises ValueError with 'not found'."""
    from aila.modules.vulnerability.tools.verify_remediation import verify_remediation
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    with pytest.raises(ValueError, match="not found"):
        verify_remediation(target="nonexistent-host", cve_id="CVE-2024-1234", settings=settings)


def test_tool_forward_action_check(tmp_path):
    """VerifyRemediationTool().forward(action='check', target='h', cve_id='CVE-x') returns dict."""
    from aila.modules.vulnerability.tools.verify_remediation import VerifyRemediationTool
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="web-01", host="10.0.0.1")
    _insert_finding(settings, host="10.0.0.1", package_name="openssl",
                    cve_id="CVE-2024-1234", fixed_version="3.0.14")
    tool = VerifyRemediationTool(settings=settings)
    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "3.0.14\n"
    with patch("aila.modules.vulnerability.tools.verify_remediation.SSHService", return_value=mock_ssh):
        result = tool.forward(action="check", target="web-01", cve_id="CVE-2024-1234")
    assert isinstance(result, dict)
    assert "verified" in result


def test_tool_rejects_bad_action(tmp_path):
    """VerifyRemediationTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.verify_remediation import VerifyRemediationTool
    settings = _make_settings(tmp_path)
    _setup_db(settings)
    tool = VerifyRemediationTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad", target="web-01", cve_id="CVE-2024-1234")

"""Tests for service_active_check() (INTEL-06 / plan 34-02, Task 2)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

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


def _insert_system(settings, *, name: str, host: str, username: str = "admin") -> None:
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_service_active(tmp_path):
    """run_command returns 'active\\n' → active=True."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="host-a", host="10.0.0.1")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "active\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = service_active_check(target="host-a", service="nginx", settings=settings)

    assert result["active"] is True
    assert result["service"] == "nginx"
    assert result["host"] == "10.0.0.1"
    assert result["raw_output"] == "active"


def test_service_inactive(tmp_path):
    """run_command returns 'inactive\\n' → active=False."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="host-b", host="10.0.0.2")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "inactive\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = service_active_check(target="host-b", service="nginx", settings=settings)

    assert result["active"] is False


def test_service_unknown(tmp_path):
    """run_command returns 'unknown\\n' → active=False."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="host-c", host="10.0.0.3")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "unknown\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = service_active_check(target="host-c", service="sshd", settings=settings)

    assert result["active"] is False


def test_service_failed(tmp_path):
    """run_command returns 'failed\\n' → active=False."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="host-d", host="10.0.0.4")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "failed\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = service_active_check(target="host-d", service="apache2", settings=settings)

    assert result["active"] is False


def test_ssh_error_raises_runtime(tmp_path):
    """run_command raises RuntimeError → service_active_check() re-raises RuntimeError."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="host-e", host="10.0.0.5")

    mock_ssh = MagicMock()
    mock_ssh.run_command.side_effect = RuntimeError("SSH command failed: exit code 255")

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        with pytest.raises(RuntimeError):
            service_active_check(target="host-e", service="nginx", settings=settings)


def test_system_not_found_raises(tmp_path):
    """ManagedSystemRecord not found for target → raises ValueError."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    with pytest.raises(ValueError, match="not found"):
        service_active_check(target="nonexistent-host", service="nginx", settings=settings)


def test_tool_rejects_bad_action(tmp_path):
    """ServiceCheckTool().forward(action='bad', ...) raises ValueError."""
    from aila.modules.vulnerability.tools.service_check import ServiceCheckTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = ServiceCheckTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad", target="x", service="nginx")


def test_result_keys_present(tmp_path):
    """Result dict always has keys: host, service, active, raw_output."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    settings = _make_settings(tmp_path)
    _setup_db(settings)
    _insert_system(settings, name="host-f", host="10.0.0.6")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "active\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = service_active_check(target="host-f", service="sshd", settings=settings)

    assert set(result.keys()) >= {"host", "service", "active", "raw_output"}

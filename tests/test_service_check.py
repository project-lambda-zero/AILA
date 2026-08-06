"""Tests for service_active_check() (INTEL-06 / plan 34-02, Task 2)."""
from __future__ import annotations

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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_service_active(test_db):
    """run_command returns 'active\\n' -> active=True."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    _insert_system(name="host-a", host="10.0.0.1")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "active\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = await service_active_check(target="host-a", service="nginx")

    assert result["active"] is True
    assert result["service"] == "nginx"
    assert result["host"] == "10.0.0.1"
    assert result["raw_output"] == "active"


async def test_service_inactive(test_db):
    """run_command returns 'inactive\\n' -> active=False."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    _insert_system(name="host-b", host="10.0.0.2")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "inactive\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = await service_active_check(target="host-b", service="nginx")

    assert result["active"] is False


async def test_service_unknown(test_db):
    """run_command returns 'unknown\\n' -> active=False."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    _insert_system(name="host-c", host="10.0.0.3")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "unknown\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = await service_active_check(target="host-c", service="sshd")

    assert result["active"] is False


async def test_service_failed(test_db):
    """run_command returns 'failed\\n' -> active=False."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    _insert_system(name="host-d", host="10.0.0.4")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "failed\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = await service_active_check(target="host-d", service="apache2")

    assert result["active"] is False


async def test_ssh_error_raises_runtime(test_db):
    """run_command raises RuntimeError -> service_active_check() re-raises RuntimeError."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    _insert_system(name="host-e", host="10.0.0.5")

    mock_ssh = MagicMock()
    mock_ssh.run_command.side_effect = RuntimeError("SSH command failed: exit code 255")

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        with pytest.raises(RuntimeError):
            await service_active_check(target="host-e", service="nginx")


async def test_system_not_found_raises(test_db):
    """ManagedSystemRecord not found for target -> raises ValueError."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    with pytest.raises(ValueError, match="not found"):
        await service_active_check(target="nonexistent-host", service="nginx")


async def test_tool_rejects_bad_action(test_db):
    """ServiceCheckTool().forward(action='bad', ...) raises ValueError."""
    from aila.modules.vulnerability.tools.service_check import ServiceCheckTool

    tool = ServiceCheckTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad", target="x", service="nginx")


async def test_result_keys_present(test_db):
    """Result dict always has keys: host, service, active, raw_output."""
    from aila.modules.vulnerability.tools.service_check import service_active_check

    _insert_system(name="host-f", host="10.0.0.6")

    mock_ssh = MagicMock()
    mock_ssh.run_command.return_value = "active\n"

    with patch("aila.modules.vulnerability.tools.service_check.SSHService", return_value=mock_ssh):
        result = await service_active_check(target="host-f", service="sshd")

    assert set(result.keys()) >= {"host", "service", "active", "raw_output"}

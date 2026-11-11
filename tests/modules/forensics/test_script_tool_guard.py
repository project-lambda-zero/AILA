"""Script policy enforcement at the ``ScriptExecutorTool`` boundary.

``ScriptExecutorTool.forward`` is the execution chokepoint for every
consumer, so a banned script MUST be rejected inside the tool before any
SSH, temp-file, upload, or run side effect. These tests use only inert
synthetic fixtures; no banned script is ever executed and no real SSH or
network is used (``get_ssh_service`` is replaced with an AsyncMock).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aila.modules.forensics.agents.investigator import HonestInvestigator
from aila.modules.forensics.tools.script_tool import ScriptExecutorTool

_INTEGRATION: dict = {
    "id": 1,
    "name": "test-host",
    "host": "192.168.1.10",
    "username": "user",
    "port": 22,
    "distro": "ubuntu",
    "description": "",
    "private_key_path": None,
    "password_secret_id": None,
    "known_hosts_path": None,
    "host_key_fingerprint": None,
}

_BENIGN_SCRIPT: str = "print('hello')\n"

# Inert banned fixtures: they are only ever parsed by the policy, never run.
_BANNED_SCRIPTS: list[str] = [
    "import socket\n",
    "eval('1')\n",
    "x = ().__class__\n",
]


def _mock_ssh() -> AsyncMock:
    ssh = AsyncMock()
    ssh.upload_file = AsyncMock(return_value=None)
    ssh.run_command = AsyncMock(return_value="C:\\Temp")
    ssh.run_command_full = AsyncMock(return_value=("hello\n", "", 0))
    return ssh


@pytest.mark.parametrize("analyzer_os", ["linux", "windows"])
@pytest.mark.parametrize("script", _BANNED_SCRIPTS)
async def test_forward_rejects_banned_script_before_any_ssh_side_effect(
    script: str, analyzer_os: str,
) -> None:
    ssh = _mock_ssh()
    tool = ScriptExecutorTool(settings=None)
    factory = AsyncMock(return_value=ssh)
    with patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=factory,
    ):
        with pytest.raises(ValueError, match="^blocked:"):
            await tool.forward(
                script_content=script,
                integration=_INTEGRATION,
                analyzer_os=analyzer_os,
            )

    factory.assert_not_awaited()
    ssh.run_command.assert_not_awaited()
    ssh.upload_file.assert_not_awaited()
    ssh.run_command_full.assert_not_awaited()


async def test_forward_benign_script_uploads_and_runs_once() -> None:
    ssh = _mock_ssh()
    tool = ScriptExecutorTool(settings=None)
    with patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=AsyncMock(return_value=ssh),
    ):
        result = await tool.forward(
            script_content=_BENIGN_SCRIPT,
            integration=_INTEGRATION,
            analyzer_os="linux",
        )

    ssh.upload_file.assert_awaited_once()
    ssh.run_command_full.assert_awaited_once()
    assert result["stdout"] == "hello\n"
    assert result["exit_code"] == 0
    assert result["ok"] is True


async def test_investigator_execute_script_returns_policy_rejection() -> None:
    """The investigator pre-check returns the shared rejection and never reaches the tool."""
    inv = HonestInvestigator.__new__(HonestInvestigator)
    inv.investigation_id = "inv-test-310"
    forward = AsyncMock()
    with patch.object(ScriptExecutorTool, "forward", new=forward):
        result = await inv._execute_script("import socket\n")

    assert result["exit_code"] == 1
    assert result["stdout"] == ""
    assert result["stderr"].startswith("blocked:")
    forward.assert_not_awaited()

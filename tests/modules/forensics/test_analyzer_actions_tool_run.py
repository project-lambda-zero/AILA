"""Forensics ``analyzer.run_command`` JSON contract for ``tool_run`` turns.

``parse_tool_run_command`` is the single gate between the LLM's ``tool_run``
envelope and the analyzer shell. Only ``analyzer.run_command`` with a non-blank
``args.command`` string is accepted. ``execute_command`` runs the unwrapped
shell string through ``SSHService.run_command``; the SSH service is replaced
with an in-memory fake so no analyzer is reached.
"""
from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest

from aila.modules.forensics.services import analyzer_actions
from aila.modules.forensics.services.analyzer_actions import (
    ToolRunContractError,
    execute_command,
    parse_tool_run_command,
)
from aila.platform.contracts.reasoning import ReasoningTurnDecision


def _envelope(tool: str, command: Any) -> str:
    return json.dumps({"tool": tool, "args": {"command": command}})


def test_tool_run_decision_carries_analyzer_envelope_to_shell_string() -> None:
    envelope = _envelope("analyzer.run_command", "uname -a")
    decision = ReasoningTurnDecision(
        reasoning=f"inspect host {uuid4().hex[:8]}",
        action="tool_run",
        command=envelope,
    )

    assert parse_tool_run_command(decision.command or "") == "uname -a"


@pytest.mark.parametrize(
    "tool",
    ["audit_mcp.semantic_search", "run_command", "analyzer.run", "rea.analyze"],
)
def test_non_analyzer_tool_name_is_rejected(tool: str) -> None:
    with pytest.raises(ToolRunContractError, match="analyzer.run_command"):
        parse_tool_run_command(_envelope(tool, "uname -a"))


@pytest.mark.parametrize("command", ["   ", "", None, 7])
def test_blank_or_non_string_command_is_rejected(command: Any) -> None:
    with pytest.raises(ToolRunContractError):
        parse_tool_run_command(_envelope("analyzer.run_command", command))


def test_missing_args_command_key_is_rejected() -> None:
    raw = json.dumps({"tool": "analyzer.run_command", "args": {}})

    with pytest.raises(ToolRunContractError):
        parse_tool_run_command(raw)


def test_non_json_command_is_rejected() -> None:
    with pytest.raises(ToolRunContractError):
        parse_tool_run_command("uname -a")


class _FakeSSH:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.commands: list[str] = []

    async def run_command(self, integration: dict[str, Any], command: str, **_kwargs: Any) -> str:
        self.commands.append(command)
        return self.stdout


async def test_execute_command_runs_unwrapped_shell_string_and_returns_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ssh = _FakeSSH(stdout="Linux analyzer 6.1\n")

    async def fake_get_ssh_service(_settings: Any) -> _FakeSSH:
        return ssh

    async def fake_timeout(_key: str) -> float:
        return 30.0

    monkeypatch.setattr(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service", fake_get_ssh_service,
    )
    monkeypatch.setattr(analyzer_actions, "_read_float_config", fake_timeout)

    shell = parse_tool_run_command(_envelope("analyzer.run_command", "uname -a"))
    result = await execute_command(
        settings=None,  # type: ignore[arg-type]
        integration={"id": 1, "host": "192.168.1.10"},
        investigation_id=f"inv-{uuid4().hex[:8]}",
        command=shell,
    )

    assert ssh.commands == ["uname -a"]
    assert result["stdout"] == "Linux analyzer 6.1\n"
    assert result["exit_code"] == 0

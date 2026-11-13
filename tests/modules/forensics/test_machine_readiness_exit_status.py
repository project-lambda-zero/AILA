"""Tests for issue #417: readiness probes honor the tool's exit status.

A probe counts as a pass only when its check command exits 0 and prints no
not-found message. Before this fix, a piped probe such as
``zeek --version 2>&1 | grep -iq zeek`` reported the pipeline's exit status,
so a missing binary could still read as installed.

The SSH layer is replaced by a fake that mirrors the real service contract:
``run_command_full`` returns ``(stdout, stderr, exit_code)`` and
``run_command`` raises ``UpstreamError`` on nonzero exit. The fake is patched
in at the ``get_ssh_service`` seam, so no host is contacted.
"""
from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from aila.modules.forensics.contracts.machine import MachineReadinessResult
from aila.modules.forensics.services.machine_readiness import (
    MachineReadinessService,
    _load_tool_requirements,
)
from aila.platform.exceptions import UpstreamError

_INTEGRATION: dict[str, Any] = {
    "id": 1,
    "name": "analyzer",
    "host": "192.168.1.10",
    "username": "user",
}

# MachineReadinessService only stores settings; the probes never read them.
_SETTINGS: Any = None


class _FakeSSH:
    """Returns a canned ``(stdout, stderr, exit_code)`` for the first matching key."""

    def __init__(self, responses: dict[str, tuple[str, str, int]], default: tuple[str, str, int]) -> None:
        self._responses = responses
        self._default = default

    def _lookup(self, command: str) -> tuple[str, str, int]:
        for needle, reply in self._responses.items():
            if needle in command:
                return reply
        return self._default

    async def run_command_full(
        self, _integration: dict[str, Any], command: str, **_: Any,
    ) -> tuple[str, str, int]:
        return self._lookup(command)

    async def run_command(self, _integration: dict[str, Any], command: str, **_: Any) -> str:
        stdout, stderr, exit_code = self._lookup(command)
        if exit_code != 0:
            raise UpstreamError(f"command exited {exit_code}: {stderr}")
        return stdout


def _single_tool(name: str, command: str, required: bool) -> dict[str, list[dict[str, Any]]]:
    return {
        "network": [{
            "name": name,
            "required": required,
            "linux": {"check_command": command, "install_commands": []},
        }],
    }


async def _check(fake: _FakeSSH, requirements: dict[str, list[dict[str, Any]]] | None = None) -> MachineReadinessResult:
    """Run Linux readiness against ``fake``; ``requirements=None`` uses the bundled JSON."""
    return await _check_os(fake, "linux", requirements)


async def _check_os(
    fake: _FakeSSH, analyzer_os: str, requirements: dict[str, list[dict[str, Any]]] | None = None,
) -> MachineReadinessResult:
    """Run readiness for ``analyzer_os`` against ``fake``; ``requirements=None`` uses the bundled JSON."""
    service = MachineReadinessService(_SETTINGS)
    patches = [patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        AsyncMock(return_value=fake),
    )]
    if requirements is not None:
        patches.append(patch(
            "aila.modules.forensics.services.machine_readiness._load_tool_requirements",
            return_value=requirements,
        ))
    for p in patches:
        p.start()
    try:
        return await service.check_readiness(
            integration=_INTEGRATION,
            system_id=1,
            system_name="analyzer",
            analyzer_os=analyzer_os,
            install_missing=False,
        )
    finally:
        for p in patches:
            p.stop()


def _tool(result: MachineReadinessResult, name: str):
    return next(t for t in result.tools if t.tool_name == name)


async def test_exit_zero_with_not_found_text_marks_required_tool_missing() -> None:
    fake = _FakeSSH({"tshark": ("", "bash: tshark: command not found", 0)}, default=("ok", "", 0))

    result = await _check(fake, _single_tool("tshark", "tshark --version", required=True))

    assert _tool(result, "tshark").status == "missing"
    assert result.ready is False


async def test_nonzero_exit_marks_required_tool_missing() -> None:
    fake = _FakeSSH({"tshark": ("", "", 127)}, default=("ok", "", 0))

    result = await _check(fake, _single_tool("tshark", "tshark --version", required=True))

    assert _tool(result, "tshark").status == "missing"
    assert result.ready is False


async def test_exit_zero_with_version_line_reports_installed_with_that_version() -> None:
    fake = _FakeSSH({"tshark": ("TShark (Wireshark) 4.2.0\nsecond line\n", "", 0)}, default=("ok", "", 0))

    result = await _check(fake, _single_tool("tshark", "tshark --version", required=True))

    tshark = _tool(result, "tshark")
    assert tshark.status == "installed"
    assert tshark.version == "TShark (Wireshark) 4.2.0"
    assert result.ready is True


_SINGLE_PIPE = re.compile(r"(?<!\|)\|(?!\|)")


@pytest.mark.parametrize(
    ("tool", "os_name", "check_command"),
    [
        pytest.param(
            tool["name"], os_name, tool[os_name]["check_command"], id=f"{tool['name']}-{os_name}",
        )
        for tools in _load_tool_requirements().values()
        for tool in tools
        for os_name in ("linux", "macos", "windows")
        if os_name in tool
    ],
)
def test_bundled_check_commands_have_no_pipe_masking_the_tool_exit(
    tool: str, os_name: str, check_command: str,
) -> None:
    """A pipe stage reports its own exit status, so a missing tool reads as present."""
    assert not _SINGLE_PIPE.search(check_command), f"{tool}/{os_name}: {check_command}"


async def test_windows_readiness_skips_foremost_instead_of_reporting_it_installed() -> None:
    fake = _FakeSSH({}, default=("present 1.0", "", 0))

    result = await _check_os(fake, "windows")

    foremost = _tool(result, "foremost")
    assert foremost.status == "skipped"
    assert result.ready is True

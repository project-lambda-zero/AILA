"""Binary-analysis collector issues every remote step in the analyzer's form (#440).

Drives the real ``collect_binary_analysis_artifacts`` with a recording SSH
fake: nothing is executed. One discovery result is a PE sample, so the
Ghidra stage is reached too.
"""
from __future__ import annotations

import json
import shlex
from typing import Any

from aila.modules.forensics.workflow.states.collectors.binary_analysis import (
    collect_binary_analysis_artifacts,
)

_WINDOWS_TEMP = r"C:\Users\analyst\AppData\Local\Temp"
_SAMPLE = {"sha256": "ab" * 32, "size": 4096, "filetype": "pe", "basename": "drop.exe"}


class _RecordingSsh:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.uploads: list[str] = []

    async def run_command(self, _integration: dict, command: str, timeout_seconds: float) -> str:
        self.commands.append(command)
        if "dissect.target" in command:
            return "windows\n"
        if command.startswith("echo "):
            return _WINDOWS_TEMP + "\n"
        if "aila_binaryscan_" in command and not command.startswith(("del ", "rm ")):
            return json.dumps({"candidates": [{"path": "x", "size": 1}], "results": [_SAMPLE]})
        return "NO\n"

    async def upload_file(
        self, _integration: dict, _local: str, remote: str, timeout_seconds: float,
    ) -> None:
        self.uploads.append(remote)


class _Emitter:
    def __init__(self) -> None:
        self.stages: list[dict[str, Any]] = []

    async def emit(self, _kind: str, _message: str, meta: dict[str, Any]) -> None:
        self.stages.append(meta)


async def _collect(analyzer_os: str, path: str) -> tuple[_RecordingSsh, _Emitter, list[dict[str, Any]]]:
    ssh, emitter = _RecordingSsh(), _Emitter()
    artifacts = await collect_binary_analysis_artifacts(
        ssh, {"host": "analyzer"}, path, analyzer_os, emitter=emitter,
    )
    return ssh, emitter, artifacts


async def test_posix_analyzer_gets_posix_commands_and_a_quoted_image_path() -> None:
    image = "/evidence/case one/it's $HOME `id`.E01"

    ssh, emitter, artifacts = await _collect("linux", image)

    sniff, run, cleanup = ssh.commands
    assert shlex.split(sniff)[0] == "python3"
    assert shlex.split(sniff)[-1] == image
    assert ssh.uploads == [shlex.split(run)[1]]
    assert ssh.uploads[0].startswith("/tmp/aila_binaryscan_")
    assert shlex.split(run) == ["python3", ssh.uploads[0]]
    assert shlex.split(cleanup) == ["rm", "-f", ssh.uploads[0]]
    for command in ssh.commands:
        assert "%TEMP%" not in command
        assert "\\" not in command
        assert "del /f /q" not in command
    assert [a["type"] for a in artifacts] == ["binary_analysis"]
    ghidra = [s for s in emitter.stages if s["stage"] == "ghidra_stage_skipped"]
    assert [s["reason"] for s in ghidra] == ["analyzer_os_unsupported"]


async def test_windows_analyzer_keeps_windows_commands() -> None:
    image = r"C:\evidence\case one\disk.E01"

    ssh, _emitter, artifacts = await _collect("windows", image)

    sniff, echo, run, cleanup, scratch_probe = ssh.commands
    assert sniff.startswith('python -c "import sys; ')
    assert sniff.endswith(f' "{image}"')
    assert echo == "echo %TEMP%"
    (remote_script,) = ssh.uploads
    assert remote_script.startswith(_WINDOWS_TEMP + "\\aila_binaryscan_")
    assert run == f'python "{remote_script}"'
    assert cleanup == f'del /f /q "{remote_script}" 2>nul'
    assert scratch_probe.startswith("if exist ")
    assert [a["type"] for a in artifacts] == ["binary_analysis"]

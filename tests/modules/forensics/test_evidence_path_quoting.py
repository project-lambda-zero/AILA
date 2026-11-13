"""Evidence paths reach remote commands and generated scripts as one literal (#445).

Deep-analysis runners, the intake directory listing, and the binary-analysis
script builder run for real against a recording SSH fake; nothing executes.
POSIX commands are checked with ``shlex.split``, the generated script with
``ast.parse``, and the PowerShell listing by decoding its single-quoted
literal.
"""
from __future__ import annotations

import ast
import re
import shlex
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aila.modules.forensics.services.evidence_classifier import classify_evidence_directory
from aila.modules.forensics.workflow.states import deep_analysis
from aila.modules.forensics.workflow.states.collectors.binary_analysis import _build_analysis_script

_NAMES = [
    "sample name.bin",
    'sample"name.bin',
    "sample'name.bin",
    "sample$HOME.bin",
    "sample`id`.bin",
    "sample;id.bin",
    "sample\nname.bin",
]


def _words(command: str) -> list[str]:
    """POSIX shell words, with unquoted control operators (``;``, ``|``, ...) split out."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def _has_live_expansion(command: str) -> bool:
    """True when a ``$`` or backtick sits where a POSIX shell would expand it."""
    quote: str | None = None
    escaped = False
    for ch in command:
        if escaped:
            escaped = False
        elif quote == "'":
            quote = None if ch == "'" else quote
        elif ch == "\\":
            escaped = True
        elif quote == '"' and ch == '"':
            quote = None
        elif quote is None and ch in "'\"":
            quote = ch
        elif ch in "$`":
            return True
    return False


class _RecordingSsh:
    def __init__(self) -> None:
        self.commands: list[str] = []

    async def run_command(self, _integration: dict, command: str, timeout_seconds: float) -> str:
        self.commands.append(command)
        return ""


@pytest.mark.parametrize("name", _NAMES)
async def test_deep_analysis_posix_commands_carry_the_exact_path(name: str) -> None:
    path = f"/evidence/{name}"
    ssh = _RecordingSsh()

    await deep_analysis._extract_strings_iocs(ssh, {}, path, "linux", "2>/dev/null")
    await deep_analysis._run_floss(ssh, {}, path, "linux", "2>/dev/null")
    await deep_analysis._run_capa(ssh, {}, path, "linux", "2>/dev/null")
    await deep_analysis._run_ghidra_list_functions(ssh, {}, path, "linux")

    tool_commands = [c for c in ssh.commands if not c.startswith("mkdir ")]
    assert len(tool_commands) == 4
    for command in tool_commands:
        assert _words(command).count(path) == 1
        assert not _has_live_expansion(command)


async def _listing_command(directory: str, analyzer_os: str) -> str:
    ssh = _RecordingSsh()
    with patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=AsyncMock(return_value=ssh),
    ):
        await classify_evidence_directory(MagicMock(), {}, directory, analyzer_os=analyzer_os)
    (command,) = ssh.commands
    return command


@pytest.mark.parametrize("name", _NAMES)
async def test_intake_posix_listing_carries_the_exact_directory(name: str) -> None:
    directory = f"/evidence/{name}"

    command = await _listing_command(directory, "linux")
    tokens = _words(command)

    assert not _has_live_expansion(command)
    assert tokens[0] == "find"
    assert tokens[1] == directory
    assert tokens[tokens.index("ls") + 2] == directory
    assert tokens.count(directory) == 2


def _powershell_literal_after(flag: str, command: str) -> str:
    match = re.search(re.escape(flag) + r" '((?:[^']|'')*)'", command)
    assert match is not None
    return match.group(1).replace("''", "'")


@pytest.mark.parametrize("directory", [r"C:\evidence\o'brien case", r"D:\cases\it's\x"])
async def test_intake_windows_listing_embeds_single_quotes(directory: str) -> None:
    command = await _listing_command(directory, "windows")

    assert _powershell_literal_after("-LiteralPath", command) == directory


@pytest.mark.parametrize("name", [*_NAMES, "trailing\\"])
def test_generated_binary_analysis_script_carries_the_exact_image_path(name: str) -> None:
    image = f"/evidence/{name}"

    tree = ast.parse(_build_analysis_script(image, ["tmp"], False, user_appdata=False))

    opened = [
        ast.literal_eval(node.args[0])
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "Target"
    ]
    assert opened == [image]

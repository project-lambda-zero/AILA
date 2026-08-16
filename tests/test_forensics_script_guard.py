"""AST-level script guard for the forensics investigator.

Regression coverage for issue #118: the earlier substring blocklist was
trivially bypassable via aliasing, string concatenation, ``importlib``,
and dunder walks. The guard now parses the script and rejects the same
capabilities structurally, and any construct that would have needed the
substring check gets blocked at the AST level.
"""
from __future__ import annotations

import pytest

from aila.modules.forensics.agents.investigator import _script_rejection


@pytest.mark.parametrize(
    "script",
    [
        # Issue #118 payload: getattr(__import__('o'+'s'),'system')
        "getattr(__import__('o'+'s'),'system')('id')",
        # Aliasing bypass (Name-load reference to __import__).
        "im = __import__\nim('socket')",
        # importlib.import_module route to a banned module.
        "import importlib\nimportlib.import_module('socket')",
        # Classic ``()__class__`` sandbox walk.
        "x = ().__class__.__base__.__subclasses__()",
        # Direct banned import (the substring guard already caught this;
        # AST guard must keep catching it).
        "import socket\ns = socket.socket()",
        # Dynamic-execution primitives.
        "exec('print(1)')",
        "eval('1+1')",
        "compile('1', '<x>', 'exec')",
        # Destructive filesystem calls the substring list originally guarded.
        "import shutil\nshutil.rmtree('/tmp/x')",
        "import os\nos.rmdir('/tmp/x')",
        # Unparseable input: fail-closed.
        "def broken(:",
    ],
)
def test_dangerous_scripts_rejected(script: str) -> None:
    reason = _script_rejection(script)
    assert reason is not None, f"expected rejection, got None for: {script!r}"
    assert reason.startswith("blocked:"), reason


@pytest.mark.parametrize(
    "script",
    [
        # Typical benign forensic-script shape: stdlib, path walking, JSON.
        (
            "import os\n"
            "import json\n"
            "from pathlib import Path\n"
            "for entry in os.scandir('/tmp'):\n"
            "    if entry.is_file():\n"
            "        print(json.dumps({'path': entry.path, 'size': entry.stat().st_size}))\n"
        ),
        # Non-dunder getattr with a literal attribute name.
        "x = getattr({}, 'get', None)",
        # Non-dunder getattr with a dynamic attribute name (documented
        # pragmatic allowance -- the dunder walk is caught structurally).
        "name = 'get'\nx = getattr({}, name, None)",
    ],
)
def test_benign_scripts_accepted(script: str) -> None:
    assert _script_rejection(script) is None

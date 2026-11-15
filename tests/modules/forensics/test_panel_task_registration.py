"""Worker-facing forensics task import registers both panel callables."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_fresh_process_registers_panel_investigate_and_writeup() -> None:
    root = Path(__file__).resolve().parents[3]
    code = r'''
import aila.modules.forensics.workflow.task
from aila.platform.tasks.template import _REGISTRY
expected = {
    "aila.modules.forensics.workflow.panel.task.run_forensics_panel_investigate",
    "aila.modules.forensics.workflow.panel.writeup.run_forensics_panel_writeup",
}
registered = {task.name for task in _REGISTRY.tasks}
missing = expected - registered
assert not missing, missing
for name in expected:
    task = _REGISTRY.get_task(name)
    assert task is not None and task.track == "forensics"
    assert task.definition is not None
'''
    env = dict(os.environ, PYTHONPATH="src")
    completed = subprocess.run(
        [sys.executable, "-c", code], cwd=root, env=env,
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

"""Evidence classification and the analysis lanes intake derives from it.

Synthetic directory listings only; the SSH service is replaced with a fake
that returns a canned ``find -printf '%s %p'`` listing, so nothing runs on
an analyzer.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from aila.modules.forensics.services.evidence_classifier import _classify_file
from aila.modules.forensics.workflow.states.intake import state_intake


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        # Disk images, including the .img extension.
        ("disk.img", "disk_image"),
        ("DISK.IMG", "disk_image"),
        ("webserver01_root.img", "disk_image"),
        ("disk.raw", "disk_image"),
        ("disk.E01", "disk_image"),
        # Memory images named memory*.raw win over the generic raw rule.
        ("memory.raw", "memory_dump"),
        ("Memory.raw", "memory_dump"),
        ("memory_dump.raw", "memory_dump"),
        ("memdump.raw", "memory_dump"),
        ("memory.raw.gz", "memory_dump"),
        ("host.vmem", "memory_dump"),
        # Logs, including extensionless syslog and its rotations.
        ("syslog", "log_file"),
        ("SYSLOG", "log_file"),
        ("syslog.1", "log_file"),
        ("/var/log/syslog", "log_file"),
        ("auth.log", "log_file"),
        ("Security.evtx", "log_file"),
        # Unrelated names stay unknown on a disk-evidence project.
        ("notes.txt", "unknown"),
        ("mysyslog", "unknown"),
        ("syslog.conf", "unknown"),
        ("image.png", "unknown"),
    ],
)
def test_classify_file(filename: str, expected: str) -> None:
    assert _classify_file(filename) == expected


class _Emitter:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    async def emit(self, stage: str, message: str, meta: dict[str, Any]) -> None:
        self.events.append((stage, message, meta))


async def _run_intake(listing: str, project_id: str) -> Any:
    ssh = AsyncMock()
    ssh.run_command.return_value = listing
    services = SimpleNamespace(
        emitter=_Emitter(),
        settings=None,
        evidence_directory="/evidence",
        integration={"id": 1, "host": "analyzer.invalid"},
        run_id="run-446",
    )
    with patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=AsyncMock(return_value=ssh),
    ):
        return await state_intake(
            {"project_id": project_id, "analyzer_os": "linux"}, services,
        )


@pytest.mark.usefixtures("test_db")
@pytest.mark.parametrize(
    ("listing", "lanes"),
    [
        ("1048576 /evidence/webserver01_root.img\n", ["binary_analysis", "disk"]),
        ("2048 /evidence/var/log/syslog\n", ["log"]),
        ("4096 /evidence/memory.raw\n", ["memory"]),
    ],
)
async def test_intake_activates_lane_for_classified_evidence(
    listing: str, lanes: list[str],
) -> None:
    result = await _run_intake(listing, project_id="proj-446")

    assert result.next_state == "collection"
    assert result.output["active_lanes"] == lanes

"""Evidence classification and the analysis lanes intake derives from it.

Synthetic directory listings only; the SSH service is replaced with a fake
that returns a canned ``find -printf '%s %p'`` listing, so nothing runs on
an analyzer.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from aila.modules.forensics.services.evidence_classifier import _classify_file
from aila.modules.forensics.workflow.states.intake import (
    state_intake,
    uow_prefetch_evidence,
)


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


# Matches ForensicsConfigSchema.intake_hash_max_bytes' default (2 GiB).
_CAP_BYTES = 2 * 1024 * 1024 * 1024
_DIGEST = "ab" * 32


class _Analyzer:
    """Canned analyzer. ``find`` returns the listing; every other command is a
    hash command, recorded in ``hash_commands`` and answered from
    ``hash_output`` keyed by file path."""

    def __init__(self, listing: str, hash_output: dict[str, str]) -> None:
        self.listing = listing
        self.hash_output = hash_output
        self.hash_commands: list[str] = []

    async def run_command(
        self, integration: dict[str, Any], command: str, timeout_seconds: float = 0.0,
    ) -> str:
        if command.startswith("find "):
            return self.listing
        self.hash_commands.append(command)
        for path, output in self.hash_output.items():
            if path in command:
                return output
        return "sha256sum: cannot read file\n"


async def _intake(project_id: str, analyzer: _Analyzer) -> None:
    services = SimpleNamespace(
        emitter=_Emitter(),
        settings=None,
        evidence_directory="/evidence",
        integration={"id": 1, "host": "analyzer.invalid"},
        run_id="run-418",
    )
    with patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=AsyncMock(return_value=analyzer),
    ):
        await state_intake({"project_id": project_id, "analyzer_os": "linux"}, services)


async def _stored(project_id: str) -> dict[str, Any]:
    rows = await uow_prefetch_evidence(project_id)
    return {row.file_path: row for row in rows}


def _project_id() -> str:
    return f"proj-418-{uuid4().hex[:8]}"


def _hash_status(row: Any) -> str:
    return json.loads(row.metadata_json)["hash_status"]


@pytest.mark.usefixtures("test_db")
async def test_intake_stores_sha256_for_file_at_cap() -> None:
    path = "/evidence/webserver01_root.img"
    analyzer = _Analyzer(
        f"{_CAP_BYTES} {path}\n", {path: f"{_DIGEST}  {path}\n"},
    )

    project_id = _project_id()
    await _intake(project_id, analyzer)

    row = (await _stored(project_id))[path]
    assert row.file_hash_sha256 == _DIGEST
    assert _hash_status(row) == "computed"
    assert len(analyzer.hash_commands) == 1


@pytest.mark.usefixtures("test_db")
async def test_intake_defers_file_over_cap_without_contacting_analyzer() -> None:
    path = "/evidence/webserver01_root.img"
    analyzer = _Analyzer(f"{_CAP_BYTES + 1} {path}\n", {})

    project_id = _project_id()
    await _intake(project_id, analyzer)

    row = (await _stored(project_id))[path]
    assert row.file_hash_sha256 is None
    assert _hash_status(row) == "deferred_over_cap"
    assert analyzer.hash_commands == []


@pytest.mark.usefixtures("test_db")
async def test_intake_records_failed_status_when_hash_output_is_not_a_digest() -> None:
    path = "/evidence/memory.raw"
    analyzer = _Analyzer(
        f"4096 {path}\n", {path: "sha256sum: permission denied\n"},
    )

    project_id = _project_id()
    await _intake(project_id, analyzer)

    row = (await _stored(project_id))[path]
    assert row.file_hash_sha256 is None
    assert _hash_status(row) == "failed"


@pytest.mark.usefixtures("test_db")
async def test_rerun_clears_stale_digest_when_file_grows_past_cap() -> None:
    path = "/evidence/webserver01_root.img"
    project_id = _project_id()
    await _intake(
        project_id,
        _Analyzer(f"1048576 {path}\n", {path: f"{_DIGEST}  {path}\n"}),
    )
    assert (await _stored(project_id))[path].file_hash_sha256 == _DIGEST

    await _intake(project_id, _Analyzer(f"{_CAP_BYTES + 1} {path}\n", {}))

    row = (await _stored(project_id))[path]
    assert row.file_hash_sha256 is None
    assert _hash_status(row) == "deferred_over_cap"


@pytest.mark.usefixtures("test_db")
async def test_rerun_does_not_rehash_unchanged_file() -> None:
    path = "/evidence/webserver01_root.img"
    project_id = _project_id()
    await _intake(
        project_id,
        _Analyzer(f"1048576 {path}\n", {path: f"{_DIGEST}  {path}\n"}),
    )

    rerun = _Analyzer(f"1048576 {path}\n", {path: f"{'cd' * 32}  {path}\n"})
    await _intake(project_id, rerun)

    assert rerun.hash_commands == []
    rows = await uow_prefetch_evidence(project_id)
    assert len(rows) == 1
    assert rows[0].file_hash_sha256 == _DIGEST
    assert _hash_status(rows[0]) == "computed"

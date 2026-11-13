"""Binary-analysis results persist one artifact per sample (#459).

Runs the real collection state, its ``_on_artifact`` persistence callback,
and the real binary-analysis collector against the test database. SSH is a
fake that answers the OS sniff and returns a synthetic analyzer payload;
nothing executes.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.forensics.db_models import ArtifactRecord
from aila.modules.forensics.workflow.states.collection import _state_collection_body
from aila.storage.database import async_session_scope

pytestmark = pytest.mark.usefixtures("test_db")


def _success(name: str) -> dict[str, Any]:
    return {
        "path": f"/tmp/{name}", "basename": name, "sha256": name * 8,
        "size": 64, "filetype": "script",
    }


_ERROR = {"path": "/tmp/unreadable", "error": "read failed: permission denied"}


class _AnalyzerSsh:
    def __init__(self, results: list[dict[str, Any]]) -> None:
        self.results = results

    async def run_command(self, _integration: dict, command: str, timeout_seconds: float) -> str:
        if "dissect.target" in command:
            return "linux\n"
        if command.startswith("python3 ") and "aila_binaryscan_" in command:
            return json.dumps({"candidates": [{"path": r["path"], "size": 64} for r in self.results],
                               "results": self.results})
        return ""

    async def upload_file(self, _integration: dict, _local: str, _remote: str, timeout_seconds: float) -> None:
        return None


class _Emitter:
    def __init__(self) -> None:
        self.stages: list[dict[str, Any]] = []

    async def emit(self, _kind: str, _message: str, meta: dict[str, Any]) -> None:
        self.stages.append(meta)


async def _collect(project_id: str, evidence_id: str, results: list[dict[str, Any]]) -> _Emitter:
    emitter = _Emitter()
    services = SimpleNamespace(settings=None, integration={}, emitter=emitter)
    with patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=AsyncMock(return_value=_AnalyzerSsh(results)),
    ):
        await _state_collection_body({
            "project_id": project_id,
            "active_lanes": ["binary_analysis"],
            "analyzer_os": "linux",
            "evidence_files": [{
                "id": evidence_id, "file_path": "/evidence/disk.E01",
                "evidence_type": "disk_image", "size_bytes": 1024,
            }],
        }, services)
    return emitter


async def _stored(project_id: str) -> list[dict[str, Any]]:
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(ArtifactRecord).where(
                ArtifactRecord.project_id == project_id,
                ArtifactRecord.artifact_type == "binary_analysis",
            )
        )).all()
    return [json.loads(r.data_json) for r in rows]


def _ids() -> tuple[str, str]:
    return f"proj-{uuid4().hex[:8]}", f"ev-{uuid4().hex[:8]}"


@pytest.mark.parametrize(
    "results",
    [
        [_ERROR, _success("a"), _success("b")],
        [_success("a"), _success("b"), _ERROR],
    ],
    ids=["error_first", "error_last"],
)
async def test_each_successful_sample_persists_and_a_read_failure_is_an_event(
    results: list[dict[str, Any]],
) -> None:
    project_id, evidence_id = _ids()

    emitter = await _collect(project_id, evidence_id, results)

    stored = await _stored(project_id)
    assert sorted(d["path"] for d in stored) == ["/tmp/a", "/tmp/b"]
    failures = [s for s in emitter.stages if s["stage"] == "binary_analysis_sample_failed"]
    assert [f["sample_path"] for f in failures] == ["/tmp/unreadable"]


async def test_stored_error_row_does_not_block_a_later_success() -> None:
    project_id, evidence_id = _ids()
    async with async_session_scope() as session:
        session.add(ArtifactRecord(
            project_id=project_id, artifact_family="malware", artifact_type="binary_analysis",
            source_tool="capa+floss+strings+pefile", source_evidence_id=evidence_id,
            data_json=json.dumps({"evidence_path": "/evidence/disk.E01", **_ERROR}),
        ))
        await session.commit()

    await _collect(project_id, evidence_id, [_success("a")])

    stored = await _stored(project_id)
    assert sorted(d["path"] for d in stored) == ["/tmp/a", "/tmp/unreadable"]


async def test_rerun_does_not_duplicate_successful_rows() -> None:
    project_id, evidence_id = _ids()
    results = [_success("a"), _success("b")]

    await _collect(project_id, evidence_id, results)
    await _collect(project_id, evidence_id, results)

    stored = await _stored(project_id)
    assert sorted(d["path"] for d in stored) == ["/tmp/a", "/tmp/b"]

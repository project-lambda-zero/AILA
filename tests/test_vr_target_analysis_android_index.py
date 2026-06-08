"""F-3 — TargetAnalysisService._android_index_decompiled unit tests.

The worker hands the jadx Java tree to audit-mcp's `index_codebase`,
polls until READY, and writes `audit_mcp_decompiled_index_id` +
`audit_mcp_decompiled_indexed_at` into mcp_handles_json. These tests
exercise the worker in isolation — no DB, no real MCP — by passing
mocked bridges into the service constructor and a stub tracker.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from aila.modules.vr.contracts.target_stages import StageName
from aila.modules.vr.services.stage_tracker import _DEFAULT_TIMEOUTS
from aila.modules.vr.services.target_analysis import (
    _ANDROID_STAGES,
    TargetAnalysisError,
    TargetAnalysisService,
)


class _RecordingTracker:
    """Stand-in for StageTracker that captures record_output calls.

    The real tracker uses an async context manager + DB row mutation.
    For pure worker-method unit tests we only need ``record_output``.
    """

    def __init__(self) -> None:
        self.outputs: list[dict[str, Any]] = []

    def record_output(self, **kwargs: Any) -> None:
        self.outputs.append(dict(kwargs))


def _build_service(
    audit_forward: AsyncMock | None = None,
    android_forward: AsyncMock | None = None,
) -> TargetAnalysisService:
    audit = MagicMock()
    audit.forward = audit_forward or AsyncMock()
    android = MagicMock()
    android.forward = android_forward or AsyncMock()
    ida = MagicMock()
    return TargetAnalysisService(
        ida=ida, audit_mcp=audit, android_mcp=android,
    )


@pytest.mark.asyncio
async def test_index_decompiled_kicks_off_and_records_handles() -> None:
    """Happy path: jadx dir present, index_codebase returns id, poll READY."""
    audit_forward = AsyncMock()
    audit_forward.side_effect = [
        # index_codebase response — kickoff returns the new index id.
        {"status": "ready", "index_id": "idx-abc123"},
        # poll_index — single READY on first poll exits the loop.
        {"status": "ready", "state": "READY"},
    ]
    svc = _build_service(audit_forward=audit_forward)
    tracker = _RecordingTracker()

    current_handles = {
        "android_mcp_decompiled_dir": "/work/decompiled/sampleapp",
        "android_mcp_decoded_dir": "/work/decoded/sampleapp",
    }
    await svc._android_index_decompiled(  # noqa: SLF001 — unit-testing private API
        target_id="t-1",
        descriptor={"apk_path": "/work/sampleapp.apk"},
        current_handles=current_handles,
        tracker=tracker,
    )

    # index_codebase should be called once with path + java language.
    kickoff_call = audit_forward.await_args_list[0]
    assert kickoff_call.kwargs["action"] == "index_codebase"
    assert kickoff_call.kwargs["path"] == "/work/decompiled/sampleapp"
    assert kickoff_call.kwargs["language"] == "java"

    # poll_index follows with the returned index_id.
    poll_call = audit_forward.await_args_list[1]
    assert poll_call.kwargs["action"] == "poll_index"
    assert poll_call.kwargs["index_id"] == "idx-abc123"

    # tracker.record_output called once with the new handle keys present.
    assert len(tracker.outputs) == 1
    persisted = json.loads(tracker.outputs[0]["mcp_handles_json"])
    assert persisted["audit_mcp_decompiled_index_id"] == "idx-abc123"
    assert "audit_mcp_decompiled_indexed_at" in persisted
    # Existing handles are preserved.
    assert persisted["android_mcp_decompiled_dir"] == "/work/decompiled/sampleapp"
    assert persisted["android_mcp_decoded_dir"] == "/work/decoded/sampleapp"


@pytest.mark.asyncio
async def test_index_decompiled_handles_nested_data_index_id() -> None:
    """index_codebase sometimes wraps under data.index_id (mirror of _ingest_source_repo)."""
    audit_forward = AsyncMock()
    audit_forward.side_effect = [
        {"status": "ready", "data": {"index_id": "idx-wrapped"}},
        {"status": "ready", "state": "READY"},
    ]
    svc = _build_service(audit_forward=audit_forward)
    tracker = _RecordingTracker()

    await svc._android_index_decompiled(  # noqa: SLF001
        target_id="t-1",
        descriptor={"apk_path": "/work/y.apk"},
        current_handles={"android_mcp_decompiled_dir": "/work/d"},
        tracker=tracker,
    )

    persisted = json.loads(tracker.outputs[0]["mcp_handles_json"])
    assert persisted["audit_mcp_decompiled_index_id"] == "idx-wrapped"


@pytest.mark.asyncio
async def test_index_decompiled_soft_skips_when_no_jadx_output() -> None:
    """Missing android_mcp_decompiled_dir is a soft-skip, not a raise."""
    audit_forward = AsyncMock()  # Should never be called.
    svc = _build_service(audit_forward=audit_forward)
    tracker = _RecordingTracker()

    await svc._android_index_decompiled(  # noqa: SLF001
        target_id="t-1",
        descriptor={"apk_path": "/work/y.apk"},
        current_handles={},  # No decompiled_dir.
        tracker=tracker,
    )

    audit_forward.assert_not_called()
    assert len(tracker.outputs) == 1
    persisted = json.loads(tracker.outputs[0]["mcp_handles_json"])
    # No index_id was created.
    assert "audit_mcp_decompiled_index_id" not in persisted
    # Skip marker is present.
    assert persisted["audit_mcp_decompiled_index"]["skipped"] == "no jadx output"


@pytest.mark.asyncio
async def test_index_decompiled_raises_when_audit_mcp_errors() -> None:
    """An error response from index_codebase fails the stage."""
    audit_forward = AsyncMock(
        return_value={"status": "error", "error": "audit-mcp unreachable"},
    )
    svc = _build_service(audit_forward=audit_forward)
    tracker = _RecordingTracker()

    with pytest.raises(TargetAnalysisError, match="audit-mcp unreachable"):
        await svc._android_index_decompiled(  # noqa: SLF001
            target_id="t-1",
            descriptor={"apk_path": "/work/y.apk"},
            current_handles={"android_mcp_decompiled_dir": "/work/d"},
            tracker=tracker,
        )
    # No handles written when the kickoff fails.
    assert tracker.outputs == []


@pytest.mark.asyncio
async def test_index_decompiled_raises_when_no_index_id_returned() -> None:
    """index_codebase that returns status=ready but no index_id is a hard error."""
    audit_forward = AsyncMock(return_value={"status": "ready", "data": {}})
    svc = _build_service(audit_forward=audit_forward)
    tracker = _RecordingTracker()

    with pytest.raises(TargetAnalysisError, match="no index_id"):
        await svc._android_index_decompiled(  # noqa: SLF001
            target_id="t-1",
            descriptor={"apk_path": "/work/y.apk"},
            current_handles={"android_mcp_decompiled_dir": "/work/d"},
            tracker=tracker,
        )
    assert tracker.outputs == []


@pytest.mark.asyncio
async def test_index_decompiled_raises_when_descriptor_missing_apk_path() -> None:
    """Worker validates the descriptor invariant before any MCP call.

    Every android_apk target carries apk_path in its descriptor (set
    by POST /vr/targets/upload-apk). Failing fast here gives a clearer
    error than letting audit-mcp reject a stray call later.
    """
    audit_forward = AsyncMock()
    svc = _build_service(audit_forward=audit_forward)
    tracker = _RecordingTracker()

    with pytest.raises(TargetAnalysisError, match="apk_path"):
        await svc._android_index_decompiled(  # noqa: SLF001
            target_id="t-1",
            descriptor={},  # No apk_path — descriptor invariant breach.
            current_handles={"android_mcp_decompiled_dir": "/work/d"},
            tracker=tracker,
        )
    audit_forward.assert_not_called()
    assert tracker.outputs == []


def test_android_stages_set_includes_index_decompiled() -> None:
    """The android-applicable stage set covers INDEX_DECOMPILED."""
    assert StageName.INDEX_DECOMPILED in _ANDROID_STAGES


def test_index_decompiled_has_extended_timeout() -> None:
    """Trailmark + Semble cold build on a jadx Java tree needs >>15 min."""
    assert _DEFAULT_TIMEOUTS[StageName.INDEX_DECOMPILED] >= 3600.0

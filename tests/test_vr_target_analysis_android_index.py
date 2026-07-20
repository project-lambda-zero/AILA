"""F-3 -- TargetAnalysisService._android_index_decompiled unit tests.

The worker was rewritten to build ONE audit-mcp index over both the
jadx Java tree AND the React Native decompile output (when present):

  * builds a per-target unified staging tree at
    ``~/.android-mcp/work/apk-unified-<sha>/`` with junction/symlink
    entries into the source dirs
  * probes the staging tree for language extensions
  * hands the staging path (NOT the raw jadx dir) plus the detected
    languages to ``audit_mcp.index_codebase``
  * polls until READY via ``_poll_audit_mcp``
  * persists ``audit_mcp_decompiled_index_id`` +
    ``audit_mcp_decompiled_indexed_at`` +
    ``audit_mcp_unified_staging_dir`` via ``_merge_handles_locked``
    (NOT via ``tracker.record_output`` -- parallel sibling stages
    would clobber each other's disjoint keys otherwise)

These tests exercise the worker in isolation by patching the heavy
filesystem + DB helpers (``_build_unified_staging``,
``_detect_staging_languages``, ``_merge_handles_locked``,
``_poll_audit_mcp``) so no real disk write and no real DB row are
required for a pure unit test.
"""
from __future__ import annotations

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


def _stub_heavy_helpers(
    monkeypatch: pytest.MonkeyPatch,
    svc: TargetAnalysisService,
    *,
    staging_path: str = "/fake/staging/apk-unified-cafebabe",
    languages: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Replace filesystem + DB helpers with test doubles.

    - ``_build_unified_staging`` is called via ``asyncio.to_thread`` on
      the module; monkey-patch it to skip the real symlink dance.
    - ``_detect_staging_languages`` probes real files; return a fixed
      list instead.
    - ``svc._merge_handles_locked`` is captured into the returned list
      so each test can assert on the handle writes.
    - ``svc._poll_audit_mcp`` becomes a no-op AsyncMock so no bridge
      round-trip is needed.
    """
    import aila.modules.vr.services.target_analysis as ta_mod

    monkeypatch.setattr(
        ta_mod, "_build_unified_staging",
        lambda **kwargs: staging_path,  # noqa: ARG005 -- signature match only
    )
    monkeypatch.setattr(
        ta_mod, "_detect_staging_languages",
        lambda _path: list(languages or ["java"]),
    )
    handle_writes: list[dict[str, Any]] = []

    async def _capture_merge(target_id: str, new_keys: dict[str, Any]) -> None:
        handle_writes.append(
            {"target_id": target_id, "new_keys": dict(new_keys)},
        )

    svc._merge_handles_locked = _capture_merge  # type: ignore[method-assign]  # noqa: SLF001
    svc._poll_audit_mcp = AsyncMock(return_value=None)  # type: ignore[method-assign]  # noqa: SLF001
    return handle_writes


@pytest.mark.asyncio
async def test_index_decompiled_kicks_off_and_records_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: jadx dir present -> unified staging built ->
    audit_mcp.index_codebase called on the staging path -> new
    handles persisted via _merge_handles_locked.
    """
    audit_forward = AsyncMock(
        return_value={"status": "ready", "index_id": "idx-abc123"},
    )
    svc = _build_service(audit_forward=audit_forward)
    handle_writes = _stub_heavy_helpers(
        monkeypatch, svc,
        staging_path="/fake/staging/apk-unified-cafebabe",
        languages=["java"],
    )

    current_handles = {
        "android_mcp_decompiled_dir": "/work/decompiled/sampleapp",
        "android_mcp_decoded_dir": "/work/decoded/sampleapp",
    }
    await svc._android_index_decompiled(  # noqa: SLF001 -- unit-testing private API
        target_id="t-1",
        descriptor={"apk_path": "/work/sampleapp.apk"},
        current_handles=current_handles,
        tracker=MagicMock(),  # tracker is `del`ed by the impl; any value
    )

    # index_codebase called once against the unified staging dir,
    # NOT the raw jadx dir. Language comes from the extension probe.
    audit_forward.assert_awaited_once()
    kickoff_call = audit_forward.await_args
    assert kickoff_call.kwargs["action"] == "index_codebase"
    assert kickoff_call.kwargs["path"] == "/fake/staging/apk-unified-cafebabe"
    assert kickoff_call.kwargs["language"] == "java"

    # Handles persist via _merge_handles_locked, NOT tracker.record_output.
    assert len(handle_writes) == 1
    persisted = handle_writes[0]["new_keys"]
    assert persisted["audit_mcp_decompiled_index_id"] == "idx-abc123"
    assert "audit_mcp_decompiled_indexed_at" in persisted
    assert persisted["audit_mcp_unified_staging_dir"] == (
        "/fake/staging/apk-unified-cafebabe"
    )


@pytest.mark.asyncio
async def test_index_decompiled_handles_nested_data_index_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """index_codebase sometimes wraps under data.index_id -- mirror of
    _ingest_source_repo. The worker unwraps it either way.
    """
    audit_forward = AsyncMock(
        return_value={"status": "ready", "data": {"index_id": "idx-wrapped"}},
    )
    svc = _build_service(audit_forward=audit_forward)
    handle_writes = _stub_heavy_helpers(monkeypatch, svc)

    await svc._android_index_decompiled(  # noqa: SLF001
        target_id="t-1",
        descriptor={"apk_path": "/work/y.apk"},
        current_handles={"android_mcp_decompiled_dir": "/work/d"},
        tracker=MagicMock(),
    )

    assert handle_writes[0]["new_keys"]["audit_mcp_decompiled_index_id"] == (
        "idx-wrapped"
    )


@pytest.mark.asyncio
async def test_index_decompiled_uses_comma_joined_language_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the staging tree carries multiple languages, the worker
    passes them all to audit_mcp (comma-joined) rather than 'auto'.
    Passing 'auto' would let trailmark's language detector filter out
    minority languages -- e.g. RN JS slices being dropped in favour
    of the dominant Java tree -- so the explicit list is essential.
    """
    audit_forward = AsyncMock(
        return_value={"status": "ready", "index_id": "idx-multi"},
    )
    svc = _build_service(audit_forward=audit_forward)
    _stub_heavy_helpers(
        monkeypatch, svc,
        languages=["java", "kotlin", "javascript"],
    )

    await svc._android_index_decompiled(  # noqa: SLF001
        target_id="t-1",
        descriptor={"apk_path": "/work/multi.apk"},
        current_handles={
            "android_mcp_decompiled_dir": "/work/jadx",
            "android_mcp_rn_decompiled_dir": "/work/rn",
        },
        tracker=MagicMock(),
    )

    assert audit_forward.await_args.kwargs["language"] == "java,kotlin,javascript"


@pytest.mark.asyncio
async def test_index_decompiled_soft_skips_when_no_java_or_react(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing BOTH android_mcp_decompiled_dir AND
    android_mcp_rn_decompiled_dir is a soft-skip, not a raise. The
    worker still persists a skip marker via _merge_handles_locked.
    Skip reason string now reads 'no jadx or rn output' -- the old
    'no jadx output' string was tightened when RN was folded in.
    """
    audit_forward = AsyncMock()  # Should never be called.
    svc = _build_service(audit_forward=audit_forward)
    handle_writes = _stub_heavy_helpers(monkeypatch, svc)

    await svc._android_index_decompiled(  # noqa: SLF001
        target_id="t-1",
        descriptor={"apk_path": "/work/y.apk"},
        current_handles={},  # No java, no RN.
        tracker=MagicMock(),
    )

    audit_forward.assert_not_called()
    assert len(handle_writes) == 1
    skip_key = handle_writes[0]["new_keys"]["audit_mcp_decompiled_index"]
    assert skip_key == {"skipped": "no jadx or rn output"}


@pytest.mark.asyncio
async def test_index_decompiled_raises_when_audit_mcp_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An error response from index_codebase fails the stage."""
    audit_forward = AsyncMock(
        return_value={"status": "error", "error": "audit-mcp unreachable"},
    )
    svc = _build_service(audit_forward=audit_forward)
    handle_writes = _stub_heavy_helpers(monkeypatch, svc)

    with pytest.raises(TargetAnalysisError, match="audit-mcp unreachable"):
        await svc._android_index_decompiled(  # noqa: SLF001
            target_id="t-1",
            descriptor={"apk_path": "/work/y.apk"},
            current_handles={"android_mcp_decompiled_dir": "/work/d"},
            tracker=MagicMock(),
        )
    # No handles written when the kickoff fails.
    assert handle_writes == []


@pytest.mark.asyncio
async def test_index_decompiled_raises_when_no_index_id_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """index_codebase that returns status=ready but no index_id is a
    hard error -- there's no id to persist and nothing to poll.
    """
    audit_forward = AsyncMock(return_value={"status": "ready", "data": {}})
    svc = _build_service(audit_forward=audit_forward)
    handle_writes = _stub_heavy_helpers(monkeypatch, svc)

    with pytest.raises(TargetAnalysisError, match="no index_id"):
        await svc._android_index_decompiled(  # noqa: SLF001
            target_id="t-1",
            descriptor={"apk_path": "/work/y.apk"},
            current_handles={"android_mcp_decompiled_dir": "/work/d"},
            tracker=MagicMock(),
        )
    assert handle_writes == []


@pytest.mark.asyncio
async def test_index_decompiled_raises_when_descriptor_missing_apk_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Worker validates the descriptor invariant before any MCP call.

    Every android_apk target carries apk_path in its descriptor (set
    by POST /vr/targets/upload-apk). Failing fast here gives a clearer
    error than letting audit-mcp reject a stray call later.
    """
    audit_forward = AsyncMock()
    svc = _build_service(audit_forward=audit_forward)
    handle_writes = _stub_heavy_helpers(monkeypatch, svc)

    with pytest.raises(TargetAnalysisError, match="apk_path"):
        await svc._android_index_decompiled(  # noqa: SLF001
            target_id="t-1",
            descriptor={},  # No apk_path -- descriptor invariant breach.
            current_handles={"android_mcp_decompiled_dir": "/work/d"},
            tracker=MagicMock(),
        )
    audit_forward.assert_not_called()
    assert handle_writes == []


def test_android_stages_set_includes_index_decompiled() -> None:
    """The android-applicable stage set covers INDEX_DECOMPILED."""
    assert StageName.INDEX_DECOMPILED in _ANDROID_STAGES


def test_index_decompiled_has_extended_timeout() -> None:
    """Trailmark + Semble cold build on a jadx Java tree needs >>15 min."""
    assert _DEFAULT_TIMEOUTS[StageName.INDEX_DECOMPILED] >= 3600.0

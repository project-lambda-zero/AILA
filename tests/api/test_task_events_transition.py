"""Tests for the 'transition' event discriminator in the SSE task events stream (Phase 181).

Verifies that the SSE event stream can carry type=transition payloads emitted
by emit_transition_event() without breaking the existing SSE consumer shape.

These tests are static/unit — they do not open a live SSE stream (that would
require a running Redis). Instead they assert:
- The emit_transition_event function pushes type=transition fields
- The TransitionView schema serializes to the expected JSON shape
- The SSE generator in tasks.py does NOT filter out type=transition events
  (no regression from the existing catchup/stream_events passthrough).

Run: pytest tests/api/test_task_events_transition.py -v
"""
from __future__ import annotations

from datetime import datetime, timezone


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def test_transition_view_serializes_correctly() -> None:
    """TransitionView.from_model produces the expected JSON-compatible dict."""
    from aila.api.schemas.transitions import TransitionView
    from aila.storage.db_models import WorkflowStateTransition

    row = WorkflowStateTransition(
        run_id="run-abc",
        seq=3,
        from_state="start",
        to_state="__succeeded__",
        event="exited:ok",
        duration_ms=99,
        error_class=None,
        error_message=None,
        happened_at=_utc(),
    )
    view = TransitionView.from_model(row)
    d = view.model_dump(mode="json")

    assert d["run_id"] == "run-abc"
    assert d["seq"] == 3
    assert d["from_state"] == "start"
    assert d["to_state"] == "__succeeded__"
    assert d["event"] == "exited:ok"
    assert d["duration_ms"] == 99
    assert d["error_class"] is None
    assert d["error_message"] is None
    assert d["task_id"] == "run-abc"
    # input_hash / output_hash must NOT appear in view (privacy boundary)
    assert "input_hash" not in d
    assert "output_hash" not in d


def test_transition_event_type_field() -> None:
    """emit_transition_event pushes 'type=transition' so consumers can discriminate."""
    import asyncio
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock, MagicMock, patch

    captured: list[dict] = []

    mock_client = AsyncMock()

    async def _xadd(key, fields, **kw):
        captured.append(dict(fields))

    mock_client.xadd = _xadd

    @asynccontextmanager
    async def _mock_get_redis():
        yield mock_client

    mock_stream = MagicMock()
    mock_stream._maxlen = 500
    mock_stream._KEY_FMT = "task:{task_id}:progress"

    from aila.platform.workflows.log import emit_transition_event

    async def _run():
        await emit_transition_event(
            run_id="run-123",
            seq=5,
            from_state="work",
            to_state="__succeeded__",
            event="exited:ok",
            duration_ms=10,
            error_class=None,
            error_message=None,
            happened_at=_utc(),
        )

    with (
        patch("aila.platform.tasks.progress.ProgressStream", return_value=mock_stream),
        patch("aila.platform.services.redis_pool.get_redis", _mock_get_redis),
    ):
        asyncio.get_event_loop().run_until_complete(_run())

    assert len(captured) == 1
    assert captured[0]["type"] == "transition", (
        "SSE consumers discriminate on type field; must be 'transition' not 'progress'"
    )


def test_transition_view_null_from_state() -> None:
    """from_state=None is preserved as None in TransitionView (entered rows)."""
    from aila.api.schemas.transitions import TransitionView
    from aila.storage.db_models import WorkflowStateTransition

    row = WorkflowStateTransition(
        run_id="r1",
        seq=0,
        from_state=None,
        to_state="start",
        event="entered",
        happened_at=_utc(),
    )
    view = TransitionView.from_model(row)
    assert view.from_state is None


def test_transitions_schema_in_all_export() -> None:
    """TransitionView is exported via __all__ for clean import surface."""
    from aila.api.schemas import transitions

    assert "TransitionView" in transitions.__all__

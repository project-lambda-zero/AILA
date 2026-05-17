"""Unit tests for emit_transition_event() in platform/workflows/log.py.

Verifies:
- Correct signature (kwargs-only, no row object)
- Best-effort: exceptions from Redis are swallowed, never re-raised
- Fields pushed to xadd match what the engine passes

Run: pytest tests/platform/workflows/test_log_emit.py -v
"""
from __future__ import annotations

import inspect
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch


def _utc() -> datetime:
    return datetime.now(UTC)


def test_emit_signature_is_kwargs_only() -> None:
    """emit_transition_event must accept only keyword arguments (no positional row)."""
    from aila.platform.workflows.log import emit_transition_event

    sig = inspect.signature(emit_transition_event)
    params = list(sig.parameters.values())
    # All params (after self, if any) must be KEYWORD_ONLY
    for p in params:
        assert p.kind in (
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.VAR_KEYWORD,
        ), f"param {p.name!r} is not keyword-only: {p.kind}"


def test_emit_required_fields_present() -> None:
    """emit_transition_event must declare all fields the engine passes."""
    from aila.platform.workflows.log import emit_transition_event

    sig = inspect.signature(emit_transition_event)
    param_names = set(sig.parameters.keys())
    required = {
        "run_id", "seq", "from_state", "to_state", "event",
        "duration_ms", "error_class", "error_message", "happened_at",
    }
    missing = required - param_names
    assert not missing, f"emit_transition_event missing params: {missing}"


async def _call_emit(**kw) -> None:
    from aila.platform.workflows.log import emit_transition_event
    await emit_transition_event(**kw)


def _base_kwargs(*, event: str = "exited:ok") -> dict:
    return dict(
        run_id="run-abc",
        seq=3,
        from_state="start",
        to_state="__succeeded__",
        event=event,
        duration_ms=42,
        error_class=None,
        error_message=None,
        happened_at=_utc(),
    )


def test_emit_swallows_redis_unavailable(monkeypatch) -> None:
    """If Redis pool raises, emit must log a warning and return — never re-raise."""
    import asyncio

    async def _broken_redis_ctx(*a, **kw):
        raise RuntimeError("redis is down")

    with (
        patch("aila.platform.tasks.progress.ProgressStream", side_effect=RuntimeError("redis is down")),
    ):
        # Should not raise
        asyncio.run(_call_emit(**_base_kwargs()))


def test_emit_swallows_xadd_error(monkeypatch) -> None:
    """If xadd raises, emit must log and return — never re-raise."""
    import asyncio
    from contextlib import asynccontextmanager

    mock_client = AsyncMock()
    mock_client.xadd = AsyncMock(side_effect=ConnectionError("xadd failed"))

    @asynccontextmanager
    async def _mock_get_redis():
        yield mock_client

    mock_stream = MagicMock()
    mock_stream._maxlen = 1000
    mock_stream._KEY_FMT = "task:{task_id}:progress"

    with (
        patch("aila.platform.tasks.progress.ProgressStream", return_value=mock_stream),
        patch("aila.platform.services.redis_pool.get_redis", _mock_get_redis),
    ):
        asyncio.run(_call_emit(**_base_kwargs()))


def test_emit_calls_xadd_with_correct_fields(monkeypatch) -> None:
    """Happy path: xadd is called with the expected field dict."""
    import asyncio
    from contextlib import asynccontextmanager

    captured: list[dict] = []

    mock_client = AsyncMock()

    async def _mock_xadd(key, fields, **kw):
        captured.append(dict(fields))

    mock_client.xadd = _mock_xadd

    @asynccontextmanager
    async def _mock_get_redis():
        yield mock_client

    mock_stream = MagicMock()
    mock_stream._maxlen = 1000
    mock_stream._KEY_FMT = "task:{task_id}:progress"

    now = _utc()
    with (
        patch("aila.platform.tasks.progress.ProgressStream", return_value=mock_stream),
        patch("aila.platform.services.redis_pool.get_redis", _mock_get_redis),
    ):
        asyncio.run(
            _call_emit(
                run_id="run-xyz",
                seq=7,
                from_state="start",
                to_state="__succeeded__",
                event="exited:ok",
                duration_ms=99,
                error_class=None,
                error_message=None,
                happened_at=now,
            )
        )

    assert len(captured) == 1
    f = captured[0]
    assert f["type"] == "transition"
    assert f["run_id"] == "run-xyz"
    assert f["seq"] == "7"
    assert f["from_state"] == "start"
    assert f["to_state"] == "__succeeded__"
    assert f["event"] == "exited:ok"
    assert f["duration_ms"] == "99"
    assert f["error_class"] == ""
    assert f["error_message"] == ""
    assert f["task_id"] == "run-xyz"
    assert f["happened_at"] == now.isoformat()


def test_emit_none_fields_become_empty_strings(monkeypatch) -> None:
    """None from_state / error_class / error_message must serialize to empty string."""
    import asyncio
    from contextlib import asynccontextmanager

    captured: list[dict] = []

    mock_client = AsyncMock()

    async def _mock_xadd(key, fields, **kw):
        captured.append(dict(fields))

    mock_client.xadd = _mock_xadd

    @asynccontextmanager
    async def _mock_get_redis():
        yield mock_client

    mock_stream = MagicMock()
    mock_stream._maxlen = 1000
    mock_stream._KEY_FMT = "task:{task_id}:progress"

    with (
        patch("aila.platform.tasks.progress.ProgressStream", return_value=mock_stream),
        patch("aila.platform.services.redis_pool.get_redis", _mock_get_redis),
    ):
        asyncio.run(
            _call_emit(
                run_id="r1",
                seq=0,
                from_state=None,
                to_state="start",
                event="entered",
                duration_ms=None,
                error_class=None,
                error_message=None,
                happened_at=_utc(),
            )
        )

    f = captured[0]
    assert f["from_state"] == ""
    assert f["duration_ms"] == ""
    assert f["error_class"] == ""
    assert f["error_message"] == ""

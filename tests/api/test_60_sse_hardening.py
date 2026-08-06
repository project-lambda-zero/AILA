"""Focused tests for SSE hardening (Phase 60 findings 60-3, 60-4, 60-6).

Covers three narrow behaviors introduced by the hardening slice:

  60-3: ``ProgressStream.stream_events`` has a bounded lifetime cap so a
        well-behaved client cannot pin a Redis pool connection forever.
  60-4: ``stream_task_events`` and ``stream_scan_events`` check
        ``request.is_disconnected()`` each live-loop iteration and end
        the generator promptly instead of looping until the next XREAD
        tick (up to 30 s) with a zombie client.
  60-6: ``ACTIVE_SSE`` gauge is incremented when an SSE generator starts
        and decremented in a ``finally`` when it ends, on every exit path.

All tests use mocked Redis (patched ``ProgressStream``) and a mocked
``Request.is_disconnected``; no live Redis, no live infrastructure.
Follows the proven SSE-test mock pattern in
``tests/api/test_96_sse_streaming_verification.py``.
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.auth import issue_jwt_token
from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope

# ---------------------------------------------------------------------------
# Helpers -- mirror ``test_96_sse_streaming_verification._async_iter`` /
# ``_seed_task`` so the mocks satisfy the same route contracts.
# ---------------------------------------------------------------------------


def _seed_task(user_id: str, group_id: str, task_id: str) -> None:
    """Insert a RUNNING TaskRecord so the SSE handler's access check passes."""
    record = TaskRecord(
        id=task_id,
        user_id=user_id,
        group_id=group_id,
        track="vulnerability",
        fn_path="aila.api.routers.scans.run_platform_handle",
        fn_module="__platform__",
        kwargs_json="{}",
        status=TaskStatus.RUNNING,
        created_at=utc_now(),
        started_at=utc_now(),
    )
    with session_scope() as db:
        db.add(record)
        db.commit()


async def _async_iter(items):
    """Return a real async iterator over ``items``.

    The scans/tasks SSE routes consume ``stream_events`` with ``async for``,
    so a plain ``iter([...])`` raises ``TypeError`` inside the route.
    """
    for item in items:
        yield item


async def _infinite_live_events():
    """Async generator that yields events forever.

    Used to prove the disconnect check ends the SSE loop on the very next
    iteration; without the check the outer ``async for`` would consume
    events indefinitely and the httpx request would never resolve.
    """
    i = 0
    while True:
        i += 1
        yield {
            "stage": f"s{i}",
            "message": "m",
            "percent": str(i),
            "timestamp": "t",
        }


def _make_platform_stub_with_redis() -> MagicMock:
    """Create a stub platform whose config_registry.get returns a Redis URL."""
    stub = MagicMock()
    stub.runtime.config_registry.get.return_value = "redis://localhost:6379"
    return stub


@pytest_asyncio.fixture
async def sse_client(test_db, admin_key_record):
    """AsyncClient wired against a stub platform so SSE handlers run end-to-end."""
    from aila.api.app import create_app

    app = create_app()
    app.state.platform = _make_platform_stub_with_redis()
    app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver",
    ) as c:
        yield c, admin_key_record


# ===========================================================================
# 60-3: ProgressStream.stream_events lifetime cap
# ===========================================================================


class TestStreamEventsLifetimeCap:
    """Prove stream_events terminates once MAX_STREAM_LIFETIME_S elapses."""

    @pytest.mark.asyncio
    async def test_lifetime_cap_ends_generator(self) -> None:
        """After the cap elapses the generator returns cleanly on the next loop iteration."""
        from aila.platform.tasks.progress import MAX_STREAM_LIFETIME_S, ProgressStream

        mock_client = MagicMock()
        # xread always returns a fresh live event so the loop would iterate
        # forever without the lifetime guard. The cap is the ONLY thing that
        # can end this generator.
        event_data = {"stage": "s", "message": "m", "percent": "0", "timestamp": "t"}
        mock_client.xread = AsyncMock(
            return_value=[("task:t:progress", [("1-0", event_data)])],
        )

        @asynccontextmanager
        async def _cm():
            yield mock_client

        # monotonic() call 1 = t=0 sets `started` before the loop; call 2 is
        # the first iteration's cap check (still 0, so the first event yields);
        # call 3 jumps past the cap so the loop-top check bails out on the next
        # iteration. The generator therefore yields exactly one event then ends.
        times = iter([0.0, 0.0, float(MAX_STREAM_LIFETIME_S) + 1.0])

        def _fake_monotonic() -> float:
            try:
                return next(times)
            except StopIteration:
                return float(MAX_STREAM_LIFETIME_S) + 1.0

        with (
            patch("aila.platform.tasks.progress.get_redis", _cm),
            patch("aila.platform.tasks.progress.time.monotonic", _fake_monotonic),
        ):
            ps = ProgressStream(maxlen=1000)
            gen = ps.stream_events("t")

            first = await gen.__anext__()
            assert first == event_data

            # Next iteration re-enters the loop; elapsed >= cap so it returns.
            with pytest.raises(StopAsyncIteration):
                await gen.__anext__()

    def test_max_stream_lifetime_matches_sse_max_connection(self) -> None:
        """Lifetime cap mirrors the outer SSE endpoint's MAX_CONNECTION_S."""
        from aila.api.routers.sse_events import MAX_CONNECTION_S
        from aila.platform.tasks.progress import MAX_STREAM_LIFETIME_S

        assert MAX_STREAM_LIFETIME_S == MAX_CONNECTION_S


# ===========================================================================
# 60-4: request.is_disconnected() ends the SSE generator promptly
# ===========================================================================


class TestSseHandlerDisconnectDetection:
    """Prove scans/tasks SSE handlers exit the live loop on client disconnect."""

    @pytest.mark.asyncio
    async def test_scan_sse_stops_when_client_disconnects(self, sse_client) -> None:
        """A mocked ``request.is_disconnected() == True`` ends the stream promptly."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-dc-60-4")

        async def _always_disconnected(self):  # noqa: ARG001
            return True

        with (
            patch("aila.api.routers.scans.pool_available", return_value=True),
            patch("aila.api.routers.scans.ProgressStream") as mock_ps,
            patch("starlette.requests.Request.is_disconnected", _always_disconnected),
        ):
            instance = mock_ps.return_value
            instance.catchup = AsyncMock(return_value=[])
            instance.stream_events = MagicMock(return_value=_infinite_live_events())

            resp = await client.get(
                "/scans/scan-dc-60-4/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        # The request completed (did NOT hang on the infinite stream) and
        # only the synthetic Connected event landed -- the live loop exited
        # on the first is_disconnected check.
        assert resp.status_code == 200
        data_lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
        assert len(data_lines) == 1, (
            f"Expected only the Connected event after immediate disconnect, "
            f"got {len(data_lines)}: {data_lines}"
        )

    @pytest.mark.asyncio
    async def test_task_sse_stops_when_client_disconnects(self, sse_client) -> None:
        """tasks SSE also honours ``request.is_disconnected()`` each iteration."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="task-dc-60-4")

        async def _always_disconnected(self):  # noqa: ARG001
            return True

        with (
            patch("aila.api.routers.tasks.pool_available", return_value=True),
            # tasks.py imports ProgressStream lazily inside _sse_generator,
            # so patch at the source module (mirrors test_105).
            patch("aila.platform.tasks.progress.ProgressStream") as mock_ps,
            patch("starlette.requests.Request.is_disconnected", _always_disconnected),
        ):
            instance = mock_ps.return_value
            instance.catchup = AsyncMock(return_value=[])
            instance.stream_events = MagicMock(return_value=_infinite_live_events())

            resp = await client.get(
                "/tasks/task-dc-60-4/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        # tasks SSE emits no synthetic Connected event; catchup was empty
        # and the live loop bailed on its first iteration.
        data_lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
        assert data_lines == [], (
            f"Expected no data lines after immediate disconnect, got {data_lines}"
        )


# ===========================================================================
# 60-6: ACTIVE_SSE gauge inc/dec pairs on every exit path
# ===========================================================================


class TestActiveSseGauge:
    """Prove ACTIVE_SSE.inc() runs on start and .dec() runs in finally."""

    @pytest.mark.asyncio
    async def test_scan_sse_increments_then_decrements(self, sse_client) -> None:
        """scans SSE brackets its generator with ACTIVE_SSE inc/dec in order."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-gauge-60-6")

        parent = MagicMock()  # single parent captures ordered inc/dec calls

        with (
            patch("aila.api.routers.scans.pool_available", return_value=True),
            patch("aila.api.routers.scans.ProgressStream") as mock_ps,
            patch("aila.api.routers.scans.ACTIVE_SSE.inc", parent.inc),
            patch("aila.api.routers.scans.ACTIVE_SSE.dec", parent.dec),
        ):
            instance = mock_ps.return_value
            instance.catchup = AsyncMock(return_value=[])
            instance.stream_events = MagicMock(return_value=_async_iter([]))

            resp = await client.get(
                "/scans/scan-gauge-60-6/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        assert parent.inc.call_count == 1
        assert parent.dec.call_count == 1
        # Order matters: dec MUST fire after inc so the gauge is always
        # non-negative and never leaks a phantom active connection.
        parent.assert_has_calls([call.inc(), call.dec()])

    @pytest.mark.asyncio
    async def test_task_sse_increments_then_decrements(self, sse_client) -> None:
        """tasks SSE also brackets its generator with ACTIVE_SSE inc/dec."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="task-gauge-60-6")

        parent = MagicMock()

        with (
            patch("aila.api.routers.tasks.pool_available", return_value=True),
            patch("aila.platform.tasks.progress.ProgressStream") as mock_ps,
            patch("aila.api.routers.tasks.ACTIVE_SSE.inc", parent.inc),
            patch("aila.api.routers.tasks.ACTIVE_SSE.dec", parent.dec),
        ):
            instance = mock_ps.return_value
            instance.catchup = AsyncMock(return_value=[])
            instance.stream_events = MagicMock(return_value=_async_iter([]))

            resp = await client.get(
                "/tasks/task-gauge-60-6/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        assert parent.inc.call_count == 1
        assert parent.dec.call_count == 1
        parent.assert_has_calls([call.inc(), call.dec()])

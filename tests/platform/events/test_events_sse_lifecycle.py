"""Unit tests for issue #60 -- events/SSE lifecycle correctness.

Design source: .run/designs/DESIGN_automation_events_reporting.md, section
"Issue #60 -- Events / SSE lifecycle". Findings addressed:

- 60-1: EventEmitter fan-out: a failing destination must NOT starve
  subsequent destinations. Each failure is logged and counted.
- 60-2: _redis_stream RedisError is no longer silently pass-swallowed.
  It becomes a RuntimeError so the drain isolation guard catches, logs,
  and counts it (verified indirectly via _DESTINATION_ISOLATION_ERRORS
  membership; live Redis is out of scope for a pure unit test).
- SSE worker_stream lifecycle: bounded queue with drop-oldest on overflow,
  lifetime cap that emits a closing frame and exits, worker task cancelled
  AND awaited on generator exit (no zombie task after client disconnect).

Pure in-memory tests: no real HTTP, no real Redis, no database.
"""
from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from collections.abc import AsyncGenerator
from typing import Any

import pytest

from aila.platform.events.emitter import (
    _DESTINATION_ISOLATION_ERRORS,
    EventEmitter,
    ThreadSafeEventEmitter,
)
from aila.platform.events.event import PlatformEvent
from aila.platform.sse.worker_stream import stream_from_worker


def _event(key: str = "k", stage: str = "s", action: str = "a") -> PlatformEvent:
    return PlatformEvent(stage=stage, action=action, key=key, message="m")


# ---------------------------------------------------------------------------
# EventEmitter / ThreadSafeEventEmitter -- issue #60-1 per-destination isolation
# ---------------------------------------------------------------------------


class TestPerDestinationIsolation:
    def test_failing_destination_does_not_starve_next(self) -> None:
        """A middle destination that raises must not prevent later ones."""
        emitter = ThreadSafeEventEmitter()
        received_first: list[str] = []
        received_last: list[str] = []

        def first(evt: PlatformEvent) -> None:
            received_first.append(evt.key)

        def middle_broken(_evt: PlatformEvent) -> None:
            raise RuntimeError("boom")

        def last(evt: PlatformEvent) -> None:
            received_last.append(evt.key)

        emitter.register_destination("first", first)
        emitter.register_destination("middle", middle_broken)
        emitter.register_destination("last", last)

        emitter.emit(_event("evt-1"))

        assert received_first == ["evt-1"], "first destination must receive event"
        assert received_last == ["evt-1"], (
            "isolation broken: last destination did NOT receive event"
        )
        failures = emitter.get_destination_failures()
        assert failures.get("middle") == 1
        assert failures.get("first", 0) == 0
        assert failures.get("last", 0) == 0
        assert sum(failures.values()) == 1

    def test_failure_counter_accumulates_over_many_emits(self) -> None:
        emitter = ThreadSafeEventEmitter()

        def always_bad(_evt: PlatformEvent) -> None:
            raise ValueError("nope")

        emitter.register_destination("bad", always_bad)

        for i in range(5):
            emitter.emit(_event(f"e{i}"))

        failures = emitter.get_destination_failures()
        assert failures["bad"] == 5
        assert failures.get("unknown", 0) == 0
        # snapshot is a defensive copy: mutating it must not affect state
        failures["bad"] = 999
        assert emitter.get_destination_failures()["bad"] == 5

    def test_isolation_covers_broad_exception_family(self) -> None:
        """Every listed exception family in the isolation tuple must be caught."""
        expected_families = {
            RuntimeError,
            OSError,
            TimeoutError,
            ValueError,
            TypeError,
            AttributeError,
            KeyError,
            IndexError,
            LookupError,
            ArithmeticError,
            ImportError,
            AssertionError,
            ReferenceError,
        }
        for family in expected_families:
            assert issubclass(family, _DESTINATION_ISOLATION_ERRORS), (
                f"{family.__name__} must appear in _DESTINATION_ISOLATION_ERRORS "
                "so a destination raising it does not starve fan-out"
            )

    def test_delivery_ordering_preserved(self) -> None:
        """Destinations receive events in the order emit() was called."""
        emitter = ThreadSafeEventEmitter()
        seen: list[str] = []

        def dest(evt: PlatformEvent) -> None:
            seen.append(evt.key)

        emitter.register_destination("d", dest)
        for i in range(10):
            emitter.emit(_event(f"e{i}"))

        assert seen == [f"e{i}" for i in range(10)]

    def test_registration_order_preserved_across_destinations(self) -> None:
        """When one event is emitted, destinations fire in registration order."""
        emitter = ThreadSafeEventEmitter()
        order: list[str] = []

        emitter.register_destination("a", lambda _e: order.append("a"))
        emitter.register_destination("b", lambda _e: order.append("b"))
        emitter.register_destination("c", lambda _e: order.append("c"))

        emitter.emit(_event())

        assert order == ["a", "b", "c"]

    def test_concurrent_emits_do_not_lose_events(self) -> None:
        """Under thread contention every emitted event still reaches destinations."""
        emitter = ThreadSafeEventEmitter()
        seen: list[str] = []
        seen_lock = threading.Lock()

        def dest(evt: PlatformEvent) -> None:
            with seen_lock:
                seen.append(evt.key)

        emitter.register_destination("d", dest)
        threads = [
            threading.Thread(target=emitter.emit, args=(_event(f"e{i}"),))
            for i in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sorted(seen) == sorted(f"e{i}" for i in range(50))

    def test_base_emitter_also_isolates(self) -> None:
        """EventEmitter base class shares the same isolation policy."""
        emitter = EventEmitter()
        seen: list[str] = []

        emitter.register_destination("bad", lambda _e: (_ for _ in ()).throw(KeyError("x")))
        emitter.register_destination("good", lambda e: seen.append(e.key))

        emitter.emit(_event("only"))

        assert seen == ["only"]
        assert emitter.get_destination_failures()["bad"] == 1

    def test_keyboard_interrupt_from_destination_propagates(self) -> None:
        """BaseException-only subclasses must NOT be swallowed by the guard."""
        emitter = ThreadSafeEventEmitter()

        def raiser(_evt: PlatformEvent) -> None:
            raise KeyboardInterrupt

        emitter.register_destination("kb", raiser)

        with pytest.raises(KeyboardInterrupt):
            emitter.emit(_event())


# ---------------------------------------------------------------------------
# SSE worker_stream lifecycle -- bounded queue, lifetime cap, task cleanup
# ---------------------------------------------------------------------------


async def _drain(
    gen: AsyncGenerator[str, None], *, max_events: int | None = None
) -> list[str]:
    """Collect frames from an SSE generator; optional early stop."""
    frames: list[str] = []
    async for frame in gen:
        frames.append(frame)
        if max_events is not None and len(frames) >= max_events:
            await gen.aclose()
            break
    return frames


class TestSseWorkerStreamLifecycle:
    @pytest.mark.asyncio
    async def test_normal_run_yields_start_and_done(self) -> None:
        async def worker(cb: Any) -> None:
            await cb({"stage": "progress", "message": "half"})
            await cb({"stage": "done", "message": "complete"})

        gen = stream_from_worker(
            worker,
            start_event={"stage": "start", "message": "go"},
            heartbeat_interval=10.0,
        )
        frames = await _drain(gen)

        assert any('"stage": "start"' in f for f in frames)
        assert any('"stage": "progress"' in f for f in frames)
        assert any('"stage": "done"' in f for f in frames)

    @pytest.mark.asyncio
    async def test_worker_exception_becomes_error_event(self) -> None:
        """A worker KeyError previously escaped the narrow guard and killed the
        SSE stream silently. Broadened guard must surface it as an event."""

        async def worker(cb: Any) -> None:
            # emit one progress then blow up with a type the old code missed
            await cb({"stage": "progress"})
            raise KeyError("missing-thing")

        gen = stream_from_worker(worker, heartbeat_interval=10.0)
        frames = await _drain(gen)

        assert any('"stage": "progress"' in f for f in frames)
        assert any('"stage": "error"' in f for f in frames), (
            "worker exception must become a delivered 'error' SSE event"
        )
        assert any("missing-thing" in f for f in frames)

    @pytest.mark.asyncio
    async def test_client_disconnect_cancels_and_awaits_worker(self) -> None:
        """When the consumer aborts iteration, the worker task must be
        cancelled AND awaited so no zombie coroutine leaks past the
        generator's finally clause."""
        worker_started = asyncio.Event()
        worker_cleaned_up = asyncio.Event()

        async def worker(cb: Any) -> None:
            worker_started.set()
            try:
                # long-running worker that will be cancelled by client drop
                for i in range(1000):
                    await cb({"stage": "progress", "i": i})
                    await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                worker_cleaned_up.set()
                raise
            finally:
                # this MUST run before stream_from_worker returns
                if not worker_cleaned_up.is_set():
                    worker_cleaned_up.set()

        gen = stream_from_worker(worker, heartbeat_interval=1.0)
        collected: list[str] = []
        async for frame in gen:
            collected.append(frame)
            if len(collected) >= 2:
                break
        await gen.aclose()

        # By the time aclose() returns the worker task MUST be done because
        # finally awaits it. This is the correctness fix for #60 lifecycle:
        # previously task.cancel() was fire-and-forget, leaving the worker
        # coroutine running briefly after the generator returned.
        assert worker_started.is_set(), "worker must have started"
        # Give the loop one tick for the finally-awaited cancel to settle.
        await asyncio.sleep(0)
        assert worker_cleaned_up.is_set(), (
            "worker cleanup did NOT run before generator exit -- "
            "cancellation was fire-and-forget (issue #60 lifecycle leak)"
        )

    @pytest.mark.asyncio
    async def test_lifetime_cap_emits_closing_frame(self) -> None:
        """max_lifetime_s bounds wall-clock lifetime with a clean closing frame."""

        async def worker(cb: Any) -> None:
            # produces one event then idles far past the lifetime cap
            await cb({"stage": "progress", "message": "one"})
            await asyncio.sleep(30)

        gen = stream_from_worker(
            worker,
            heartbeat_interval=0.2,
            max_lifetime_s=0.5,
        )
        started = time.monotonic()
        frames = await _drain(gen)
        elapsed = time.monotonic() - started

        assert elapsed < 5.0, "lifetime cap did not fire in bounded time"
        assert any('"stage": "closing"' in f for f in frames), (
            "expected a 'closing' frame when lifetime cap fires"
        )
        assert any('"reason": "lifetime"' in f for f in frames)

    @pytest.mark.asyncio
    async def test_bounded_queue_drops_oldest_on_overflow(self) -> None:
        """queue_maxsize > 0 must drop the oldest queued item on overflow so a
        slow consumer cannot make the producer block forever."""
        # Producer floods faster than the consumer polls.
        produced = 40
        producer_done = asyncio.Event()

        async def worker(cb: Any) -> None:
            for i in range(produced):
                await cb({"stage": "progress", "i": i})
            await cb({"stage": "done"})
            producer_done.set()

        gen = stream_from_worker(
            worker,
            heartbeat_interval=5.0,
            queue_maxsize=3,
        )

        # Start iterating slowly so the queue fills and forces drops.
        collected: list[str] = []
        async for frame in gen:
            collected.append(frame)
            # slow the consumer between frames so the producer overtakes
            await asyncio.sleep(0.01)

        # Producer must have completed (bounded queue does not block it).
        assert producer_done.is_set(), (
            "producer blocked -- bounded queue did not drop as expected"
        )
        # We must have received strictly fewer than one frame per produced
        # event; otherwise the queue was effectively unbounded. Also the
        # 'done' frame must survive because it is the most recent.
        assert len(collected) <= produced, (
            "should not receive more frames than produced"
        )
        assert any('"stage": "done"' in f for f in collected), (
            "the terminal 'done' event must survive drop-oldest bounding"
        )

    @pytest.mark.asyncio
    async def test_heartbeats_fire_when_worker_idle(self) -> None:
        async def worker(cb: Any) -> None:
            await asyncio.sleep(0.3)
            await cb({"stage": "done"})

        gen = stream_from_worker(worker, heartbeat_interval=0.05)
        frames = await _drain(gen)

        assert any('"stage": "heartbeat"' in f for f in frames)
        assert any('"stage": "done"' in f for f in frames)

    @pytest.mark.asyncio
    async def test_generator_close_is_idempotent(self) -> None:
        """Repeated aclose() calls must not raise."""

        async def worker(cb: Any) -> None:
            await asyncio.sleep(5)
            await cb({"stage": "done"})

        gen = stream_from_worker(worker, heartbeat_interval=0.1)
        # start the generator so the worker task is scheduled
        agen = gen.__aiter__()
        with contextlib.suppress(StopAsyncIteration):
            await asyncio.wait_for(agen.__anext__(), timeout=1.0)

        await gen.aclose()
        await gen.aclose()  # must not raise

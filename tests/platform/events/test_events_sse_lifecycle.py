"""Unit tests for issues #39 and #60 -- events/SSE lifecycle correctness.

Design source: .run/designs/DESIGN_automation_events_reporting.md, section
"Issue #60 -- Events / SSE lifecycle". Findings addressed:

- 39: Domain events carry a non-empty ``correlation_id`` when emitted
  inside a ``correlation_scope``. The base ``DomainEvent`` reads the
  ambient investigation id from the correlation ContextVar via a
  ``default_factory`` so every subclass inherits the same behaviour
  without touching call sites.
- 60-1: EventEmitter fan-out: a failing destination must NOT starve
  subsequent destinations. Each failure is logged and counted.
- 60-2: _redis_stream RedisError is no longer silently pass-swallowed.
  It becomes a RuntimeError so the drain isolation guard catches, logs,
  and counts it (verified indirectly via _DESTINATION_ISOLATION_ERRORS
  membership; live Redis is out of scope for a pure unit test).
- 60-4: ``UserFanoutRegistry`` supports multiple concurrent SSE
  subscribers per user id. Each subscribe() returns a fresh bounded
  queue and emit() delivers to every live queue for that user, so a
  second browser tab for the same user receives events independently.
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

from aila.platform.events.domain_events import (
    AssessmentCompleted,
    AssessmentCompletedPayload,
    ConfigChanged,
    ConfigChangedPayload,
    LlmCallCompleted,
    LlmCallCompletedPayload,
    SystemRegistered,
    SystemRegisteredPayload,
)
from aila.platform.events.emitter import (
    _DESTINATION_ISOLATION_ERRORS,
    EventEmitter,
    ThreadSafeEventEmitter,
)
from aila.platform.events.event import PlatformEvent
from aila.platform.llm.correlation import correlation_scope
from aila.platform.sse.user_fanout import QUEUE_MAXSIZE, UserFanoutRegistry
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


# ---------------------------------------------------------------------------
# Issue #39 -- Domain events inherit the ambient correlation id
# ---------------------------------------------------------------------------


class TestDomainEventCorrelationId:
    """Domain events must carry the investigation id when emitted inside a
    ``correlation_scope`` so the audit trail can be joined back to the
    investigation/branch/turn that produced them (issue #39 gap: the
    ``correlation_id`` field was hard-defaulted to ``""``)."""

    def test_default_correlation_id_is_empty_outside_scope(self) -> None:
        """No correlation set -> empty string, preserving prior default."""
        event = LlmCallCompleted(
            payload=LlmCallCompletedPayload(
                model="m", tokens=1, cost=0.1, duration=0.5,
            ),
        )
        assert event.correlation_id == ""

    def test_domain_event_inherits_investigation_id_from_scope(self) -> None:
        """Constructing a domain event inside a ``correlation_scope`` reads
        the ambient investigation id via the ``default_factory``."""
        with correlation_scope(
            investigation_id="inv-42", branch_id="br-1", turn_number=3,
        ):
            event = LlmCallCompleted(
                payload=LlmCallCompletedPayload(
                    model="m", tokens=1, cost=0.1, duration=0.5,
                ),
            )
        assert event.correlation_id == "inv-42"

    def test_every_domain_event_subclass_inherits_correlation(self) -> None:
        """The fix lives on the base class, so every subclass benefits."""
        with correlation_scope(investigation_id="inv-abc"):
            events = [
                SystemRegistered(
                    payload=SystemRegisteredPayload(system_id="s", hostname="h"),
                ),
                AssessmentCompleted(
                    payload=AssessmentCompletedPayload(
                        session_id="sess", score=0.9,
                    ),
                ),
                ConfigChanged(
                    payload=ConfigChangedPayload(
                        namespace="ns", key="k", old_value="o", new_value="n",
                    ),
                ),
                LlmCallCompleted(
                    payload=LlmCallCompletedPayload(
                        model="m", tokens=1, cost=0.1, duration=0.5,
                    ),
                ),
            ]
        assert [e.correlation_id for e in events] == ["inv-abc"] * 4

    def test_explicit_correlation_id_overrides_ambient(self) -> None:
        """An explicit ``correlation_id=`` argument wins over the ambient value
        so callers that already know their correlation are not surprised."""
        with correlation_scope(investigation_id="inv-ambient"):
            event = SystemRegistered(
                correlation_id="explicit-id",
                payload=SystemRegisteredPayload(system_id="s", hostname="h"),
            )
        assert event.correlation_id == "explicit-id"

    def test_scope_exit_restores_no_correlation(self) -> None:
        """Domain events built after a ``correlation_scope`` returns do NOT
        inherit the stale id (the ContextVar was reset)."""
        with correlation_scope(investigation_id="inv-during"):
            inside = LlmCallCompleted(
                payload=LlmCallCompletedPayload(
                    model="m", tokens=1, cost=0.1, duration=0.1,
                ),
            )
        outside = LlmCallCompleted(
            payload=LlmCallCompletedPayload(
                model="m", tokens=1, cost=0.1, duration=0.1,
            ),
        )
        assert inside.correlation_id == "inv-during"
        assert outside.correlation_id == ""

    def test_investigation_id_none_yields_empty(self) -> None:
        """A scope with only branch/turn set (no investigation id) still
        yields an empty correlation id because there is nothing to join on."""
        with correlation_scope(branch_id="br-only", turn_number=1):
            event = LlmCallCompleted(
                payload=LlmCallCompletedPayload(
                    model="m", tokens=1, cost=0.1, duration=0.1,
                ),
            )
        assert event.correlation_id == ""


# ---------------------------------------------------------------------------
# Issue #60-4 -- Multi-subscriber SSE fan-out registry
# ---------------------------------------------------------------------------


class TestUserFanoutRegistryMultiTab:
    """``UserFanoutRegistry`` must support multiple concurrent SSE
    subscribers per user id. The prior single-queue registry at
    ``aila.api.events`` handed the SAME queue to two tabs so events were
    consumed by whichever tab called ``get`` first, and the first tab that
    closed deleted the shared queue out from under the sibling. This
    registry replaces that behaviour: every ``subscribe`` returns a fresh
    queue and ``emit`` fans out to all of them."""

    @pytest.mark.asyncio
    async def test_subscribe_returns_fresh_queue_per_call(self) -> None:
        """Two subscribe() calls for the same user return distinct queues."""
        reg = UserFanoutRegistry()
        q1 = await reg.subscribe("user-1")
        q2 = await reg.subscribe("user-1")
        assert q1 is not q2, (
            "multi-tab breakage: subscribe() must return a fresh queue "
            "per connection; sharing one queue means only one tab wins each event"
        )
        assert await reg.subscriber_count("user-1") == 2
        assert await reg.user_count() == 1

    @pytest.mark.asyncio
    async def test_emit_fans_out_to_every_tab(self) -> None:
        """emit() delivers the payload to EVERY subscribed queue for the user."""
        reg = UserFanoutRegistry()
        tab_a = await reg.subscribe("u1")
        tab_b = await reg.subscribe("u1")
        tab_c = await reg.subscribe("u1")

        delivered = await reg.emit("u1", "hello")
        assert delivered == 3

        # Each tab has its own copy -- draining one must not empty the others.
        assert tab_a.get_nowait() == "hello"
        assert tab_b.get_nowait() == "hello"
        assert tab_c.get_nowait() == "hello"
        for tab in (tab_a, tab_b, tab_c):
            assert tab.empty()

    @pytest.mark.asyncio
    async def test_emit_across_multiple_events_preserves_order_per_tab(self) -> None:
        """Sequential emits arrive in order at every tab."""
        reg = UserFanoutRegistry()
        tab_a = await reg.subscribe("u1")
        tab_b = await reg.subscribe("u1")

        for i in range(5):
            await reg.emit("u1", f"evt-{i}")

        received_a = [tab_a.get_nowait() for _ in range(5)]
        received_b = [tab_b.get_nowait() for _ in range(5)]
        assert received_a == [f"evt-{i}" for i in range(5)]
        assert received_b == [f"evt-{i}" for i in range(5)]

    @pytest.mark.asyncio
    async def test_cross_user_isolation(self) -> None:
        """emit(u1, ...) never touches queues under u2."""
        reg = UserFanoutRegistry()
        u1_tab = await reg.subscribe("u1")
        u2_tab = await reg.subscribe("u2")

        await reg.emit("u1", "for-u1")

        assert u1_tab.get_nowait() == "for-u1"
        assert u2_tab.empty(), "u2 must not receive u1's event"

    @pytest.mark.asyncio
    async def test_unsubscribing_one_tab_leaves_sibling_live(self) -> None:
        """Closing one tab must not orphan another tab's queue."""
        reg = UserFanoutRegistry()
        tab_a = await reg.subscribe("u1")
        tab_b = await reg.subscribe("u1")

        await reg.unsubscribe("u1", tab_a)

        assert await reg.subscriber_count("u1") == 1
        # sibling tab is still registered and still receives events
        delivered = await reg.emit("u1", "post-close")
        assert delivered == 1
        assert tab_b.get_nowait() == "post-close"
        # the closed tab's queue is unchanged (not written to)
        assert tab_a.empty()

    @pytest.mark.asyncio
    async def test_last_unsubscribe_removes_user_entry(self) -> None:
        """Dropping the last subscriber cleans the user id from the registry."""
        reg = UserFanoutRegistry()
        tab = await reg.subscribe("u1")
        assert await reg.user_count() == 1
        await reg.unsubscribe("u1", tab)
        assert await reg.user_count() == 0
        assert await reg.subscriber_count("u1") == 0

    @pytest.mark.asyncio
    async def test_emit_to_unknown_user_is_noop(self) -> None:
        """Publishing to a user with no live subscribers is a silent no-op."""
        reg = UserFanoutRegistry()
        delivered = await reg.emit("ghost", "payload")
        assert delivered == 0

    @pytest.mark.asyncio
    async def test_unsubscribe_unknown_queue_is_noop(self) -> None:
        """Double-unsubscribe or unsubscribe of a foreign queue must not raise."""
        reg = UserFanoutRegistry()
        tab = await reg.subscribe("u1")
        await reg.unsubscribe("u1", tab)
        # second unsubscribe: silent no-op
        await reg.unsubscribe("u1", tab)
        # unknown queue on unknown user: silent no-op
        await reg.unsubscribe("ghost", asyncio.Queue())

    @pytest.mark.asyncio
    async def test_slow_tab_does_not_stall_sibling(self) -> None:
        """A queue-full tab is skipped with a warning; siblings still get the event.

        This is the correctness fix for the shared-queue behaviour where a
        slow consumer forced a backlog that other tabs then missed.
        """
        reg = UserFanoutRegistry(queue_maxsize=2)
        slow_tab = await reg.subscribe("u1")
        fast_tab = await reg.subscribe("u1")

        # Fill both queues to the slow tab's limit.
        assert await reg.emit("u1", "a") == 2
        assert await reg.emit("u1", "b") == 2
        # The fast tab drains -- the slow tab does not.
        assert fast_tab.get_nowait() == "a"
        assert fast_tab.get_nowait() == "b"

        # Next emit: slow_tab is full (2/2), fast_tab has room again.
        delivered = await reg.emit("u1", "c")
        assert delivered == 1, (
            "a full subscriber must be skipped so sibling delivery is not blocked"
        )

        # slow_tab keeps its two items; fast_tab received all three payloads.
        assert [slow_tab.get_nowait() for _ in range(2)] == ["a", "b"]
        assert slow_tab.empty()
        assert fast_tab.get_nowait() == "c"
        assert fast_tab.empty()

    @pytest.mark.asyncio
    async def test_default_queue_maxsize_matches_module_constant(self) -> None:
        """Default maxsize is the exported constant so operator docs stay honest."""
        reg = UserFanoutRegistry()
        tab = await reg.subscribe("u1")
        assert tab.maxsize == QUEUE_MAXSIZE

    @pytest.mark.asyncio
    async def test_zero_maxsize_rejected(self) -> None:
        """Unbounded (or negative) per-subscriber queues would leak memory on a
        stalled tab; the constructor refuses them."""
        with pytest.raises(ValueError, match="queue_maxsize must be > 0"):
            UserFanoutRegistry(queue_maxsize=0)
        with pytest.raises(ValueError, match="queue_maxsize must be > 0"):
            UserFanoutRegistry(queue_maxsize=-1)

    @pytest.mark.asyncio
    async def test_concurrent_subscribe_unsubscribe_and_emit(self) -> None:
        """Concurrent subscribe/unsubscribe/emit tasks do not lose events or
        corrupt the subscriber list. Runs on a single event loop under the
        registry's asyncio.Lock, which is the deployed threading model."""
        reg = UserFanoutRegistry()
        tabs: list[asyncio.Queue[str]] = []

        async def add_tab() -> None:
            tabs.append(await reg.subscribe("u1"))

        await asyncio.gather(*(add_tab() for _ in range(10)))
        assert await reg.subscriber_count("u1") == 10

        delivered_counts = await asyncio.gather(
            *(reg.emit("u1", f"e{i}") for i in range(5))
        )
        assert all(count == 10 for count in delivered_counts), (
            "every emit must reach every tab even under concurrent scheduling"
        )
        for tab in tabs:
            drained = [tab.get_nowait() for _ in range(5)]
            assert sorted(drained) == [f"e{i}" for i in range(5)]

        await asyncio.gather(*(reg.unsubscribe("u1", t) for t in tabs))
        assert await reg.user_count() == 0

"""Tests for the automation tick supervisor (#46 finding 46-3/46-5).

The supervisor must keep the tick loop alive across arbitrary tick faults,
back off exponentially on consecutive failures, propagate CancelledError so
shutdown stays prompt, and stop cleanly when its stop_event is set.
"""
from __future__ import annotations

import asyncio

import pytest

from aila.platform.automation.supervisor import _backoff_delay, run_tick_supervisor


class _StubRunner:
    """Runner double whose tick() raises for the first ``fail_times`` calls and
    sets ``stop_event`` once it has been called ``stop_after`` times."""

    def __init__(
        self,
        *,
        fail_times: int,
        stop_after: int,
        stop_event: asyncio.Event,
        exc: BaseException | None = None,
    ) -> None:
        self.calls = 0
        self._fail_times = fail_times
        self._stop_after = stop_after
        self._stop_event = stop_event
        self._exc = exc or KeyError("malformed schedule row")

    async def tick(self) -> int:
        self.calls += 1
        if self.calls >= self._stop_after:
            self._stop_event.set()
        if self.calls <= self._fail_times:
            raise self._exc
        return 0


def test_backoff_zero_failures_is_base_interval() -> None:
    assert _backoff_delay(0, 60.0, 300.0, 0.0) == 60.0


def test_backoff_grows_exponentially() -> None:
    assert _backoff_delay(1, 60.0, 300.0, 0.0) == 120.0
    assert _backoff_delay(2, 60.0, 300.0, 0.0) == 240.0


def test_backoff_capped_at_max() -> None:
    # 60 * 2**3 = 480 -> capped at 300; a large failure count stays capped.
    assert _backoff_delay(3, 60.0, 300.0, 0.0) == 300.0
    assert _backoff_delay(20, 60.0, 300.0, 0.0) == 300.0


def test_backoff_jitter_within_bounds() -> None:
    for _ in range(50):
        delay = _backoff_delay(0, 100.0, 300.0, 0.10)
        assert 90.0 <= delay <= 110.0


@pytest.mark.asyncio
async def test_supervisor_survives_tick_fault_and_keeps_looping() -> None:
    stop = asyncio.Event()
    runner = _StubRunner(fail_times=3, stop_after=5, stop_event=stop)
    # Tiny intervals so the backoff sleeps are negligible in the test.
    await run_tick_supervisor(
        runner,
        base_interval_s=0.001,
        max_backoff_s=0.002,
        jitter_pct=0.0,
        stop_event=stop,
    )
    # The loop survived 3 consecutive KeyErrors and kept calling tick until the
    # stop was requested; a narrow-except loop would have died on the first.
    assert runner.calls >= 5


@pytest.mark.asyncio
async def test_supervisor_reraises_cancelled() -> None:
    stop = asyncio.Event()
    runner = _StubRunner(
        fail_times=1,
        stop_after=99,
        stop_event=stop,
        exc=asyncio.CancelledError(),
    )
    with pytest.raises(asyncio.CancelledError):
        await run_tick_supervisor(
            runner,
            base_interval_s=0.001,
            max_backoff_s=0.002,
            jitter_pct=0.0,
            stop_event=stop,
        )
    # Cancelled on the first tick: propagated, not swallowed, no further calls.
    assert runner.calls == 1


@pytest.mark.asyncio
async def test_supervisor_stops_before_first_tick_when_event_preset() -> None:
    stop = asyncio.Event()
    stop.set()
    runner = _StubRunner(fail_times=0, stop_after=99, stop_event=stop)
    await run_tick_supervisor(
        runner,
        base_interval_s=0.001,
        max_backoff_s=0.002,
        jitter_pct=0.0,
        stop_event=stop,
    )
    assert runner.calls == 0

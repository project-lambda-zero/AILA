"""Supervised automation tick loop with exponential backoff (finding 46-3/46-5).

The tick loop previously inlined in ``api/app.py`` caught only a narrow
exception set and slept a fixed 60 s. A tick raising anything outside that set
-- ``KeyError``, ``RuntimeError``, ``TypeError`` from a malformed schedule row
-- escaped the loop and killed the task, silently halting all automation until
the next process restart. This supervisor catches every realistic tick fault,
keeps the loop alive, counts the failure, and backs off exponentially so a
persistently broken tick does not hot-loop. ``asyncio.CancelledError`` still
propagates so shutdown stays prompt.
"""
from __future__ import annotations

import asyncio
import logging
import random
from typing import TYPE_CHECKING

import sqlalchemy.exc

from aila.platform.exceptions import AILAError

if TYPE_CHECKING:
    from aila.platform.automation.runner import AutomationRunner

__all__ = ["run_tick_supervisor"]

_log = logging.getLogger(__name__)

# Broad but explicit fault set for a supervised tick. This mirrors the isolation
# tuple in runner.py and the cost-telemetry tuple in the LLM client, covering
# every realistic tick fault. CancelledError is a BaseException outside the set,
# so it propagates and a shutdown request is never swallowed.
_TICK_FAULTS: tuple[type[BaseException], ...] = (
    AILAError,
    sqlalchemy.exc.SQLAlchemyError,
    RuntimeError,
    ValueError,
    TypeError,
    LookupError,
    AttributeError,
    OSError,
    ImportError,
    ArithmeticError,
)


def _record_tick_failure(exception_name: str) -> None:
    """Best-effort Prometheus increment; never fails the supervisor."""
    try:
        from aila.api.metrics import AUTOMATION_TICK_FAILURES_TOTAL

        AUTOMATION_TICK_FAILURES_TOTAL.labels(exception=exception_name).inc()
    except (ImportError, AttributeError, ValueError):
        _log.debug("automation tick-failure counter unavailable", exc_info=True)


def _backoff_delay(
    consecutive_failures: int,
    base_interval_s: float,
    max_backoff_s: float,
    jitter_pct: float,
) -> float:
    """Return the sleep for the next iteration.

    Zero consecutive failures yields ``base_interval_s``. ``n`` failures yield
    ``base_interval_s * 2**n`` capped at ``max_backoff_s``. A non-zero
    ``jitter_pct`` then spreads the delay by +/- that fraction so many replicas
    do not resynchronize on the same wake.
    """
    if consecutive_failures <= 0:
        delay = base_interval_s
    else:
        delay = min(base_interval_s * (2.0 ** consecutive_failures), max_backoff_s)
    if jitter_pct > 0.0:
        spread = delay * jitter_pct
        delay += random.uniform(-spread, spread)
    return max(delay, 0.0)


async def _sleep_or_stop(delay: float, stop_event: asyncio.Event | None) -> bool:
    """Sleep ``delay`` seconds, waking early if ``stop_event`` is set.

    Returns ``True`` when a stop was observed (the caller should exit),
    ``False`` when the full delay elapsed. ``asyncio.CancelledError`` from the
    underlying wait propagates unchanged.
    """
    if stop_event is None:
        await asyncio.sleep(delay)
        return False
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=delay)
    except TimeoutError:
        return False
    return True


async def run_tick_supervisor(
    runner: AutomationRunner,
    *,
    base_interval_s: float = 60.0,
    max_backoff_s: float = 300.0,
    jitter_pct: float = 0.10,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Supervised tick loop; never exits except on cancellation or stop_event.

    Each iteration runs ``runner.tick()``. ``asyncio.CancelledError`` propagates
    so shutdown stays prompt. Every fault in ``_TICK_FAULTS`` is logged with a
    traceback, counted on ``aila_automation_tick_failures_total``, and
    swallowed; the consecutive-failure count drives an exponential backoff that
    resets on the first success. A set ``stop_event`` returns the loop cleanly
    at the next boundary -- checked before each tick and honored during the
    sleep window.
    """
    consecutive_failures = 0
    while True:
        if stop_event is not None and stop_event.is_set():
            return
        try:
            await runner.tick()
        except asyncio.CancelledError:
            raise
        except _TICK_FAULTS as exc:
            consecutive_failures += 1
            _log.exception(
                "automation tick failed (consecutive=%d)", consecutive_failures,
            )
            _record_tick_failure(type(exc).__name__)
        else:
            consecutive_failures = 0
        delay = _backoff_delay(
            consecutive_failures, base_interval_s, max_backoff_s, jitter_pct,
        )
        if await _sleep_or_stop(delay, stop_event):
            return

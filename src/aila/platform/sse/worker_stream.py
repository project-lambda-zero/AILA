"""Stream SSE events from an async worker via a progress callback.

Encapsulates the Queue + create_task + wait_for pattern so module-layer API
routers do not need to touch asyncio primitives directly.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any

from aila.platform.exceptions import AILAError

__all__ = ["stream_from_worker"]

_log = logging.getLogger(__name__)

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None]]
Worker = Callable[[ProgressCallback], Awaitable[None]]


# Exceptions the worker may raise that must NOT propagate out of the SSE
# generator; each becomes a single "stage: error" event delivered to the
# client. Cancellation is handled separately (must re-raise so FastAPI
# tears the response down cleanly).
_WORKER_ISOLATION_ERRORS: tuple[type[BaseException], ...] = (
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
    AILAError,
)


async def stream_from_worker(
    worker: Worker,
    *,
    heartbeat_interval: float = 5.0,
    start_event: dict[str, Any] | None = None,
    done_stages: tuple[str, ...] = ("done",),
    queue_maxsize: int = 0,
    max_lifetime_s: float | None = None,
) -> AsyncGenerator[str, None]:
    """Run ``worker(progress_cb)`` concurrently and stream its events as SSE.

    The ``worker`` is an async callable that accepts a ``progress_cb`` and
    calls it for each event it wants streamed. It should emit an event whose
    ``stage`` matches one of ``done_stages`` as its final event.

    Heartbeat events (``{"stage": "heartbeat", ...}``) are emitted when the
    worker has not produced an event within ``heartbeat_interval`` seconds.

    Additional lifecycle knobs (issue #60):

    - ``queue_maxsize`` -- when > 0, bounds the internal producer/consumer
      queue. On overflow the OLDEST buffered event is dropped in favour of
      the new one and a warning is logged, preventing an unbounded memory
      leak when a client stalls while the worker still fires events. The
      default 0 preserves the previous unbounded behaviour for existing
      callers.
    - ``max_lifetime_s`` -- when set, the generator emits a final
      ``stage: closing`` frame and returns once wall-clock lifetime exceeds
      the limit. Prevents infinite-lived SSE connections; the default None
      keeps the previous behaviour so existing callers see no change.

    Task lifecycle:

    - The worker task is cancelled AND awaited in the ``finally`` block on
      any generator exit (client disconnect, completion, timeout). Previously
      only ``task.cancel()`` was called, so the worker coroutine kept running
      briefly after the generator returned and could leak resources it held
      (files, sessions, transport handles). Now cancellation is deterministic.
    - Worker exceptions in the enumerated ``_WORKER_ISOLATION_ERRORS`` set
      become a single ``stage: error`` event; ``asyncio.CancelledError`` is
      always re-raised so FastAPI cleanup runs correctly.
    """
    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
        maxsize=max(0, queue_maxsize)
    )

    async def _cb(event: dict[str, Any]) -> None:
        if queue_maxsize <= 0:
            await queue.put(event)
            return
        # Bounded: drop the oldest queued item on overflow so a slow or dead
        # consumer cannot pin the worker forever. This is the standard SSE
        # backpressure fallback -- SSE has no in-protocol flow control, so
        # dropping stale events beats blocking the producer indefinitely.
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            with contextlib.suppress(asyncio.QueueEmpty):
                queue.get_nowait()
            _log.warning(
                "SSE queue overflow (maxsize=%d); dropping oldest buffered event",
                queue_maxsize,
            )
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(event)

    async def _run() -> None:
        try:
            await worker(_cb)
        except asyncio.CancelledError:
            raise
        except _WORKER_ISOLATION_ERRORS as exc:
            _log.exception("SSE worker failed: %s", exc)
            with contextlib.suppress(asyncio.QueueFull, asyncio.CancelledError):
                await _cb({"stage": "error", "message": str(exc)[:500]})
        finally:
            with contextlib.suppress(asyncio.QueueFull, asyncio.CancelledError):
                await _cb(None)

    task = asyncio.create_task(_run())
    started_at = time.monotonic()

    if start_event is not None:
        yield f"data: {json.dumps(start_event)}\n\n"

    try:
        while True:
            # Bound the get() by the shorter of heartbeat and remaining
            # lifetime so the generator wakes to honor the lifetime cap
            # even when the worker is idle.
            wait_for = heartbeat_interval
            if max_lifetime_s is not None:
                remaining = max_lifetime_s - (time.monotonic() - started_at)
                if remaining <= 0:
                    yield 'data: {"stage": "closing", "reason": "lifetime"}\n\n'
                    return
                wait_for = min(wait_for, remaining)

            try:
                event = await asyncio.wait_for(queue.get(), timeout=wait_for)
            except TimeoutError:
                if max_lifetime_s is not None and (
                    time.monotonic() - started_at
                ) >= max_lifetime_s:
                    yield 'data: {"stage": "closing", "reason": "lifetime"}\n\n'
                    return
                yield f"data: {json.dumps({'stage': 'heartbeat', 'message': 'working...'})}\n\n"
                continue

            if event is None:
                break

            yield f"data: {json.dumps(event)}\n\n"

            if event.get("stage") in done_stages:
                break
    finally:
        # Deterministic cleanup: cancel AND await the worker so the
        # coroutine and every resource it holds are released before the
        # response finishes. Suppress CancelledError from the task itself;
        # exceptions the worker raised are already surfaced by _run().
        if not task.done():
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError, *_WORKER_ISOLATION_ERRORS):
            await task

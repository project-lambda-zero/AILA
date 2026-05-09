"""Stream SSE events from an async worker via a progress callback.

Encapsulates the Queue + create_task + wait_for pattern so module-layer API
routers do not need to touch asyncio primitives directly.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any

from aila.platform.exceptions import AILAError

__all__ = ["stream_from_worker"]

_log = logging.getLogger(__name__)

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None]]
Worker = Callable[[ProgressCallback], Awaitable[None]]


async def stream_from_worker(
    worker: Worker,
    *,
    heartbeat_interval: float = 5.0,
    start_event: dict[str, Any] | None = None,
    done_stages: tuple[str, ...] = ("done",),
) -> AsyncGenerator[str, None]:
    """Run ``worker(progress_cb)`` concurrently and stream its events as SSE.

    The ``worker`` is an async callable that accepts a ``progress_cb`` and
    calls it for each event it wants streamed. It should emit an event whose
    ``stage`` matches one of ``done_stages`` as its final event.

    Heartbeat events (``{"stage": "heartbeat", ...}``) are emitted when the
    worker has not produced an event within ``heartbeat_interval`` seconds.
    """
    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    async def _cb(event: dict[str, Any]) -> None:
        await queue.put(event)

    async def _run() -> None:
        try:
            await worker(_cb)
        except (RuntimeError, OSError, TimeoutError, ValueError, AILAError) as exc:
            _log.exception("SSE worker failed: %s", exc)
            await queue.put({"stage": "error", "message": str(exc)[:500]})
        finally:
            await queue.put(None)

    task = asyncio.create_task(_run())

    if start_event is not None:
        yield f"data: {json.dumps(start_event)}\n\n"

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=heartbeat_interval)
            except TimeoutError:
                yield f"data: {json.dumps({'stage': 'heartbeat', 'message': 'working...'})}\n\n"
                continue

            if event is None:
                break

            yield f"data: {json.dumps(event)}\n\n"

            if event.get("stage") in done_stages:
                break
    finally:
        if not task.done():
            task.cancel()

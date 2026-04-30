"""Redis Streams wrapper for task progress events (TASK-08/TASK-09).

Emits and reads progress events via Redis Streams (XADD/XRANGE/XREAD).
Key format: task:{task_id}:progress
MAXLEN=1000 keeps the last 1000 events per task (auto-trim).

Late-connect replay: a client opening SSE after the task started calls
catchup(task_id, last_id='0') to replay all events, then stream_events()
for live updates (D-16/D-17/TASK-09).

Ownership: Platform -- not module-specific.

Connection management: Uses the shared async Redis pool from
``aila.platform.services.redis_pool`` instead of creating per-instance
connections (OPS-01).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from aila.platform.contracts._common import utc_now
from aila.platform.services.redis_pool import get_redis
from aila.platform.tasks.constants import (
    PROGRESS_STREAM_MAXLEN,
    TASK_PROGRESS_KEY_TEMPLATE,
    XREAD_BLOCK_MS,
)

__all__ = ["ProgressStream"]

_log = logging.getLogger(__name__)


class ProgressStream:
    """Redis Streams wrapper for task progress events (D-16/TASK-08).

    Uses Redis Streams (XADD/XREAD) not pub/sub, enabling late-connect
    replay: a client opening SSE after the task started replays all events
    from last_id='0' (D-17/TASK-09).

    Key format: task:{task_id}:progress
    MAXLEN=1000 keeps last 1000 events per task (auto-trim).

    Connection management: Uses the shared async Redis pool (OPS-01).
    No per-instance connections are created.
    """

    _KEY_FMT = TASK_PROGRESS_KEY_TEMPLATE

    def __init__(self, maxlen: int | None = None) -> None:
        """Configure stream parameters.

        Args:
            maxlen: Max events per stream. Defaults to ConfigRegistry value
                or PROGRESS_STREAM_MAXLEN constant.
        """
        if maxlen is not None:
            self._maxlen = maxlen
        else:
            from aila.platform.tasks import get_task_tuning

            self._maxlen = get_task_tuning("progress_stream_maxlen", PROGRESS_STREAM_MAXLEN)

    async def emit(self, task_id: str, stage: str, message: str, percent: int) -> None:
        """Append a progress event to the Redis Stream for task_id.

        Uses XADD with MAXLEN=1000 (exact trim) to prevent unbounded growth.
        The timestamp field captures when the event was emitted (UTC ISO-8601).

        Args:
            task_id: TaskRecord UUID.
            stage: Stage name (e.g. "inventory", "scoring").
            message: Human-readable progress message.
            percent: Completion percentage 0-100.
        """
        key = self._KEY_FMT.format(task_id=task_id)
        async with get_redis() as client:
            await client.xadd(
                key,
                {
                    "stage": stage,
                    "message": message,
                    "percent": str(percent),
                    "timestamp": utc_now().isoformat(),
                },
                maxlen=self._maxlen,
                approximate=False,
            )

    async def catchup(self, task_id: str, last_id: str = "0") -> list[dict[str, str]]:
        """Fetch all events from last_id to the end of the stream.

        Used by the SSE endpoint on connect to replay missed events so late
        clients receive the full history (D-17/TASK-09).

        Args:
            task_id: TaskRecord UUID.
            last_id: Redis Stream ID to start reading from.
                '0' means all events from the beginning of the stream.

        Returns:
            List of event dicts with keys: stage, message, percent, timestamp.
            Empty list if no events exist yet.
        """
        key = self._KEY_FMT.format(task_id=task_id)
        async with get_redis() as client:
            raw = await client.xrange(key, last_id, "+")
            return [fields for _, fields in raw]

    async def stream_events(
        self,
        task_id: str,
        last_id: str = "0",
    ) -> AsyncGenerator[dict[str, str], None]:
        """Read new events from the Redis Stream.

        Yields event dicts as they arrive via XREAD with block=30000ms.
        Yields a ping sentinel dict on timeout so SSE connections stay alive.
        Intended for use inside a FastAPI StreamingResponse async generator.

        Args:
            task_id: TaskRecord UUID.
            last_id: Stream ID to start reading from. Use '0' to read from
                the beginning; use '$' to read only new events.

        Yields:
            Event dicts with stage/message/percent/timestamp keys, or
            {"type": "ping"} on 30-second timeout (SSE keepalive).
        """
        key = self._KEY_FMT.format(task_id=task_id)
        current_id = last_id
        while True:
            async with get_redis() as client:
                raw_result = await client.xread(
                    {key: current_id}, block=XREAD_BLOCK_MS, count=100,
                )
            if raw_result:
                for _stream_key, events in raw_result:
                    for event_id, event_data in events:
                        current_id = event_id
                        yield event_data
            else:
                yield {"type": "ping"}

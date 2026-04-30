"""Session-scoped Redis Streams SSE adapter for the SbD NFR module.

Design references: D-13, PLAT-03, T-135-09.

Uses the platform-owned async Redis pool and only owns the session-specific
stream key format. Connection lifecycle, pooling, and transport setup remain
platform responsibilities.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from aila.platform.contracts._common import utc_now
from aila.platform.services.redis_pool import get_redis

__all__ = ["SessionEventStream"]

_log = logging.getLogger(__name__)

_XREAD_BLOCK_MS = 30_000  # 30-second block timeout (keepalive ping)
_XREAD_COUNT = 100


class SessionEventStream:
    """Redis Streams wrapper scoped to a single SbD session.

    The module owns only the stream key namespace (``session:{session_id}:events``).
    Redis connection management is delegated to the platform pool.
    """

    _KEY_FMT = "session:{session_id}:events"

    def __init__(self, maxlen: int = 1000) -> None:
        self._maxlen = maxlen

    async def emit(self, session_id: str, event: str, **data: object) -> None:
        """Append a session event to the Redis Stream for ``session_id``."""
        key = self._KEY_FMT.format(session_id=session_id)
        fields: dict[str, str] = {
            "event": event,
            "timestamp": utc_now().isoformat(),
            **{k: str(v) for k, v in data.items()},
        }
        async with get_redis() as client:
            await client.xadd(key, fields, maxlen=self._maxlen, approximate=False)

    async def catchup_async(
        self,
        session_id: str,
        last_id: str = "0",
    ) -> list[dict[str, str]]:
        """Return all events from ``last_id`` to the current stream tail."""
        key = self._KEY_FMT.format(session_id=session_id)
        async with get_redis() as client:
            raw = await client.xrange(key, last_id, "+")
        return [fields for _, fields in raw]

    async def astream_events(
        self,
        session_id: str,
        last_id: str = "0",
    ) -> AsyncGenerator[dict[str, str], None]:
        """Yield new events from the Redis Stream for ``session_id``."""
        key = self._KEY_FMT.format(session_id=session_id)
        current_id = last_id
        while True:
            async with get_redis() as client:
                raw_result = await client.xread(
                    {key: current_id},
                    block=_XREAD_BLOCK_MS,
                    count=_XREAD_COUNT,
                )
            if raw_result:
                for _stream_key, events in raw_result:
                    for event_id, event_data in events:
                        current_id = event_id
                        yield event_data
            else:
                yield {"event": "ping", "timestamp": utc_now().isoformat()}
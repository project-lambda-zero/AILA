"""Workflow progress emitter for the forensics module.

Publishes forensic workflow stage progress to the platform's Redis Streams
via ``ProgressStream.emit``, so the frontend's SSE feed at
``/forensics/projects/.../investigations/.../events`` actually receives
live events instead of sitting on "Waiting for events…".

Also logs locally so the worker log remains a reliable post-mortem surface
even when Redis is misconfigured.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from aila.platform.services.redis_pool import pool_available
from aila.platform.tasks.progress import ProgressStream

__all__ = ["ForensicsWorkflowEmitter"]

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class ForensicsWorkflowEmitter:
    """Emit forensics workflow progress events.

    ``run_id`` is the task_id for which the platform keys its Redis stream.
    Each ``emit`` call:
      1. Appends to an in-memory history (used by in-process inspectors).
      2. Logs at INFO so /tmp/aila_worker_forensics.log reflects every step.
      3. Writes to the Redis stream so the SSE endpoint can fan it out to
         the frontend's live feed. Failure here is non-fatal -- instrumentation
         must never break the workflow.
    """

    run_id: str
    module_id: str
    stage_history: list[dict[str, Any]] = field(default_factory=list)
    _progress: ProgressStream | None = None

    def _stream(self) -> ProgressStream:
        if self._progress is None:
            self._progress = ProgressStream()
        return self._progress

    async def emit(self, stage: str, message: str, data: dict[str, Any] | None = None) -> None:
        """Emit a workflow stage progress event to log + Redis Stream.

        The ``data`` payload is JSON-encoded into a ``data_json`` field on the
        stream record so the SSE consumer can reconstruct it without the
        field count exploding per event.
        """
        event = {
            "run_id": self.run_id,
            "module_id": self.module_id,
            "stage": stage,
            "message": message,
            "data": data or {},
        }
        self.stage_history.append(event)
        _log.info("forensics[%s] stage=%s: %s", self.run_id[:8], stage, message)

        if not pool_available():
            # Redis not configured -- SSE feed will stay empty by design.
            return

        try:
            key = ProgressStream.stream_key(self.run_id)
            from aila.platform.contracts import utc_now
            from aila.platform.services.redis_pool import get_redis

            async with get_redis() as client:
                await client.xadd(
                    key,
                    {
                        "stage": stage,
                        "message": message,
                        "percent": str(data.get("percent", 0)) if data else "0",
                        "timestamp": utc_now().isoformat(),
                        "data_json": json.dumps(data or {}, default=str),
                    },
                    maxlen=1000,
                    approximate=False,
                )
        except (OSError, RuntimeError, TimeoutError) as exc:
            _log.warning(
                "forensics[%s] failed to publish event to Redis stream: %s",
                self.run_id[:8], exc,
            )

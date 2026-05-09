from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

import sqlalchemy.exc

from .event import PlatformEvent

if TYPE_CHECKING:
    from sqlmodel import Session

    from aila.platform.contracts.runtime import RunState


# A destination is any callable that accepts a PlatformEvent and keyword context.
# Context kwargs are optional — destinations may ignore what they don't need.
DestinationFn = Callable[..., None]


class EventEmitter:
    """Fan-out emitter: one emit() call delivers to all registered destinations.

    Destinations are registered at construction time via register_destination().
    Adding a new destination never requires changes at call sites (per EMIT-03).
    """

    def __init__(self) -> None:
        self._destinations: list[tuple[str, DestinationFn]] = []

    def register_destination(self, name: str, fn: DestinationFn) -> None:
        """Add a named destination callable to the fan-out list.

        Destinations receive every future emitted event. The name is used for
        debugging only — it is not surfaced in event payloads. Destinations are
        registered at emitter construction time, not per-event, so the set is
        stable for the lifetime of a request.
        """
        self._destinations.append((name, fn))

    def emit(self, event: PlatformEvent) -> None:
        """Deliver the event to all registered destinations in registration order."""
        for _name, fn in self._destinations:
            fn(event)


class ThreadSafeEventEmitter(EventEmitter):
    """Thread-safe variant: serializes emit() calls through an internal queue.

    Parallel SSH workers, DAG stages, and scoring threads all call emit()
    safely without external locking (per EMIT-04).

    Async-ready: the drain loop is synchronous. Async destinations (SSE,
    WebSocket) register via register_destination() and receive events in
    drain order; they do not block fast synchronous destinations (per EMIT-05).
    """

    def __init__(self) -> None:
        super().__init__()
        self._queue: queue.SimpleQueue[PlatformEvent] = queue.SimpleQueue()
        self._lock = threading.Lock()

    def emit(self, event: PlatformEvent) -> None:
        """Enqueue the event and attempt to drain the queue under a non-blocking lock.

        If another thread is already draining, this call exits immediately after
        enqueuing — the event is still in the queue and will be delivered by the
        draining thread before it releases the lock.
        """
        self._queue.put(event)
        self._drain()

    def _drain(self) -> None:
        """Deliver all queued events to destinations while holding the drain lock.

        Non-blocking lock acquisition means concurrent emit() callers skip the
        drain and return immediately. The current drain owner processes all
        enqueued events before releasing, so no events are lost.
        """
        if not self._lock.acquire(blocking=False):
            return
        try:
            while True:
                try:
                    event = self._queue.get_nowait()
                except queue.Empty:
                    break
                for _name, fn in self._destinations:
                    fn(event)
        finally:
            self._lock.release()


def build_emitter(
    session: Session,
    run_state: RunState,
    progress_callback: Callable | None = None,
) -> EventEmitter:
    """Construct an EventEmitter with four destinations wired.

    Destinations (per EMIT-01):
      1. audit_db       — writes AuditEventRecord via record_audit_event
      2. run_history    — appends WorkflowEvent to run_state.events
      3. progress       — calls progress_callback(ProgressUpdate(...)) if provided
      4. redis_stream   — publishes to Redis Stream for SSE frontend consumption
    """
    from aila.platform.contracts.platform import ProgressUpdate
    from aila.platform.services.audit import record_audit_event
    from aila.storage.memory import append_run_event

    emitter = ThreadSafeEventEmitter()

    def _audit_db(event: PlatformEvent) -> None:
        try:
            record_audit_event(
                session,
                run_id=event.run_id,
                stage=event.stage,
                action=event.action,
                details=event.details or {},
            )
        except sqlalchemy.exc.SQLAlchemyError:
            # Session may be in a failed transaction state — don't let audit
            # event failure cascade and kill the entire scan
            import logging as _logging
            _logging.getLogger(__name__).debug("audit_db emit failed (session may be in failed state)", exc_info=True)

    def _run_history(event: PlatformEvent) -> None:
        append_run_event(run_state, event.key, event.message)

    def _progress(event: PlatformEvent) -> None:
        if progress_callback is None:
            return
        progress_callback(
            ProgressUpdate(
                stage=event.stage,
                message=event.progress_message or event.message,
                current=event.current,
                total=event.total,
            )
        )

    def _redis_stream(event: PlatformEvent) -> None:
        """Publish progress event to Redis Stream for SSE frontend.

        Uses a sync Redis client to avoid event loop blocking issues
        (async create_task gets starved when sync HTTP calls block the loop).
        """
        task_id = event.run_id
        if not task_id:
            return
        try:
            import os

            import redis

            from aila.platform.contracts._common import utc_now

            redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL")
            if not redis_url:
                return

            percent = 0
            if event.total and event.total > 0 and event.current is not None:
                percent = int((event.current / event.total) * 100)

            key = f"task:{task_id}:progress"
            client = redis.from_url(redis_url, decode_responses=True)
            try:
                client.xadd(
                    key,
                    {
                        "stage": event.stage,
                        "message": event.progress_message or event.message,
                        "percent": str(percent),
                        "timestamp": utc_now().isoformat(),
                    },
                    maxlen=1000,
                )
            finally:
                client.close()
        except redis.exceptions.RedisError:
            pass  # Never let Redis failure break the scan

    emitter.register_destination("audit_db", _audit_db)
    emitter.register_destination("run_history", _run_history)
    emitter.register_destination("progress", _progress)
    emitter.register_destination("redis_stream", _redis_stream)
    return emitter


__all__ = ["EventEmitter", "ThreadSafeEventEmitter", "build_emitter"]

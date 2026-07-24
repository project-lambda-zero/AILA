from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

import sqlalchemy.exc

from aila.platform.exceptions import AILAError

from .event import PlatformEvent

if TYPE_CHECKING:
    from sqlmodel import Session

    from aila.platform.contracts.runtime import RunState


_log = logging.getLogger(__name__)


# Cached sync Redis clients keyed by URL (#60-2). The redis_stream destination
# runs in the drain thread and previously opened + closed a fresh connection per
# event, so a scan emitting hundreds of stage events paid hundreds of TCP
# handshakes. A redis-py client owns an internal, thread-safe connection pool,
# so one cached client per URL is reused across events and drains.
_SYNC_REDIS_CLIENTS: dict[str, object] = {}
_SYNC_REDIS_LOCK = threading.Lock()


def _get_sync_redis_client(redis_url: str):
    """Return a process-cached sync Redis client for ``redis_url``."""
    client = _SYNC_REDIS_CLIENTS.get(redis_url)
    if client is not None:
        return client
    import redis

    with _SYNC_REDIS_LOCK:
        client = _SYNC_REDIS_CLIENTS.get(redis_url)
        if client is None:
            client = redis.from_url(redis_url, decode_responses=True)
            _SYNC_REDIS_CLIENTS[redis_url] = client
        return client


# A destination is any callable that accepts a PlatformEvent and keyword context.
# Context kwargs are optional -- destinations may ignore what they don't need.
DestinationFn = Callable[..., None]


# Destination names whose failures also surface on SSE_WRITE_FAILURES_TOTAL.
# The other destinations (``audit_db``, ``run_history``) already have their
# own operator-visible signals; duplicating them on the SSE counter would
# muddy the metric that operators use to spot fan-out drop.
_SSE_DESTINATION_NAMES: frozenset[str] = frozenset({"progress", "redis_stream"})


def _bump_sse_write_failure(source: str) -> None:
    """Best-effort SSE write-failure signal via the ResilienceLayer facade.

    Deferred import (both the metric and the facade) keeps the emitter
    module importable in contexts (tests, CLI, tools) where the API
    package is not initialised. Any exception from the counter path is
    itself swallowed inside the layer -- an observability increment
    MUST NEVER kill the caller's turn. Delegating here means every fail-
    open site funnels through the same signal path (RFC-07 acceptance
    bullet 2) instead of each carrying its own bump line.
    """
    try:
        from aila.platform.services.resilience import (
            get_default_resilience_layer,
        )

        get_default_resilience_layer().record_signal(
            op="sse_write", source=source,
        )
    except (ImportError, AttributeError, RuntimeError, ValueError) as exc:
        _log.debug("resilience signal skipped: %s", exc)


# Comprehensive tuple used to isolate destination failures at fan-out time.
# Any exception a destination might reasonably raise (I/O, coercion, missing
# key, config bug, platform error) is caught, logged, and counted so the
# next destination in the registration list still receives the event.
# BaseException-only subclasses (KeyboardInterrupt, SystemExit) intentionally
# propagate -- the interpreter is going down and drain must not swallow that.
_DESTINATION_ISOLATION_ERRORS: tuple[type[BaseException], ...] = (
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


class EventEmitter:
    """Fan-out emitter: one emit() call delivers to all registered destinations.

    Destinations are registered at construction time via register_destination().
    Adding a new destination never requires changes at call sites (per EMIT-03).
    """

    def __init__(self) -> None:
        self._destinations: list[tuple[str, DestinationFn]] = []
        # Per-destination running failure count. Public read via
        # destination_failure_count(name); test/telemetry hook.
        self._destination_failures: dict[str, int] = {}

    def register_destination(self, name: str, fn: DestinationFn) -> None:
        """Add a named destination callable to the fan-out list.

        Destinations receive every future emitted event. The name is used for
        debugging only -- it is not surfaced in event payloads. Destinations are
        registered at emitter construction time, not per-event, so the set is
        stable for the lifetime of a request.
        """
        self._destinations.append((name, fn))

    def emit(self, event: PlatformEvent) -> None:
        """Deliver the event to all registered destinations in registration order.

        A failure in one destination is isolated: the remaining destinations
        still receive the event, the exception is logged with full traceback,
        and destination_failure_count(name) increments. This matches issue #60-1:
        the previous unisolated for-loop silently dropped every downstream
        destination when an earlier one raised.
        """
        for name, fn in self._destinations:
            self._dispatch(name, fn, event)

    def _dispatch(self, name: str, fn: DestinationFn, event: PlatformEvent) -> None:
        """Call one destination under the isolation guard.

        Kept as a hook so ThreadSafeEventEmitter reuses the identical
        per-destination policy from inside its drain loop.

        SSE / progress-stream destinations (``progress`` and
        ``redis_stream``) additionally increment SSE_WRITE_FAILURES_TOTAL
        on failure so an operator can spot a silently degrading fan-out
        without diffing per-destination failure dicts. The counter
        import is deferred so importing the emitter module never pulls
        in prometheus_client on paths that do not need it.
        """
        try:
            fn(event)
        except _DESTINATION_ISOLATION_ERRORS as exc:
            _log.warning(
                "emitter destination %r raised on event %s/%s: %s",
                name,
                event.stage,
                event.action,
                exc.__class__.__name__,
                exc_info=True,
            )
            self._destination_failures[name] = (
                self._destination_failures.get(name, 0) + 1
            )
            if name in _SSE_DESTINATION_NAMES:
                _bump_sse_write_failure("emitter")

    def get_destination_failures(self) -> dict[str, int]:
        """Return a snapshot of per-destination failure counts.

        The returned mapping is a defensive copy: mutating it does not
        affect the emitter, and reads on a live emitter under concurrent
        emit() are safe because dict.copy() is atomic under CPython. A
        destination that has never failed (or never been registered) is
        absent from the mapping; treat missing keys as zero. Test and
        telemetry hook -- production code should not branch on this value.
        """
        return dict(self._destination_failures)


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
        enqueuing -- the event is still in the queue and will be delivered by the
        draining thread before it releases the lock.
        """
        self._queue.put(event)
        self._drain()

    def _drain(self) -> None:
        """Deliver all queued events to destinations while holding the drain lock.

        Non-blocking lock acquisition means concurrent emit() callers skip the
        drain and return immediately. The current drain owner processes all
        enqueued events before releasing, so no events are lost. Each
        destination call is isolated via _dispatch so one broken destination
        cannot starve the rest.
        """
        if not self._lock.acquire(blocking=False):
            return
        try:
            while True:
                try:
                    event = self._queue.get_nowait()
                except queue.Empty:
                    break
                for name, fn in self._destinations:
                    self._dispatch(name, fn, event)
        finally:
            self._lock.release()


def build_emitter(
    session: Session,
    run_state: RunState,
    progress_callback: Callable | None = None,
) -> EventEmitter:
    """Construct an EventEmitter with four destinations wired.

    Destinations (per EMIT-01):
      1. audit_db       -- writes AuditEventRecord via record_audit_event
      2. run_history    -- appends WorkflowEvent to run_state.events
      3. progress       -- calls progress_callback(ProgressUpdate(...)) if provided
      4. redis_stream   -- publishes to Redis Stream for SSE frontend consumption
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
        except sqlalchemy.exc.SQLAlchemyError as exc:
            # #52-3.5: fail-loud. The previous DEBUG swallow hid audit-trail
            # loss under any in-flight session-transaction failure, so
            # dropped audit rows never surfaced. Re-raise as RuntimeError so
            # the emitter's _dispatch guard logs at ERROR with the full
            # traceback and increments _destination_failures['audit_db']
            # -- mirroring the redis_stream escalation pattern below.
            # Full fail-closed rollback + dead-letter destination is on the
            # #52 journal-migration roadmap and stays out of scope for this
            # pass (needs infra/migration wiring).
            raise RuntimeError(
                f"audit_db emit failed: {exc.__class__.__name__}",
            ) from exc

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
        Redis-side failures propagate to the drain isolation guard as
        RuntimeError so the failure is logged, counted, and does not starve
        subsequent destinations (issue #60-1 / #60-2).
        """
        task_id = event.run_id
        if not task_id:
            return
        import os

        import redis

        from aila.platform.contracts import utc_now

        redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL")
        if not redis_url:
            return

        percent = 0
        if event.total and event.total > 0 and event.current is not None:
            percent = int((event.current / event.total) * 100)

        key = f"task:{task_id}:progress"
        # Reuse the process-cached pooled client (#60-2) instead of opening and
        # closing a connection per event.
        client = _get_sync_redis_client(redis_url)
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
                approximate=True,
            )
        except redis.exceptions.RedisError as exc:
            # Re-raise as RuntimeError so the drain isolation guard (which does
            # not import redis) catches, logs, and counts the failure instead
            # of the previous silent pass-swallow.
            raise RuntimeError(
                f"redis stream publish failed: {exc.__class__.__name__}"
            ) from exc

    emitter.register_destination("audit_db", _audit_db)
    emitter.register_destination("run_history", _run_history)
    emitter.register_destination("progress", _progress)
    emitter.register_destination("redis_stream", _redis_stream)
    return emitter


__all__ = ["EventEmitter", "ThreadSafeEventEmitter", "build_emitter"]

"""Per-request adapter over the unified typed event bus (RFC #134).

RFC #134 consolidated the two parallel event systems (``DomainEventBus``
+ ``EventEmitter``/``PlatformEvent``) into a single typed bus (see
:mod:`.bus`). ``EventEmitter`` survives as a thin per-request adapter:
it wraps the shared bus, translates the legacy per-request
:class:`PlatformEvent` into a typed
:class:`~aila.platform.events.domain_events.WorkflowStageAnnounced`
domain event, and dispatches to the four request-scoped destinations
(``audit_db``, ``run_history``, ``progress``, ``redis_stream``) that
require per-request context (session, run_state, progress callback).

Every ``emit(PlatformEvent)`` therefore feeds the unified bus once
(so the process-wide journal + Redis fanout subscribers see it) AND
runs the request-scoped destinations that carry per-run
observability. ``ThreadSafeEventEmitter`` is kept as an alias for
backwards compatibility -- the drain-and-dispatch primitive lives in
the bus now (:class:`aila.platform.events.bus.DomainEventBus`), so
every request-scoped emitter is thread-safe by default.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

import sqlalchemy.exc

from ._dispatch import safe_dispatch
from .bus import DomainEventBus, default_bus
from .domain_events import (
    DomainEvent,
    WorkflowStageAnnounced,
    WorkflowStagePayload,
)
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


def _workflow_stage_event(event: PlatformEvent) -> WorkflowStageAnnounced:
    """Build the typed :class:`WorkflowStageAnnounced` mirror of ``event``.

    Every ``EventEmitter.emit(PlatformEvent)`` publishes one of these
    on the shared bus so the process-wide subscribers (journal, Redis
    cross-process fanout) see the per-request stage announcement as a
    typed domain event. Fields map 1:1 from the frozen dataclass to
    the Pydantic payload; ``details`` is copied defensively so a later
    mutation of the caller's dict cannot alter the persisted payload.
    """
    return WorkflowStageAnnounced(
        source_module="platform.workflow",
        payload=WorkflowStagePayload(
            stage=event.stage,
            action=event.action,
            key=event.key,
            message=event.message,
            details=dict(event.details or {}),
            run_id=event.run_id,
            current=event.current,
            total=event.total,
            progress_message=event.progress_message,
        ),
    )


class EventEmitter:
    """Per-request adapter over the unified typed event bus (RFC #134).

    Every :meth:`emit` publishes a typed
    :class:`~aila.platform.events.domain_events.WorkflowStageAnnounced`
    domain event on the shared bus (feeding the journal + Redis
    cross-process fanout subscribers) AND dispatches to the emitter's
    own per-request destinations (audit_db, run_history, progress,
    redis_stream). Destinations are registered at construction time
    via :meth:`register_destination`; adding one does not require any
    change at call sites.

    ``register_destination`` and per-destination failure isolation
    remain unchanged from the pre-consolidation ``EventEmitter`` --
    call sites see the same shape. The single publish surface is the
    behavioural change: the same event now feeds the bus AND the
    request-scoped destinations, so a worker-emitted stage event
    reaches SSE subscribers via the Redis bridge without any extra
    wiring at the call site.
    """

    def __init__(self, *, bus: DomainEventBus | None = None) -> None:
        self._destinations: list[tuple[str, DestinationFn]] = []
        # Per-destination running failure count. Public read via
        # destination_failure_count(name); test/telemetry hook.
        self._destination_failures: dict[str, int] = {}
        # RFC #134 -- feed the typed bus on every emit. Tests may inject
        # a fresh bus to isolate subscribers.
        self._bus = bus if bus is not None else default_bus()

    def register_destination(self, name: str, fn: DestinationFn) -> None:
        """Add a named destination callable to the fan-out list.

        Destinations receive every future emitted event. The name is used for
        debugging only -- it is not surfaced in event payloads. Destinations are
        registered at emitter construction time, not per-event, so the set is
        stable for the lifetime of a request.
        """
        self._destinations.append((name, fn))

    def emit(self, event: PlatformEvent) -> None:
        """Publish the typed event on the shared bus AND fan out to destinations.

        Every emit does two things:

        1. Publish a
           :class:`~aila.platform.events.domain_events.WorkflowStageAnnounced`
           mirror of ``event`` on the shared bus so the process-wide
           subscribers (journal, Redis cross-process fanout) see it.
           A worker-emitted stage event therefore reaches API-process
           SSE subscribers via the Redis bridge without any per-call
           wiring.
        2. Dispatch to each registered destination in registration
           order under the shared isolation guard so a failure in one
           destination is logged, counted, and skipped past.
        """
        # (1) Publish on the shared bus. The bus itself is thread-safe
        # and drains on the publishing thread; a subscriber failure is
        # isolated there. A bus failure is logged and swallowed so a
        # broken subscriber never breaks the caller's request.
        try:
            self._bus.publish(_workflow_stage_event(event))
        except (RuntimeError, OSError, TimeoutError, ValueError, TypeError) as exc:
            _log.warning(
                "emitter shared-bus publish failed for event %s/%s: %s",
                event.stage, event.action, exc.__class__.__name__,
                exc_info=True,
            )
        # (2) Local per-request destinations. Fanout preserves the
        # legacy per-destination isolation contract (issue #60-1).
        for name, fn in self._destinations:
            self._dispatch(name, fn, event)

    def publish(self, event: DomainEvent) -> None:
        """Publish a typed domain event on the shared bus.

        Convenience for call sites that are already typed: LLM cost
        accounting, config-registry security changes, module workflow
        lifecycle. The event goes through the same bus every emit
        feeds, so journal + Redis fanout + any in-process subscriber
        see it exactly once.
        """
        self._bus.publish(event)

    def _dispatch(self, name: str, fn: DestinationFn, event: PlatformEvent) -> None:
        """Call one destination under the shared isolation guard.

        The isolation exception tuple and the try/except/log block live
        in :mod:`aila.platform.events._dispatch` so this emitter and
        :class:`aila.platform.events.bus.DomainEventBus` cannot drift.

        SSE / progress-stream destinations (``progress`` and
        ``redis_stream``) additionally increment SSE_WRITE_FAILURES_TOTAL
        on failure so an operator can spot a silently degrading fan-out
        without diffing per-destination failure dicts. The counter
        import is deferred so importing the emitter module never pulls
        in prometheus_client on paths that do not need it.
        """
        safe_dispatch(
            name,
            fn,
            event,
            log_label="emitter destination",
            event_description=f"event {event.stage}/{event.action}",
            on_failure=self._record_destination_failure,
        )

    def _record_destination_failure(self, name: str, _exc: BaseException) -> None:
        """Bump per-destination failure count and any additional signals.

        Invoked by :func:`safe_dispatch` after the isolation guard has
        already logged the exception. Splitting the counter policy out
        of the guard keeps the shared primitive free of destination-set
        knowledge (the SSE bump is emitter-specific).
        """
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


# ``ThreadSafeEventEmitter`` alias -- RFC #134 folded the drain-and-dispatch
# primitive into the bus, so every ``EventEmitter`` is thread-safe by
# construction. The alias is kept because existing call sites and tests
# spell it out explicitly; new call sites should reach for ``EventEmitter``.
ThreadSafeEventEmitter = EventEmitter


def build_emitter(
    session: Session,
    run_state: RunState,
    progress_callback: Callable | None = None,
) -> EventEmitter:
    """Construct an EventEmitter with four request-scoped destinations wired.

    Destinations (per EMIT-01):
      1. audit_db       -- writes AuditEventRecord via record_audit_event
      2. run_history    -- appends WorkflowEvent to run_state.events
      3. progress       -- calls progress_callback(ProgressUpdate(...)) if provided
      4. redis_stream   -- publishes to Redis Stream for SSE frontend consumption

    RFC #134 additionally publishes a typed
    :class:`~aila.platform.events.domain_events.WorkflowStageAnnounced`
    on the shared bus for every emit, so the process-wide journal +
    Redis cross-process fanout subscribers receive the same event
    without any per-call wiring.
    """
    from aila.platform.contracts.platform import ProgressUpdate
    from aila.platform.services.audit import record_audit_event
    from aila.storage.memory import append_run_event

    emitter = EventEmitter()

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

"""Unified typed event bus (RFC #134 / #60).

Domain events (:class:`DomainEvent` and subclasses in
:mod:`aila.platform.events.domain_events`) are typed, versioned
lifecycle records the platform publishes when a system is registered,
an LLM call completes, a config value changes, a module workflow
starts / finishes, or a per-run workflow stage advances.

Before RFC #134 the platform ran two parallel event systems:

* ``DomainEventBus`` (this module) dispatched typed
  :class:`DomainEvent` values to a journal subscriber and, via the
  #106 Redis bridge, to a cross-process fanout.
* ``EventEmitter`` (in :mod:`.emitter`) dispatched frozen
  :class:`~aila.platform.events.event.PlatformEvent` values to four
  per-request destinations (audit_db, run_history, progress,
  redis_stream) with no bridge to the typed bus.

The two systems shared a fan-out isolation primitive but nothing
else -- worker-emitted :class:`DomainEvent` values never reached SSE
subscribers, and 9 of 10 domain event types had no publishers. The
consolidation folds both surfaces into a single typed :func:`publish`
call. Every per-request stage announcement now travels as a typed
:class:`~aila.platform.events.domain_events.WorkflowStageAnnounced`
domain event through the same bus, so:

* the durable journal subscriber (see
  :mod:`aila.platform.events.persistence`) records EVERY event in the
  hash-chained platform journal;
* the Redis cross-process publisher (see
  :mod:`aila.platform.events.redis_bridge`) XADDs EVERY event to the
  shared stream so a worker publish reaches the API process's
  in-process subscribers (SSE fanout);
* the per-request :class:`~aila.platform.events.emitter.EventEmitter`
  additionally dispatches to its four request-scoped destinations for
  the workflow-stage events matching its ``run_id``, using the same
  bus and the same isolation contract.

The bus uses the thread-safe drain pattern that previously lived only
inside ``ThreadSafeEventEmitter``: :meth:`publish` enqueues the event
and attempts a non-blocking drain, so parallel worker threads can
:meth:`publish` concurrently without external locking. The current
drain owner processes the whole queue before releasing the drain lock,
so no event is lost. Each subscriber invocation is isolated via
:func:`aila.platform.events._dispatch.safe_dispatch` -- one broken
subscriber cannot starve the rest and cannot propagate an exception
into the caller.

Callers do NOT construct a bus; they use the module-level
:func:`publish` / :func:`subscribe` / :func:`unsubscribe` helpers which
resolve to :func:`default_bus` (the process-wide singleton). Tests may
build a fresh :class:`DomainEventBus` and pass it around when they need
isolation.
"""
from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import Any

from ._dispatch import safe_dispatch
from .domain_events import DomainEvent

__all__ = [
    "DomainEventBus",
    "SubscriberFn",
    "default_bus",
    "publish",
    "subscribe",
    "unsubscribe",
]

SubscriberFn = Callable[[DomainEvent], None]


class DomainEventBus:
    """Process-local typed event bus with thread-safe drain (RFC #134).

    Subscribers register once at wiring time; publishers call
    :meth:`publish` from anywhere -- request handlers, workflow
    states, LLM call sites, worker threads -- and the bus fans the
    event out to every registered subscriber in registration order.
    A subscriber that raises is logged with the offending class name
    and ``event_type``; the failure counter under its registered name
    is incremented so operators can spot a consistently broken
    subscriber without diffing logs.

    Drain contract: :meth:`publish` enqueues the event and attempts a
    non-blocking drain. If another thread is already draining, this
    call exits immediately after enqueuing -- the event is still in
    the queue and will be delivered by the draining thread before it
    releases the lock. Parallel worker threads therefore
    :meth:`publish` without external locking, and one slow subscriber
    never blocks a new registration.

    The subscriber list is guarded by an internal lock so concurrent
    :meth:`subscribe` + drain cannot race; individual subscribers still
    run outside the lock so a slow subscriber does not stall a new
    registration.
    """

    def __init__(self) -> None:
        self._subscribers: list[tuple[str, SubscriberFn]] = []
        self._failures: dict[str, int] = {}
        self._subs_lock = threading.Lock()
        self._queue: queue.SimpleQueue[DomainEvent] = queue.SimpleQueue()
        self._drain_lock = threading.Lock()

    def subscribe(self, name: str, handler: SubscriberFn) -> None:
        """Register ``handler`` under ``name``.

        ``name`` is used for failure counters and log lines only; it is
        never surfaced in event payloads. Duplicate names are permitted
        (two independent subscribers may share a label); the failure
        counter is keyed on the label so a bad one hides no matter how
        many good ones share it.
        """
        with self._subs_lock:
            self._subscribers.append((name, handler))

    def unsubscribe(self, handler: SubscriberFn) -> None:
        """Drop the first registration whose handler identity matches.

        Silent no-op when the handler is not registered; test-teardown
        callers should not have to guard on prior state.
        """
        with self._subs_lock:
            for i, (_, fn) in enumerate(self._subscribers):
                if fn is handler:
                    self._subscribers.pop(i)
                    return

    def publish(self, event: DomainEvent) -> None:
        """Enqueue ``event`` and attempt a non-blocking drain.

        Concurrent callers race on :attr:`_drain_lock`; whoever wins
        drains the whole queue before releasing so no event is lost.
        Losers return immediately -- their event is still in the queue
        and will be delivered by the current drain owner. Every
        subscriber call is isolated via :func:`safe_dispatch` so a
        broken subscriber cannot starve the rest.
        """
        self._queue.put(event)
        self._drain()

    def _drain(self) -> None:
        """Deliver all queued events to subscribers while holding the drain lock.

        Non-blocking lock acquisition means concurrent :meth:`publish`
        callers skip the drain and return immediately. The current
        drain owner processes all enqueued events before releasing,
        so no events are lost.
        """
        if not self._drain_lock.acquire(blocking=False):
            return
        try:
            while True:
                try:
                    event = self._queue.get_nowait()
                except queue.Empty:
                    break
                with self._subs_lock:
                    snapshot = list(self._subscribers)
                description = event.event_type or event.__class__.__name__
                for name, fn in snapshot:
                    safe_dispatch(
                        name,
                        fn,
                        event,
                        log_label="domain-event subscriber",
                        event_description=description,
                        on_failure=self._record_subscriber_failure,
                    )
        finally:
            self._drain_lock.release()

    def _record_subscriber_failure(self, name: str, _exc: BaseException) -> None:
        """Bump the named subscriber's failure counter under the subs lock.

        Invoked by :func:`safe_dispatch` after the guard has already
        logged the exception. The lock guards the counter map so a
        concurrent :meth:`failure_counts` snapshot sees a consistent
        integer, matching the pre-consolidation behaviour.
        """
        with self._subs_lock:
            self._failures[name] = self._failures.get(name, 0) + 1

    def failure_counts(self) -> dict[str, int]:
        """Snapshot of per-subscriber failure counts. Test/telemetry hook."""
        with self._subs_lock:
            return dict(self._failures)

    def subscriber_count(self) -> int:
        """Number of currently registered subscribers."""
        with self._subs_lock:
            return len(self._subscribers)

    def _reset_for_tests(self) -> None:
        """Drop every subscriber and failure count. Tests only."""
        with self._subs_lock:
            self._subscribers.clear()
            self._failures.clear()


_DEFAULT_BUS: DomainEventBus | None = None
_DEFAULT_BUS_LOCK = threading.Lock()


def default_bus() -> DomainEventBus:
    """Return the process-wide singleton bus, constructing on first call.

    The first call also wires two process-wide subscribers:

    * :func:`aila.platform.events.persistence.persist_domain_event`
      appends every published event to the hash-chained platform
      journal (``kind="domain_event"``) so every event is durably
      persisted.
    * :func:`aila.platform.events.redis_bridge.install_redis_publisher`
      subscribes the Redis-stream publisher so a worker publish also
      lands in the API process's in-process bus (where SSE
      subscribers live). Publisher is fail-open: unavailable Redis
      means the event stays in-process only, no exception raised.

    Wiring at first-use avoids an import cycle between the bus module
    and the persistence / redis-bridge modules while still
    guaranteeing that any caller reaching :func:`publish` gets both
    destinations for free. The Redis-stream consumer is API-process
    only and is started explicitly by the FastAPI lifespan hook.
    """
    global _DEFAULT_BUS
    if _DEFAULT_BUS is not None:
        return _DEFAULT_BUS
    with _DEFAULT_BUS_LOCK:
        if _DEFAULT_BUS is None:
            bus = DomainEventBus()
            # Import inside the lock so the cycle
            # (bus <- persistence <- journal) is resolved lazily.
            from .persistence import persist_domain_event

            bus.subscribe("journal_persist", persist_domain_event)
            # #106 -- attach the Redis cross-process publisher so a
            # DomainEvent emitted in a worker also lands in the API
            # process's local bus (where SSE subscribers live). The
            # publisher is fail-open: unavailable Redis means the
            # emit stays in-process only, no exception raised. The
            # matching consumer is API-process-only and is started
            # explicitly by the FastAPI lifespan hook.
            from .redis_bridge import install_redis_publisher

            install_redis_publisher(bus)
            _DEFAULT_BUS = bus
    return _DEFAULT_BUS


def publish(event: DomainEvent) -> None:
    """Publish ``event`` on the default bus. Convenience for call sites."""
    default_bus().publish(event)


def subscribe(name: str, handler: SubscriberFn) -> None:
    """Register ``handler`` on the default bus under ``name``."""
    default_bus().subscribe(name, handler)


def unsubscribe(handler: SubscriberFn) -> None:
    """Drop ``handler`` from the default bus."""
    default_bus().unsubscribe(handler)


def _reset_default_bus_for_tests() -> None:
    """Drop the module-level singleton so the next :func:`default_bus`
    rebuilds a bus + rewires the persistence subscriber. Tests only."""
    global _DEFAULT_BUS
    with _DEFAULT_BUS_LOCK:
        _DEFAULT_BUS = None


def _payload_dict(event: DomainEvent) -> dict[str, Any]:
    """Coerce ``event.payload`` (Pydantic BaseModel) to a plain dict.

    Kept here so the persistence subscriber and any test helper share
    a single serialisation surface. Non-Pydantic ``payload`` attributes
    fall back to their ``__dict__`` (frozen dataclasses expose this)
    and finally to ``str(payload)`` so publish never crashes on an
    unforeseen shape.
    """
    payload = getattr(event, "payload", None)
    if payload is None:
        return {}
    dump = getattr(payload, "model_dump", None)
    if callable(dump):
        return dict(dump(mode="json"))
    dct = getattr(payload, "__dict__", None)
    if isinstance(dct, dict):
        return {k: v for k, v in dct.items() if not k.startswith("_")}
    return {"value": str(payload)}

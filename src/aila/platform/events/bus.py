"""In-process domain-event dispatch bus (#60).

Domain events (:class:`DomainEvent` and subclasses in
:mod:`aila.platform.events.domain_events`) are typed, versioned
lifecycle records the platform publishes when a system is registered,
an assessment finishes, an LLM call completes, or a config value
changes. Before this module existed the classes were declared but had
no dispatch surface -- publishing was a no-op and subscribers could not
listen. This module wires the small in-process bus that :func:`publish`
routes events through.

The bus is deliberately minimal: a synchronous call to :meth:`publish`
walks the subscriber list in registration order and calls each handler
inside an isolation guard so one broken subscriber cannot starve the
rest. There is no ordering guarantee across subscribers, no
delivery-receipt, and no back-pressure. Persistence is the primary
subscriber and is wired at import time (see
:mod:`aila.platform.events.persistence`) so every published event
lands in the hash-chained platform journal via
``kind="domain_event"``.

Callers do NOT construct a bus; they use the module-level
:func:`publish` / :func:`subscribe` / :func:`unsubscribe` helpers which
resolve to :func:`default_bus` (the process-wide singleton). Tests may
build a fresh :class:`DomainEventBus` and pass it around when they need
isolation.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from aila.platform.exceptions import AILAError

from .domain_events import DomainEvent

__all__ = [
    "DomainEventBus",
    "SubscriberFn",
    "default_bus",
    "publish",
    "subscribe",
    "unsubscribe",
]

_log = logging.getLogger(__name__)


SubscriberFn = Callable[[DomainEvent], None]


# Same isolation policy as the PlatformEvent emitter (see
# aila.platform.events.emitter._DESTINATION_ISOLATION_ERRORS). A
# subscriber that raises one of these is logged + counted; the bus
# continues to deliver to the remaining subscribers. BaseException
# subclasses (KeyboardInterrupt, SystemExit) intentionally propagate.
_SUBSCRIBER_ISOLATION_ERRORS: tuple[type[BaseException], ...] = (
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


class DomainEventBus:
    """Process-local synchronous domain-event bus.

    Subscribers register once at wiring time; publishers call
    :meth:`publish` from anywhere -- request handlers, workflow
    states, LLM call sites -- and the bus fans the event out to every
    registered handler in a single synchronous pass. A ``handler``
    that raises is logged with the offending class name and
    ``event_type``; the failure counter under ``handler.__name__`` (or
    the registered name) is incremented so operators can spot a
    consistently broken subscriber without diffing logs.

    Thread-safe: the subscriber list and failure map are guarded by
    an internal lock so concurrent :meth:`subscribe` + :meth:`publish`
    from parallel workers do not race. Individual handlers still run
    outside the lock so a slow subscriber never blocks a new
    registration.
    """

    def __init__(self) -> None:
        self._subscribers: list[tuple[str, SubscriberFn]] = []
        self._failures: dict[str, int] = {}
        self._lock = threading.Lock()

    def subscribe(self, name: str, handler: SubscriberFn) -> None:
        """Register ``handler`` under ``name``.

        ``name`` is used for failure counters and log lines only; it is
        never surfaced in event payloads. Duplicate names are permitted
        (two independent subscribers may share a label); the failure
        counter is keyed on the label so a bad one hides no matter how
        many good ones share it.
        """
        with self._lock:
            self._subscribers.append((name, handler))

    def unsubscribe(self, handler: SubscriberFn) -> None:
        """Drop the first registration whose handler identity matches.

        Silent no-op when the handler is not registered; test-teardown
        callers should not have to guard on prior state.
        """
        with self._lock:
            for i, (_, fn) in enumerate(self._subscribers):
                if fn is handler:
                    self._subscribers.pop(i)
                    return

    def publish(self, event: DomainEvent) -> None:
        """Deliver ``event`` to every registered subscriber.

        A subscriber failure is isolated: the remaining subscribers
        still receive the event, the exception is logged with full
        traceback, and :meth:`failure_count` for the named subscriber
        increments. Snapshot under the lock so a concurrent subscribe
        cannot mutate the list mid-iteration.
        """
        with self._lock:
            snapshot = list(self._subscribers)
        for name, fn in snapshot:
            try:
                fn(event)
            except _SUBSCRIBER_ISOLATION_ERRORS as exc:
                _log.warning(
                    "domain-event subscriber %r raised on %s: %s",
                    name,
                    event.event_type or event.__class__.__name__,
                    exc.__class__.__name__,
                    exc_info=True,
                )
                with self._lock:
                    self._failures[name] = self._failures.get(name, 0) + 1

    def failure_counts(self) -> dict[str, int]:
        """Snapshot of per-subscriber failure counts. Test/telemetry hook."""
        with self._lock:
            return dict(self._failures)

    def subscriber_count(self) -> int:
        """Number of currently registered subscribers."""
        with self._lock:
            return len(self._subscribers)

    def _reset_for_tests(self) -> None:
        """Drop every subscriber and failure count. Tests only."""
        with self._lock:
            self._subscribers.clear()
            self._failures.clear()


_DEFAULT_BUS: DomainEventBus | None = None
_DEFAULT_BUS_LOCK = threading.Lock()


def default_bus() -> DomainEventBus:
    """Return the process-wide singleton bus, constructing on first call.

    The first call also wires the default persistence subscriber -- an
    :func:`aila.platform.events.persistence.persist_domain_event` handler
    that appends every published event to the hash-chained platform
    journal (kind=``domain_event``). Wiring at first-use avoids an
    import cycle between the bus module and the persistence module while
    still guaranteeing that any caller reaching :func:`publish` gets
    persistence for free.
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

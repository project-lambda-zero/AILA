"""Shared fan-out isolation primitive for the platform's event systems.

Both :class:`aila.platform.events.emitter.EventEmitter` (per-request
fan-out to audit_db, run_history, progress, redis_stream) and
:class:`aila.platform.events.bus.DomainEventBus` (process-wide
domain-event singleton) implement the same per-subscriber isolation
contract: iterate registered handlers, call each one under a guard,
log with full traceback on failure, and continue past the failure so
the remaining handlers still receive the event. Before this module
existed the two systems each carried a private copy of the isolation
exception tuple and the try/except/log block; the copies were
documented as "must stay in sync" but drift was one edit away.

This module owns the shared parts (the isolation exception tuple and
the guard-log block); each event system keeps its own log label,
event-description formatting, and per-subscriber counter policy.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from aila.platform.exceptions import AILAError

__all__ = ["ISOLATION_ERRORS", "safe_dispatch"]

_log = logging.getLogger(__name__)


# Comprehensive tuple used to isolate subscriber/destination failures at
# fan-out time. Any exception a subscriber might reasonably raise (I/O,
# coercion, missing key, config bug, platform error) is caught, logged
# by :func:`safe_dispatch`, and forwarded to the caller's ``on_failure``
# hook so the next subscriber in registration order still receives the
# event. BaseException-only subclasses (KeyboardInterrupt, SystemExit)
# intentionally propagate -- the interpreter is going down and drain
# must not swallow that.
ISOLATION_ERRORS: tuple[type[BaseException], ...] = (
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


def safe_dispatch(
    name: str,
    fn: Callable[[Any], None],
    event: Any,
    *,
    log_label: str,
    event_description: str,
    on_failure: Callable[[str, BaseException], None] | None = None,
) -> None:
    """Call ``fn(event)`` under the shared per-subscriber isolation guard.

    Any exception in :data:`ISOLATION_ERRORS` is caught, logged at
    WARNING with full traceback, and forwarded to ``on_failure(name,
    exc)`` so the caller can bump per-subscriber counters or emit
    additional signals (e.g. SSE write-failure metric). The exception
    NEVER propagates to the caller; that is the whole point of the
    guard. BaseException-only subclasses (KeyboardInterrupt,
    SystemExit) DO propagate -- see :data:`ISOLATION_ERRORS`.

    ``log_label`` names the dispatch role in log lines
    ("emitter destination", "domain-event subscriber").
    ``event_description`` names the payload for the same log line
    (e.g. ``"event stage/action"`` or the domain-event type). Callers
    format these to keep operator-visible grep patterns stable across
    the extraction.
    """
    try:
        fn(event)
    except ISOLATION_ERRORS as exc:
        _log.warning(
            "%s %r raised on %s: %s",
            log_label,
            name,
            event_description,
            exc.__class__.__name__,
            exc_info=True,
        )
        if on_failure is not None:
            on_failure(name, exc)

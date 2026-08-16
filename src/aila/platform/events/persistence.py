"""Default DomainEventBus subscriber: persist to the platform journal (#39).

Every published :class:`~aila.platform.events.domain_events.DomainEvent`
is written as one row into the hash-chained platform journal
(``platform_journal``) with ``kind="domain_event"``. This closes issue
39 without a new migration: the existing audit / journal substrate
already stores tamper-evident, versioned payloads and joins back on
``investigation_id`` / ``branch_id`` / ``turn_number`` via the
correlation ContextVar (see
:mod:`aila.platform.llm.correlation`).

Persistence is best-effort at the caller boundary -- a broken chain
routes through :func:`append_or_deadletter` so a domain-event publish
never propagates failure into the business action that raised it. When
the append succeeds the row rides the caller's transaction if one is
already open, or a short-lived session otherwise. The
``run_in_executor`` shim below handles both the "already inside an
event loop" case (module-published events from an async handler) and
the "no loop at all" case (a worker-thread emit).

Wired at first use by :func:`aila.platform.events.bus.default_bus`.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from aila.platform.exceptions import AILAError

from .bus import _payload_dict
from .domain_events import DomainEvent

__all__ = ["persist_domain_event"]

_log = logging.getLogger(__name__)


# Failure-mode isolation for the async worker used by the persistence
# subscriber. Runtime errors from asyncio.run + SQLAlchemy errors are
# absorbed so a broken journal never blocks the business action that
# fired the domain event. ``SQLAlchemyError`` is mandatory here (#122):
# without it a DB hiccup during a background persist escapes into the
# discarded Future the executor holds and the failure is silently lost --
# no log, no metric, no dead-letter row.
_PERSIST_ERRORS: tuple[type[BaseException], ...] = (
    RuntimeError,
    OSError,
    TimeoutError,
    ValueError,
    TypeError,
    AttributeError,
    KeyError,
    ImportError,
    SQLAlchemyError,
    AILAError,
)


# Dedicated single-threaded executor for the "we are already inside a
# running event loop" path. asyncio.run() would refuse to construct a
# second loop and the module-published event would silently no-op;
# routing through a background thread lets us open a short-lived loop
# for the append coroutine without touching the caller's loop. Kept
# process-lifetime so a burst of events does not pay per-event thread
# construction cost.
_PERSIST_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None
_PERSIST_EXECUTOR_LOCK = threading.Lock()


def _get_persist_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Return the process-cached ThreadPoolExecutor for background persists."""
    global _PERSIST_EXECUTOR
    if _PERSIST_EXECUTOR is not None:
        return _PERSIST_EXECUTOR
    with _PERSIST_EXECUTOR_LOCK:
        if _PERSIST_EXECUTOR is None:
            _PERSIST_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
                max_workers=2,
                thread_name_prefix="aila-domain-event-persist",
            )
    return _PERSIST_EXECUTOR


def _build_entry_payload(event: DomainEvent) -> dict[str, Any]:
    """Build the journal ``payload_json`` body for ``event``.

    Includes the versioned event metadata (event_id, event_type,
    version, timestamp, correlation_id, source_module, team_id) plus
    the typed Pydantic ``payload`` dumped in JSON mode. This is the full
    replay-grade record; the journal writer additionally computes a
    payload hash + row hash on top so the row is tamper-evident.
    """
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "version": event.version,
        "timestamp": event.timestamp.isoformat(),
        "correlation_id": event.correlation_id,
        "source_module": event.source_module,
        "team_id": event.team_id,
        "payload": _payload_dict(event),
    }


async def _append_domain_event(event: DomainEvent) -> None:
    """Open a short-lived session and append the event to the journal.

    Uses :func:`append_or_deadletter` so a chain-hash violation or an
    infra hiccup lands in the dead-letter table rather than propagating
    a failure back into the business action that emitted the event.
    """
    # Deferred imports avoid a cycle: events -> services.journal ->
    # storage -> services -> events would loop on module load.
    from aila.platform.services.journal import (
        JournalEntry,
        append_or_deadletter,
    )
    from aila.storage.database import async_session_scope

    entry = JournalEntry(
        kind="domain_event",
        source=event.source_module or "platform.events",
        action=event.event_type or event.__class__.__name__,
        actor_kind="system",
        actor_id="platform",
        status="ok",
        payload=_build_entry_payload(event),
        correlation_id=event.correlation_id or None,
        investigation_id=event.correlation_id or None,
    )
    async with async_session_scope() as session:
        await append_or_deadletter(
            session, entry=entry, team_id=event.team_id,
        )
        await session.commit()


def _run_persist_in_thread(event: DomainEvent) -> None:
    """Run :func:`_append_domain_event` in a background thread's own loop.

    Used when the caller is already inside a running asyncio loop:
    asyncio.run refuses to construct a nested loop, so we hand the
    coroutine to a dedicated worker thread that owns a private
    short-lived loop.
    """
    try:
        asyncio.run(_append_domain_event(event))
    except _PERSIST_ERRORS as exc:
        _log.warning(
            "domain_event persist thread failed for %s: %s",
            event.event_type or event.__class__.__name__,
            exc,
            exc_info=True,
        )


def persist_domain_event(event: DomainEvent) -> None:
    """DomainEventBus subscriber: append ``event`` to the platform journal.

    Publishes happen from both async request handlers and worker-thread
    emit paths. When called from inside a running event loop the append
    is offloaded to the persistence executor so we do not create a
    nested loop; when called from a sync context (no loop) we run the
    coroutine directly. Either way the caller returns immediately -- the
    subscriber is synchronous (per :class:`DomainEventBus` contract) but
    the DB write is a background best-effort so a slow journal never
    stalls the emitter.

    Skipped on Redis-consumer replay (#106): a peer process already
    journaled the event on the emit side, so writing a second row here
    would double the journal without gaining tamper-evidence -- the
    origin process's row is authoritative. See
    :func:`aila.platform.events.redis_bridge.is_inbound_replay`.
    """
    # Deferred import: redis_bridge -> bus, and bus imports this
    # module lazily. A top-level import here would risk a cycle.
    from .redis_bridge import is_inbound_replay

    if is_inbound_replay():
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop: safe to synchronously drive the coroutine.
        try:
            asyncio.run(_append_domain_event(event))
        except _PERSIST_ERRORS as exc:
            _log.warning(
                "domain_event persist failed for %s: %s",
                event.event_type or event.__class__.__name__,
                exc,
                exc_info=True,
            )
        return
    # Inside a running loop -- offload so we do not nest loops. The
    # future is deliberately fire-and-forget: the emitter contract
    # returns synchronously and the journal write must not add latency
    # to the caller's turn.
    executor = _get_persist_executor()
    del loop  # only needed to detect "loop is running"
    executor.submit(_run_persist_in_thread, event)

"""Cross-process bridge for :class:`DomainEventBus` (#106).

Today's :class:`aila.platform.events.bus.DomainEventBus` is a
process-local singleton: a :func:`publish` from an ARQ worker never
reaches an SSE subscriber running in the API process. This module
adds a Redis-stream transport so worker-emitted domain events land in
the API process's in-process bus without requiring every subscriber to
know about Redis.

Wire diagram (per event)::

    Worker process                          API process
    --------------                          -----------
    publish(event)                          consumer task (xread loop)
      -> journal_persist   (local)              |
      -> redis_bridge      -----XADD----->     xread
                                                v
                                           _INBOUND_REPLAY=True
                                           default_bus().publish(event)
                                             -> journal_persist  (SKIPPED on replay)
                                             -> redis_bridge     (SKIPPED on replay)
                                             -> any SSE / typed subscriber

Same-process publish stays in-process: the origin id embedded in every
XADD lets the consumer drop messages this process emitted itself, so a
subscriber running in the same process as the publisher only sees the
event once (via the direct in-process delivery).

Fail-open by contract. If Redis is unavailable at publish time -- pool
down, package missing, network hiccup -- the XADD is skipped with a
warning; local delivery is unaffected and no exception propagates to
the caller. If the consumer's XREAD fails, it backs off and retries.
Consumers see no exception; a Redis outage silently degrades to
today's in-process-only behaviour.

Serialisation is a small JSON blob keyed by ``event_type``; the
:data:`_EVENT_TYPE_REGISTRY` table maps the type string back to the
:class:`DomainEvent` subclass + Pydantic payload class so the receiver
reconstructs the same typed object the publisher emitted.

The consumer is API-process-only and is started/stopped by the
FastAPI lifespan hook in :mod:`aila.api.app`. The publisher is
subscribed to the shared bus the first time :func:`default_bus` runs
in either the API or a worker, so any process that touches the bus
also produces to the stream.
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import threading
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from ..contracts._common import utc_now
from .domain_events import (
    ConfigChanged,
    ConfigChangedPayload,
    DomainEvent,
    LlmCallCompleted,
    LlmCallCompletedPayload,
    ModuleWorkflowCompleted,
    ModuleWorkflowCompletedPayload,
    ModuleWorkflowStarted,
    ModuleWorkflowStartedPayload,
    SystemDeregistered,
    SystemDeregisteredPayload,
    SystemRegistered,
    SystemRegisteredPayload,
    WorkflowStageAnnounced,
    WorkflowStagePayload,
)

if TYPE_CHECKING:
    from .bus import DomainEventBus

__all__ = [
    "PROCESS_ORIGIN_ID",
    "REDIS_STREAM_KEY",
    "install_redis_publisher",
    "is_inbound_replay",
    "start_consumer",
    "stop_consumer",
]

_log = logging.getLogger(__name__)


# Redis stream key. Fixed name -- the transport is one shared stream
# for every DomainEvent type; the consumer discriminates by
# ``event_type`` after xread. A per-type stream would multiply xread
# calls without buying isolation (all types feed the same in-process
# bus on the receiver side).
REDIS_STREAM_KEY: str = "aila:domain_events"

# Per-process unique origin id, embedded in every published message so
# the consumer can drop messages this process emitted itself
# (loopback). A fresh uuid at import time is enough because a process
# only ever compares against its own value.
PROCESS_ORIGIN_ID: str = str(uuid.uuid4())


# ContextVar set to True by the consumer while it re-publishes an
# inbound event onto the local bus. The publisher subscriber checks
# this to avoid re-XADDing an event we just received; the persistence
# subscriber checks :func:`is_inbound_replay` to avoid a second journal
# row for an event the origin process already persisted.
_INBOUND_REPLAY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "aila_domain_event_inbound_replay", default=False,
)


def is_inbound_replay() -> bool:
    """Return True when the current publish is a Redis consumer replay.

    Non-Redis-aware subscribers (persistence, future SSE fanout) call
    this to decide whether they are looking at an event this process
    already handled locally when it was first emitted, versus an event
    that arrived from a peer process via the stream.
    """
    return _INBOUND_REPLAY.get()


# Map event_type strings to (EventClass, PayloadClass) used to
# reconstruct a typed :class:`DomainEvent` on the consumer side. The
# publisher does NOT consult this table -- serialisation reads the
# already-typed event -- so an event class missing from the registry
# publishes fine but its inbound copy is dropped with a debug log.
_EVENT_TYPE_REGISTRY: dict[str, tuple[type[DomainEvent], type[Any]]] = {
    "system.registered": (SystemRegistered, SystemRegisteredPayload),
    "system.deregistered": (SystemDeregistered, SystemDeregisteredPayload),
    "config.changed": (ConfigChanged, ConfigChangedPayload),
    "llm.call.completed": (LlmCallCompleted, LlmCallCompletedPayload),
    "module.workflow.started": (
        ModuleWorkflowStarted, ModuleWorkflowStartedPayload,
    ),
    "module.workflow.completed": (
        ModuleWorkflowCompleted, ModuleWorkflowCompletedPayload,
    ),
    "workflow.stage.announced": (
        WorkflowStageAnnounced, WorkflowStagePayload,
    ),
}


# --- Publisher (sync; runs in whatever thread called bus.publish) ----------

_PUBLISHER_LOCK = threading.Lock()
_PUBLISHER_INSTALLED_BUSES: set[int] = set()

# Sync Redis client cache, keyed by URL. Mirrors the
# :func:`aila.platform.events.emitter._get_sync_redis_client` pattern:
# redis-py's Redis client owns an internal, thread-safe connection
# pool, so one cached client per URL is reused across events.
_SYNC_CLIENT_LOCK = threading.Lock()
_SYNC_CLIENTS: dict[str, Any] = {}


def _get_sync_client() -> Any | None:
    """Return a process-cached sync Redis client, or None when unavailable.

    Returns None (silently) when ``AILA_PLATFORM_REDIS_URL`` is unset
    or when the ``redis`` package is missing -- either is a legitimate
    fail-open path today (see :func:`_publish_to_redis`).
    """
    url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not url:
        return None
    client = _SYNC_CLIENTS.get(url)
    if client is not None:
        return client
    with _SYNC_CLIENT_LOCK:
        client = _SYNC_CLIENTS.get(url)
        if client is not None:
            return client
        try:
            import redis  # local import: absence is fail-open
        except ImportError:
            _log.warning(
                "domain-event redis bridge: 'redis' package missing; "
                "cross-process delivery disabled (in-process only)",
            )
            return None
        try:
            client = redis.from_url(url, decode_responses=True)
        except (ValueError, OSError, RuntimeError) as exc:
            _log.warning(
                "domain-event redis bridge: sync client init failed "
                "(%s: %s); cross-process delivery disabled",
                exc.__class__.__name__, exc,
            )
            return None
        _SYNC_CLIENTS[url] = client
    return client


def _serialize_event(event: DomainEvent) -> dict[str, str]:
    """Serialise ``event`` to the flat string map that ``XADD`` requires.

    Redis streams store field-value pairs where both are strings; the
    full event body is a JSON blob under ``json`` plus two top-level
    breakouts (``event_type``, ``origin``) for the consumer's
    quick-reject path (unknown type / self-origin) without a JSON
    decode.
    """
    # Local import to break the bus <-> redis_bridge import cycle.
    from .bus import _payload_dict

    body = {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "version": event.version,
        "timestamp": event.timestamp.isoformat(),
        "correlation_id": event.correlation_id,
        "source_module": event.source_module,
        "team_id": event.team_id,
        "payload": _payload_dict(event),
    }
    return {
        "event_type": event.event_type or "",
        "origin": PROCESS_ORIGIN_ID,
        "json": json.dumps(body, default=str),
    }


def _publish_to_redis(event: DomainEvent) -> None:
    """DomainEventBus subscriber: XADD ``event`` to the shared stream.

    Fail-open: any error (Redis down, package missing, malformed
    payload) is logged at WARNING and swallowed so a Redis outage does
    not raise into the caller. When the current publish is a Redis
    consumer replay, the XADD is skipped so we do not re-broadcast an
    event this process just received.
    """
    if _INBOUND_REPLAY.get():
        return
    client = _get_sync_client()
    if client is None:
        # Fail-open: unavailable Redis is not an emit-time error.
        return
    try:
        fields = _serialize_event(event)
    except (TypeError, ValueError) as exc:
        _log.warning(
            "domain-event redis bridge: serialise failed for %s (%s: %s); "
            "event stays in-process only",
            event.event_type or event.__class__.__name__,
            exc.__class__.__name__, exc,
        )
        return
    try:
        import redis  # local: driver-specific error tree
    except ImportError:
        _log.debug(
            "domain-event redis bridge: redis package not installed; "
            "event stays in-process only",
        )
        return
    try:
        # ``maxlen`` bounds the stream so a stalled consumer cannot
        # grow Redis memory without limit; ``approximate=True`` lets
        # Redis trim on segment boundaries which is much cheaper than
        # exact trimming and is safe for a transport whose durability
        # story is owned by the journal, not this stream.
        client.xadd(
            REDIS_STREAM_KEY, fields, maxlen=10_000, approximate=True,
        )
    except (redis.exceptions.RedisError, OSError, TimeoutError) as exc:
        # Every driver-side failure (ConnectionError, TimeoutError,
        # ResponseError) is a RedisError subclass; OSError covers the
        # rare socket-level raise that escapes redis-py's wrapping.
        # Fail-open: the local subscribers already delivered above,
        # a peer SSE process just misses this one event.
        _log.warning(
            "domain-event redis bridge: XADD failed for %s (%s: %s); "
            "event stays in-process only",
            event.event_type or event.__class__.__name__,
            exc.__class__.__name__, exc,
        )


def install_redis_publisher(bus: DomainEventBus) -> None:
    """Subscribe :func:`_publish_to_redis` on ``bus`` (idempotent per bus).

    Called from :func:`aila.platform.events.bus.default_bus` at
    singleton construction so both the API process and every worker
    that touches the bus start publishing to Redis without an explicit
    bootstrap. Idempotent by ``id(bus)`` so a repeat call (e.g. a test
    that resets the singleton and rebuilds it) does not double-
    subscribe.
    """
    key = id(bus)
    if key in _PUBLISHER_INSTALLED_BUSES:
        return
    with _PUBLISHER_LOCK:
        if key in _PUBLISHER_INSTALLED_BUSES:
            return
        bus.subscribe("redis_bridge_publisher", _publish_to_redis)
        _PUBLISHER_INSTALLED_BUSES.add(key)


# --- Consumer (async; API-process only, started by lifespan) ---------------


def _deserialize_event(fields: dict[str, str]) -> DomainEvent | None:
    """Reconstruct a :class:`DomainEvent` from a stream message payload.

    Returns None when the ``json`` field is missing (message from a
    peer speaking a different protocol) or when ``event_type`` is not
    in :data:`_EVENT_TYPE_REGISTRY` (unknown type: newer publisher /
    older consumer). Either case is logged at DEBUG and skipped so the
    consumer loop stays alive.
    """
    body_json = fields.get("json")
    if not body_json:
        return None
    try:
        body = json.loads(body_json)
    except (ValueError, TypeError):
        _log.debug(
            "domain-event redis bridge: skipping malformed JSON payload",
        )
        return None
    if not isinstance(body, dict):
        return None
    event_type = body.get("event_type") or fields.get("event_type", "")
    entry = _EVENT_TYPE_REGISTRY.get(event_type)
    if entry is None:
        _log.debug(
            "domain-event redis bridge: unknown event_type %r; skipping",
            event_type,
        )
        return None
    event_cls, payload_cls = entry
    payload_dict = body.get("payload") or {}
    try:
        payload = payload_cls.model_validate(payload_dict)
    except (TypeError, ValueError) as exc:
        _log.warning(
            "domain-event redis bridge: payload validation failed for "
            "%s (%s: %s); skipping",
            event_type, exc.__class__.__name__, exc,
        )
        return None
    timestamp_raw = body.get("timestamp")
    timestamp = utc_now()
    if isinstance(timestamp_raw, str):
        try:
            timestamp = datetime.fromisoformat(timestamp_raw)
        except ValueError:
            pass
    try:
        return event_cls(
            event_id=str(body.get("event_id") or ""),
            version=int(body.get("version") or 1),
            timestamp=timestamp,
            team_id=body.get("team_id"),
            source_module=str(body.get("source_module") or ""),
            correlation_id=str(body.get("correlation_id") or ""),
            payload=payload,
        )
    except (TypeError, ValueError) as exc:
        _log.warning(
            "domain-event redis bridge: event construction failed for "
            "%s (%s: %s); skipping",
            event_type, exc.__class__.__name__, exc,
        )
        return None


async def _consume_loop(stop_event: asyncio.Event) -> None:
    """Read the shared stream and replay each event onto the local bus.

    Uses ``$`` as the starting id so only messages published AFTER the
    consumer starts are delivered; a restart deliberately drops the
    backlog because DomainEvent durability is owned by the journal,
    not this transport (the journal subscriber already persisted the
    event on the origin process).

    Cooperative stop: each ``xread`` blocks up to 1s so the loop can
    observe ``stop_event`` promptly on shutdown; ``asyncio.CancelledError``
    is also honoured for a hard cancel from the lifespan hook.
    """
    url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not url:
        _log.info(
            "domain-event redis bridge: consumer skipped "
            "(AILA_PLATFORM_REDIS_URL unset); worker-emitted DomainEvents "
            "will NOT reach this process's subscribers",
        )
        return

    try:
        import redis.asyncio as aioredis
        from redis.exceptions import RedisError as _RedisError
    except ImportError:
        _log.warning(
            "domain-event redis bridge: 'redis' package missing; "
            "consumer disabled",
        )
        return

    try:
        client = aioredis.from_url(url, decode_responses=True)
    except (ValueError, OSError, RuntimeError, _RedisError) as exc:
        _log.warning(
            "domain-event redis bridge: consumer init failed "
            "(%s: %s); worker-emitted DomainEvents will NOT reach "
            "this process's subscribers",
            exc.__class__.__name__, exc,
        )
        return

    # Deferred import to avoid: bus -> redis_bridge -> bus on module load.
    from .bus import default_bus

    bus = default_bus()
    last_id = "$"
    _log.info(
        "domain-event redis bridge: consumer started "
        "(stream=%s, origin=%s)",
        REDIS_STREAM_KEY, PROCESS_ORIGIN_ID,
    )
    try:
        while not stop_event.is_set():
            try:
                resp = await client.xread(
                    {REDIS_STREAM_KEY: last_id}, block=1000, count=100,
                )
            except asyncio.CancelledError:
                raise
            except (_RedisError, OSError, TimeoutError) as exc:
                _log.warning(
                    "domain-event redis bridge: XREAD failed "
                    "(%s: %s); backing off 5s",
                    exc.__class__.__name__, exc,
                )
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=5.0)
                    return
                except TimeoutError:
                    continue
            if not resp:
                continue
            for _stream_key, messages in resp:
                for message_id, fields in messages:
                    last_id = message_id
                    if fields.get("origin") == PROCESS_ORIGIN_ID:
                        # Self-origin: this process already delivered
                        # the event via the in-process bus at publish
                        # time. Skipping avoids double-delivery to
                        # every local subscriber.
                        continue
                    event = _deserialize_event(fields)
                    if event is None:
                        continue
                    token = _INBOUND_REPLAY.set(True)
                    try:
                        bus.publish(event)
                    finally:
                        _INBOUND_REPLAY.reset(token)
    finally:
        try:
            await client.aclose()
        except (_RedisError, OSError, RuntimeError):
            _log.debug(
                "domain-event redis bridge: client aclose failed",
                exc_info=True,
            )
        _log.info("domain-event redis bridge: consumer stopped")


_CONSUMER_TASK: asyncio.Task[None] | None = None
_CONSUMER_STOP: asyncio.Event | None = None


def start_consumer() -> None:
    """Start the API-side consumer task (idempotent).

    MUST be called from inside a running event loop (typically the
    FastAPI lifespan hook). No-op when a live consumer task is
    already running. When ``AILA_PLATFORM_REDIS_URL`` is unset the
    consumer starts, discovers the missing URL, logs, and exits --
    matches the fail-open publisher path.
    """
    global _CONSUMER_TASK, _CONSUMER_STOP
    if _CONSUMER_TASK is not None and not _CONSUMER_TASK.done():
        return
    _CONSUMER_STOP = asyncio.Event()
    _CONSUMER_TASK = asyncio.create_task(
        _consume_loop(_CONSUMER_STOP),
        name="domain-event-redis-bridge",
    )


async def stop_consumer() -> None:
    """Signal the consumer to stop and await its exit (idempotent).

    Called from the FastAPI lifespan shutdown branch. Silent when no
    consumer was started. Swallows :class:`asyncio.CancelledError` so
    a hard cancel does not raise into the shutdown path.
    """
    global _CONSUMER_TASK, _CONSUMER_STOP
    task = _CONSUMER_TASK
    stop = _CONSUMER_STOP
    if stop is not None:
        stop.set()
    if task is None:
        return
    if not task.done():
        # Give the cooperative stop a moment; then cancel as backstop.
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=3.0)
        except TimeoutError:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, RuntimeError, OSError):
                pass
        except asyncio.CancelledError:
            pass
        except (RuntimeError, OSError):
            # Consumer loop already swallows transport errors, but a
            # cascading teardown (event loop closing under us) can
            # surface RuntimeError from awaiting a dead loop. Best-
            # effort shutdown -- swallow and move on.
            pass
    _CONSUMER_TASK = None
    _CONSUMER_STOP = None

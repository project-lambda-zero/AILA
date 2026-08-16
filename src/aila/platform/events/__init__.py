"""Platform event bus and typed domain events.

RFC #134 -- one typed event system. Every call site publishes via the
single :func:`publish` surface (or the per-request
:class:`EventEmitter` adapter that wraps it) and the process-wide bus
fans the event out to the journal + Redis cross-process fanout
subscribers. The Redis bridge (#106) delivers worker-emitted events
into the API process's local bus so SSE fanout sees them.
"""

from __future__ import annotations

from .bus import (
    DomainEventBus,
    SubscriberFn,
    default_bus,
    publish,
    subscribe,
    unsubscribe,
)
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
from .emitter import EventEmitter, ThreadSafeEventEmitter, build_emitter
from .event import PlatformEvent
from .redis_bridge import (
    PROCESS_ORIGIN_ID,
    REDIS_STREAM_KEY,
    install_redis_publisher,
    is_inbound_replay,
    start_consumer,
    stop_consumer,
)

__all__ = [
    "ConfigChanged",
    "ConfigChangedPayload",
    "DomainEvent",
    "DomainEventBus",
    "EventEmitter",
    "LlmCallCompleted",
    "LlmCallCompletedPayload",
    "ModuleWorkflowCompleted",
    "ModuleWorkflowCompletedPayload",
    "ModuleWorkflowStarted",
    "ModuleWorkflowStartedPayload",
    "PROCESS_ORIGIN_ID",
    "PlatformEvent",
    "REDIS_STREAM_KEY",
    "SubscriberFn",
    "SystemDeregistered",
    "SystemDeregisteredPayload",
    "SystemRegistered",
    "SystemRegisteredPayload",
    "ThreadSafeEventEmitter",
    "WorkflowStageAnnounced",
    "WorkflowStagePayload",
    "build_emitter",
    "default_bus",
    "install_redis_publisher",
    "is_inbound_replay",
    "publish",
    "start_consumer",
    "stop_consumer",
    "subscribe",
    "unsubscribe",
]

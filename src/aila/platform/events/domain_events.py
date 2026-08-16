"""Frozen dataclass domain events with versioned Pydantic payloads.

Platform-owned infrastructure event catalog. All events inherit
DomainEvent and carry typed Pydantic payloads. Events carry IDs not
full objects -- consumers query services for details.

The platform owns only generic, cross-module infrastructure events
(system lifecycle, config change, LLM call accounting, generic
module workflow lifecycle, per-run workflow-stage announcements).
Module-domain vocabulary (a scan, a finding, an investigation) is
NOT a platform concern -- a module that needs to publish a workflow
or entity event declares its own event in its own package. The
scan/finding events that once lived here were never emitted; they
were removed (RFC-05 concern c) and the
platform_owns_event_vocabulary honesty rule blocks re-adding
domain-named event classes here.

RFC #134 -- consolidation. The frozen ``PlatformEvent`` per-request
stage payload was folded into :class:`WorkflowStageAnnounced` so
every per-request stage announcement travels the same typed
:func:`aila.platform.events.publish` path as the process-wide domain
events. The obsolete ``AssessmentCreated`` / ``AssessmentCompleted``
and ``ModuleEntityBatchUpserted`` types had no publishers in the
codebase and were deleted as part of the same pass; wire them
back in on the module side when a real need arrives.

Frozen dataclasses prevent mutation after creation (T-165-01 mitigation).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import BaseModel, Field

from ..contracts import JsonObject
from ..contracts._common import utc_now
from ..llm.correlation import current_join_keys

__all__ = [
    "ConfigChanged",
    "ConfigChangedPayload",
    "DomainEvent",
    "LlmCallCompleted",
    "LlmCallCompletedPayload",
    "ModuleWorkflowCompleted",
    "ModuleWorkflowCompletedPayload",
    "ModuleWorkflowStarted",
    "ModuleWorkflowStartedPayload",
    "SystemDeregistered",
    "SystemDeregisteredPayload",
    "SystemRegistered",
    "SystemRegisteredPayload",
    "WorkflowStageAnnounced",
    "WorkflowStagePayload",
]

# --- Base ---


def _default_correlation_id() -> str:
    """Return the ambient investigation id (#39) as the domain-event correlation.

    Reads the correlation ContextVar populated by the agent turn loop
    (``aila.platform.llm.correlation.correlation_scope``). Events emitted
    inside a correlation scope inherit the investigation id automatically
    so the audit trail can be joined back to the investigation/branch/turn
    that produced them. Events emitted outside any correlation scope carry
    an empty string, preserving the previous ``correlation_id: str = ""``
    default so callers that pass their own id are not surprised.

    Callers may still override this by passing ``correlation_id=...`` at
    construction time; the explicit value wins because the default factory
    only runs when the field is unset.
    """
    investigation_id, _branch_id, _turn_number = current_join_keys()
    return investigation_id or ""


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Base domain event per D-03.  All events carry IDs, not full objects."""

    event_type: str = ""
    version: int = 1
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=utc_now)
    team_id: str | None = None
    source_module: str = ""
    correlation_id: str = field(default_factory=_default_correlation_id)


# --- Payloads (Pydantic) ---


class SystemRegisteredPayload(BaseModel):
    """Payload for system.registered events."""

    system_id: str
    hostname: str


class SystemDeregisteredPayload(BaseModel):
    """Payload for system.deregistered events."""

    system_id: str
    reason: str


class ConfigChangedPayload(BaseModel):
    """Payload for config.changed events."""

    namespace: str
    key: str
    old_value: str
    new_value: str


class LlmCallCompletedPayload(BaseModel):
    """Payload for llm.call.completed events."""

    model: str
    tokens: int
    cost: float
    duration: float


class ModuleWorkflowStartedPayload(BaseModel):
    """Payload for module.workflow.started events.

    ``module_id`` names the owning module (e.g. "vulnerability",
    "forensics"); ``workflow_id`` is the module-scoped workflow name
    (e.g. "scan", "investigation"). The payload identifies WHICH module
    started WHAT workflow -- the platform event class itself carries no
    module vocabulary.
    """

    module_id: str
    run_id: str
    workflow_id: str
    metadata: JsonObject = Field(default_factory=dict)


class ModuleWorkflowCompletedPayload(BaseModel):
    """Payload for module.workflow.completed events.

    ``metrics`` carries whatever counters the module considers salient
    for the completed run (finding_count, duration_s, artifact_count).
    """

    module_id: str
    run_id: str
    workflow_id: str
    metrics: JsonObject = Field(default_factory=dict)


class WorkflowStagePayload(BaseModel):
    """Payload for workflow.stage.announced events (RFC #134).

    Carries the per-request lifecycle-stage announcement that used to
    ride the ``PlatformEvent`` frozen dataclass through the parallel
    ``EventEmitter`` system. Every workflow phase transition, LLM
    pipeline audit checkpoint, config-security change, and platform
    tool exec is now a typed event on the single bus so subscribers
    (journal, cross-process Redis fanout, per-request audit_db /
    run_history / progress / redis_stream destinations) receive them
    through one path.

    Fields mirror the legacy PlatformEvent shape so the migration is
    a payload-swap at each call site; the ``details`` JsonObject holds
    the arbitrary structured context a stage wants to attach.
    """

    stage: str
    action: str
    key: str
    message: str
    details: JsonObject = Field(default_factory=dict)
    run_id: str = ""
    current: int | None = None
    total: int | None = None
    progress_message: str | None = None


# --- Events (frozen dataclasses inheriting DomainEvent) ---


@dataclass(frozen=True, slots=True)
class SystemRegistered(DomainEvent):
    """Emitted when a new managed system is registered."""

    event_type: str = "system.registered"
    payload: SystemRegisteredPayload = field(
        default_factory=lambda: SystemRegisteredPayload(system_id="", hostname=""),
    )


@dataclass(frozen=True, slots=True)
class SystemDeregistered(DomainEvent):
    """Emitted when a managed system is removed."""

    event_type: str = "system.deregistered"
    payload: SystemDeregisteredPayload = field(
        default_factory=lambda: SystemDeregisteredPayload(system_id="", reason=""),
    )


@dataclass(frozen=True, slots=True)
class ConfigChanged(DomainEvent):
    """Emitted when a configuration value is modified."""

    event_type: str = "config.changed"
    payload: ConfigChangedPayload = field(
        default_factory=lambda: ConfigChangedPayload(
            namespace="", key="", old_value="", new_value="",
        ),
    )


@dataclass(frozen=True, slots=True)
class LlmCallCompleted(DomainEvent):
    """Emitted when an LLM API call finishes."""

    event_type: str = "llm.call.completed"
    payload: LlmCallCompletedPayload = field(
        default_factory=lambda: LlmCallCompletedPayload(
            model="", tokens=0, cost=0.0, duration=0.0,
        ),
    )


@dataclass(frozen=True, slots=True)
class ModuleWorkflowStarted(DomainEvent):
    """Emitted when a module's workflow run starts.

    Generic across every module. The owning module identifies itself
    through ``payload.module_id`` and ``payload.workflow_id``; the
    platform class holds no module vocabulary (rule 46).
    """

    event_type: str = "module.workflow.started"
    payload: ModuleWorkflowStartedPayload = field(
        default_factory=lambda: ModuleWorkflowStartedPayload(
            module_id="", run_id="", workflow_id="",
        ),
    )


@dataclass(frozen=True, slots=True)
class ModuleWorkflowCompleted(DomainEvent):
    """Emitted when a module's workflow run reaches its terminal state."""

    event_type: str = "module.workflow.completed"
    payload: ModuleWorkflowCompletedPayload = field(
        default_factory=lambda: ModuleWorkflowCompletedPayload(
            module_id="", run_id="", workflow_id="",
        ),
    )


@dataclass(frozen=True, slots=True)
class WorkflowStageAnnounced(DomainEvent):
    """Emitted at every per-request workflow-stage transition (RFC #134).

    Carries the payload the legacy ``PlatformEvent`` used to hold. Fired
    from LLM pipeline steps (classify / gate / validate / verify / seal),
    the platform module's tool-execution surface, the orchestrator's
    routing and dispatch phases, the config-registry security-change
    write, and any other per-run-scoped lifecycle notification.

    Subscribers on the process-wide bus receive it through the same
    :func:`publish` path as every other domain event; the per-request
    :class:`aila.platform.events.emitter.EventEmitter` additionally
    dispatches to its four run-scoped destinations (audit_db /
    run_history / progress / redis_stream) when the payload's
    ``run_id`` matches the emitter's scope.
    """

    event_type: str = "workflow.stage.announced"
    payload: WorkflowStagePayload = field(
        default_factory=lambda: WorkflowStagePayload(
            stage="", action="", key="", message="",
        ),
    )

"""Frozen dataclass domain events with versioned Pydantic payloads.

Platform-owned infrastructure event catalog. All events inherit
DomainEvent and carry typed Pydantic payloads. Events carry IDs not
full objects -- consumers query services for details.

The platform owns only generic, cross-module infrastructure events
(system lifecycle, config change, assessment lifecycle, LLM call
accounting). Module-domain vocabulary (a scan, a finding, an
investigation) is NOT a platform concern -- a module that needs to
publish a workflow or entity event declares its own event in its own
package. The scan/finding events that once lived here were never
emitted; they were removed (RFC-05 concern c) and the
platform_owns_event_vocabulary honesty rule blocks re-adding
domain-named event classes here.

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
    "AssessmentCompleted",
    "AssessmentCompletedPayload",
    "AssessmentCreated",
    "AssessmentCreatedPayload",
    "ConfigChanged",
    "ConfigChangedPayload",
    "DomainEvent",
    "LlmCallCompleted",
    "LlmCallCompletedPayload",
    "ModuleEntityBatchUpserted",
    "ModuleEntityBatchUpsertedPayload",
    "ModuleWorkflowCompleted",
    "ModuleWorkflowCompletedPayload",
    "ModuleWorkflowStarted",
    "ModuleWorkflowStartedPayload",
    "SystemDeregistered",
    "SystemDeregisteredPayload",
    "SystemRegistered",
    "SystemRegisteredPayload",
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


class AssessmentCreatedPayload(BaseModel):
    """Payload for assessment.created events."""

    session_id: str
    framework: str


class AssessmentCompletedPayload(BaseModel):
    """Payload for assessment.completed events."""

    session_id: str
    score: float


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


class ModuleEntityBatchUpsertedPayload(BaseModel):
    """Payload for module.entity.batch_upserted events.

    Generic bulk-upsert notification. ``entity_type`` is a
    module-scoped table/entity name; ``items`` carries the upserted
    rows as plain JSON objects so subscribers do not need module
    imports.
    """

    module_id: str
    entity_type: str
    items: list[JsonObject] = Field(default_factory=list)


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
class AssessmentCreated(DomainEvent):
    """Emitted when a new security assessment session begins."""

    event_type: str = "assessment.created"
    payload: AssessmentCreatedPayload = field(
        default_factory=lambda: AssessmentCreatedPayload(
            session_id="", framework="",
        ),
    )


@dataclass(frozen=True, slots=True)
class AssessmentCompleted(DomainEvent):
    """Emitted when a security assessment session finishes."""

    event_type: str = "assessment.completed"
    payload: AssessmentCompletedPayload = field(
        default_factory=lambda: AssessmentCompletedPayload(session_id="", score=0.0),
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
class ModuleEntityBatchUpserted(DomainEvent):
    """Emitted when a module upserts a batch of domain entities."""

    event_type: str = "module.entity.batch_upserted"
    payload: ModuleEntityBatchUpsertedPayload = field(
        default_factory=lambda: ModuleEntityBatchUpsertedPayload(
            module_id="", entity_type="",
        ),
    )

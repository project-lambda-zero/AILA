"""Frozen dataclass domain events with versioned Pydantic payloads.

10-event catalog per D-03.  All events inherit DomainEvent and carry
typed Pydantic payloads.  Events carry IDs not full objects -- consumers
query services for details.

Frozen dataclasses prevent mutation after creation (T-165-01 mitigation).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import BaseModel

from ..contracts._common import utc_now

# --- Base ---


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Base domain event per D-03.  All events carry IDs, not full objects."""

    event_type: str = ""
    version: int = 1
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=utc_now)
    team_id: str | None = None
    source_module: str = ""
    correlation_id: str = ""


# --- Payloads (Pydantic) ---


class ScanStartedPayload(BaseModel):
    """Payload for scan.started events."""

    system_ids: list[str]
    run_id: str


class ScanCompletedPayload(BaseModel):
    """Payload for scan.completed events."""

    run_id: str
    finding_count: int
    duration: float


class FindingUpsertedItem(BaseModel):
    """Single finding within a batch upsert."""

    host: str
    cve_id: str
    severity: str
    score: float


class FindingUpsertedPayload(BaseModel):
    """Batch payload per D-03 -- list of individual findings."""

    items: list[FindingUpsertedItem]


class FindingResolvedPayload(BaseModel):
    """Payload for finding.resolved events."""

    host: str
    cve_id: str
    resolution: str


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


# --- Events (frozen dataclasses inheriting DomainEvent) ---


@dataclass(frozen=True, slots=True)
class ScanStarted(DomainEvent):
    """Emitted when a vulnerability scan begins."""

    event_type: str = "scan.started"
    payload: ScanStartedPayload = field(
        default_factory=lambda: ScanStartedPayload(system_ids=[], run_id=""),
    )


@dataclass(frozen=True, slots=True)
class ScanCompleted(DomainEvent):
    """Emitted when a vulnerability scan finishes."""

    event_type: str = "scan.completed"
    payload: ScanCompletedPayload = field(
        default_factory=lambda: ScanCompletedPayload(
            run_id="", finding_count=0, duration=0.0,
        ),
    )


@dataclass(frozen=True, slots=True)
class FindingUpserted(DomainEvent):
    """Emitted when findings are created or updated (batched)."""

    event_type: str = "finding.upserted"
    payload: FindingUpsertedPayload = field(
        default_factory=lambda: FindingUpsertedPayload(items=[]),
    )


@dataclass(frozen=True, slots=True)
class FindingResolved(DomainEvent):
    """Emitted when a finding is marked as resolved."""

    event_type: str = "finding.resolved"
    payload: FindingResolvedPayload = field(
        default_factory=lambda: FindingResolvedPayload(
            host="", cve_id="", resolution="",
        ),
    )


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

"""Typed SSE event envelopes for the VR module (08_FRONTEND_UX.md §2.1).

Every event emitted by ``/vr/projects/{id}/events`` or
``/vr/investigations/{id}/messages/stream`` is wrapped in a
``VREvent`` envelope so consumers can branch on ``event.type``
without parsing the inner payload.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "VREventEnvelope",
    "VREventType",
]


class VREventType(StrEnum):
    """Vocabulary of typed events the backend emits."""

    # Investigation timeline events
    MESSAGE_CREATED = "message.created"
    TURN_STARTED = "turn.started"
    TURN_COMPLETED = "turn.completed"
    BRANCH_CREATED = "branch.created"
    BRANCH_STATE_CHANGED = "branch.state_changed"
    OUTCOME_CREATED = "outcome.created"

    # Hypothesis lifecycle (derived from branch operations + persona
    # spawn outcomes — same wire shape as branch.state_changed but
    # named for the consumer that cares about hypothesis tracking).
    HYPOTHESIS_STATE_CHANGED = "hypothesis.state_changed"

    # Fuzz campaign events
    CAMPAIGN_CRASH_FOUND = "campaign.crash_found"
    CAMPAIGN_PROGRESS = "campaign.progress"

    # Obligation / disclosure events
    OBLIGATION_CHANGED = "obligation.changed"
    DISCLOSURE_STATE_CHANGED = "disclosure.state_changed"

    # Operator-driven events
    OPERATOR_STEERING = "operator.steering"

    # Connection liveness
    HEARTBEAT = "heartbeat"
    DONE = "done"


class VREventEnvelope(BaseModel):
    """Typed envelope wrapping every SSE event payload.

    Wire format on the SSE channel is
    ``event: <type>\\ndata: <envelope_json>\\n\\n`` — both the SSE
    ``event:`` field and the inner ``type`` are set so callers can
    discriminate without parsing JSON.
    """

    model_config = ConfigDict(extra="forbid")

    type: VREventType
    ts: str
    project_id: str | None = None
    investigation_id: str | None = None
    campaign_id: str | None = None
    branch_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

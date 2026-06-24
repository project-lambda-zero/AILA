"""Investigation message contracts (M3.R-1).

Per D-43, investigations are conversational — operator and engine
exchange typed messages. Each message has a payload_kind matching one
of the 10 D-44 typed payloads (text, tool_call, code_pointer,
graph_view, taint_flow, xref_view, patch_diff, decompiled_function,
hypothesis_update, outcome_pending).

This module defines the shape of the message record. The 10 payload
shapes themselves are NOT defined here as separate Pydantic models —
they live as ``payload: dict[str, Any]`` for v0.3 v1 and get typed
shapes when consumers actually need validation. Per the M3.T lesson:
don't pre-define schemas that aren't yet exercised.

Operator-typed messages get an intent classification (D-43 GA-30) by a
cheap LLM call so the engine knows how to react. Operator can override
the classification through the UI.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# PayloadKind hoisted to platform so the platform-level MCP adapters
# can reference it without violating the platform-cannot-import-from-modules
# direction rule. Re-exported here so existing ``from aila.modules.vr.contracts
# the symbol is re-exported here so existing call sites keep working.
from aila.platform.contracts.mcp_payload import PayloadKind

__all__ = [
    "OperatorIntent",
    "PayloadKind",
    "SenderKind",
    "VRMessageCreate",
    "VRMessageSummary",
]


class SenderKind(StrEnum):
    """Who sent this message.

    fix §250 — added ``SYSTEM`` so system-authored steering messages
    (outcome_review draft requests, future system notices) can be
    distinguished from human-typed OPERATOR messages by sender_kind
    alone. UI filters and prompt-builder broadcast queries that need
    to surface both should match on ``{OPERATOR, SYSTEM}``.
    """

    ENGINE = "engine"
    OPERATOR = "operator"
    SYSTEM = "system"


class OperatorIntent(StrEnum):
    """How the engine should interpret an operator message (D-43 GA-30).

    Auto-classified by a cheap Haiku call at insertion time. Operator
    can override via the UI ('interpret as ___').
    """

    STEERING = "steering"
    QUESTION = "question"
    CORRECTION = "correction"
    DISMISSAL = "dismissal"
    OUTCOME_SELECTION = "outcome_selection"
    BRANCH_COMMAND = "branch_command"
    UNCLASSIFIED = "unclassified"


class VRMessageCreate(BaseModel):
    """Input payload for an operator-sent message.

    Engine messages are NOT created via this API — they emit from the
    reasoning loop directly. This shape is operator-only.
    """

    model_config = ConfigDict(extra="forbid")

    branch_id: str | None = Field(
        default=None,
        description="Branch context for the message. When None, applies to the investigation's primary branch.",
    )
    text: str = Field(min_length=1, description="Free-form operator input. Engine classifies intent.")
    explicit_intent: OperatorIntent | None = Field(
        default=None,
        description="When set, skip auto-classification and use this intent directly.",
    )


class VRMessageSummary(BaseModel):
    """Read-only projection of one message.

    The ``payload`` dict shape depends on ``payload_kind`` and is
    rendered by the frontend per-kind. Evidence refs are AgentStepRecord
    IDs supporting the message's claims.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    branch_id: str
    sender_kind: SenderKind
    sender_id: str | None = None
    payload_kind: PayloadKind
    payload: dict[str, Any] = Field(default_factory=dict)
    operator_intent: OperatorIntent | None = None
    at_turn: int | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: datetime | None = None

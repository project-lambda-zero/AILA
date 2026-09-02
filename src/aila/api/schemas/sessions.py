"""Pydantic schemas for conversation session endpoints (Phase 55, TASK-02/03/05/06)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aila.api.schemas.common import APIModel, PaginatedResponse

__all__ = [
    "DanteActionModel",
    "SessionCreateRequest",
    "SessionMessageRequest",
    "SessionResponse",
    "SessionMessageResponse",
    "SessionMessagesResponse",
    "SessionSummary",
    "SessionListResponse",
]


class SessionCreateRequest(APIModel):
    """Request body for POST /sessions (D-10, TASK-02)."""

    title: str = Field(default="Untitled", description="Human-readable session title")


class SessionMessageRequest(APIModel):
    """Request body for POST /sessions/{id}/messages (D-11, TASK-03)."""

    content: str = Field(..., min_length=1, description="Message text from the user")


class SessionResponse(APIModel):
    """Response for a single session (TASK-02)."""

    session_id: str
    user_id: str
    title: str
    created_at: datetime


class DanteActionModel(BaseModel):
    """One proposed DanteAction on a dante assistant turn (req 25).

    Frozen per-kind contract: ``kind`` + ``label`` + ``summary`` are
    always present; each kind carries its own subset of the remaining
    optional params (``module_id`` / ``target_id`` for ``open_wizard``,
    ``query`` / ``system_ids`` for ``enqueue_scan``, ``key`` for
    ``create_tag`` / ``delete_tag``, ``investigation_id`` / ``steering_text``
    for ``steer_investigation``). Extras are ignored rather than
    rejected so downstream additions to the contract cannot break the
    response serializer.
    """

    model_config = ConfigDict(extra="ignore")

    kind: str
    label: str
    summary: str = ""
    module_id: str | None = None
    target_id: str | None = None
    investigation_id: str | None = None
    steering_text: str | None = None
    query: str | None = None
    system_ids: list[str] | None = None
    key: str | None = None


class SessionMessageResponse(APIModel):
    """Response after adding a message to a session (TASK-03).

    run_id is populated when the assistant response triggered a background scan (TASK-06).
    actions carries proposed DanteAction rows on dante assistant turns (req 25); empty
    on user turns and on assistant turns that did not propose an action.
    """

    message_id: str
    role: Literal["user", "assistant"]
    content: str
    run_id: str | None = None
    created_at: datetime
    actions: list[DanteActionModel] = Field(default_factory=list)


SessionMessagesResponse = PaginatedResponse[SessionMessageResponse]


class SessionSummary(APIModel):
    """Lightweight session summary for /sessions list endpoint (Phase 176c).

    Includes a last-message preview so the chat sidebar can render title +
    timestamp + snippet without a second round-trip per session.
    """

    session_id: str
    user_id: str
    title: str
    created_at: datetime
    last_message_at: datetime | None = None
    last_message_preview: str | None = None
    message_count: int = 0


class SessionListResponse(APIModel):
    """Response for GET /sessions -- paginated session summaries for the caller."""

    total: int
    items: list[SessionSummary]

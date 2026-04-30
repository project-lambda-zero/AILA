"""Pydantic schemas for conversation session endpoints (Phase 55, TASK-02/03/05/06)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from aila.api.schemas.common import APIModel, PaginatedResponse

__all__ = [
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


class SessionMessageResponse(APIModel):
    """Response after adding a message to a session (TASK-03).

    run_id is populated when the assistant response triggered a background scan (TASK-06).
    """

    message_id: str
    role: Literal["user", "assistant"]
    content: str
    run_id: str | None = None
    created_at: datetime


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

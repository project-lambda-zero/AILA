"""Task API response schemas.

Pydantic models for the task queue REST API surface:
- TaskResponse: Single task status with all lifecycle fields
- TaskListResponse: Scoped list of tasks with total count
- TaskEventData: SSE event payload for progress streaming (TASK-08/09)

Ownership: Platform API layer — not module-specific.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .common import APIModel

__all__ = [
    "DrainQueueResponse",
    "ScanSubmissionRequest",
    "ScanStatusResponse",
    "TaskActionResponse",
    "TaskCreateRequest",
    "TaskListResponse",
    "TaskResponse",
    "TaskSubmitResponse",
]


class TaskResponse(APIModel):
    """Single task status response.

    Mirrors the TaskRecord fields surfaced via the API. All optional fields
    (started_at, completed_at, heartbeat_at, error, result_path) are None
    until the relevant lifecycle transition occurs.

    has_checkpoint indicates whether a workflow cursor snapshot exists
    for this run (Phase 179: sourced from ``workflow_state_cursor``;
    Phase 180 wires the lookup).

    result_path is a filesystem path (INFRA-06: no blob storage in DB).
    """

    task_id: str = Field(description="TaskRecord UUID")
    track: str = Field(description="Task track (ARQ queue name)")
    status: Literal[
        "queued", "waiting", "running", "paused", "done", "failed", "cancelled", "dead_letter"
    ] = Field(description="Task lifecycle status")
    user_id: str = Field(description="User ID from ApiKeyRecord.id (D-21)")
    group_id: str | None = Field(
        default=None,
        description="Group ID from ApiKeyRecord.role (D-21). Tolerant of NULL for legacy rows and system-submitted tasks.",
    )
    fn_path: str = Field(description="Fully-qualified function path")
    fn_module: str = Field(description="Module ID that owns the task function")
    created_at: datetime = Field(description="When task was submitted")
    started_at: datetime | None = Field(default=None, description="When worker picked up the task")
    completed_at: datetime | None = Field(default=None, description="When task reached terminal state")
    heartbeat_at: datetime | None = Field(default=None, description="Last worker heartbeat timestamp")
    error: str | None = Field(default=None, description="Error message if status=failed")
    result_path: str | None = Field(
        default=None,
        description="Filesystem path to task output file (INFRA-06: file-path not blob)",
    )
    has_checkpoint: bool = Field(
        description="True if a checkpoint snapshot is stored (MOD-12: resume from checkpoint)"
    )


class TaskListResponse(APIModel):
    """Scoped list of tasks for the authenticated user.

    tasks contains all records visible to the requesting user's group_id
    (D-22/MOD-13: admin sees all, others see their group only).
    """

    tasks: list[TaskResponse]
    total: int = Field(description="Total number of matching tasks")


class TaskCreateRequest(APIModel):
    """Request body for POST /task freeform query (D-09, TASK-01)."""

    query_text: str = Field(..., min_length=1, description="Freeform query text for AILAPlatform.handle()")


class TaskSubmitResponse(APIModel):
    """Response for POST /task and POST /analyze (ASYNC-01, TASK-01)."""

    run_id: str
    status: Literal["submitted"] = "submitted"


class TaskActionResponse(APIModel):
    """Response for task lifecycle actions (cancel, resume).

    Returns the task_id and the resulting status after the action.
    """

    task_id: str = Field(description="TaskRecord UUID")
    status: str = Field(description="Resulting task status after action")


class DrainQueueResponse(APIModel):
    """Response for POST /tasks/drain (OPS-05).

    Returns the number of pending tasks and whether draining is active.
    """

    pending: int = Field(description="Number of tasks still pending in the queue")
    draining: bool = Field(description="Whether the queue is now in draining mode")


class ScanStatusResponse(APIModel):
    """Response for GET /scans/{run_id} scan status polling (API-02, ASYNC-02).

    Returns the current lifecycle state of a submitted scan.
    """

    run_id: str = Field(description="Workflow run identifier")
    status: str = Field(description="Task lifecycle status")
    track: str = Field(description="Task track (queue name)")
    started_at: str | None = Field(default=None, description="ISO-8601 timestamp when scan started")
    completed_at: str | None = Field(default=None, description="ISO-8601 timestamp when scan completed")
    result_path: str | None = Field(default=None, description="Filesystem path to scan output file")


class ScanSubmissionRequest(APIModel):
    """Request body for POST /analyze (D-01, API-01)."""

    query_text: str = Field(..., min_length=1, description="Vulnerability scan query, e.g. 'scan web01 for vulnerabilities'")
    targets: list[str] = Field(default_factory=list, description="Optional list of target host names")

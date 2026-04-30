"""Findings API response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, model_validator

from .common import APIModel, PaginatedResponse

__all__ = [
    "BULK_ALLOWED_STATUSES",
    "BULK_ALLOWED_WORKFLOW_STATES",
    "BulkStatusUpdateRequest",
    "BulkUpdateResponse",
    "FacetsResponse",
    "FindingDetailResponse",
    "FindingFeedbackRequest",
    "FindingFeedbackResponse",
    "FindingResponse",
    "FindingsListResponse",
]


class FindingDetailResponse(APIModel):
    """Full detail for a single vulnerability finding, including parsed scoring context.

    The ``details`` field contains the deserialized ``PrioritizedFinding`` blob
    (facts, inference, recommended_action, uncertainty, etc.) for the detail panel.
    """

    id: int
    cve_id: str
    package: str
    host: str
    severity: str
    score: float
    status: str
    workflow_state: str
    fixed_version: str | None = None
    nvd_url: str
    rationale: str
    is_kev: bool
    compliance_tags: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    last_scanned_at: datetime | None = None
    created_at: datetime | None = None


class FindingResponse(APIModel):
    """A single vulnerability finding from a workflow run.

    Fields mirror the LatestFindingRecord / ReportArtifactRecord shape surfaced
    by the vulnerability module. All fields are optional because the exact set
    depends on the owning module.
    """

    id: int | None = Field(default=None, description="DB row ID")
    run_id: str = Field(description="Workflow run that produced this finding")
    cve_id: str | None = Field(default=None, description="CVE identifier (e.g. CVE-2023-12345)")
    package: str | None = Field(default=None, description="Affected package name")
    version: str | None = Field(default=None, description="Affected package version")
    host: str | None = Field(default=None, description="System hostname where found")
    severity: str | None = Field(default=None, description="Severity level (CRITICAL, HIGH, MEDIUM, LOW)")
    kev: bool = Field(default=False, description="True if in CISA KEV catalog")
    is_kev: bool = Field(default=False, description="True if in CISA KEV catalog (materialized column)")
    score: float | None = Field(default=None, description="Platform risk score (0.0-1.0)")
    status: str | None = Field(default=None, description="Remediation status")
    workflow_state: str = Field(default="new", description="Triage workflow state")
    created_at: datetime | None = Field(default=None, description="When this finding was first recorded")


FindingsListResponse = PaginatedResponse[FindingResponse]
FindingsListResponse.__doc__ = "Paginated list of vulnerability findings."


class FacetsResponse(APIModel):
    """Facet counts for findings filter badges.

    Returns an extensible dict of facet groups. Each group maps a facet value
    to its count within the filtered result set. Standard groups: severity,
    host, package, kev, workflow_state. Additional groups may be added by modules.

    Example:
        {"severity": {"CRITICAL": 5, "HIGH": 12}, "kev": {"true": 2}}
    """

    facets: dict[str, dict[str, int]] = Field(
        default_factory=dict,
        description="Facet group name -> value -> count mapping",
    )


BULK_ALLOWED_STATUSES: tuple[str, ...] = ("open", "remediated", "accepted", "deferred")
BULK_ALLOWED_WORKFLOW_STATES: tuple[str, ...] = (
    "new", "investigating", "mitigated", "verified", "closed"
)


class BulkStatusUpdateRequest(APIModel):
    """Request body for PATCH /findings/bulk (D-14, API-16).

    All finding_ids are updated atomically — all succeed or all fail (D-14).
    At least one of status or workflow_state must be provided.
    status must be one of BULK_ALLOWED_STATUSES.
    workflow_state must be one of BULK_ALLOWED_WORKFLOW_STATES.
    """

    finding_ids: list[int] = Field(..., min_length=1, description="IDs of LatestFindingRecord rows to update")
    status: str | None = Field(default=None, description="New status: open | remediated | accepted | deferred")
    workflow_state: str | None = Field(
        default=None,
        description="New workflow state: new | investigating | mitigated | verified | closed",
    )

    @model_validator(mode="after")
    def _validate_fields(self) -> "BulkStatusUpdateRequest":
        if self.status is None and self.workflow_state is None:
            raise ValueError("At least one of 'status' or 'workflow_state' must be provided")
        if self.status is not None and self.status not in BULK_ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {BULK_ALLOWED_STATUSES}")
        if self.workflow_state is not None and self.workflow_state not in BULK_ALLOWED_WORKFLOW_STATES:
            raise ValueError(f"workflow_state must be one of {BULK_ALLOWED_WORKFLOW_STATES}")
        return self


class BulkUpdateResponse(APIModel):
    """Response for PATCH /findings/bulk (API-16)."""

    status: str = "updated"
    count: int


FEEDBACK_ALLOWED_REASONS: tuple[str, ...] = ("incorrect", "doesnt_apply")


class FindingFeedbackRequest(APIModel):
    """Request body for POST /findings/{id}/feedback (FIND-11).

    reason must be one of FEEDBACK_ALLOWED_REASONS.
    notes is optional free-text context.
    """

    reason: str = Field(..., description="incorrect | doesnt_apply")
    notes: str = Field(default="", description="Optional free-text notes (max 500 chars)")

    @model_validator(mode="after")
    def _validate_reason(self) -> "FindingFeedbackRequest":
        if self.reason not in FEEDBACK_ALLOWED_REASONS:
            raise ValueError(f"reason must be one of {FEEDBACK_ALLOWED_REASONS}")
        if len(self.notes) > 500:
            raise ValueError("notes must be 500 characters or fewer")
        return self


class FindingFeedbackResponse(APIModel):
    """Response for POST /findings/{id}/feedback (FIND-11)."""

    id: int
    finding_id: int
    reason: str
    notes: str = Field(default="")
    created_at: datetime | None = Field(default=None)

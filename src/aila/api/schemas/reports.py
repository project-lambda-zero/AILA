"""Report API response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from .common import APIModel

__all__ = [
    "ExplainCachedResponse",
    "ExplainQueuedResponse",
    "FindingSummary",
    "ReportCountResponse",
    "ReportDetail",
    "ReportSummary",
    "ReportSummaryResponse",
]

# Severity labels (lower-case API contract, D-16 / D-17). Maps from
# LatestFindingRecord.criticality via _criticality_to_severity at the router
# boundary (CRITICAL -> critical, …, UNKNOWN -> info).
_SEVERITY_LITERAL = Literal["critical", "high", "medium", "low", "info"]


class ReportSummaryResponse(APIModel):
    """Summary metadata for a single workflow run report.

    Returned by GET /reports/{run_id}. Does NOT include the full findings
    list -- use GET /findings?run_id=<run_id> for that.
    """

    run_id: str = Field(description="Unique workflow run identifier")
    query_text: str = Field(description="Original query that triggered this run")
    module_id: str = Field(description="Feature module that handled this run")
    status: str = Field(description="Run status: running | completed | failed")
    target_count: int = Field(default=0, description="Number of systems scanned")
    total_findings: int = Field(default=0, description="Total findings across all targets")
    kev_count: int = Field(default=0, description="Findings in CISA KEV catalog")
    severity_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Finding counts by severity level",
    )
    created_at: datetime | None = Field(default=None, description="When this run started")
    completed_at: datetime | None = Field(default=None, description="When this run finished")


class ReportCountResponse(APIModel):
    """Module-delegated count breakdown for a report.

    Returned by GET /reports/{run_id}/count. The counts dict shape is
    module-specific: vulnerability returns severity breakdown + kev_count;
    future modules return their own shapes.
    """

    run_id: str = Field(description="Workflow run identifier")
    module_id: str = Field(description="Module that owns this run")
    counts: dict[str, Any] = Field(
        default_factory=dict,
        description="Module-specific count breakdown",
    )


class ExplainCachedResponse(APIModel):
    """Cached CVE explanation returned by GET /reports/{run_id}/explain (200).

    Returned when the explanation is already in ExplainCacheRecord.
    """

    run_id: str = Field(description="Workflow run identifier")
    content: str = Field(description="LLM-generated explanation text")
    cached: Literal[True] = Field(default=True, description="Always true for cached responses")


class ExplainQueuedResponse(APIModel):
    """Queued explanation response from GET /reports/{run_id}/explain (202).

    Returned when the explanation is not cached and a background explain
    task has been submitted to the task queue.
    """

    run_id: str = Field(description="Workflow run identifier")
    task_id: str = Field(description="Background task ID to poll for completion")
    status: Literal["queued"] = Field(default="queued", description="Always 'queued' for newly submitted tasks")


# ---------------------------------------------------------------------------
# Phase 176a: reports-list + reports-detail schemas (D-16 / D-17).
# ---------------------------------------------------------------------------


class FindingSummary(APIModel):
    """Per-finding shape returned inside ReportDetail.findings (D-17).

    severity is lower-case (API contract); LatestFindingRecord.criticality maps
    CRITICAL->critical, HIGH->high, MEDIUM->medium, LOW->low, UNKNOWN->info.
    """

    id: int = Field(description="Finding id (primary key of LatestFindingRecord)")
    cve_id: str | None = Field(default=None, description="CVE identifier, if any")
    title: str = Field(description="Short human-readable finding title")
    severity: _SEVERITY_LITERAL = Field(description="Lower-case severity label")
    host: str = Field(description="Target host the finding was observed on")
    package: str | None = Field(default=None, description="Affected package name")


class ReportSummary(APIModel):
    """Shape of a single row in GET /vulnerability/reports/list (D-16).

    The ``severity_counts`` dict always has exactly the five keys
    ``{critical, high, medium, low, info}``; missing severities are zero.
    ``finding_count`` equals the sum of severity_counts values.
    """

    id: str = Field(description="WorkflowRunRecord id (string UUID)")
    title: str = Field(description="Report title -- derived from workflow query_text")
    target: str = Field(description="Primary scanned target (host / fleet label)")
    created_at: datetime = Field(description="Run creation timestamp")
    status: str = Field(description="Run status: running | completed | failed")
    severity_counts: dict[_SEVERITY_LITERAL, int] = Field(
        description="Counts keyed by lower-case severity label",
    )
    finding_count: int = Field(
        ge=0,
        description="Total findings in this report (sum of severity_counts values)",
    )


class ReportDetail(ReportSummary):
    """Shape returned by GET /vulnerability/reports/detail/{id} (D-17).

    Extends ReportSummary with the full findings list, free-form metadata,
    and optional remediation notes.
    """

    findings: list[FindingSummary] = Field(
        default_factory=list,
        description="Per-finding summary list (may be empty for runs with no findings)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form run metadata (decoded route_json plus derived fields)",
    )
    remediation_notes: str | None = Field(
        default=None,
        description="Optional operator remediation notes for the report",
    )

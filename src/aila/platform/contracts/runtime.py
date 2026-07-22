from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from ._common import ActionId, JsonObject
from .platform import RouteDecision, WorkflowEvent

# ---------------------------------------------------------------------------
# Per-action payload models
# ---------------------------------------------------------------------------


class VulnSummaryPayload(BaseModel):
    """module_payload when action produces a report summary."""

    query_mode: Literal["report_summary"]
    report: JsonObject | None = None


class VulnCountPayload(BaseModel):
    """module_payload when action counts CVEs in a report."""

    query_mode: Literal["report_count"]
    count: int
    count_type: str
    cve_count: int
    row_count: int
    rows_scanned: int
    scan_truncated: bool
    report: JsonObject = Field(default_factory=dict)


class VulnFindingsPayload(BaseModel):
    """module_payload when action returns filtered findings."""

    query_mode: Literal["report_findings"]
    scope_label: str = ""
    findings_count: int = 0
    rows_scanned: int = 0
    findings: list[JsonObject] = Field(default_factory=list)
    ranking: JsonObject | None = None
    # Additional fields present in real call sites
    filters: JsonObject = Field(default_factory=dict)
    requested: int | None = None
    returned: int = 0
    total_matches: int = 0
    items: list[JsonObject] = Field(default_factory=list)
    report: JsonObject = Field(default_factory=dict)


class VulnAnalysisPayload(BaseModel):
    """module_payload when action ran a live fleet analysis."""

    query_mode: Literal["report_analyze"] = "report_analyze"
    summary: JsonObject = Field(default_factory=dict)
    analysis: JsonObject = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    target_reports: list[JsonObject] = Field(default_factory=list)


class VulnNoReportPayload(BaseModel):
    """module_payload when no cached report is available."""

    query_mode: Literal["no_report"]
    report: None = None


class VulnExplainPayload(BaseModel):
    """module_payload when action explains CVEs from cached report rows."""

    query_mode: Literal["explain_cves"]
    requested: int | None = None
    returned: int = 0
    rows_scanned: int = 0
    scan_truncated: bool = False
    items: list[JsonObject] = Field(default_factory=list)
    report: JsonObject = Field(default_factory=dict)


class PlatformRegistryPayload(BaseModel):
    """module_payload for platform SSH integration actions."""

    query_mode: Literal["ssh_registry"] = "ssh_registry"
    registry: JsonObject = Field(default_factory=dict)


class PlatformCommandPayload(BaseModel):
    """module_payload for remote command execution results."""

    query_mode: Literal["remote_command"] = "remote_command"
    command: str = ""
    requested_targets: list[str] = Field(default_factory=list)
    run_all_targets: bool = False
    rationale: str = ""
    results: list[JsonObject] = Field(default_factory=list)
    command_results: list[JsonObject] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Discriminated union
# ---------------------------------------------------------------------------

class UnroutablePayload(BaseModel):
    """module_payload when the router could not confidently route the query."""

    query_mode: Literal["unroutable"] = "unroutable"
    supported_actions: list[str] = Field(default_factory=list)


# Real Pydantic v2 discriminated union keyed on ``query_mode``: the tag selects
# exactly one member instead of first-match guessing, so a dict can no longer
# silently satisfy the wrong model (#61). Free-form module payloads (forensics,
# hello_world, and _template dump arbitrary result dicts) carry no query_mode
# and fall through to the ``dict[str, Any]`` arm on PlatformResponse rather than
# being coerced into an unrelated member.
ModulePayload = Annotated[
    VulnSummaryPayload
    | VulnCountPayload
    | VulnFindingsPayload
    | VulnAnalysisPayload
    | VulnNoReportPayload
    | VulnExplainPayload
    | PlatformRegistryPayload
    | PlatformCommandPayload
    | UnroutablePayload,
    Field(discriminator="query_mode"),
]


# ---------------------------------------------------------------------------
# Core runtime models
# ---------------------------------------------------------------------------


class RunState(BaseModel):
    """Mutable per-request runtime state shared across platform components.

    Created at the start of each handle() call and passed through routing,
    module dispatch, and event emission. Not persisted directly -- its contents
    are serialized into WorkflowRunRecord at finalization.
    """

    run_id: str = Field(description="Unique identifier for this run.")
    query: str = Field(description="Original user query.")
    route: RouteDecision | None = Field(default=None, description="Routing decision for this run.")
    events: list[WorkflowEvent] = Field(
        default_factory=list,
        description="Ordered workflow events.",
    )
    artifacts: dict[str, str] = Field(
        default_factory=dict,
        description="Artifact IDs produced so far, keyed by artifact type.",
    )


class PlatformResponse(BaseModel):
    """The top-level response returned by AILAPlatform.handle() for every request.

    Carries the selected action, human-readable message, optional module-specific
    payload, and artifact IDs produced during the run. state_history is populated
    only in debug mode (debug=True) -- stripped at the orchestrator level before
    returning in production to avoid leaking internal execution traces.
    """

    run_id: str = Field(description="Unique identifier for this execution run.")
    action_id: ActionId = Field(
        description="Dot-separated module.action identifier that produced this response."
    )
    message: str = Field(description="Human-readable summary of the result.")
    route: RouteDecision | None = Field(
        default=None,
        description="Routing decision that selected the module and action.",
    )
    module_payload: ModulePayload | dict[str, Any] | None = Field(
        default=None,
        description=(
            "Action-specific payload. A dict carrying a known query_mode is "
            "validated as the matching discriminated member; a free-form module "
            "result dict passes through untyped. Shape depends on action_id."
        ),
    )
    artifacts: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Artifact IDs produced by this run, keyed by artifact type "
            "(e.g. 'report', 'summary')."
        ),
        examples=[{"report": "42", "summary": "43"}],
    )
    state_history: list[WorkflowEvent] = Field(
        default_factory=list,
        description=(
            "Ordered workflow events for this run. Empty in production responses. "
            "Populated only when the request includes debug=True."
        ),
    )


__all__ = [
    "ModulePayload",
    "PlatformCommandPayload",
    "PlatformRegistryPayload",
    "PlatformResponse",
    "RunState",
    "UnroutablePayload",
    "VulnAnalysisPayload",
    "VulnCountPayload",
    "VulnExplainPayload",
    "VulnFindingsPayload",
    "VulnNoReportPayload",
    "VulnSummaryPayload",
]

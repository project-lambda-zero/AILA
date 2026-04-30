from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ._common import JsonObject

_INTERNAL_PATH_DESCRIPTION = "Internal storage path. Use the corresponding artifact_id field for API access."


class TargetReportReference(BaseModel):
    """Reference to a per-target report artifact within a fleet-scope run.

    Embedded in LatestReportResult.target_reports to let callers retrieve
    individual target summaries without downloading the full fleet report.
    """

    system_id: int | None = None
    system_name: str
    host: str
    report_artifact_id: int | None = None
    summary_artifact_id: int | None = None
    rows_artifact_id: int | None = None
    summary: JsonObject = Field(default_factory=dict)


class LatestReportResult(BaseModel):
    """The result of a latest_report query returned by ReportRepository.

    Carries report metadata, optional content, and artifact IDs for both
    the primary report and per-target sub-reports. The rows_document field
    is an internal transport field excluded from to_payload() to prevent
    raw row data from leaking into public API responses.
    """

    message: str
    run_id: str
    module_id: str | None = None
    completed_at: str | None = None
    report_scope: str
    report_path: str = Field(description=_INTERNAL_PATH_DESCRIPTION)
    report_artifact_id: int | None = None
    summary_path: str | None = Field(default=None, description=_INTERNAL_PATH_DESCRIPTION)
    summary_artifact_id: int | None = None
    rows_artifact_id: int | None = None
    summary: JsonObject = Field(default_factory=dict)
    target: TargetReportReference | None = None
    target_reports: list[TargetReportReference] = Field(default_factory=list)
    artifact_storage: str | None = None
    report_content: str | None = None
    summary_document: JsonObject | None = None
    rows_document: list[JsonObject] | None = None

    def to_payload(self) -> JsonObject:
        """Serialize to a public API payload, stripping internal transport fields.

        Excludes rows_document because raw report rows belong in the
        latest_rows endpoint, not in the summary response.
        """
        return self.model_dump(
            exclude_none=True,
            exclude={"rows_document"},
            mode="json",
        )


class LatestReportRowsResult(BaseModel):
    """Paginated result of a latest_rows query from ReportRepository.

    Returned by the reports.query tool's latest_rows and latest_target_rows
    actions. Includes per-source attribution when multiple target reports
    contribute rows (sources list), enabling callers to trace findings back
    to their originating scan.
    """

    message: str
    run_id: str | None = None
    module_id: str | None = None
    completed_at: str | None = None
    report_scope: str
    report_path: str | None = Field(default=None, description=_INTERNAL_PATH_DESCRIPTION)
    report_artifact_id: int | None = None
    summary_path: str | None = Field(default=None, description=_INTERNAL_PATH_DESCRIPTION)
    summary_artifact_id: int | None = None
    rows_artifact_id: int | None = None
    summary: JsonObject = Field(default_factory=dict)
    target: TargetReportReference | None = None
    artifact_storage: str | None = None
    sources: list[ReportRowsSourceReference] = Field(default_factory=list)
    total_rows: int
    offset: int
    limit: int
    rows: list[JsonObject] = Field(default_factory=list)

    def to_payload(self) -> JsonObject:
        """Serialize to a public API payload using each source's own to_payload shape."""
        data = self.model_dump(exclude_none=True, mode="json")
        # sources serialized via their own to_payload for consistent shape
        if self.sources:
            data["sources"] = [s.to_payload() for s in self.sources]
        return data


class ReportRowsSourceReference(BaseModel):
    """Metadata for one source report that contributed rows to a merged rows result.

    When a latest_target_rows query aggregates rows from multiple per-target
    reports, each source is described here so callers know which scan each
    row came from.
    """

    run_id: str
    module_id: str | None = None
    completed_at: str | None = None
    report_scope: str
    report_path: str | None = Field(default=None, description=_INTERNAL_PATH_DESCRIPTION)
    report_artifact_id: int | None = None
    summary_path: str | None = Field(default=None, description=_INTERNAL_PATH_DESCRIPTION)
    summary_artifact_id: int | None = None
    rows_artifact_id: int | None = None
    target: TargetReportReference | None = None
    summary: JsonObject = Field(default_factory=dict)
    total_rows: int = 0

    def to_payload(self) -> JsonObject:
        """Serialize source reference metadata to a public API payload."""
        return self.model_dump(exclude_none=True, mode="json")


def normalize_report_summary_payload(payload: JsonObject | None) -> JsonObject:
    """Normalize a raw report summary dict into a canonical shape for storage and display.

    Strips empty notes, coerces scoring_counts to non-negative integers, and
    ensures the returned dict is always a plain dict regardless of the input
    type. Called before persisting summary data to prevent schema drift between
    run records.
    """
    if not isinstance(payload, dict):
        return {}
    normalized = dict(payload)
    raw_notes: Any = normalized.get("notes")
    notes = [str(note).strip() for note in (raw_notes or []) if str(note).strip()]
    scoring_counts = normalized.get("scoring_counts")
    if isinstance(scoring_counts, dict):
        normalized["scoring_counts"] = {
            "model": _coerce_count(scoring_counts.get("model")),
            "cache": _coerce_count(scoring_counts.get("cache")),
        }
    normalized["notes"] = notes
    return normalized


def _coerce_count(value: str | int | float | None) -> int:
    try:
        return max(int(value), 0)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0

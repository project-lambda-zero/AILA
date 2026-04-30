from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..contracts._common import JsonObject
from ._common import Tool


class ReportWriteSettings(Protocol):
    """Minimal settings interface required by ReportWriteTool.

    Implemented by ApplicationSettings and any settings object that needs to
    control where report files are written.
    """

    report_dir: Path


@dataclass(frozen=True, slots=True)
class TargetReportArtifactInput:
    system_name: str
    host: str
    report_content: str
    summary_payload: JsonObject
    summary: JsonObject
    system_id: int | None = None
    rows_payload: list[JsonObject] = field(default_factory=list)
    report_extension: str = "csv"


class ReportWriteTool(Tool):
    """Platform tool for writing the primary report, summary, rows, and per-target report files.

    Called by module workflow states to flush a completed analysis run to disk.
    Each run produces {run_id}.csv (or other extension), {run_id}.summary.json,
    and optionally {run_id}.rows.json plus per-target variants. File paths are
    returned in write_bundle() output so callers can store them as artifact IDs.
    """

    name = "write_report_artifacts"
    description = "Persist module-provided report artifacts and summary documents."
    inputs = {
        "run_id": {"type": "string", "description": "Workflow run identifier."},
        "report_content": {"type": "string", "description": "Rendered primary report content."},
        "summary_payload": {"type": "object", "description": "Summary payload for the primary report."},
        "rows_payload": {
            "type": "array",
            "description": "Optional structured row payload for web/API consumption.",
            "nullable": True,
        },
        "target_reports": {
            "type": "array",
            "description": "Optional module-defined target report artifacts.",
            "nullable": True,
        },
        "report_extension": {
            "type": "string",
            "description": "Primary report file extension.",
            "nullable": True,
        },
    }
    output_type = "string"

    def __init__(self, settings: ReportWriteSettings):
        self.settings = settings

    def forward(
        self,
        run_id: str,
        report_content: str,
        summary_payload: JsonObject,
        rows_payload: list[JsonObject] | None = None,
        target_reports: list[JsonObject] | None = None,
        report_extension: str = "csv",
    ) -> str:
        bundle = self.write_bundle(
            run_id=run_id,
            report_content=report_content,
            summary_payload=summary_payload,
            rows_payload=rows_payload,
            target_reports=target_reports,
            report_extension=report_extension,
        )
        return bundle["report_path"]

    def write_bundle(
        self,
        run_id: str,
        report_content: str,
        summary_payload: JsonObject,
        rows_payload: list[JsonObject] | None = None,
        target_reports: list[TargetReportArtifactInput | JsonObject] | None = None,
        report_extension: str = "csv",
    ) -> JsonObject:
        """Compute synthetic artifact reference keys for a run.

        No files are written to disk. Returns a dict with report_path,
        summary_path, optional rows_path, and target_reports list using
        synthetic path strings derived from run_id. These serve as stable
        reference keys stored in ReportArtifactRecord.path — the DB record
        is the sole source of truth (EXPORT-04).

        report_dir.mkdir() is kept so the directory is available for other
        platform uses (e.g., on-demand export endpoints that write files).
        """
        # report_content / summary_payload accepted for the tool-input contract;
        # the actual content is persisted via storage.report_store. This method
        # only synthesizes reference path strings (EXPORT-04).
        del report_content, summary_payload
        self.settings.report_dir.mkdir(parents=True, exist_ok=True)

        report_path = self.settings.report_dir / f"{run_id}.{report_extension}"
        summary_path = self.settings.report_dir / f"{run_id}.summary.json"
        rows_path = self.settings.report_dir / f"{run_id}.rows.json"

        persisted_targets: list[JsonObject] = []
        for target in [self._coerce_target_input(item) for item in (target_reports or [])]:
            safe_target = _sanitize_report_component(target.system_name or target.host or str(target.system_id))
            target_report_path = self.settings.report_dir / f"{run_id}.target.{safe_target}.{target.report_extension}"
            target_summary_path = self.settings.report_dir / f"{run_id}.target.{safe_target}.summary.json"
            target_rows_path = self.settings.report_dir / f"{run_id}.target.{safe_target}.rows.json"

            persisted_targets.append(
                {
                    "system_id": target.system_id,
                    "system_name": target.system_name,
                    "host": target.host,
                    "report_path": str(target_report_path),
                    "summary_path": str(target_summary_path),
                    "rows_path": str(target_rows_path) if target.rows_payload is not None else None,
                    "summary": dict(target.summary),
                }
            )

        return {
            "report_path": str(report_path),
            "summary_path": str(summary_path),
            "rows_path": str(rows_path) if rows_payload is not None else None,
            "target_reports": persisted_targets,
        }

    @staticmethod
    def _coerce_target_input(item: TargetReportArtifactInput | JsonObject) -> TargetReportArtifactInput:
        if isinstance(item, TargetReportArtifactInput):
            return item
        return TargetReportArtifactInput(**item)


def _sanitize_report_component(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return sanitized or "target"

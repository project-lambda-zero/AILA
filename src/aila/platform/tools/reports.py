from __future__ import annotations

from ...storage.database import async_session_scope
from ...storage.report_repository import ReportRepository
from ..config import PlatformSettings
from ._common import Tool, normalize_limit, normalize_offset, optional_text, require_text


class ReportsQueryTool(Tool):
    """Platform tool for querying persisted module report data.

    Returns raw, unfiltered report data — module-specific filtering (e.g.
    vulnerability severity filters) happens in the module's workflow layer
    via filter_report_rows(). This separation ensures the same stored report
    can be filtered differently by different queries without re-scanning.

    The latest_target_rows action calls ReportRepository.latest_materialized_findings(),
    which aggregates rows across all per-target reports for a module — this is
    the registered materialized query pattern (STD-08).

    Supports actions: latest_report, latest_rows, latest_target_rows, has_target_reports.
    """

    name = "reports_query"
    description = "Load persisted module reports and raw report rows without applying module-specific filters."
    inputs = {
        "action": {
            "type": "string",
            "description": "One of latest_report, latest_rows, latest_target_rows, or has_target_reports.",
        },
        "module_id": {
            "type": "string",
            "description": "Module identifier whose persisted reports should be queried.",
        },
        "target": {
            "type": "string",
            "description": "Optional target system name or host for target-scoped report queries.",
            "nullable": True,
        },
        "offset": {
            "type": "integer",
            "description": "Row offset for row queries.",
            "nullable": True,
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of rows to return for row queries.",
            "nullable": True,
        },
        "include_content": {
            "type": "boolean",
            "description": "Whether latest_report should include stored report content.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings, repository: ReportRepository | None = None):
        self.settings = settings
        self.repository = repository or ReportRepository()

    async def forward(
        self,
        action: str,
        module_id: str,
        target: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        include_content: bool = False,
    ) -> dict:
        normalized_action = require_text(action, tool_name="reports.query", field_name="action").lower()
        normalized_module_id = require_text(module_id, tool_name="reports.query", field_name="module_id")
        normalized_target = optional_text(target, tool_name="reports.query", field_name="target")
        normalized_include_content = normalize_optional_boolean(
            include_content,
            field_name="include_content",
        )
        async with async_session_scope(self.settings) as session:
            if normalized_action == "latest_report":
                if offset is not None or limit is not None:
                    raise ValueError("reports.query latest_report does not accept offset or limit.")
                return (await self.repository.latest_report(
                    session=session,
                    target=normalized_target,
                    include_content=normalized_include_content,
                    module_id=normalized_module_id,
                )).to_payload()
            if normalized_action == "latest_rows":
                if normalized_include_content:
                    raise ValueError("reports.query latest_rows does not accept include_content.")
                return (await self.repository.latest_report_rows(
                    session=session,
                    target=normalized_target,
                    offset=normalize_offset(offset),
                    limit=normalize_limit(limit, default=100, maximum=1000),
                    module_id=normalized_module_id,
                )).to_payload()
            if normalized_action == "latest_target_rows":
                if normalized_target is not None:
                    raise ValueError("reports.query latest_target_rows does not accept target.")
                if normalized_include_content:
                    raise ValueError("reports.query latest_target_rows does not accept include_content.")
                return (await self.repository.latest_materialized_findings(
                    session=session,
                    offset=normalize_offset(offset),
                    limit=normalize_limit(limit, default=100, maximum=1000),
                    module_id=normalized_module_id,
                )).to_payload()
            if normalized_action == "has_target_reports":
                if normalized_target is not None or offset is not None or limit is not None or normalized_include_content:
                    raise ValueError("reports.query has_target_reports does not accept target, offset, limit, or include_content.")
                return {
                    "module_id": normalized_module_id,
                    "available": await self.repository.has_target_reports(
                        session=session,
                        module_id=normalized_module_id,
                    ),
                }
        raise ValueError(f"Unsupported reports.query action '{action}'.")


def normalize_optional_boolean(value: str | bool | int | None, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    raise ValueError(f"reports.query {field_name} must be a boolean.")

"""Artifact query tool for reading normalized artifacts from the store."""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools import Tool

TOOL_ALIAS = "artifact_query"
CAPABILITY = "Query normalized forensic artifacts by project, family, and type."

__all__ = ["ArtifactQueryTool"]


class ArtifactQueryTool(Tool):
    """Query the normalized artifact store for a forensics project."""

    name = "artifact_query"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": "One of: list, get, search."},
        "project_id": {"type": "string", "description": "Forensics project identifier."},
        "artifact_family": {"type": "string", "description": "Filter by artifact family.", "nullable": True},
        "artifact_type": {"type": "string", "description": "Filter by artifact type.", "nullable": True},
        "artifact_id": {"type": "string", "description": "Artifact ID for 'get' action.", "nullable": True},
        "search_text": {"type": "string", "description": "Text to search within artifact data for 'search' action.", "nullable": True},
        "limit": {"type": "integer", "description": "Max results.", "nullable": True},
    }
    output_type = "object"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "list",
        project_id: str = "",
        artifact_family: str | None = None,
        artifact_type: str | None = None,
        artifact_id: str | None = None,
        search_text: str | None = None,
        limit: int | None = None,
    ) -> dict:
        """Query artifacts from the forensics store.

        Actions:
            list: Return paginated artifacts matching filters.
            get:  Return a single artifact by ``artifact_id``.
            search: Full-text search within ``data_json`` for ``search_text``.

        Returns:
            Dict with 'artifacts' list and 'total' count.
        """

        from sqlmodel import select

        from aila.modules.forensics.db_models import ArtifactRecord
        from aila.platform.uow import UnitOfWork

        effective_limit = min(limit or 100, 500)

        if action == "get":
            if not artifact_id:
                raise ValueError("artifact_id is required for 'get' action.")
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    select(ArtifactRecord).where(ArtifactRecord.id == artifact_id)
                )).first()
            if row is None or row.project_id != project_id:
                return {"total": 0, "artifacts": []}
            return {
                "total": 1,
                "artifacts": [_serialize_artifact(row)],
            }

        async with UnitOfWork() as uow:
            query = select(ArtifactRecord).where(ArtifactRecord.project_id == project_id)
            if artifact_family:
                query = query.where(ArtifactRecord.artifact_family == artifact_family)
            if artifact_type:
                query = query.where(ArtifactRecord.artifact_type == artifact_type)
            if action == "search" and search_text:
                query = query.where(ArtifactRecord.data_json.contains(search_text))  # type: ignore[union-attr]
            query = query.limit(effective_limit)
            rows = list(await uow.session.exec(query))

        return {
            "total": len(rows),
            "artifacts": [_serialize_artifact(r) for r in rows],
        }


def _serialize_artifact(r: object) -> dict:
    """Convert an ArtifactRecord to a JSON-safe dict."""
    import json
    return {
        "id": r.id,  # type: ignore[attr-defined]
        "artifact_family": r.artifact_family,  # type: ignore[attr-defined]
        "artifact_type": r.artifact_type,  # type: ignore[attr-defined]
        "source_tool": r.source_tool,  # type: ignore[attr-defined]
        "data": json.loads(r.data_json),  # type: ignore[attr-defined]
        "lead_score": r.lead_score,  # type: ignore[attr-defined]
    }


def create_tool(settings: Settings) -> ArtifactQueryTool:
    """Construct an ArtifactQueryTool with the given settings."""
    return ArtifactQueryTool(settings)

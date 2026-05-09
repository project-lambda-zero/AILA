from __future__ import annotations

import json

from sqlalchemy import desc
from sqlmodel import select

from ...storage.database import async_session_scope
from ...storage.db_models import ArtifactRecord
from ..config import PlatformSettings
from ..contracts._common import JsonObject
from ._common import Tool, normalize_limit, normalize_offset, optional_text, require_text


class ArtifactStoreTool(Tool):
    """Platform tool for writing, reading, and deleting module artifact records.

    Artifacts are binary or JSON payloads produced by module workflows and stored
    in the DB with run_id, module_id, type, scope, and optional target metadata.
    The artifact_id returned from a write is the stable reference used by
    PlatformResponse.artifacts and subsequent read/delete operations.

    Supports actions: write, read, delete.
    """

    name = "artifacts_store"
    description = "Persist and retrieve generic module artifacts in the database."
    inputs = {
        "action": {"type": "string", "description": "One of write, read, or delete."},
        "artifact_id": {
            "type": "integer",
            "description": "Artifact identifier for read or delete actions.",
            "nullable": True,
        },
        "module_id": {
            "type": "string",
            "description": "Owning module identifier for write, read, and delete actions.",
            "nullable": True,
        },
        "run_id": {
            "type": "string",
            "description": "Optional workflow run identifier associated with the artifact.",
            "nullable": True,
        },
        "artifact_type": {
            "type": "string",
            "description": "Artifact type label such as json, log, trace, diff, or evidence.",
            "nullable": True,
        },
        "label": {
            "type": "string",
            "description": "Optional human-readable artifact label.",
            "nullable": True,
        },
        "scope": {
            "type": "string",
            "description": "Optional artifact scope, such as module, fleet, target, or run.",
            "nullable": True,
        },
        "target_name": {
            "type": "string",
            "description": "Optional target system name for target-scoped artifacts.",
            "nullable": True,
        },
        "target_host": {
            "type": "string",
            "description": "Optional target host for target-scoped artifacts.",
            "nullable": True,
        },
        "content": {
            "type": "object",
            "description": "Artifact content as a string, object, or array.",
            "nullable": True,
        },
        "content_type": {
            "type": "string",
            "description": "Optional content type override.",
            "nullable": True,
        },
        "metadata": {
            "type": "object",
            "description": "Optional structured artifact metadata.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings):
        self.settings = settings

    async def forward(
        self,
        action: str,
        artifact_id: int | None = None,
        module_id: str | None = None,
        run_id: str | None = None,
        artifact_type: str | None = None,
        label: str | None = None,
        scope: str | None = None,
        target_name: str | None = None,
        target_host: str | None = None,
        content: object | None = None,
        content_type: str | None = None,
        metadata: JsonObject | None = None,
    ) -> JsonObject:
        normalized_action = require_text(action, tool_name="artifacts.store", field_name="action").lower()
        async with async_session_scope(self.settings) as session:
            if normalized_action == "write":
                if artifact_id is not None:
                    raise ValueError("artifacts.store write does not accept artifact_id.")
                normalized_module_id = require_text(module_id, tool_name="artifacts.store", field_name="module_id")
                normalized_artifact_type = require_text(artifact_type, tool_name="artifacts.store", field_name="artifact_type")
                if metadata is not None and not isinstance(metadata, dict):
                    raise ValueError("artifacts.store write requires metadata to be an object.")
                serialized_metadata = serialize_json_object(
                    metadata if metadata is not None else {},
                    field_name="metadata",
                )
                body, resolved_content_type = _serialize_artifact_content(content, content_type=content_type)
                record = ArtifactRecord(
                    run_id=optional_text(run_id, tool_name="artifacts.store", field_name="run_id"),
                    module_id=normalized_module_id,
                    scope=optional_text(scope, tool_name="artifacts.store", field_name="scope") or "module",
                    artifact_type=normalized_artifact_type,
                    label=optional_text(label, tool_name="artifacts.store", field_name="label") or "",
                    target_name=optional_text(target_name, tool_name="artifacts.store", field_name="target_name"),
                    target_host=optional_text(target_host, tool_name="artifacts.store", field_name="target_host"),
                    content_type=resolved_content_type,
                    body=body,
                    metadata_json=serialized_metadata,
                )
                session.add(record)
                await session.commit()
                await session.refresh(record)
                return _artifact_payload(record, include_content=False)
            if normalized_action == "read":
                if artifact_id is None:
                    raise ValueError("artifacts.store read requires artifact_id.")
                reject_present_arguments(
                    tool_name="artifacts.store",
                    action="read",
                    arguments={
                        "run_id": run_id,
                        "artifact_type": artifact_type,
                        "label": label,
                        "scope": scope,
                        "target_name": target_name,
                        "target_host": target_host,
                        "content": content,
                        "content_type": content_type,
                        "metadata": metadata,
                    },
                )
                normalized_module_id = require_module_id(module_id, action="read")
                record = await session.get(ArtifactRecord, artifact_id)
                if record is None:
                    raise ValueError(f"Artifact id {artifact_id} was not found.")
                if record.module_id != normalized_module_id:
                    raise ValueError(
                        f"Artifact id {artifact_id} belongs to module '{record.module_id}', not '{normalized_module_id}'."
                    )
                return _artifact_payload(record, include_content=True)
            if normalized_action == "delete":
                if artifact_id is None:
                    raise ValueError("artifacts.store delete requires artifact_id.")
                reject_present_arguments(
                    tool_name="artifacts.store",
                    action="delete",
                    arguments={
                        "run_id": run_id,
                        "artifact_type": artifact_type,
                        "label": label,
                        "scope": scope,
                        "target_name": target_name,
                        "target_host": target_host,
                        "content": content,
                        "content_type": content_type,
                        "metadata": metadata,
                    },
                )
                normalized_module_id = require_module_id(module_id, action="delete")
                record = await session.get(ArtifactRecord, artifact_id)
                if record is None:
                    return {"artifact_id": artifact_id, "deleted": False}
                if record.module_id != normalized_module_id:
                    raise ValueError(
                        f"Artifact id {artifact_id} belongs to module '{record.module_id}', not '{normalized_module_id}'."
                    )
                await session.delete(record)
                await session.commit()
                return {"artifact_id": artifact_id, "deleted": True}
        raise ValueError(f"Unsupported artifacts.store action '{action}'.")


class ArtifactSearchTool(Tool):
    """Platform tool for querying module artifact metadata with multiple filter dimensions.

    Returns a paginated list of artifact records matching the specified filters.
    module_id is always required so cross-module artifact access is not possible
    through this tool.
    """

    name = "artifacts_search"
    description = "Search generic module artifacts stored in the database."
    inputs = {
        "module_id": {
            "type": "string",
            "description": "Module identifier to restrict results.",
            "nullable": True,
        },
        "run_id": {
            "type": "string",
            "description": "Optional workflow run identifier to restrict results.",
            "nullable": True,
        },
        "artifact_type": {
            "type": "string",
            "description": "Optional artifact type filter.",
            "nullable": True,
        },
        "scope": {
            "type": "string",
            "description": "Optional scope filter.",
            "nullable": True,
        },
        "label": {
            "type": "string",
            "description": "Optional exact label filter.",
            "nullable": True,
        },
        "target_name": {
            "type": "string",
            "description": "Optional target name filter.",
            "nullable": True,
        },
        "target_host": {
            "type": "string",
            "description": "Optional target host filter.",
            "nullable": True,
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of results to return.",
            "nullable": True,
        },
        "offset": {
            "type": "integer",
            "description": "Result offset.",
            "nullable": True,
        },
        "include_content": {
            "type": "boolean",
            "description": "Whether artifact content should be included in results.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings):
        self.settings = settings

    async def forward(
        self,
        module_id: str | None = None,
        run_id: str | None = None,
        artifact_type: str | None = None,
        scope: str | None = None,
        label: str | None = None,
        target_name: str | None = None,
        target_host: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
        include_content: bool = False,
    ) -> JsonObject:
        normalized_module_id = require_module_id(module_id, action="search")
        normalized_limit = normalize_limit(limit, default=50, maximum=1000)
        normalized_offset = normalize_offset(offset)
        normalized_include_content = require_boolean(
            include_content,
            field_name="include_content",
        )
        async with async_session_scope(self.settings) as session:
            statement = select(ArtifactRecord).order_by(
                desc(ArtifactRecord.updated_at),
                desc(ArtifactRecord.created_at),
                desc(ArtifactRecord.id),
            )
            statement = statement.where(ArtifactRecord.module_id == normalized_module_id)
            normalized_run_id = optional_text(run_id, tool_name="artifacts.search", field_name="run_id")
            normalized_artifact_type = optional_text(artifact_type, tool_name="artifacts.search", field_name="artifact_type")
            normalized_scope = optional_text(scope, tool_name="artifacts.search", field_name="scope")
            normalized_label = optional_text(label, tool_name="artifacts.search", field_name="label")
            normalized_target_name = optional_text(target_name, tool_name="artifacts.search", field_name="target_name")
            normalized_target_host = optional_text(target_host, tool_name="artifacts.search", field_name="target_host")
            if normalized_run_id:
                statement = statement.where(ArtifactRecord.run_id == normalized_run_id)
            if normalized_artifact_type:
                statement = statement.where(ArtifactRecord.artifact_type == normalized_artifact_type)
            if normalized_scope:
                statement = statement.where(ArtifactRecord.scope == normalized_scope)
            if normalized_label:
                statement = statement.where(ArtifactRecord.label == normalized_label)
            if normalized_target_name:
                statement = statement.where(ArtifactRecord.target_name == normalized_target_name)
            if normalized_target_host:
                statement = statement.where(ArtifactRecord.target_host == normalized_target_host)
            records = list(await session.exec(statement.offset(normalized_offset).limit(normalized_limit)))
        return {
            "count": len(records),
            "returned": len(records),
            "offset": normalized_offset,
            "limit": normalized_limit,
            "items": [_artifact_payload(record, include_content=normalized_include_content) for record in records],
        }


def _serialize_artifact_content(content: object | None, *, content_type: str | None) -> tuple[str, str]:
    normalized_content_type = optional_text(
        content_type,
        tool_name="artifacts.store",
        field_name="content_type",
    ) or ""
    if isinstance(content, str):
        return content, normalized_content_type or "text/plain"
    if content is None:
        return "", normalized_content_type or "text/plain"
    return (
        serialize_json_object(content, field_name="content", indent=2),
        normalized_content_type or "application/json",
    )


def _artifact_payload(record: ArtifactRecord, *, include_content: bool) -> JsonObject:
    payload: JsonObject = {
        "id": record.id,
        "run_id": record.run_id,
        "module_id": record.module_id,
        "scope": record.scope,
        "artifact_type": record.artifact_type,
        "label": record.label,
        "target_name": record.target_name,
        "target_host": record.target_host,
        "content_type": record.content_type,
        "metadata": _parse_json_object(record.metadata_json),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }
    if include_content:
        payload["content"] = _deserialize_artifact_body(record.body, content_type=record.content_type)
    return payload


def _deserialize_artifact_body(body: str, *, content_type: str) -> object:
    normalized_content_type = content_type.strip().lower()
    if normalized_content_type.startswith("application/json"):
        try:
            return json.loads(body or "null")
        except json.JSONDecodeError:
            return body
    return body


def _parse_json_object(value: str | None) -> JsonObject:
    try:
        payload = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def require_module_id(value: str | None, *, action: str) -> str:
    tool_name = "artifacts.search" if action == "search" else "artifacts.store"
    return require_text(value, tool_name=tool_name, field_name="module_id")


def require_boolean(value: object, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    raise ValueError(f"artifacts.search {field_name} must be a boolean.")


def reject_present_arguments(*, tool_name: str, action: str, arguments: dict[str, object]) -> None:
    unexpected = [name for name, value in arguments.items() if value is not None]
    if unexpected:
        names = ", ".join(unexpected)
        raise ValueError(f"{tool_name} {action} does not accept {names}.")


def serialize_json_object(value: object, *, field_name: str, indent: int | None = None) -> str:
    try:
        return json.dumps(value, indent=indent, sort_keys=True)
    except TypeError as exc:
        raise ValueError(f"artifacts.store {field_name} must be JSON-serializable.") from exc

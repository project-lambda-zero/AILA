from __future__ import annotations

import json

from sqlalchemy import desc
from sqlmodel import select

from ...storage.database import async_session_scope
from ...storage.db_models import AuditEventRecord
from ..config import PlatformSettings
from ..services.audit import record_audit_event
from ._common import Tool, normalize_limit, optional_text, require_text


class AuditLogTool(Tool):
    """Platform tool for recording and querying audit trail events.

    Agents use this tool to write explicit audit records (record action) or to
    query the audit trail by run_id, stage, action, status, or target (list action).
    Platform-internal events are written automatically via the emitter's audit_db
    destination; this tool exposes the same audit surface to agents for custom events.

    Supports actions: record, list.
    """

    name = "audit_log"
    description = "Record or query platform audit events."
    inputs = {
        "action": {"type": "string", "description": "One of record or list."},
        "run_id": {
            "type": "string",
            "description": "Workflow run identifier.",
            "nullable": True,
        },
        "stage": {
            "type": "string",
            "description": "Audit stage name.",
            "nullable": True,
        },
        "event_action": {
            "type": "string",
            "description": "Audit action value.",
            "nullable": True,
        },
        "status": {
            "type": "string",
            "description": "Audit event status.",
            "nullable": True,
        },
        "target": {
            "type": "string",
            "description": "Optional audit target.",
            "nullable": True,
        },
        "details": {
            "type": "object",
            "description": "Optional structured audit details.",
            "nullable": True,
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of events to return for list.",
            "nullable": True,
        },
        "user_id": {
            "type": "string",
            "description": "User identity to record or filter by.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings):
        self.settings = settings

    async def forward(
        self,
        action: str,
        run_id: str | None = None,
        stage: str | None = None,
        event_action: str | None = None,
        status: str | None = None,
        target: str | None = None,
        details: dict | None = None,
        limit: int | None = None,
        user_id: str | None = None,
    ) -> dict:
        normalized_action = require_text(action, tool_name="audit.log", field_name="action").lower()
        async with async_session_scope(self.settings) as session:
            if normalized_action == "record":
                if limit is not None:
                    raise ValueError("audit.log record does not accept limit.")
                normalized_run_id = require_text(run_id, tool_name="audit.log", field_name="run_id")
                normalized_stage = require_text(stage, tool_name="audit.log", field_name="stage")
                normalized_event_action = require_text(event_action, tool_name="audit.log", field_name="event_action")
                if details is not None and not isinstance(details, dict):
                    raise ValueError("audit.log record requires details to be an object.")
                record_audit_event(
                    session,
                    run_id=normalized_run_id,
                    stage=normalized_stage,
                    action=normalized_event_action,
                    status=optional_text(status, tool_name="audit.log", field_name="status") or "completed",
                    target=optional_text(target, tool_name="audit.log", field_name="target") or "",
                    user_id=optional_text(user_id, tool_name="audit.log", field_name="user_id") or "system",
                    details=details,
                )
                await session.commit()
                return {
                    "recorded": True,
                    "run_id": normalized_run_id,
                    "stage": normalized_stage,
                    "action": normalized_event_action,
                }
            if normalized_action == "list":
                if details is not None:
                    raise ValueError("audit.log list does not accept details.")
                normalized_run_id = optional_text(run_id, tool_name="audit.log", field_name="run_id")
                normalized_stage = optional_text(stage, tool_name="audit.log", field_name="stage")
                normalized_event_action = optional_text(event_action, tool_name="audit.log", field_name="event_action")
                normalized_status = optional_text(status, tool_name="audit.log", field_name="status")
                normalized_target = optional_text(target, tool_name="audit.log", field_name="target")
                normalized_user_id = optional_text(user_id, tool_name="audit.log", field_name="user_id")
                if not any(
                    value is not None
                    for value in (
                        normalized_run_id,
                        normalized_stage,
                        normalized_event_action,
                        normalized_status,
                        normalized_target,
                        normalized_user_id,
                    )
                ):
                    raise ValueError("audit.log list requires at least one selector.")
                normalized_limit = normalize_limit(limit, default=50, maximum=500)
                statement = select(AuditEventRecord).order_by(
                    desc(AuditEventRecord.created_at),
                    desc(AuditEventRecord.id),
                )
                if normalized_run_id:
                    statement = statement.where(AuditEventRecord.run_id == normalized_run_id)
                if normalized_stage:
                    statement = statement.where(AuditEventRecord.stage == normalized_stage)
                if normalized_event_action:
                    statement = statement.where(AuditEventRecord.action == normalized_event_action)
                if normalized_status:
                    statement = statement.where(AuditEventRecord.status == normalized_status)
                if normalized_target:
                    statement = statement.where(AuditEventRecord.target == normalized_target)
                if normalized_user_id:
                    statement = statement.where(AuditEventRecord.user_id == normalized_user_id)
                records = list(await session.exec(statement.limit(normalized_limit)))
                return {
                    "count": len(records),
                    "returned": len(records),
                    "limit": normalized_limit,
                    "items": [_audit_event_payload(record) for record in records],
                }
        raise ValueError(f"Unsupported audit.log action '{action}'.")


def _audit_event_payload(record: AuditEventRecord) -> dict:
    return {
        "id": record.id,
        "run_id": record.run_id,
        "stage": record.stage,
        "action": record.action,
        "status": record.status,
        "target": record.target,
        "user_id": record.user_id,
        "details": _parse_json(record.details_json),
        "created_at": record.created_at.isoformat(),
    }


def _parse_json(payload: str | None) -> dict:
    try:
        loaded = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}



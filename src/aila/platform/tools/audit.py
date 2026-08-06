from __future__ import annotations

import json

from sqlalchemy import desc
from sqlmodel import select

from ...storage.database import async_session_scope
from ...storage.db_models import AuditEventRecord
from ..config import PlatformSettings
from ..exceptions import ValidationError
from ..services.audit import record_audit_event
from ..tasks.queue import _current_task_user_id
from ._common import Tool, normalize_limit, optional_text, require_text

# #53: cap on the serialized ``details_json`` written per audit record.
# 32 KiB matches the observation cap the platform uses elsewhere for
# untrusted JSON blobs and keeps a single agent-produced entry from
# blowing up the audit table row budget.
_DETAILS_JSON_MAX_BYTES = 32 * 1024

# #53: hard ceiling on list pagination. The auditor UI pages in
# reasonable chunks; a 500-per-page cap keeps a run-away agent from
# pulling the whole table in a single call.
_AUDIT_LIST_DEFAULT = 50
_AUDIT_LIST_MAX = 500


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
        "offset": {
            "type": "integer",
            "description": "Zero-based offset for list pagination.",
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
        offset: int | None = None,
    ) -> dict:
        # #53: user_id is NOT accepted from the agent -- it is derived at
        # tool-execution time via the authenticated task context. An agent
        # attempting to write an audit row "as" another user cannot spoof.
        authenticated_user_id = _current_task_user_id.get() or "system"
        normalized_action = require_text(action, tool_name="audit.log", field_name="action").lower()
        async with async_session_scope(self.settings) as session:
            if normalized_action == "record":
                if limit is not None:
                    raise ValueError("audit.log record does not accept limit.")
                if offset is not None:
                    raise ValueError("audit.log record does not accept offset.")
                normalized_run_id = require_text(run_id, tool_name="audit.log", field_name="run_id")
                normalized_stage = require_text(stage, tool_name="audit.log", field_name="stage")
                normalized_event_action = require_text(event_action, tool_name="audit.log", field_name="event_action")
                if details is not None and not isinstance(details, dict):
                    raise ValueError("audit.log record requires details to be an object.")
                if details is not None:
                    _enforce_details_size(details)
                record_audit_event(
                    session,
                    run_id=normalized_run_id,
                    stage=normalized_stage,
                    action=normalized_event_action,
                    status=optional_text(status, tool_name="audit.log", field_name="status") or "completed",
                    target=optional_text(target, tool_name="audit.log", field_name="target") or "",
                    user_id=authenticated_user_id,
                    details=details,
                )
                await session.commit()
                return {
                    "recorded": True,
                    "run_id": normalized_run_id,
                    "stage": normalized_stage,
                    "action": normalized_event_action,
                    "user_id": authenticated_user_id,
                }
            if normalized_action == "list":
                if details is not None:
                    raise ValueError("audit.log list does not accept details.")
                normalized_run_id = optional_text(run_id, tool_name="audit.log", field_name="run_id")
                normalized_stage = optional_text(stage, tool_name="audit.log", field_name="stage")
                normalized_event_action = optional_text(event_action, tool_name="audit.log", field_name="event_action")
                normalized_status = optional_text(status, tool_name="audit.log", field_name="status")
                normalized_target = optional_text(target, tool_name="audit.log", field_name="target")
                if not any(
                    value is not None
                    for value in (
                        normalized_run_id,
                        normalized_stage,
                        normalized_event_action,
                        normalized_status,
                        normalized_target,
                    )
                ):
                    raise ValueError("audit.log list requires at least one selector.")
                normalized_limit = normalize_limit(
                    limit, default=_AUDIT_LIST_DEFAULT, maximum=_AUDIT_LIST_MAX,
                )
                normalized_offset = _normalize_offset(offset)
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
                records = list(await session.exec(
                    statement.offset(normalized_offset).limit(normalized_limit),
                ))
                return {
                    "count": len(records),
                    "returned": len(records),
                    "limit": normalized_limit,
                    "offset": normalized_offset,
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


def _enforce_details_size(details: dict) -> None:
    """Refuse an audit ``details`` payload that serializes to more than
    :data:`_DETAILS_JSON_MAX_BYTES` (#53).

    Serialization is deliberately done inside the tool (not later, inside
    :func:`record_audit_event`) so the size check runs before the DB write
    is attempted and the error carries the shape ``ValidationError`` --
    consistent with the other input-guard rejections the tool raises.
    """
    try:
        payload = json.dumps(details, separators=(",", ":"), sort_keys=True, default=str)
    except (TypeError, ValueError) as exc:  # non-serializable content
        raise ValidationError(f"audit.log details is not JSON-serializable: {exc}") from exc
    if len(payload.encode("utf-8")) > _DETAILS_JSON_MAX_BYTES:
        raise ValidationError(
            f"audit.log details exceeds {_DETAILS_JSON_MAX_BYTES} bytes",
        )


def _normalize_offset(value: int | None) -> int:
    """Return a non-negative int offset for list pagination (#53)."""
    if value is None:
        return 0
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError("audit.log list offset must be an integer.")
    if value < 0:
        raise ValidationError("audit.log list offset must be >= 0.")
    return value


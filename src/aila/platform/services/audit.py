from __future__ import annotations

import json

from ...storage.db_models import AuditEventRecord


def record_audit_event(
    session,
    *,
    run_id: str,
    stage: str,
    action: str,
    status: str = "completed",
    target: str = "",
    user_id: str = "system",
    details: dict | None = None,
) -> None:
    """Write a single AuditEventRecord to the database within the active session.

    Called by the ThreadSafeEventEmitter's audit_db destination on every
    PlatformEvent emission. The session is not committed here -- the caller's
    transaction boundary controls commit timing. Raises ValueError if details
    is not JSON-serializable.
    """
    try:
        details_json = json.dumps(details if details is not None else {}, sort_keys=True)
    except TypeError as exc:
        raise ValueError("audit.log record details must be JSON-serializable.") from exc
    session.add(
        AuditEventRecord(
            run_id=run_id,
            stage=stage,
            action=action,
            status=status,
            target=target,
            user_id=user_id,
            details_json=details_json,
        )
    )

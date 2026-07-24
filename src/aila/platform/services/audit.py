from __future__ import annotations

import json

from ...storage.db_models import AuditEventRecord
from ..tasks.queue import _current_task_team_id
from .journal import JournalEntry, append_sync

__all__ = ["record_audit_event", "record_audit_event_sync"]


def record_audit_event(
    session,
    *,
    run_id: str,
    stage: str,
    action: str,
    status: str = "completed",
    target: str = "",
    user_id: str = "system",
    team_id: str | None = None,
    details: dict | None = None,
) -> None:
    """Write a single AuditEventRecord to the database within the active session.

    Called by the ThreadSafeEventEmitter's audit_db destination on every
    PlatformEvent emission. The session is not committed here -- the caller's
    transaction boundary controls commit timing. Raises ValueError if details
    is not JSON-serializable.

    team_id scopes the row so the team-filtered audit read surfaces it (#36).
    Request handlers pass auth.team_id; when omitted, the running task's team
    (from the task-engine context var) is used, so worker and workflow audit
    events carry their team. None (god-tier / pre-auth) stays team-less.
    """
    try:
        details_json = json.dumps(details if details is not None else {}, sort_keys=True)
    except TypeError as exc:
        raise ValueError("audit.log record details must be JSON-serializable.") from exc
    effective_team_id = team_id if team_id is not None else _current_task_team_id.get()
    session.add(
        AuditEventRecord(
            run_id=run_id,
            stage=stage,
            action=action,
            status=status,
            target=target,
            user_id=user_id,
            team_id=effective_team_id,
            details_json=details_json,
        )
    )


def record_audit_event_sync(
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
    """Append an audit row to the hash-chained platform journal (C2 / #52) from a
    sync-session caller (the CLI).

    Fail-closed: a broken chain raises :class:`JournalWriteError`, aborting the
    caller's transaction rather than losing the audit row. This is the
    journal-backed sync counterpart to :func:`record_audit_event`; during the
    #52 rollout the legacy async path still writes ``AuditEventRecord`` while
    migrated sync callers write the tamper-evident journal. The caller owns the
    commit boundary -- this only appends inside the active transaction.
    """
    append_sync(
        session,
        entry=JournalEntry(
            kind="audit",
            source=f"audit.{stage}" if stage else "audit",
            action=action,
            status=status,
            actor_kind="user" if user_id not in ("system", "") else "system",
            actor_id=user_id or "system",
            run_id=run_id,
            payload={"target": target, "details": details or {}},
        ),
    )

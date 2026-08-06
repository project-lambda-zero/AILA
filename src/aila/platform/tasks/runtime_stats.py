"""Task-runtime statistics derived from the platform-owned taskrecord table.

Platform-owned so feature modules never issue raw SQL against
``taskrecord``. Modules that want a derived task-runtime figure call a
helper here.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import psycopg

from aila.config import get_settings

_log = logging.getLogger(__name__)

__all__ = ["active_task_runtime_seconds"]


def active_task_runtime_seconds(investigation_id: str) -> int | None:
    """Return total seconds a worker was actively executing tasks for an
    investigation.

    Sums ``COALESCE(completed_at, heartbeat_at) - started_at`` across every
    ``taskrecord`` row whose ``kwargs_json`` references the investigation.
    The wall-clock ``updated_at - created_at`` measure includes every idle
    hour between re-enqueues, which inflates the duration for an
    investigation that was only actively running for a short window; this
    counts only the intervals a worker was executing.

    Best-effort: returns ``None`` when ``taskrecord`` cannot be read (so a
    caller such as a report renderer degrades to omitting the field).
    """
    try:
        url = get_settings().database_url.replace(
            "postgresql+asyncpg://", "postgresql://",
        )
        parsed = urlparse(url)
        with psycopg.connect(
            host=parsed.hostname,
            port=parsed.port or 5432,
            user=parsed.username,
            password=parsed.password,
            dbname=(parsed.path or "/").lstrip("/"),
        ) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(SUM(EXTRACT(EPOCH FROM "
                "(COALESCE(completed_at, heartbeat_at) - started_at))), 0) "
                "FROM taskrecord "
                "WHERE started_at IS NOT NULL "
                "AND kwargs_json::text LIKE %s",
                (f"%{investigation_id}%",),
            )
            row = cur.fetchone()
            secs = int(row[0]) if row and row[0] else 0
            return secs if secs > 0 else None
    except (OSError, ValueError, RuntimeError, ImportError) as exc:
        _log.warning(
            "active-runtime taskrecord query FAILED investigation_id=%s reason=%s",
            investigation_id, exc,
        )
        return None

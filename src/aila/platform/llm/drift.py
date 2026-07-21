"""Confidence drift tracking per (target_name, task_type).

Detects when LLM confidence for the same target drifts over time,
indicating model degradation, prompt drift, or adversarial manipulation.

Uses a sliding window of recent confidence scores and computes standard
deviation via the stdlib statistics module (no external dependencies).
Minimum 5 samples required before alerting to prevent false positives
on new targets.

Thresholds:
  - std_dev < 0.1  -> "stable"   (no alert)
  - std_dev 0.1-0.2 -> "degrading" (alert fired)
  - std_dev > 0.2  -> "volatile"  (alert fired)
"""

from __future__ import annotations

import json
import logging
import statistics
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

_log = logging.getLogger(__name__)

_DEFAULT_WINDOW = 10
_MIN_SAMPLES = 5
_VOLATILE_THRESHOLD = 0.2
_DEGRADING_THRESHOLD = 0.1

# Retention window for ConfidenceDriftRecord rows. Every drift check inserts a
# new row (drift.py::record_and_check), so the table grows unbounded without
# a periodic sweep. 90 days matches the operator-visible reporting horizon
# for drift trending. Note on config pattern: seal.py resolves a per-request
# retention via ConfigRegistry (platform.llm_seal_retention_days) because its
# purge runs in the request path where a config_provider is in scope. This
# purge runs from the reaper cron with no config_provider (mirroring
# idempotency_cache.run_purge_expired_cron), so a module constant is the
# right fit; the cron caller has no natural injection point.
_DEFAULT_RETENTION_DAYS = 90


@dataclass(frozen=True)
class DriftResult:
    """Immutable result of a drift check."""

    status: str  # "stable" | "degrading" | "volatile" | "insufficient_data"
    mean: float
    std_dev: float
    sample_count: int
    alert_fired: bool


class ConfidenceDriftTracker:
    """Track confidence drift per (target_name, task_type) using sliding window.

    Each call to record_and_check() fetches the most recent drift record for
    the (target, task_type) pair, appends the new score to the window, computes
    statistics, and persists a new ConfidenceDriftRecord.  This approach avoids
    querying AuditSealRecord (which stores string confidence levels, not numeric
    scores) and keeps drift history self-contained.
    """

    def __init__(self, window_size: int = _DEFAULT_WINDOW) -> None:
        self._window_size = max(window_size, _MIN_SAMPLES)

    async def record_and_check(
        self,
        target_name: str,
        task_type: str,
        confidence_score: float,
    ) -> DriftResult:
        """Record a confidence score and check for drift.

        Args:
            target_name: System or target identifier.
            task_type: LLM task type routing key.
            confidence_score: Numeric confidence score (0.0-1.0).

        Returns:
            DriftResult with computed status and statistics.
        """
        if not target_name or not task_type:
            return DriftResult(
                status="insufficient_data",
                mean=0.0,
                std_dev=0.0,
                sample_count=0,
                alert_fired=False,
            )

        from sqlmodel import select

        from aila.storage.database import async_session_scope
        from aila.storage.db_models import ConfidenceDriftRecord

        # Fetch the most recent drift record for this (target, task_type) pair
        # to recover the sliding window of scores.
        scores: list[float] = []
        async with async_session_scope() as session:
            stmt = (
                select(ConfidenceDriftRecord.confidence_scores_json)
                .where(ConfidenceDriftRecord.target_name == target_name)
                .where(ConfidenceDriftRecord.task_type == task_type)
                .order_by(ConfidenceDriftRecord.computed_at.desc())  # type: ignore[union-attr]
                .limit(1)
            )
            row = (await session.exec(stmt)).first()  # type: ignore[call-overload]

        if row is not None:
            try:
                previous = json.loads(row)
                if isinstance(previous, list):
                    scores = [float(s) for s in previous if isinstance(s, (int, float))]
            except (json.JSONDecodeError, TypeError, ValueError):
                scores = []

        # Prepend new score and trim to window size
        scores.insert(0, confidence_score)
        scores = scores[: self._window_size]

        if len(scores) < _MIN_SAMPLES:
            return DriftResult(
                status="insufficient_data",
                mean=0.0,
                std_dev=0.0,
                sample_count=len(scores),
                alert_fired=False,
            )

        mean = statistics.mean(scores)
        std_dev = statistics.stdev(scores) if len(scores) > 1 else 0.0

        # Determine drift status
        if std_dev > _VOLATILE_THRESHOLD:
            status = "volatile"
            alert = True
        elif std_dev > _DEGRADING_THRESHOLD:
            status = "degrading"
            alert = True
        else:
            status = "stable"
            alert = False

        # Persist drift record
        async with async_session_scope() as session:
            record = ConfidenceDriftRecord(
                target_name=target_name,
                task_type=task_type,
                window_size=len(scores),
                confidence_scores_json=json.dumps(scores),
                mean_confidence=round(mean, 4),
                std_deviation=round(std_dev, 4),
                drift_status=status,
                alert_fired=alert,
            )
            session.add(record)
            await session.commit()

        # Update Prometheus metrics
        from aila.api.metrics import CONFIDENCE_DRIFT, DRIFT_ALERTS

        CONFIDENCE_DRIFT.labels(target=target_name, task_type=task_type).set(std_dev)
        if alert:
            DRIFT_ALERTS.labels(target=target_name, task_type=task_type).inc()
            _log.warning(
                "Confidence drift alert: target=%s task_type=%s status=%s "
                "std_dev=%.4f mean=%.4f samples=%d",
                target_name,
                task_type,
                status,
                std_dev,
                mean,
                len(scores),
            )

        return DriftResult(
            status=status,
            mean=round(mean, 4),
            std_dev=round(std_dev, 4),
            sample_count=len(scores),
            alert_fired=alert,
        )


async def purge_old_records(
    session: object,
    retention_days: int = _DEFAULT_RETENTION_DAYS,
) -> int:
    """Delete ConfidenceDriftRecord rows older than the retention window.

    Every call to :meth:`ConfidenceDriftTracker.record_and_check` inserts a
    fresh row (no upsert, no windowed table), so the table grows without
    bound. This sweep is wired into the platform reaper cron alongside
    :func:`aila.platform.llm.idempotency_cache.purge_expired` so the table
    stays bounded to ``retention_days`` of history.

    Bounded single DELETE with WHERE computed_at < cutoff. Idempotent: a
    second call in the same tick with no rows past the cutoff returns 0
    without side effects. Best-effort: transport errors are logged at
    WARNING and swallowed so the cron continues.

    Returns the count of rows deleted, or 0 on transport error.
    """
    from datetime import timedelta

    from sqlalchemy.exc import DBAPIError, SQLAlchemyError
    from sqlmodel import delete

    from aila.platform.contracts._common import utc_now
    from aila.storage.db_models import ConfidenceDriftRecord

    cutoff = utc_now() - timedelta(days=retention_days)
    try:
        result = await session.execute(
            delete(ConfidenceDriftRecord).where(
                ConfidenceDriftRecord.computed_at < cutoff,
            )
        )
        await session.commit()
        # Some drivers report rowcount=-1 when the row count is unknown;
        # clamp at zero to keep the cron log line non-negative (mirrors
        # idempotency_cache.purge_expired).
        rc = int(getattr(result, "rowcount", 0) or 0)
        return rc if rc >= 0 else 0
    except (SQLAlchemyError, DBAPIError) as exc:
        _log.warning("confidence drift retention purge failed: %s", exc)
        return 0


async def run_purge_old_records_cron() -> int:
    """Open a session and call :func:`purge_old_records`.

    Wired into ``platform/tasks/worker.py:reaper`` next to the idempotency
    cache purge. Standalone helper so the cron import surface stays narrow
    -- the reaper does not need to know about session scopes.
    """
    from aila.storage.database import async_session_scope

    async with async_session_scope() as session:
        return await purge_old_records(session)

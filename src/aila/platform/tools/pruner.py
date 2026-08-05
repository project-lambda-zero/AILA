"""Periodic prune for platform-owned tool storage tables (#56).

Both ``permanentmemoryrecord`` (backing ``PermanentMemoryTool`` and
``DecisionCacheTool``) and ``artifactrecord`` (backing
``ArtifactStoreTool``) accumulate rows on every write because their
tool surfaces never evict. ``DecisionCacheTool`` fails closed at read
against ``routing_decision_cache_ttl_hours``, so a stale row is not
returned to a caller -- but it still sits in the table forever.

This module owns the actual eviction pass. It is registered as an
``AutomationAction`` in ``aila.platform.automation.maintenance`` so the
existing tick supervisor schedules it (an operator sets the cadence via
``POST /automation/schedules`` with ``action_id='platform.tool_storage_prune'``).
Each pass applies:

* age-based prune (delete rows where ``updated_at`` / ``created_at`` is
  older than the platform-namespace ``*_max_age_days`` config value),
* per-scope row-count cap (keep the newest N rows per namespace for
  memory, per module_id for artifacts).

Every knob accepts ``<= 0`` to disable that half of the prune without
a code change. ``ConfigRegistry.get_sync`` is the resolution path so an
operator override lands on the next tick without a worker restart.
"""

from __future__ import annotations

__all__ = [
    "ToolStoragePruneReport",
    "prune_tool_storage",
]

import logging
from datetime import timedelta
from typing import TypedDict

import sqlalchemy.exc
from sqlalchemy import delete, func, select

from aila.platform.contracts import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import ArtifactRecord
from aila.storage.memory import PermanentMemoryStore
from aila.storage.registry import ConfigRegistry

_log = logging.getLogger(__name__)

# Isolated failure classes for the two prune halves. Same policy as the
# health-check probes (``aila.platform.automation.maintenance``): any
# realistic infra fault is captured so the automation runner records a
# structured last_run_result; ``BaseException``-only subclasses
# (``KeyboardInterrupt``, ``SystemExit``, ``asyncio.CancelledError``)
# intentionally propagate so a shutdown is not swallowed.
_PRUNE_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    TimeoutError,
    RuntimeError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    ConnectionError,
)


class ToolStoragePruneReport(TypedDict):
    """Structured summary of a single ``prune_tool_storage`` invocation.

    Every field is always populated (0 when a half was disabled by config
    or found nothing to delete) so downstream consumers can rely on the
    shape without ``.get`` guards. ``errors`` names the failed half plus
    the exception class -- message bodies are redacted per the platform's
    structured-summary policy; full tracebacks land in the worker log.
    """

    memory_age_deleted: int
    memory_overflow_deleted: int
    artifact_age_deleted: int
    artifact_overflow_deleted: int
    errors: list[str]


def _resolve_int_config(
    registry: ConfigRegistry | None, key: str, default: int,
) -> int:
    """Read a platform-namespace int knob via ``ConfigRegistry.get_sync``.

    Mirrors ``CyberReasoningEngine._resolve_platform_int``: missing
    registry, DB failure, or non-numeric value all fall back to
    ``default`` so a prune tick never crashes on config drift.
    """
    if registry is None:
        return default
    try:
        raw = registry.get_sync("platform", key)
    except _PRUNE_ERRORS:
        return default
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


async def _prune_artifacts_age(session, *, max_age_days: int) -> int:
    """Delete artifact rows whose ``created_at`` is older than the cap.

    ``created_at`` is indexed on ``artifactrecord`` (see
    ``db_models.ArtifactRecord``). ``updated_at`` is not, and artifacts
    are effectively write-once (rewrites do not happen in the current
    tool surface) so this stays a single-index range scan.
    """
    if max_age_days <= 0:
        return 0
    cutoff = utc_now() - timedelta(days=max_age_days)
    result = await session.execute(
        delete(ArtifactRecord).where(ArtifactRecord.created_at < cutoff)
    )
    await session.commit()
    return int(result.rowcount or 0)


async def _prune_artifacts_overflow(
    session, *, max_rows_per_module: int,
) -> int:
    """Cap each module's artifact rows at ``max_rows_per_module`` newest.

    Delete strategy is a per-module keep-set: fetch the newest N ids by
    ``created_at DESC`` then delete every other row for that module in
    a single statement. Same shape as ``PermanentMemoryStore.prune_overflow``.
    """
    if max_rows_per_module <= 0:
        return 0
    oversized = (await session.execute(
        select(ArtifactRecord.module_id, func.count().label("rows"))
        .group_by(ArtifactRecord.module_id)
        .having(func.count() > max_rows_per_module)
    )).all()
    if not oversized:
        return 0
    deleted_total = 0
    for module_id, _rows in oversized:
        keep_ids_stmt = (
            select(ArtifactRecord.id)
            .where(ArtifactRecord.module_id == module_id)
            .order_by(ArtifactRecord.created_at.desc())  # type: ignore[attr-defined]
            .limit(max_rows_per_module)
        )
        keep_ids = [row[0] for row in (await session.execute(keep_ids_stmt)).all()]
        if not keep_ids:
            continue
        result = await session.execute(
            delete(ArtifactRecord).where(
                ArtifactRecord.module_id == module_id,
                ArtifactRecord.id.notin_(keep_ids),  # type: ignore[attr-defined]
            )
        )
        deleted_total += int(result.rowcount or 0)
    await session.commit()
    return deleted_total


async def prune_tool_storage(
    *,
    config_registry: ConfigRegistry | None = None,
    **kwargs: object,
) -> ToolStoragePruneReport:
    """Run the two tool-storage prune passes and return a structured report.

    Wired as an ``AutomationAction`` (see
    ``aila.platform.automation.maintenance.register_maintenance_actions``)
    so an operator schedules the cadence via the standard automation
    surface. Called directly by tests with an explicit
    ``config_registry`` to override the platform defaults; the
    automation runner passes only ``target_name`` /
    ``execution_context`` kwargs, both of which we swallow via
    ``**kwargs``.

    Each half is isolated: a failure in the memory prune does not
    prevent the artifact prune from running, and the reverse. Every
    failure is captured in ``errors`` with the exception class name so
    the ``last_run_result`` snapshot on the schedule row is
    self-describing. Full tracebacks land in the worker log via
    ``_log.warning(..., exc_info=exc)``.
    """
    _ = kwargs  # runner-injected metadata; not used here

    memory_max_age = _resolve_int_config(
        config_registry, "tool_storage_memory_max_age_days", 90,
    )
    memory_max_rows = _resolve_int_config(
        config_registry, "tool_storage_memory_max_rows_per_namespace", 10_000,
    )
    artifact_max_age = _resolve_int_config(
        config_registry, "tool_storage_artifact_max_age_days", 180,
    )
    artifact_max_rows = _resolve_int_config(
        config_registry, "tool_storage_artifact_max_rows_per_module", 10_000,
    )

    report: ToolStoragePruneReport = {
        "memory_age_deleted": 0,
        "memory_overflow_deleted": 0,
        "artifact_age_deleted": 0,
        "artifact_overflow_deleted": 0,
        "errors": [],
    }

    memory_store = PermanentMemoryStore()

    try:
        async with async_session_scope() as session:
            report["memory_age_deleted"] = await memory_store.prune_expired(
                session, max_age_days=memory_max_age,
            )
    except _PRUNE_ERRORS as exc:
        _log.warning(
            "tool_storage_prune: memory-age pass failed (%s)",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"memory_age:{type(exc).__name__}")

    try:
        async with async_session_scope() as session:
            report["memory_overflow_deleted"] = await memory_store.prune_overflow(
                session, max_rows_per_namespace=memory_max_rows,
            )
    except _PRUNE_ERRORS as exc:
        _log.warning(
            "tool_storage_prune: memory-overflow pass failed (%s)",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"memory_overflow:{type(exc).__name__}")

    try:
        async with async_session_scope() as session:
            report["artifact_age_deleted"] = await _prune_artifacts_age(
                session, max_age_days=artifact_max_age,
            )
    except _PRUNE_ERRORS as exc:
        _log.warning(
            "tool_storage_prune: artifact-age pass failed (%s)",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"artifact_age:{type(exc).__name__}")

    try:
        async with async_session_scope() as session:
            report["artifact_overflow_deleted"] = await _prune_artifacts_overflow(
                session, max_rows_per_module=artifact_max_rows,
            )
    except _PRUNE_ERRORS as exc:
        _log.warning(
            "tool_storage_prune: artifact-overflow pass failed (%s)",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"artifact_overflow:{type(exc).__name__}")

    _log.info(
        "tool_storage_prune completed memory_age=%d memory_overflow=%d "
        "artifact_age=%d artifact_overflow=%d errors=%d",
        report["memory_age_deleted"],
        report["memory_overflow_deleted"],
        report["artifact_age_deleted"],
        report["artifact_overflow_deleted"],
        len(report["errors"]),
    )
    return report

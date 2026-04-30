"""Transition-log writer and hash helper for the durable workflows engine.

All log writes are NOT best-effort (D-34). INSERT failures raise. Audit
integrity is more important than throughput.

Hash format (D-18):
    hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",",":"))).hexdigest()[:16]

Chosen for storage-compact diff identification. This is NOT a cryptographic
commitment -- collisions are acceptable for audit use since the log is
append-only and every pair of (run_id, seq) is unique.

Expected row rate: ~2 rows per state per run (one ``entered`` + one
``exited:*``). Retention/pruning is deferred to Phase 181 admin endpoints
(T-178-02 accepts DoS via transition-log growth).

Error-message truncation (D-44): ``error_message`` is truncated at 2000
characters. Full stack traces go to structlog on the worker, NOT to the
audit table -- this keeps the audit log query-friendly and reduces the
chance of secrets leaking into persisted rows (T-178-04).

Phase 178 fix-pass updates:
    - ``write_entered`` / ``write_exited`` now allocate ``seq`` via an
      atomic ``INSERT ... SELECT max(seq)+1`` so two workers racing for
      the same ``run_id`` cannot read the same ``max(seq)`` then both
      INSERT. On an ``IntegrityError`` (PK collision) the write retries a
      bounded number of times inside the same session; if it still
      fails the caller's transaction is aborted and the error propagates
      -- ARQ retries the whole job.
    - ``seq`` is no longer an argument: callers must not pre-allocate it.
      The returned value tells the caller which seq was used.
    - ``safe_exc_message`` enforces audit-log redaction by default (only
      classes inheriting ``WorkflowSafeMessage`` preserve the full
      ``str(exc)``).
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from aila.storage.db_models import WorkflowStateTransition

from .errors import WorkflowSafeMessage

_log = logging.getLogger(__name__)

_ERROR_MESSAGE_MAX: Final[int] = 2000  # D-44

# Bounded retries on PK collision when two workers race to allocate the
# same ``seq`` for one ``run_id``. Each retry re-reads max(seq) within
# the same session; the cursor's optimistic lock is the primary defence,
# this is the secondary guard on the audit table.
_SEQ_INSERT_MAX_RETRIES: Final[int] = 5


def safe_exc_message(exc: BaseException) -> str:
    """Return a redacted message suitable for persisting in the audit log.

    Default behaviour (Phase 178 security fix): returns
    ``type(exc).__name__`` so handler exception text never reaches the
    audit table. Handlers that deliberately want their message preserved
    must raise an exception that inherits from ``WorkflowSafeMessage``;
    for those, the full ``str(exc)`` (truncated at 2000 chars by the
    writer) is returned instead.
    """
    if isinstance(exc, WorkflowSafeMessage):
        return str(exc)
    return type(exc).__name__


def compute_hash(obj: Any | None) -> str | None:
    """Return a 16-char sha256-hex digest of ``obj``, or ``None`` for ``None``.

    Stable across key order (uses ``sort_keys=True``). Uses
    ``(",", ":")`` separators so whitespace never affects the digest.

    ``default=str`` lets datetimes/UUIDs appear in the payload without
    raising; the goal is stable audit fingerprints, not strict JSON
    validation (strict validation lives on ``StateResult`` per D-36).
    """
    if obj is None:
        return None
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


async def _insert_transition_atomic(
    session: AsyncSession,
    *,
    run_id: str,
    from_state: str,
    to_state: str,
    event: str,
    input_hash: str | None,
    output_hash: str | None,
    duration_ms: int | None,
    error_class: str | None,
    error_message: str | None,
) -> int:
    """Atomically allocate seq and INSERT a transition row. Return seq.

    Uses ``INSERT ... SELECT COALESCE(MAX(seq), -1) + 1 ... RETURNING seq``
    so the seq is computed within the same statement's snapshot. Two
    concurrent workers for the same ``run_id`` may still collide on the
    PK (``run_id``, ``seq``); on ``IntegrityError`` the write retries a
    bounded number of times with a savepoint, so the outer transaction
    remains usable.
    """
    table = WorkflowStateTransition.__table__  # type: ignore[attr-defined]
    max_seq_subq = (
        sa.select(
            sa.func.coalesce(sa.func.max(table.c.seq), -1) + 1
        )
        .where(table.c.run_id == run_id)
        .scalar_subquery()
    )
    last_exc: Exception | None = None
    for _ in range(_SEQ_INSERT_MAX_RETRIES):
        stmt = (
            sa.insert(table)
            .from_select(
                [
                    "run_id",
                    "seq",
                    "from_state",
                    "to_state",
                    "event",
                    "input_hash",
                    "output_hash",
                    "duration_ms",
                    "error_class",
                    "error_message",
                ],
                sa.select(
                    sa.literal(run_id).label("run_id"),
                    max_seq_subq.label("seq"),
                    sa.literal(from_state).label("from_state"),
                    sa.literal(to_state).label("to_state"),
                    sa.literal(event).label("event"),
                    sa.literal(input_hash).label("input_hash"),
                    sa.literal(output_hash).label("output_hash"),
                    sa.literal(duration_ms).label("duration_ms"),
                    sa.literal(error_class).label("error_class"),
                    sa.literal(error_message).label("error_message"),
                ),
            )
            .returning(table.c.seq)
        )
        # Wrap the INSERT in a SAVEPOINT so an IntegrityError does not
        # poison the caller's outer transaction. We re-try within the
        # same outer transaction -- the read of max(seq) observes the
        # committed state plus any rows INSERTed by this session so far.
        try:
            async with session.begin_nested():
                result = await session.execute(stmt)
                row = result.first()
                if row is None:  # pragma: no cover -- defensive
                    raise RuntimeError(
                        "INSERT ... RETURNING seq returned no row"
                    )
                return int(row[0])
        except IntegrityError as exc:
            last_exc = exc
            # Savepoint auto-rolled back; loop to retry.
            continue
    if last_exc is None:
        raise RuntimeError("INSERT ... RETURNING seq retry loop exited without exception")
    raise last_exc


async def write_entered(
    session: AsyncSession,
    *,
    run_id: str,
    from_state: str,
    to_state: str,
    state_input: dict[str, Any],
) -> int:
    """Atomically INSERT one ``entered`` row. Returns the allocated seq.

    ``from_state`` / ``to_state`` are equal for an ``entered`` event
    unless the engine threads the previous state for cross-state
    transitions (Phase 178 fix 11 -- ``from_state`` is the cursor's
    previous state, ``to_state`` is the state we just entered).

    Raises on failure (D-34). Seq allocation is atomic; see
    ``_insert_transition_atomic``.
    """
    return await _insert_transition_atomic(
        session,
        run_id=run_id,
        from_state=from_state,
        to_state=to_state,
        event="entered",
        input_hash=compute_hash(state_input),
        output_hash=None,
        duration_ms=None,
        error_class=None,
        error_message=None,
    )


async def write_exited(
    session: AsyncSession,
    *,
    run_id: str,
    from_state: str,
    to_state: str,
    event: str,
    output: dict[str, Any] | None,
    duration_ms: int,
    error_class: str | None,
    error_message: str | None,
) -> int:
    """Atomically INSERT one ``exited:*`` row. Returns the allocated seq.

    ``event`` is one of:
        - ``"exited:ok"`` -- handler returned cleanly
        - ``"exited:retry"`` -- retriable exception, will raise arq.Retry
        - ``"exited:failed"`` -- non-retriable or retries exhausted
        - ``"exited:timeout"`` -- asyncio.wait_for fired
        - ``"exited:failed_in_failure_handler"`` -- failure handler raised (D-33)

    ``error_message`` is truncated at 2000 chars (D-44); callers must NOT
    rely on full-string persistence. Full tracebacks go to structlog.

    The engine calls this inside the same session as the cursor UPDATE
    so both writes commit atomically (Phase 178 fix 1 -- no split-brain
    between audit and cursor).
    """
    truncated = error_message[:_ERROR_MESSAGE_MAX] if error_message else None
    return await _insert_transition_atomic(
        session,
        run_id=run_id,
        from_state=from_state,
        to_state=to_state,
        event=event,
        input_hash=None,
        output_hash=compute_hash(output),
        duration_ms=duration_ms,
        error_class=error_class,
        error_message=truncated,
    )


# ---------------------------------------------------------------------------
# Phase 181: SSE emission (D-02)
# ---------------------------------------------------------------------------


async def emit_transition_event(
    *,
    run_id: str,
    seq: int,
    from_state: str | None,
    to_state: str,
    event: str,
    duration_ms: int | None,
    error_class: str | None,
    error_message: str | None,
    happened_at: datetime,
) -> None:
    """Best-effort XADD of a transition event onto the per-run progress stream.

    Called by the engine AFTER the outer DB commit succeeds (D-02). The
    Redis stream key ``task:{run_id}:progress`` is shared with the existing
    ``ProgressStream`` used by ``GET /tasks/{id}/events`` SSE: consumers
    discriminate on the ``type`` field.

    Contract (Phase 181 D-03):
        - Fields are all strings (Redis stream values) or stringified
          numerics/None -> empty string.
        - ``type="transition"`` lets the SSE generator emit an
          ``event: transition`` frame instead of the default
          ``event: progress``.
        - ``error_message`` is passed through VERBATIM -- already redacted
          at write time (Phase 178 ``WorkflowSafeMessage``, 2000-char cap).

    Failure modes (T-181-08 accepted):
        - Redis unreachable / Memurai offline -> WARNING log, return.
        - XADD raises for any reason -> WARNING log, return.
        - Never re-raises. The engine commit has already landed; losing
          the SSE fan-out must not roll it back.
    """
    try:
        # Local import: avoid importing Redis plumbing at module-load
        # time so ``log.py`` stays importable in contexts (tests, CLI)
        # where the Redis pool is not initialised.
        from aila.platform.tasks.progress import ProgressStream

        stream = ProgressStream()
        fields: dict[str, str] = {
            "type": "transition",
            "run_id": run_id,
            "seq": str(seq),
            "from_state": from_state if from_state is not None else "",
            "to_state": to_state,
            "event": event,
            "duration_ms": "" if duration_ms is None else str(duration_ms),
            "error_class": error_class if error_class is not None else "",
            # D-08: pre-redacted at write time, pass through verbatim.
            "error_message": error_message if error_message is not None else "",
            "happened_at": happened_at.isoformat(),
            "task_id": run_id,
        }
        # Reuse ProgressStream's private key format + maxlen/approximate
        # contract. Calling xadd directly via the shared Redis pool
        # mirrors ``ProgressStream.emit`` without adding a new public
        # method (scope discipline).
        from aila.platform.services.redis_pool import get_redis

        key = ProgressStream._KEY_FMT.format(task_id=run_id)
        async with get_redis() as client:
            await client.xadd(
                key,
                fields,
                maxlen=stream._maxlen,
                approximate=False,
            )
    except Exception:
        _log.warning(
            "transition emit failed (run_id=%s seq=%s)",
            run_id,
            seq,
            exc_info=True,
        )

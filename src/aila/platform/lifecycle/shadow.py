"""RFC-10 shadow runner (G2): off-path replay report over recorded turns.

Complements :mod:`aila.platform.lifecycle.controller`. Where the controller's
``shadow`` method REGISTERS a candidate as an off-path assignment (so the
router keeps handing production to every real turn), this module ACTUALLY
RUNS the off-path comparison: it samples recent recorded turns, rebuilds
each into an :class:`aila.platform.eval.transcript.EvalTranscriptRecord`
via :class:`TranscriptRecorder`, and replays each transcript under the
candidate version through :meth:`aila.platform.eval.runner.EvalRunner.replay`.
The per-turn :class:`DecisionDiff` results are aggregated into a single
:class:`ShadowReportRecord` row (mean faithfulness, mean determinism, count
of replays whose faithfulness falls below a floor) and a SHADOW-to-SHADOW
metrics-update row is journaled so an inspector sees the report id inline
with the transition history.

Off the critical path by construction:

* Reads only already-persisted data (``llm_idempotency_cache`` +
  ``llm_cost_records`` + ``platform_journal``) via ``TranscriptRecorder``,
  never touches a live investigation's state.
* Runs zero production LLM calls -- the replay bridge issues its own
  requests against the candidate prompt body, and the fake client
  injected by tests substitutes deterministic responses.
* Only fires when an operator hits the admin endpoint OR a scheduled job
  triggers ``run_shadow`` explicitly; the module never registers a hook
  on the live turn path.

A single broken or missing transcript SKIPS that sample (increments
``sample_attempted`` without ``sample_succeeded``) and logs the reason;
one dropped tuple must never abort the whole run.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Field, SQLModel, select

from aila.platform.contracts import utc_now
from aila.platform.eval.replay import ReplayError
from aila.platform.eval.runner import EvalRunner
from aila.platform.eval.transcript import (
    TranscriptAssemblyError,
    TranscriptRecorder,
)
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.llm.idempotency_cache import LLMIdempotencyCache
from aila.storage.database import async_session_scope

if TYPE_CHECKING:
    from aila.platform.eval.replay import ReplayLLMClient
    from aila.platform.lifecycle.controller import AgentLifecycleController

__all__ = [
    "DEFAULT_FAITHFULNESS_FLOOR",
    "ShadowReportRecord",
    "latest_shadow_report",
    "run_shadow",
]

_log = logging.getLogger(__name__)

# Floor below which a per-sample faithfulness score counts as a
# regression on the shadow report. 0.9 is the same operational band the
# RFC-08 replay harness uses for "meaningfully different from the
# recorded decision"; a run whose ``regressions`` count is non-zero
# tells the operator at least one sample diverged enough that the
# original prompt would not have reproduced the recorded decision on
# most of its fields.
DEFAULT_FAITHFULNESS_FLOOR: float = 0.9


class ShadowReportRecord(SQLModel, table=True):
    """One shadow run summary: aggregate replay-diff metrics per (key, version).

    ``assignment_id`` is nullable because a report may be produced for a
    (key, version) whose active shadow assignment was later superseded;
    keeping the id lets an inspection re-attach the report to the row
    that was live at run time even if the current active assignment
    points at a newer version. ``diff_summary_json`` carries the raw
    per-sample summary (transcript_id, faithfulness, determinism, and
    the per-field diff report) plus the attempt trail for skipped
    tuples so the operator inspection surfaces WHY a run collected
    fewer successes than attempts without a second query.
    """

    __tablename__ = "lifecycle_shadow_reports"
    __table_args__ = (
        Index(
            "ix_lifecycle_shadow_reports_key_version_created",
            "key", "version", "created_at",
        ),
        Index(
            "ix_lifecycle_shadow_reports_created_at", "created_at",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256, index=True)
    version: str = Field(max_length=32)
    assignment_id: str | None = Field(default=None, max_length=64)
    sample_attempted: int = Field(default=0)
    sample_succeeded: int = Field(default=0)
    mean_faithfulness: float = Field(default=0.0)
    mean_determinism: float = Field(default=0.0)
    regressions: int = Field(default=0)
    diff_summary_json: str = Field(default="{}", sa_type=Text)
    actor: str = Field(default="", max_length=128)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )


async def run_shadow(
    *,
    controller: AgentLifecycleController,
    key: str,
    version: str,
    sample_n: int = 5,
    actor: str = "shadow_runner",
    llm_client: ReplayLLMClient | None = None,
    faithfulness_floor: float = DEFAULT_FAITHFULNESS_FLOOR,
) -> ShadowReportRecord:
    """Sample recent turns, replay under ``version``, persist a report row.

    Guard: the (key, version) pair MUST already be the ACTIVE shadow
    assignment for the key -- else raises
    :class:`aila.platform.lifecycle.controller.StageTransitionError`.
    The shadow assignment is what the controller's ``shadow`` method
    writes; running a report against a candidate that never entered
    shadow would compare the wrong thing.

    Sampling: reads recent tuples from ``llm_idempotency_cache`` (the
    same substrate ``TranscriptRecorder`` reads) with turn_number set,
    preferring rows whose ``llm_cost_records.task_type`` matches the
    second half of the key (``vr/decide`` -> ``decide``). Rows without
    a companion cost record are excluded up front because
    ``record_from_history`` cannot rebuild them.

    Per-sample: rebuild the transcript, run one replay through
    ``EvalRunner.replay``. A :class:`TranscriptAssemblyError` /
    :class:`ReplayError` / DB error SKIPS that sample (bumps
    ``sample_attempted`` without ``sample_succeeded``) and appends a
    ``status='skipped'`` row to ``diff_summary.attempts``; the run
    continues to the next candidate tuple until ``sample_n``
    successes accumulate or the pool is exhausted.

    Persistence: writes exactly one :class:`ShadowReportRecord` row and
    one SHADOW-to-SHADOW :class:`LifecycleTransitionRecord` row whose
    ``metrics_snapshot_json`` embeds the report id + aggregates so the
    transition journal is a self-describing audit of when a shadow run
    happened, who ran it, and what it saw.

    Off the critical path: reads recorded state, writes report rows,
    zero effect on any live investigation.
    """
    # Deferred import: controller imports shadow indirectly at
    # module-load time through admin_lifecycle; keeping this import
    # inside the function keeps the module cycle-safe.
    from aila.platform.lifecycle.controller import StageTransitionError
    from aila.platform.lifecycle.models import (
        LifecycleStage,
        LifecycleTransitionRecord,
    )

    if sample_n <= 0:
        raise ValueError("sample_n must be positive")
    if faithfulness_floor < 0.0 or faithfulness_floor > 1.0:
        raise ValueError("faithfulness_floor must sit in [0.0, 1.0]")

    active = await controller.active_shadow(key)
    if active is None or active.version != version:
        raise StageTransitionError(
            f"cannot run_shadow key={key!r} version={version!r}: no ACTIVE "
            "shadow assignment on record for this (key, version)",
        )
    assignment_id = active.id
    module_id, task_type_hint = _split_key(key)

    tuples = await _sample_recent_tuples(
        task_type_hint=task_type_hint, sample_n=sample_n,
    )

    recorder = TranscriptRecorder()
    runner = EvalRunner()

    attempted = 0
    succeeded = 0
    faithfulness_sum = 0.0
    determinism_sum = 0.0
    regressions = 0
    attempts: list[dict[str, Any]] = []
    successes: list[dict[str, Any]] = []

    for inv_id, branch_id, turn_number in tuples:
        if succeeded >= sample_n:
            break
        attempted += 1
        try:
            transcript_id = await recorder.record_from_history(
                investigation_id=inv_id,
                branch_id=branch_id,
                turn_number=turn_number,
                module_id=module_id,
                prompt_key_override=key,
            )
        except TranscriptAssemblyError as exc:
            _log.info(
                "run_shadow skip inv=%s branch=%s turn=%s: transcript "
                "assembly failed: %s",
                inv_id, branch_id, turn_number, exc,
            )
            attempts.append({
                "investigation_id": inv_id,
                "branch_id": branch_id,
                "turn_number": turn_number,
                "status": "skipped",
                "stage": "assemble",
                "reason": str(exc),
            })
            continue
        try:
            diff = await runner.replay(
                transcript_id=transcript_id,
                candidate_version=version,
                llm_client=llm_client,
            )
        except (ReplayError, SQLAlchemyError) as exc:
            _log.info(
                "run_shadow replay skip transcript=%s: %s: %s",
                transcript_id, type(exc).__name__, exc,
            )
            attempts.append({
                "investigation_id": inv_id,
                "branch_id": branch_id,
                "turn_number": turn_number,
                "status": "skipped",
                "stage": "replay",
                "transcript_id": transcript_id,
                "reason": f"{type(exc).__name__}: {exc}",
            })
            continue

        succeeded += 1
        faithfulness_sum += diff.faithfulness
        determinism_sum += diff.determinism_score
        if diff.faithfulness < faithfulness_floor:
            regressions += 1
        successes.append({
            "transcript_id": diff.transcript_id,
            "investigation_id": inv_id,
            "branch_id": branch_id,
            "turn_number": turn_number,
            "faithfulness": diff.faithfulness,
            "determinism_score": diff.determinism_score,
            "faithful": diff.faithful,
            "field_diffs": diff.field_diffs,
        })
        attempts.append({
            "investigation_id": inv_id,
            "branch_id": branch_id,
            "turn_number": turn_number,
            "status": "ok",
            "transcript_id": diff.transcript_id,
        })

    mean_faithfulness = (
        faithfulness_sum / succeeded if succeeded > 0 else 0.0
    )
    mean_determinism = (
        determinism_sum / succeeded if succeeded > 0 else 0.0
    )

    diff_summary = {
        "faithfulness_floor": faithfulness_floor,
        "candidate_pool_size": len(tuples),
        "attempts": attempts,
        "successes": successes,
    }

    record = ShadowReportRecord(
        key=key,
        version=version,
        assignment_id=assignment_id,
        sample_attempted=attempted,
        sample_succeeded=succeeded,
        mean_faithfulness=mean_faithfulness,
        mean_determinism=mean_determinism,
        regressions=regressions,
        diff_summary_json=json.dumps(diff_summary),
        actor=actor,
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)

    # Journal a SHADOW-to-SHADOW metrics-update row so the transition
    # timeline surfaces the report id + aggregates inline. A metrics
    # update is a legitimate transition kind: from_stage == to_stage
    # is permitted by the journal schema and communicates "same stage,
    # new observation."
    journal_snapshot: dict[str, Any] = {
        "assignment_kind": "shadow",
        "shadow_report_id": record.id,
        "assignment_id": assignment_id,
        "sample_attempted": attempted,
        "sample_succeeded": succeeded,
        "mean_faithfulness": mean_faithfulness,
        "mean_determinism": mean_determinism,
        "regressions": regressions,
        "faithfulness_floor": faithfulness_floor,
    }
    journal_row = LifecycleTransitionRecord(
        key=key,
        version=version,
        from_stage=LifecycleStage.SHADOW.value,
        to_stage=LifecycleStage.SHADOW.value,
        actor=actor,
        reason="shadow run report",
        metrics_snapshot_json=json.dumps(journal_snapshot),
    )
    async with async_session_scope() as session:
        session.add(journal_row)
        await session.commit()

    _log.info(
        "run_shadow key=%s version=%s attempted=%d succeeded=%d "
        "mean_faithfulness=%.4f mean_determinism=%.4f regressions=%d",
        key, version, attempted, succeeded,
        mean_faithfulness, mean_determinism, regressions,
    )
    return record


async def latest_shadow_report(
    *, key: str, version: str,
) -> ShadowReportRecord | None:
    """Return the newest shadow report for (key, version), or None."""
    async with async_session_scope() as session:
        row = (await session.exec(
            select(ShadowReportRecord)
            .where(
                ShadowReportRecord.key == key,
                ShadowReportRecord.version == version,
            )
            .order_by(ShadowReportRecord.created_at.desc())
            .limit(1)
        )).first()
    return row


def _split_key(key: str) -> tuple[str, str]:
    """Return (module_id, task_type) from a ``module/task_type`` key.

    A key without a slash yields the whole key as module_id and an
    empty task_type; the sampling path then falls back to any recent
    turn instead of task-type-filtered ones.
    """
    if "/" in key:
        module_id, _, task_type = key.partition("/")
        return module_id, task_type
    return key, ""


async def _sample_recent_tuples(
    *, task_type_hint: str, sample_n: int,
) -> list[tuple[str, str | None, int]]:
    """Return recent ``(investigation_id, branch_id, turn_number)`` tuples.

    Preference order:

    1. Recent :class:`LLMCostRecord` rows whose ``task_type`` matches
       ``task_type_hint`` (the module-owning task type for this key).
       These are the highest-signal candidates because their prompt
       version + task_type already align with what the shadow candidate
       replaces.
    2. Backfill from recent :class:`LLMIdempotencyCache` rows with
       ``turn_number`` set to hit ``sample_n * 4`` total candidates,
       de-duplicated by ``(investigation_id, branch_id, turn_number)``.

    Cost row prefiltering excludes cache rows that
    ``record_from_history`` would raise on for missing cost data; the
    backfill still admits cache-only tuples because a cost record may
    exist for the same tuple even when the specific task_type filter
    misses (e.g. a legacy record with an empty task_type).
    """
    headroom = max(sample_n * 4, sample_n + 1)
    picks: list[tuple[str, str | None, int]] = []
    seen: set[tuple[str, str | None, int]] = set()

    async with async_session_scope() as session:
        if task_type_hint:
            stmt_pref = (
                select(
                    LLMCostRecord.investigation_id,
                    LLMCostRecord.branch_id,
                    LLMCostRecord.turn_number,
                )
                .where(
                    LLMCostRecord.task_type == task_type_hint,
                    LLMCostRecord.investigation_id.is_not(None),  # type: ignore[union-attr]
                    LLMCostRecord.turn_number.is_not(None),  # type: ignore[union-attr]
                )
                .order_by(LLMCostRecord.created_at.desc())
                .limit(headroom)
            )
            try:
                rows_pref = (await session.exec(stmt_pref)).all()
            except SQLAlchemyError as exc:
                _log.warning(
                    "run_shadow preferred-sample lookup failed for "
                    "task_type=%s: %s",
                    task_type_hint, exc,
                )
                rows_pref = []
            for inv, br, turn in rows_pref:
                if inv is None or turn is None:
                    continue
                tup = (str(inv), br, int(turn))
                if tup in seen:
                    continue
                seen.add(tup)
                picks.append(tup)

        # Backfill from any recent cache row so a fresh module without
        # a task_type match still produces a candidate pool.
        remaining = headroom - len(picks)
        if remaining > 0:
            stmt_any = (
                select(
                    LLMIdempotencyCache.investigation_id,
                    LLMIdempotencyCache.branch_id,
                    LLMIdempotencyCache.turn_number,
                )
                .where(
                    LLMIdempotencyCache.turn_number.is_not(None),  # type: ignore[union-attr]
                )
                .order_by(LLMIdempotencyCache.created_at.desc())
                .limit(remaining)
            )
            try:
                rows_any = (await session.exec(stmt_any)).all()
            except SQLAlchemyError as exc:
                _log.warning(
                    "run_shadow backfill-sample lookup failed: %s", exc,
                )
                rows_any = []
            for inv, br, turn in rows_any:
                if inv is None or turn is None:
                    continue
                tup = (str(inv), br, int(turn))
                if tup in seen:
                    continue
                seen.add(tup)
                picks.append(tup)

    return picks

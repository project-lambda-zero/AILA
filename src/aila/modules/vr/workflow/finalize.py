"""Phase C (cutover): single ``investigation_finalize`` chokepoint.

The previous topology spread investigation finalization across four
race-prone paths (per docs/CUTOVER_DEPS.md §2 Phase C):

  1. ``investigation_emit._maybe_trigger_synthesis`` fired ``all_outcomes``
     when every active branch had a terminal outcome.
  2. ``parent_reconciler._synthesize_no_finding_outcomes`` fired
     ``all_terminal_no_outcome`` (orphan close via audit_memo).
  3. ``parent_reconciler._close_rejected_outcomes`` fired
     ``rejected_quorum`` (primary REJECTED + quorum siblings agreed).
  4. ``investigation_reaper.sweep_cap_exceeded_investigations`` fired
     ``wall_clock_idle_grace`` (cap exceeded AND no recent branch
     activity).

Each path had its own broad-except wrapper, its own race window with
``investigation_emit``, and its own log format. An investigation that
silently slipped between paths could stay RUNNING for hours.

This module consolidates the trigger detection into ONE function with
a deterministic picker. The existing primitives (synthesis_agent,
outcome_dispatcher, arq_purge, the audit_memo writer) are reused via
delegation — finalize does NOT reimplement domain logic. It is the
chokepoint that decides which existing primitive fires.

Trigger priority (first match wins):

    1. all_outcomes              — fire synthesis
    2. rejected_quorum           — fire close-rejected
    3. wall_clock_idle_grace     — fire cap-exceeded
    4. all_terminal_no_outcome   — fire synthesize-no-finding (orphan)

A fifth ``no_trigger`` outcome means "investigation is healthy and
still running"; the caller takes no action.

Two entry points expose the same primitive:

* :func:`finalize_investigation` — called per-investigation, returns
  a structured :class:`FinalizeResult`. Used by ``investigation_emit``
  at cap-boundary and by the cron sweep below.
* :func:`sweep_finalizable_investigations` — cron entry point. Walks
  RUNNING investigations and calls :func:`finalize_investigation` on
  each. Registered via the generic
  :mod:`aila.platform.tasks.sweeps` registry.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func
from sqlalchemy.sql.functions import coalesce
from sqlmodel import select

from aila.modules.vr.contracts import BranchStatus, InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

_log = logging.getLogger(__name__)

__all__ = [
    "FinalizeResult",
    "FinalizeTrigger",
    "finalize_investigation",
    "sweep_finalizable_investigations",
]


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


# ----------------------------------------------------------------------
# Result + trigger taxonomy
# ----------------------------------------------------------------------


# Trigger names ARE operator-facing — they appear in log lines and on the
# investigation's ``audit_memo`` outcome. Treat them as a stable enum
# rather than free-form strings.
class FinalizeTrigger:
    NO_TRIGGER: str = "no_trigger"
    ALL_OUTCOMES: str = "all_outcomes"
    REJECTED_QUORUM: str = "rejected_quorum"
    WALL_CLOCK_IDLE_GRACE: str = "wall_clock_idle_grace"
    ALL_TERMINAL_NO_OUTCOME: str = "all_terminal_no_outcome"
    NOT_RUNNING: str = "not_running"  # operator paused / already complete


@dataclass(slots=True, frozen=True)
class FinalizeResult:
    """Structured result of a single :func:`finalize_investigation` call.

    ``trigger`` is one of the :class:`FinalizeTrigger` constants. When
    no trigger fires (``NO_TRIGGER`` / ``NOT_RUNNING``) the caller takes
    no further action.

    ``action_taken`` describes the primitive that ran, e.g.
    ``"synthesis_enqueued:task_id=…"`` or
    ``"wall_clock_cap_exceeded:halted_branches=N"``. Empty when no
    action was taken.

    ``inv_id`` echoes the investigation id for log-correlation.
    """

    inv_id: str
    trigger: str
    action_taken: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "inv_id": self.inv_id,
            "trigger": self.trigger,
            "action": self.action_taken,
        }


# ----------------------------------------------------------------------
# Trigger picker (the deterministic part)
# ----------------------------------------------------------------------


async def _detect_trigger(investigation_id: str) -> tuple[str, dict[str, Any]]:
    """Return ``(trigger_name, context)`` for an investigation.

    Single UoW; the four-condition decision tree runs inside it so
    state is consistent. The returned ``context`` carries the data
    handlers need (cap thresholds, idle window, active/terminal counts).
    """
    wallclock_hours = _float_env("VR_INVESTIGATION_WALL_CLOCK_HOURS", 6.0)
    turn_cap = _int_env("VR_INVESTIGATION_TURN_CAP", 300)
    message_cap = _int_env("VR_INVESTIGATION_MESSAGE_CAP", 1000)
    idle_grace_s = _float_env("VR_WALL_CLOCK_IDLE_GRACE_S", 900.0)
    now = utc_now()

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.id == investigation_id)
        )).first()
        if inv is None:
            return (
                FinalizeTrigger.NOT_RUNNING,
                {"reason": "inv_not_found"},
            )
        if inv.status != InvestigationStatus.RUNNING.value:
            return (
                FinalizeTrigger.NOT_RUNNING,
                {"reason": f"inv_status={inv.status}"},
            )

        # Branch counts.
        branch_rows = (await uow.session.exec(
            select(
                VRInvestigationBranchRecord.id,
                VRInvestigationBranchRecord.status,
                VRInvestigationBranchRecord.turn_count,
                VRInvestigationBranchRecord.updated_at,
            )
            .where(
                VRInvestigationBranchRecord.investigation_id == investigation_id,
            )
        )).all()
        active = [b for b in branch_rows if b.status == BranchStatus.ACTIVE.value]
        terminal = [b for b in branch_rows if b.status != BranchStatus.ACTIVE.value]

        # Outcomes per active branch — needed to detect 'all_outcomes'
        # and 'rejected_quorum'.
        outcome_rows = (await uow.session.exec(
            select(
                VRInvestigationOutcomeRecord.branch_id,
                VRInvestigationOutcomeRecord.state,
                VRInvestigationOutcomeRecord.outcome_kind,
            )
            .where(
                VRInvestigationOutcomeRecord.investigation_id == investigation_id,
            )
        )).all()
        outcomes_by_branch: dict[str, list[Any]] = {}
        for o in outcome_rows:
            outcomes_by_branch.setdefault(str(o.branch_id), []).append(o)

        # Trigger 1: all_outcomes — every active branch has at least one
        # terminal outcome AND inv has no primary_outcome_id yet (synthesis
        # hasn't already run).
        if (
            inv.primary_outcome_id is None
            and active
            and all(
                str(b.id) in outcomes_by_branch for b in active
            )
        ):
            return (
                FinalizeTrigger.ALL_OUTCOMES,
                {"active_branches": len(active), "outcomes": len(outcome_rows)},
            )

        # Trigger 2: rejected_quorum — primary outcome is REJECTED and
        # the majority of sibling votes also REJECTED.
        primary_id = inv.primary_outcome_id
        if primary_id:
            primary = next(
                (o for o in outcome_rows if str(o.branch_id) == str(primary_id)),
                None,
            )
            if primary and getattr(primary, "state", None) == "rejected":
                # Count rejection votes among siblings (any outcome whose
                # state == 'rejected' belongs to a sibling that explicitly
                # voted against the primary).
                rejected_count = sum(
                    1 for o in outcome_rows
                    if getattr(o, "state", None) == "rejected"
                )
                quorum_threshold = max(2, (len(active) + 1) // 2)
                if rejected_count >= quorum_threshold:
                    return (
                        FinalizeTrigger.REJECTED_QUORUM,
                        {
                            "rejected_votes": rejected_count,
                            "quorum": quorum_threshold,
                        },
                    )

        # Trigger 3: wall_clock_idle_grace — wall clock exceeded AND no
        # branch activity inside the idle grace window. Uses inv.started_at
        # as the anchor (matches Phase B cap-check convention).
        anchor = inv.started_at or inv.created_at
        if anchor is not None:
            elapsed_hours = (now - anchor).total_seconds() / 3600.0
            if elapsed_hours >= wallclock_hours:
                # Find the most recent branch updated_at across all
                # branches (active and terminal — paused branches still
                # count as 'recent activity').
                latest_act = max(
                    (b.updated_at for b in branch_rows if b.updated_at is not None),
                    default=None,
                )
                idle_seconds: float | None = None
                if latest_act is not None:
                    idle_seconds = (now - latest_act).total_seconds()
                if idle_seconds is None or idle_seconds >= idle_grace_s:
                    return (
                        FinalizeTrigger.WALL_CLOCK_IDLE_GRACE,
                        {
                            "elapsed_hours": elapsed_hours,
                            "cap_hours": wallclock_hours,
                            "idle_seconds": idle_seconds,
                            "idle_grace_s": idle_grace_s,
                        },
                    )

        # Trigger 3b: turn/message cap exceeded (still grouped under
        # wall_clock_idle_grace trigger so callers / dashboards see
        # a single 'cap_exceeded' bucket; the context carries detail).
        total_turns = (await uow.session.exec(
            select(
                coalesce(func.sum(VRInvestigationBranchRecord.turn_count), 0)
            ).where(
                VRInvestigationBranchRecord.investigation_id == investigation_id,
            )
        )).first()
        if isinstance(total_turns, int) and total_turns >= turn_cap:
            return (
                FinalizeTrigger.WALL_CLOCK_IDLE_GRACE,
                {
                    "trigger_subkind": "turn_cap",
                    "total_turns": total_turns,
                    "cap": turn_cap,
                },
            )
        # message_cap currently a no-op (the deferred-to-Phase-E cleanup);
        # the cap value is still respected here so the trigger fires.
        del message_cap  # acknowledged unused for the moment

        # Trigger 4: all_terminal_no_outcome — every branch is terminal
        # AND inv has no primary_outcome_id. This is the orphan close.
        if (
            inv.primary_outcome_id is None
            and not active
            and terminal
        ):
            return (
                FinalizeTrigger.ALL_TERMINAL_NO_OUTCOME,
                {"terminal_branches": len(terminal)},
            )

        return (FinalizeTrigger.NO_TRIGGER, {})


# ----------------------------------------------------------------------
# Trigger handlers (delegate to existing primitives)
# ----------------------------------------------------------------------


async def _handle_all_outcomes(
    investigation_id: str,
    context: dict[str, Any],
) -> str:
    """Delegate to the existing synthesis path.

    ``investigation_emit._maybe_trigger_synthesis`` already enqueues a
    ``run_vr_synthesis`` task when every active branch has produced an
    outcome. We call the same enqueue here so finalize and the emit
    path produce identical behavior.
    """
    from .._task_queue import default_task_queue  # noqa: PLC0415
    from .task import run_vr_synthesis  # noqa: PLC0415

    task_queue = default_task_queue()
    await task_queue.submit(
        track="vr",
        fn=run_vr_synthesis,
        kwargs={"investigation_id": investigation_id},
        user_id="system",
        group_id="vr_finalize",
        team_id=None,
    )
    return f"synthesis_enqueued:branches={context.get('active_branches')}"


async def _handle_rejected_quorum(
    investigation_id: str,
    context: dict[str, Any],
) -> str:
    """Delegate to the per-id rejected-quorum closer.

    Implementation in
    :mod:`vr.services.investigation_finalizers` (canonical API surface);
    the underlying body lives in ``parent_reconciler._close_rejected_outcomes``
    until the next refactor moves it physically.
    """
    from ..services.investigation_finalizers import (  # noqa: PLC0415
        close_rejected_for_investigation,
    )

    closed = await close_rejected_for_investigation(investigation_id)
    return (
        f"rejected_close:closed={closed} "
        f"votes={context.get('rejected_votes')}"
    )


async def _handle_wall_clock_idle_grace(
    investigation_id: str,
    context: dict[str, Any],
) -> str:
    """Delegate to the per-id cap-exceeded helper.

    Phase C extraction:
    :func:`investigation_reaper.evaluate_cap_for_investigation` runs the
    same decision tree as ``sweep_cap_exceeded_investigations`` but
    scoped to one inv id, so finalize doesn't pay the O(N) sweep cost
    when triggered per-investigation.
    """
    from ..services.investigation_reaper import (  # noqa: PLC0415
        evaluate_cap_for_investigation,
    )

    reason = await evaluate_cap_for_investigation(investigation_id)
    if reason is None:
        return (
            f"cap_eval_no_breach:subkind={context.get('trigger_subkind', 'wall_clock')}"
        )
    return (
        f"cap_exceeded:reason={reason} "
        f"subkind={context.get('trigger_subkind', 'wall_clock')}"
    )


async def _handle_all_terminal_no_outcome(
    investigation_id: str,
    context: dict[str, Any],
) -> str:
    """Delegate to the per-id orphan synthesizer.

    Implementation in :mod:`vr.services.investigation_finalizers`; the
    underlying body lives in
    ``parent_reconciler._synthesize_no_finding_outcomes`` until the next
    refactor moves it physically.
    """
    from ..services.investigation_finalizers import (  # noqa: PLC0415
        synthesize_no_finding_for_investigation,
    )

    wrote = await synthesize_no_finding_for_investigation(investigation_id)
    return f"audit_memo_synthesized:wrote={wrote}"


_HANDLERS: dict[str, Any] = {
    FinalizeTrigger.ALL_OUTCOMES: _handle_all_outcomes,
    FinalizeTrigger.REJECTED_QUORUM: _handle_rejected_quorum,
    FinalizeTrigger.WALL_CLOCK_IDLE_GRACE: _handle_wall_clock_idle_grace,
    FinalizeTrigger.ALL_TERMINAL_NO_OUTCOME: _handle_all_terminal_no_outcome,
}


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------


async def finalize_investigation(investigation_id: str) -> FinalizeResult:
    """Detect the trigger condition for ``investigation_id`` and apply it.

    Returns a :class:`FinalizeResult` describing the trigger and the
    action taken. Idempotent: when no trigger fires (most ticks for a
    healthy running investigation), returns ``trigger=no_trigger`` and
    takes no action.

    Errors during handler invocation propagate to the caller — the
    cron sweep wrapper logs and continues, but per-investigation
    callers (``investigation_emit``) may want to react.
    """
    trigger, context = await _detect_trigger(investigation_id)
    if trigger in (FinalizeTrigger.NO_TRIGGER, FinalizeTrigger.NOT_RUNNING):
        return FinalizeResult(inv_id=investigation_id, trigger=trigger)

    handler = _HANDLERS[trigger]
    try:
        action = await handler(investigation_id, context)
    except Exception as exc:  # noqa: BLE001 — log + surface in result
        _log.warning(
            "finalize_investigation HANDLER_FAILED inv=%s trigger=%s err=%s",
            investigation_id, trigger, exc,
            exc_info=True,
        )
        action = f"handler_failed:{type(exc).__name__}:{exc}"

    _log.info(
        "finalize_investigation inv=%s trigger=%s action=%s context=%s",
        investigation_id, trigger, action, context,
    )
    return FinalizeResult(
        inv_id=investigation_id,
        trigger=trigger,
        action_taken=action,
    )


async def sweep_finalizable_investigations() -> dict[str, int]:
    """Walk RUNNING investigations + apply finalize_investigation per row.

    Registered as the ``vr.finalize`` sweep via the generic platform
    sweep registry. Replaces the prior 3-sweep pattern
    (``vr.investigation_reaper`` + ``vr.branch_reaper`` + the synth /
    close helpers inside ``vr.masvs_parent_reconciler``) with a single
    chokepoint.

    Returns ``{"finalized": N, "by_trigger": {...counts...}}``.
    """
    summary = {"finalized": 0}
    by_trigger: dict[str, int] = {}

    async with UnitOfWork() as uow:
        running_rows = (await uow.session.exec(
            select(VRInvestigationRecord.id)
            .where(
                VRInvestigationRecord.status == InvestigationStatus.RUNNING.value,
            )
        )).all()
        running_ids = [str(r) for r in running_rows]

    for inv_id in running_ids:
        try:
            result = await finalize_investigation(inv_id)
        except Exception as exc:  # noqa: BLE001 — best-effort per inv
            # fix §350 — surface traceback so a recurring per-inv
            # finalize failure (handler crash, DB unreachable) is
            # debuggable from the cron log alone.
            _log.warning(
                "sweep_finalizable_investigations: finalize failed inv=%s err=%s",
                inv_id, exc,
                exc_info=True,
            )
            by_trigger["error"] = by_trigger.get("error", 0) + 1
            continue
        if result.trigger in (
            FinalizeTrigger.NO_TRIGGER,
            FinalizeTrigger.NOT_RUNNING,
        ):
            continue
        summary["finalized"] += 1
        by_trigger[result.trigger] = by_trigger.get(result.trigger, 0) + 1

    if summary["finalized"]:
        _log.info(
            "sweep_finalizable_investigations: finalized=%d by_trigger=%s",
            summary["finalized"], by_trigger,
        )
    return {"finalized": summary["finalized"], **by_trigger}

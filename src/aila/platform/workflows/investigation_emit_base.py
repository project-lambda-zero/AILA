"""Investigation emit state factory (RFC-02 Phase 4c).

Extracted from the vr and malware emit states (94% identical). The
finalization engine -- auto-continue, the investigation-level cap-exceeded
halt (turns / messages / wall-clock with idle grace), terminal status
resolution, orphan-branch cleanup, the draft-outcome review + dispatch
workflow, the synthesis and adversarial-verifier triggers, knowledge
pattern extraction, and the finalize chokepoint -- is platform-owned.

The one behavioral divergence RFC-02 resolves here: vr read its caps from
module-load ``os.environ`` constants (the os.getenv anti-pattern), while
malware read the same caps live from ``ConfigRegistry``. Both now read
live via the module ``get_int`` / ``get_float`` bindings; the default cap
values are unchanged (overall 500, investigation 300 turns / 1000 msgs /
6.0h / 900s idle grace), so a non-overriding operator sees identical
behavior while vr gains live tunability.

The module binds its record models, task functions (investigate /
synthesis / claim-verifier), ARQ track, config readers, outcome
dispatcher + pattern extractor classes, pattern-store factory,
outcome-review helpers, finalize function, and branch table. The
post-completion proposers are optional hooks (malware sets
propose_pattern / propose_playbook; vr leaves them unset).
"""
from __future__ import annotations

import json
import logging
from datetime import UTC
from typing import Any

from sqlalchemy import func as _func
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import BranchStatus, InvestigationStatus
from aila.platform.llm.client import is_llm_recently_unhealthy
from aila.platform.services.branch_cleanup import close_orphan_branches_on_terminal
from aila.platform.services.factory import ServiceFactory
from aila.platform.services.ledger import LedgerService
from aila.platform.services.outcome_review import summarize_outcome_for_review
from aila.platform.tasks.arq_purge import purge_arq_jobs_for_investigation
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)
from aila.platform.workflows.types import (
    RESERVED_FAILED,
    RESERVED_SUCCEEDED,
    StateResult,
)

_log = logging.getLogger(__name__)

__all__ = ["resolve_final_status", "state_investigation_emit"]

# RFC-13 wiring audit: bound the researcher_error auto_continue path. That
# path re-enqueues on the SAME turn (turn_count is not advanced), so
# overall_turn_cap never trips and a persistently-erroring branch loops
# forever. This per-branch counter is threaded through the auto_continue
# re-enqueue kwargs (``_auto_continue_count``) and forwarded by setup, so
# a hard ceiling stops the runaway independent of turn_count.
_MAX_AUTO_CONTINUE_CYCLES: int = 30

# Operator-requested index-readiness gate. Bounds how many times a run may
# re-enqueue while waiting for its bound code index (graph/trailmark +
# semble) to finish building, so a permanently-broken index cannot
# re-enqueue forever. Each wait re-enqueue fires ZERO agent turns; the
# TaskQueue's same-investigation fairness defer spaces them out. At the
# bound the run finalizes as FAILED (exit_reason ``index_wait_timeout``).
# Raised to cover the operator wall-clock budget (up to 144h): a large-repo
# semble build can OOM-restart and take a long time, and the investigation
# must sit ALIVE on the queue waiting rather than be failed early.
_MAX_INDEX_WAIT_CYCLES: int = 5760

# RFC-13 wiring audit: exit_reasons that mean "the branch or hub is DONE,
# do NOT auto-continue". phase_graph.make_dispatch_router emits the four
# ``hub_*`` reasons at hub->emit transitions; ``tool_loop_blocked`` is the
# tool-executor's breaker signal. Any of these MUST short-circuit
# _should_auto_continue regardless of the historical
# ``exit_reason == 'max_turns'`` matcher.
#
# RFC-13 #68: ``hub_stalled_timeout`` is a distinct reason from
# ``hub_stalled`` -- a stalled hub raises one replan request and stays
# ``hub_stalled`` (COMPLETED, historical behavior) inside the window; if
# no sibling ratifies the replan before ``platform.dispatch_replan_timeout_s``
# elapses, the hub emits ``hub_stalled_timeout`` which flips the
# investigation to STALLED via ``resolve_final_status`` and fires the
# operator escalation from ``phase_graph``.
_NON_CONTINUE_EXIT_REASONS: frozenset[str] = frozenset({
    "hub_complete",
    "hub_stalled",
    "hub_stalled_timeout",
    "hub_budget_exhausted",
    "tool_loop_blocked",
})


def resolve_final_status(exit_reason: str) -> str | None:
    """Pick the final InvestigationStatus given the loop's exit reason.

    Returns None when the status should NOT be touched -- the investigation
    stays RUNNING so sibling branches can continue. Only terminal_submit
    with no active siblings sets COMPLETED (handled in state_investigation_emit
    body, not here). researcher_error returns None so the branch fails
    silently without killing the whole investigation -- other branches
    continue, and auto_continue re-enqueues this branch.

    Pure function -- no closure over bindings/hooks -- so tests can call
    it directly to assert the exit_reason -> status contract without
    building an emit-state handler.
    """
    if exit_reason == "terminal_submit":
        return InvestigationStatus.COMPLETED.value
    if exit_reason == "max_turns":
        return InvestigationStatus.COMPLETED.value
    if exit_reason in ("hub_stalled", "hub_stalled_timeout"):
        # A dispatch-hub stall is NEVER a completion. Operator invariant:
        # a stalled investigation is never interpreted as completed -- it
        # stays STALLED and its only forward move is resume (re-enqueue).
        # ``hub_stalled_timeout`` is the escalated form (replan unratified
        # past ``platform.dispatch_replan_timeout_s``); ``hub_stalled`` is
        # the within-window form. Both mean the hub could not activate a
        # phase -- often with live, unresolved hypotheses and branches cut
        # mid-audit. Mapping either to COMPLETED (the old default
        # fallthrough for ``hub_stalled``) sealed those cut-off runs as if
        # the audit had finished, hiding open leads behind a blank
        # "completed, no outcome" row. STALLED keeps them resumable.
        return InvestigationStatus.STALLED.value
    if exit_reason.startswith(("status_flipped:", "inv_status_flipped:", "branch_status_flipped:")):
        # Loop saw the investigation OR branch flipped underneath it
        # mid-execution -- e.g. operator just paused, sibling just hit
        # terminal_submit, etc. The new status is already authoritative;
        # do NOT overwrite it with a fresh COMPLETED here. The historical
        # bug: only ``status_flipped:`` (no ``inv_`` prefix) was matched,
        # so every ``inv_status_flipped:completed`` reason fell through
        # to the default fallback and triggered a second flip to
        # COMPLETED. Harmless when the prior status WAS completed, but
        # catastrophic on operator reopen -- the moment any worker saw
        # the freshly-set RUNNING state and exited with a transient
        # flipped reason, this path re-flipped to COMPLETED, closing
        # the reopen window inside the same second.
        return None
    if exit_reason.startswith("status_locked:"):
        # Setup hit a PAUSED / COMPLETED / FAILED row and short-circuited.
        # Whatever the operator (or prior cap_exceeded) set is already
        # correct -- emit must NOT overwrite it. Without this, paused
        # investigations get flipped to completed because the default
        # fallthrough below returns COMPLETED.
        return None
    if exit_reason.startswith("researcher_error"):
        # ALL researcher errors (retryable or not) leave status untouched.
        # A single branch hitting a provider 500 should NOT kill the
        # entire investigation. auto_continue will re-enqueue the branch.
        return None
    if exit_reason == "waiting_for_index":
        # Index-readiness gate: the loop ran ZERO turns because the bound
        # code index (graph/trailmark + semble) is still building. This is
        # a deferral, NOT a completion -- leave status untouched so the
        # bounded re-enqueue keeps the run alive until the index is ready.
        return None
    if exit_reason == "index_wait_timeout":
        # The index never became ready within the bounded wait window.
        return InvestigationStatus.FAILED.value
    return InvestigationStatus.COMPLETED.value


def state_investigation_emit(
    bindings: InvestigationStateBindings,
    hooks: InvestigationStateHooks,
) -> Any:
    """Build the emit-state handler bound to *bindings* + *hooks*.

    Returns the ``_handler`` coroutine the workflow engine registers.
    The nested helpers close over *bindings* / *hooks*; they call each
    other at run time, so definition order does not matter.
    """



    async def _should_auto_continue(
        investigation_id: str,
        exit_reason: str,
        outcome_id: Any,
        branch_id: str | None = None,
        auto_continue_count: int = 0,
    ) -> tuple[bool, int]:
        """Decide whether to auto-re-enqueue + return the branch turn count.

        True when the loop hit max_turns without a terminal outcome and the
        branch's cumulative turn_count is still under overall_turn_cap.
        Branch-scoped: when ``branch_id`` is passed (always, from a real
        loop exit), we check THAT branch's turn count, not the primary's.
        Without the branch-scoping, the previous implementation always
        looked at the primary, decided based on its turn count, and the
        sibling auto-continue then enqueued without branch_id \u2192 setup
        defaulted to primary \u2192 siblings starved.

        RFC-13 wiring audit -- two extra guards land here:
          1. ``exit_reason`` in _NON_CONTINUE_EXIT_REASONS (hub_complete /
             hub_stalled / hub_budget_exhausted / tool_loop_blocked) means
             the hub or breaker has already decided the branch is done.
             The old matcher only knew ``max_turns``, so a hub->emit that
             forwarded a stale ``max_turns`` from a prior phase loop
             looked identical to a real cap breach and re-enqueued
             indefinitely (563-task runaway on one investigation).
          2. ``auto_continue_count`` >= _MAX_AUTO_CONTINUE_CYCLES stops
             the researcher_error path from looping forever without
             advancing turn_count.
          3. Investigation status gate: the loop polls status between
             turns, but a ``researcher_error`` break skips that poll.
             When the operator paused the investigation mid-flight, the
             retryable-error path used to re-enqueue unconditionally --
             the fresh run fired setup + LLM calls against a PAUSED
             investigation (observed: pause at 02:36, new run_ids +
             OmniRoute calls continuing at 02:37-02:39). Gate on
             status: PAUSED / terminal (COMPLETED / FAILED / STALLED /
             ABANDONED) never auto-continues.
        """
        if exit_reason in _NON_CONTINUE_EXIT_REASONS:
            _log.info(
                "investigation_emit AUTO_CONTINUE SKIP inv=%s branch=%s "
                "exit_reason=%s (hub/breaker terminal)",
                investigation_id, branch_id, exit_reason,
            )
            return False, 0
        is_any_researcher_error = exit_reason.startswith("researcher_error")
        if (exit_reason != "max_turns" and not is_any_researcher_error) or outcome_id is not None:
            return False, 0
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(bindings.inv_model).where(
                    bindings.inv_model.id == investigation_id,
                )
            )).first()
        if inv is not None:
            inv_status = str(getattr(inv, "status", "") or "")
            if inv_status != InvestigationStatus.RUNNING.value:
                _log.info(
                    "investigation_emit AUTO_CONTINUE SKIP inv=%s branch=%s "
                    "exit_reason=%s status=%s (not RUNNING -- pause/terminal "
                    "gate; loop's between-turn poll was skipped by the "
                    "error break)",
                    investigation_id, branch_id, exit_reason, inv_status,
                )
                return False, 0
        if auto_continue_count >= _MAX_AUTO_CONTINUE_CYCLES:
            _log.warning(
                "investigation_emit AUTO_CONTINUE_CAP_EXCEEDED inv=%s "
                "branch=%s cycles=%d cap=%d exit_reason=%s -- refusing "
                "further re-enqueues; branch stops here even though "
                "turn_count is under overall_turn_cap.",
                investigation_id, branch_id, auto_continue_count,
                _MAX_AUTO_CONTINUE_CYCLES, exit_reason,
            )
            return False, 0
        async with UnitOfWork() as uow:
            if branch_id:
                branch = (await uow.session.exec(
                    _select(bindings.branch_model).where(
                        bindings.branch_model.id == branch_id,
                    )
                )).first()
            else:
                branch = (await uow.session.exec(
                    _select(bindings.branch_model).where(
                        bindings.branch_model.investigation_id == investigation_id,
                    ).order_by(bindings.branch_model.created_at.asc()),
                )).first()
        turn_count = int(branch.turn_count) if branch is not None else 0
        overall_cap = await bindings.get_int("overall_turn_cap")
        if turn_count >= overall_cap:
            return False, turn_count
        return True, turn_count


    async def _enqueue_next_investigation_run(
        investigation_id: str,
        team_id: str | None,
        branch_id: str | None = None,
        dispatch_visited: list[str] | None = None,
        auto_continue_count: int = 0,
        index_wait_count: int = 0,
    ) -> None:
        """Submit the investigate task so the agent continues reasoning on
        the SAME branch it was running.

        Without ``branch_id``, the investigation_setup state defaults to
        the primary branch -- which is correct for ROOT auto-continues
        (single-branch investigations) but WRONG for sibling personas
        (every sibling re-enqueue would silently redirect to primary).
        Always pass branch_id when the caller knows which branch's loop
        just exited.

        RFC-13 wiring audit: ``_dispatch_visited`` and
        ``_auto_continue_count`` ride the re-enqueue kwargs so a resumed
        branch does NOT re-walk every phase the hub already activated,
        and the cycle counter survives across task boundaries. setup
        (investigation_setup_base) forwards both from its input dict
        into its output so the dispatch hub picks them back up.

        Imports are deferred so this module stays import-safe -- the worker
        boots before its ARQ client surface is wired through.
        """
        kwargs: dict[str, Any] = {"investigation_id": investigation_id}
        if branch_id:
            kwargs["branch_id"] = branch_id
        if dispatch_visited:
            # JSON-safe: list[str] serializes cleanly through ARQ + the
            # workflow engine's initial_input dict.
            kwargs["_dispatch_visited"] = list(dispatch_visited)
        if auto_continue_count:
            kwargs["_auto_continue_count"] = int(auto_continue_count)
        if index_wait_count:
            # Bounds the index-readiness wait across re-enqueues so a
            # permanently-broken index cannot re-enqueue forever.
            kwargs["_index_wait_count"] = int(index_wait_count)
        task_queue = bindings.task_queue_factory()
        await task_queue.submit(
            track=bindings.track,
            fn=bindings.task_fn,
            kwargs=kwargs,
            user_id="system",
            group_id=f"{bindings.track}_auto_continue",
            team_id=team_id,
            # AUTO_CONTINUE submits from INSIDE a running task body. Without
            # this flag, dedup_session matches the caller's own
            # TaskRecord (status='running'), returns its id without
            # enqueueing a new task, the worker exits, the queue stays
            # empty, and the branch idles forever. Diagnosed 2026-06-12
            # on inv <inv-uuid-a> maddie branch <inv-uuid-b>.
            bypass_dedup=True,
        )


    async def _handler(input: dict[str, Any], services: Any) -> StateResult:
        """Finalize investigation row + emit terminal payload."""
        del services

        investigation_id = str(input.get("investigation_id") or "")
        branch_id = str(input.get("branch_id") or "") or None
        # RFC-13 wiring audit: default to ``hub_complete`` instead of
        # ``max_turns`` when the input carries no explicit exit_reason.
        # An emit reached via the dispatch hub's clean-completion branch
        # SHOULD not auto_continue; the historical ``max_turns`` default
        # made a hub->emit with a missing reason look like a real cap
        # breach and re-enqueued the branch.
        exit_reason = str(input.get("exit_reason") or "hub_complete")
        outcome_id = input.get("outcome_id")
        # RFC-13 wiring audit: carry the dispatch walk + cycle counter
        # through the re-enqueue path so a resumed branch does not
        # re-walk every phase and the researcher_error loop is bounded.
        dispatch_visited_in = input.get("_dispatch_visited") or []
        auto_continue_count = int(input.get("_auto_continue_count") or 0)

        # Index-readiness deferral (operator-requested gate). The loop ran
        # ZERO turns because the bound code index (graph/trailmark + semble)
        # is still building. Re-enqueue the run (bounded) so it waits on the
        # queue without any agent turn firing. The TaskQueue's own
        # same-investigation fairness defer prevents a tight spin; the wait
        # counter bounds a permanently-broken index. Unreachable unless a
        # module bound ``index_readiness_fn`` (default OFF), so existing
        # modules stay behavior-identical.
        if exit_reason == "waiting_for_index":
            index_wait_count = int(input.get("_index_wait_count") or 0)
            if index_wait_count < _MAX_INDEX_WAIT_CYCLES:
                async with UnitOfWork() as uow:
                    _inv = (await uow.session.exec(
                        _select(bindings.inv_model).where(
                            bindings.inv_model.id == investigation_id,
                        ),
                    )).first()
                    team_id = _inv.team_id if _inv is not None else None
                try:
                    await _enqueue_next_investigation_run(
                        investigation_id, team_id, branch_id=branch_id,
                        dispatch_visited=(
                            list(dispatch_visited_in)
                            if dispatch_visited_in else None
                        ),
                        auto_continue_count=auto_continue_count,
                        index_wait_count=index_wait_count + 1,
                    )
                except (
                    OSError, TimeoutError, RuntimeError, ConnectionError,
                ) as exc:
                    _log.warning(
                        "investigation_emit INDEX_WAIT re-enqueue failed "
                        "inv=%s err=%s -- run stranded until operator "
                        "re-enqueues", investigation_id, exc,
                    )
                    return StateResult(
                        next_state=RESERVED_FAILED,
                        output={
                            "investigation_id": investigation_id,
                            "branch_id": branch_id,
                            "exit_reason": "index_wait_enqueue_failed",
                            "turn_count": 0,
                            "error_class": type(exc).__name__,
                        },
                    )
                _log.info(
                    "investigation_emit WAITING_FOR_INDEX inv=%s wait=%d "
                    "(re-enqueued, zero turns fired)",
                    investigation_id, index_wait_count + 1,
                )
                return StateResult(
                    next_state=RESERVED_SUCCEEDED,
                    output={
                        "investigation_id": investigation_id,
                        "status": InvestigationStatus.RUNNING.value,
                        "exit_reason": "waiting_for_index",
                        "turn_count": 0,
                        "outcome_id": None,
                    },
                )
            # Wait bound reached: stop waiting and finalize as FAILED via
            # the normal path below (resolve_final_status -> FAILED).
            _log.warning(
                "investigation_emit INDEX_WAIT_TIMEOUT inv=%s waits=%d -- "
                "giving up; code index never became ready",
                investigation_id, index_wait_count,
            )
            exit_reason = "index_wait_timeout"

        # Auto-continuation: on max_turns without a terminal outcome, re-
        # enqueue another investigate task so the agent keeps
        # reasoning across task boundaries. Skip the finalization path --
        # status stays RUNNING, no dispatch/extraction, no stopped_at.
        auto_continue, turn_count = await _should_auto_continue(
            investigation_id, exit_reason, outcome_id, branch_id=branch_id,
            auto_continue_count=auto_continue_count,
        )
        if auto_continue:
            async with UnitOfWork() as uow:
                inv = (await uow.session.exec(
                    _select(bindings.inv_model).where(
                        bindings.inv_model.id == investigation_id,
                    ),
                )).first()
                team_id = inv.team_id if inv is not None else None
            try:
                await _enqueue_next_investigation_run(
                    investigation_id, team_id, branch_id=branch_id,
                    dispatch_visited=list(dispatch_visited_in) if dispatch_visited_in else None,
                    auto_continue_count=auto_continue_count + 1,
                )
            except (OSError, TimeoutError, RuntimeError, ConnectionError) as exc:
                # Auto-continue submit failed (Redis down, queue full,
                # serialization error). Without this guard the exception
                # bubbles into the workflow engine which redacts it to a
                # bare class name and parks the cursor in __crashed__
                # without any forward progress -- branch sits "active"
                # leaving turn_count stuck and the operator with no visibility.
                # Mark the cursor crashed loudly + log the full traceback
                # to the worker log so the operator can see why.
                _log.exception(
                    "investigation_emit AUTO_CONTINUE_FAILED investigation_id=%s "
                    "branch_id=%s turn_count=%d err=%s -- branch will be stranded "
                    "until operator re-enqueues; investigation stays RUNNING "
                    "but no further turns will execute on this branch.",
                    investigation_id, branch_id, turn_count, exc,
                )
                return StateResult(
                    next_state=RESERVED_FAILED,
                    output={
                        "investigation_id": investigation_id,
                        "branch_id": branch_id,
                        "exit_reason": "auto_continue_enqueue_failed",
                        "turn_count": turn_count,
                        "error_class": type(exc).__name__,
                    },
                )
            overall_cap_log = await bindings.get_int("overall_turn_cap")
            _log.info(
                "investigation_emit AUTO_CONTINUE investigation_id=%s turn_count=%d "
                "cap=%d (re-enqueued the investigate task)",
                investigation_id, turn_count, overall_cap_log,
            )
            return StateResult(
                next_state=RESERVED_SUCCEEDED,
                output={
                    "investigation_id": investigation_id,
                    "status": InvestigationStatus.RUNNING.value,
                    "exit_reason": "auto_continue",
                    "turn_count": turn_count,
                    "outcome_id": None,
                },
            )

        final_status = resolve_final_status(exit_reason)

        # Outage hold. A hub-terminal exit (hub_complete / hub_budget_exhausted
        # / etc.) that would flip the investigation to COMPLETED with NO
        # outcome, while the LLM has been unhealthy inside the last 10 min, is
        # outage fallout: every turn died at after_turn=0 and the hub walked
        # its once-only phases straight to a terminal exit on empty turns.
        # Marking it COMPLETED here buries a live run as "completed, no
        # finding" and blocks resume -- the exact self-terminating behavior
        # reported on VR-8FD8. Mirror the finalizer guards
        # (synthesize_no_finding / abandon_stale_branches, both keyed on
        # is_llm_recently_unhealthy(600.0)) and demote to STALLED so the run
        # stays resumable and stall_recovery re-enqueues it once the node
        # recovers, instead of self-completing empty.
        if (
            final_status == InvestigationStatus.COMPLETED.value
            and outcome_id is None
            and exit_reason in _NON_CONTINUE_EXIT_REASONS
        ):
            if is_llm_recently_unhealthy(600.0):
                _log.warning(
                    "investigation_emit OUTAGE_HOLD inv=%s exit_reason=%s -- LLM "
                    "unhealthy within last 10 min and no outcome; demoting "
                    "COMPLETED->STALLED so the run resumes instead of self-"
                    "terminating empty",
                    investigation_id, exit_reason,
                )
                final_status = InvestigationStatus.STALLED.value
                exit_reason = "hub_stalled_outage"
            elif exit_reason == "hub_complete":
                # No-outcome hold. A healthy node still self-terminated:
                # the dispatch hub walked its phase graph to a terminal
                # with no finding. Same operator invariant as hub_stalled
                # above -- a no-outcome run is not a completion, it is a
                # hunt with open leads. Sealing it as "completed, no
                # finding" is the premature self-terminate reported on
                # actively-progressing runs (a t2 audit on live RCE
                # surface flipped to completed-empty during a worker
                # restart). STALLED keeps it resumable so stall_recovery
                # re-enqueues it to keep hunting. The genuine terminal is
                # the turn / message / wall-clock cap block below, which
                # still flips to COMPLETED when a real budget is spent; a
                # hub_budget_exhausted or tool_loop_blocked exit is left
                # to complete as before.
                _log.warning(
                    "investigation_emit NO_OUTCOME_HOLD inv=%s exit_reason=%s "
                    "-- hub reached a terminal with no outcome on a healthy "
                    "node; demoting COMPLETED->STALLED so the run stays "
                    "resumable and keeps hunting to the wall-clock cap",
                    investigation_id, exit_reason,
                )
                final_status = InvestigationStatus.STALLED.value
                exit_reason = "hub_complete_no_outcome"

        # Investigation-level caps (turns/messages/wall-clock). If exceeded,
        # halt ALL active branches + flip investigation to COMPLETED with a
        # cap_exceeded reason. Runs before the per-branch logic so a single
        # cap-exceeded check covers every active branch at once instead of
        # waiting for each one to independently trip.
        if investigation_id:



            async with UnitOfWork() as uow:
                inv = (await uow.session.exec(
                    _select(bindings.inv_model).where(
                        bindings.inv_model.id == investigation_id,
                    )
                )).first()
                if inv is not None and inv.status == InvestigationStatus.RUNNING.value:
                    # Cap math counts ONLY turns/messages from branches that
                    # are still live (ACTIVE or PAUSED). Abandoned and
                    # completed branches are sunk cost -- their work has
                    # already happened, their cost has already been paid,
                    # and counting them against the live cap permanently
                    # locks out any operator reopen.
                    #
                    # Observed live on PRIVACY-1 (5a358890): original run
                    # burned 305 turns / 1641 messages with all 6 branches
                    # OOM-stalled and auto-abandoned. Every operator-reopen
                    # then spawned 6 fresh branches at turn_count=0, but
                    # the cap query summed across ALL branches (including
                    # the 5 abandoned ones at 25-84 turns each) and
                    # CAP_EXCEEDED fired within 7 seconds, ARQ-purging the
                    # fresh branches before they could make a single LLM
                    # call. The investigation was permanently dead because
                    # the cap counter never reset.
                    #
                    # Filtering to live branches makes reopen actually
                    # work: the fresh batch starts with 0 inherited turns,
                    # has the full 300-turn / 1000-message budget, and
                    # only re-trips the cap when the NEW round itself
                    # exceeds it.
                    _live_statuses = ("active", "paused")
                    total_turns_row = await uow.session.exec(
                        _select(_func.coalesce(_func.sum(bindings.branch_model.turn_count), 0))
                        .where(bindings.branch_model.investigation_id == investigation_id)
                        .where(bindings.branch_model.status.in_(_live_statuses))  # type: ignore[attr-defined]
                    )
                    total_turns = int(total_turns_row.first() or 0)
                    msg_count_row = await uow.session.exec(
                        _select(_func.count(bindings.message_model.id))
                        .where(bindings.message_model.investigation_id == investigation_id)
                        .where(bindings.message_model.branch_id.in_(  # type: ignore[attr-defined]
                            _select(bindings.branch_model.id).where(
                                bindings.branch_model.investigation_id == investigation_id,
                                bindings.branch_model.status.in_(_live_statuses),  # type: ignore[attr-defined]
                            )
                        ))
                        .where(bindings.message_model.superseded_at.is_(None))
                    )
                    total_messages = int(msg_count_row.first() or 0)
                    # Clock the wall-clock cap from when work ACTUALLY began
                    # (started_at, set on first turn) -- falling back to
                    # created_at when started_at is NULL (very early in the
                    # lifecycle, before the first investigation_setup commit).
                    # Using created_at directly would punish investigations
                    # that sat queued during a long target ingestion: the
                    # moment a worker picked them up they'd insta-cap with
                    # zero actual execution time. See the observed incident
                    # (32h queue wait, all branches cap-killed on turn 1).
                    clock_start = inv.started_at or inv.created_at
                    if clock_start.tzinfo is None:
                        clock_start = clock_start.replace(tzinfo=UTC)
                    age_hours = (
                        utc_now() - clock_start
                    ).total_seconds() / 3600.0

                    investigation_turn_cap = await bindings.get_int("investigation_turn_cap")
                    investigation_message_cap = await bindings.get_int("investigation_message_cap")
                    investigation_wall_clock_hours = await bindings.get_float("investigation_wall_clock_hours")
                    breach: str | None = None
                    if total_turns >= investigation_turn_cap:
                        breach = (
                            f"investigation_turn_cap:"
                            f"{total_turns}/{investigation_turn_cap}"
                        )
                    elif total_messages >= investigation_message_cap:
                        breach = (
                            f"investigation_message_cap:"
                            f"{total_messages}/{investigation_message_cap}"
                        )
                    elif age_hours >= investigation_wall_clock_hours:
                        # Don't kill an investigation that's actively
                        # producing work just because the calendar says
                        # >24h since first turn. The wall-clock cap is a
                        # safety net against zombie state (branches that
                        # got stuck mid-run and now waste worker pool),
                        # not a guillotine for live audits.
                        #
                        # Check the freshest branch updated_at against
                        # NOW; if anything wrote within IDLE_GRACE_S
                        # (default 15 min), the audit is alive and the
                        # cap holds off. Worker activity (every tool
                        # call) bumps updated_at, so a branch mid-tool-
                        # call always trips this grace.
                        #
                        # Observed live on e1a9e13c: 25.9h/24h cap killed
                        # 7 branches with the most-recent updated_at 30s
                        # AFTER stopped_at -- renzo was running
                        # taint_paths_to and got mid-call killed.
                        idle_grace_s = await bindings.get_float("wall_clock_idle_grace_s")
                        latest_act_row = (
                            await uow.session.exec(
                                _select(_func.max(bindings.branch_model.updated_at))
                                .where(bindings.branch_model.investigation_id == investigation_id)
                                .where(bindings.branch_model.status == "active"),
                            )
                        ).first()
                        if latest_act_row is not None:
                            latest_act = (
                                latest_act_row
                                if not hasattr(latest_act_row, "__getitem__")
                                else latest_act_row[0]
                            )
                            if latest_act is not None:
                                if latest_act.tzinfo is None:
                                    latest_act = latest_act.replace(tzinfo=UTC)
                                idle_s = (utc_now() - latest_act).total_seconds()
                                if idle_s < idle_grace_s:
                                    breach = None
                                else:
                                    breach = (
                                        f"investigation_wall_clock:"
                                        f"{age_hours:.1f}h/"
                                        f"{investigation_wall_clock_hours:.1f}h"
                                        f"_idle{idle_s:.0f}s"
                                    )
                            else:
                                breach = (
                                    f"investigation_wall_clock:"
                                    f"{age_hours:.1f}h/"
                                    f"{investigation_wall_clock_hours:.1f}h"
                                )
                        else:
                            breach = (
                                f"investigation_wall_clock:"
                                f"{age_hours:.1f}h/"
                                f"{investigation_wall_clock_hours:.1f}h"
                            )

                    if breach is not None:
                        actives = (await uow.session.exec(
                            _select(bindings.branch_model).where(
                                bindings.branch_model.investigation_id == investigation_id,
                                bindings.branch_model.status == "active",
                            )
                        )).all()
                        halt_now = utc_now()
                        for branch in actives:
                            branch.status = "abandoned"
                            branch.closed_reason = f"cap_exceeded:{breach}"
                            branch.closed_at = halt_now
                            branch.updated_at = halt_now
                            uow.session.add(branch)
                        # Zero-turn cap-exceeded = the investigation
                        # was enqueued but no branch ever completed a
                        # reasoning turn (provider outage the whole
                        # window). That is a stall, not a completion.
                        _cap_status = (
                            InvestigationStatus.STALLED.value
                            if total_turns == 0
                            else InvestigationStatus.COMPLETED.value
                        )
                        inv.status = _cap_status
                        inv.stopped_at = halt_now
                        inv.updated_at = halt_now
                        uow.session.add(inv)
                        await uow.commit()
                        # Drop the investigation's pending ARQ jobs so they
                        # don't keep waking the worker post cap-exceeded.
                        try:
                            purged = await purge_arq_jobs_for_investigation(
                                investigation_id, track=bindings.track,
                            )
                            if purged.get("purged_jobs", 0) > 0:
                                _log.info(
                                    "investigation_emit CAP_EXCEEDED ARQ_PURGE inv=%s purged=%d",
                                    investigation_id, purged["purged_jobs"],
                                )
                        except (OSError, RuntimeError, ImportError) as exc:
                            _log.warning(
                                "investigation_emit CAP_EXCEEDED ARQ_PURGE failed inv=%s err=%s",
                                investigation_id, exc,
                            )
                        _log.warning(
                            "investigation_emit CAP_EXCEEDED investigation=%s "
                            "reason=%s halted_branches=%d "
                            "(turns=%d/%d msgs=%d/%d age=%.1fh/%.1fh)",
                            investigation_id, breach, len(actives),
                            total_turns, investigation_turn_cap,
                            total_messages, investigation_message_cap,
                            age_hours, investigation_wall_clock_hours,
                        )
                        return StateResult(
                            next_state=RESERVED_SUCCEEDED,
                            output={
                                "investigation_id": investigation_id,
                                "status": _cap_status,
                                "exit_reason": f"cap_exceeded:{breach}",
                                "turn_count": turn_count,
                                "outcome_id": str(outcome_id) if outcome_id else None,
                            },
                        )

        if investigation_id:
            async with UnitOfWork() as uow:
                inv = (await uow.session.exec(
                    _select(bindings.inv_model).where(
                        bindings.inv_model.id == investigation_id,
                    )
                )).first()
                if inv is not None:
                    now = utc_now()
                    if final_status == InvestigationStatus.COMPLETED.value:
                        # Only set COMPLETED if NO other branches are still live.
                        # The historical query required turn_count > 0, which
                        # excluded freshly-spawned branches sitting at turn 0
                        # waiting for their first worker pickup. Effect: when
                        # a reactivated branch reached terminal_submit before
                        # the new sibling panel had executed any turns, the
                        # check found zero qualifying siblings and flipped
                        # the investigation to COMPLETED -- closing the
                        # reopen window the moment auto_deliberation spawned
                        # fresh personas. Dropping the turn_count > 0 filter
                        # makes any non-abandoned sibling count as live; the
                        # investigation stays RUNNING until the freshly-
                        # spawned panel either submits or abandons on its
                        # own.
                        active_siblings = (await uow.session.exec(
                            _select(bindings.branch_model).where(
                                bindings.branch_model.investigation_id == investigation_id,
                                bindings.branch_model.status == "active",
                                bindings.branch_model.id != (branch_id or ""),
                            )
                        )).all()
                        if active_siblings:
                            # Other branches still working -- stay running
                            _log.info(
                                "investigation_emit: branch %s done but %d sibling(s) "
                                "still active -- keeping investigation RUNNING",
                                branch_id, len(active_siblings),
                            )
                        else:
                            inv.status = final_status
                            inv.stopped_at = now
                    elif final_status is not None:
                        inv.status = final_status
                        inv.stopped_at = now
                    if outcome_id and not inv.primary_outcome_id:
                        inv.primary_outcome_id = str(outcome_id)
                    inv.updated_at = now
                    uow.session.add(inv)
                    # Phase C surgical (BLOCK fix): when this commit will
                    # land a terminal inv.status, close any orphan
                    # ``active`` branches in the same UoW so the operator
                    # never sees a completed investigation with a branch
                    # chip still pulsing. See aila.platform.services.branch_cleanup
                    # describing the rationale and the reported bug
                    # (inv <inv-uuid> / wei branch).
                    if inv.status in (
                        InvestigationStatus.COMPLETED.value,
                        InvestigationStatus.FAILED.value,
                        InvestigationStatus.ABANDONED.value,
                        InvestigationStatus.STALLED.value,
                    ):
                        _reason_map = {
                            InvestigationStatus.COMPLETED.value: "investigation_completed",
                            InvestigationStatus.FAILED.value: "investigation_failed",
                            InvestigationStatus.ABANDONED.value: "investigation_abandoned",
                            InvestigationStatus.STALLED.value: "investigation_stalled",
                        }
                        await close_orphan_branches_on_terminal(
                            uow, investigation_id,
                            branch_table=bindings.branch_table,
                            reason=_reason_map[inv.status],
                            now=now,
                        )
                    await uow.commit()

        # Draft outcome workflow: when an outcome row exists, post a
        # review request to siblings and evaluate quorum. evaluate_quorum
        # auto-approves single-branch investigations (no siblings to read
        # the review); multi-branch investigations stay in DRAFT until
        # enough sibling reviews land via the submit_outcome_review action.
        # The dispatcher refuses any outcome whose state is not APPROVED,
        # so calling it on a still-DRAFT outcome is safe (SKIPPED result).
        dispatch_status: str | None = None
        dispatch_target: str | None = None
        dispatch_reason: str | None = None
        if outcome_id:
            try:



                async with UnitOfWork() as uow:
                    outcome_row = (await uow.session.exec(
                        _select(bindings.outcome_model).where(
                            bindings.outcome_model.id == outcome_id,
                        ),
                    )).first()
                    proposing_branch = None
                    if outcome_row is not None:
                        proposing_branch = (await uow.session.exec(
                            _select(bindings.branch_model).where(
                                bindings.branch_model.id == outcome_row.branch_id,
                            ),
                        )).first()

                if outcome_row is not None and proposing_branch is not None:
                    await bindings.post_draft_review_request(
                        investigation_id=investigation_id,
                        outcome_id=str(outcome_id),
                        proposing_branch_id=outcome_row.branch_id,
                        proposing_persona=(
                            proposing_branch.persona_voice or "unknown"
                        ),
                        outcome_kind=outcome_row.outcome_kind,
                        confidence=outcome_row.confidence,
                        payload_summary=summarize_outcome_for_review(
                            outcome_row.payload_json,
                        ),
                    )
                quorum = await bindings.evaluate_quorum(str(outcome_id))
                _log.info(
                    "investigation_emit DRAFT_REVIEW outcome=%s state=%s "
                    "approve=%d reject=%d k=%d siblings_halted=%d transition=%s",
                    outcome_id, quorum.new_state, quorum.approve_count,
                    quorum.reject_count, quorum.quorum_k,
                    quorum.siblings_active if quorum.transition_occurred else 0,
                    quorum.transition_reason or "(no change)",
                )
                # RFC-08 step 1: when quorum flips to a terminal verdict
                # (approved | rejected), hand the verdict + a payload
                # excerpt to the module's ExperienceWriter closure so a
                # signed pattern lands in the module PatternStore.
                # Gated on ``transition_occurred`` so a still-DRAFT
                # tally never pays the cost; the writer itself is also
                # skip-safe on DRAFT (redundant defense). The whole call
                # is wrapped so any write failure logs and continues --
                # this MUST NOT change ``approved`` or the dispatch
                # branch below.
                if (
                    bindings.record_experience is not None
                    and quorum.transition_occurred
                    and outcome_row is not None
                ):
                    try:
                        _payload_excerpt = summarize_outcome_for_review(
                            outcome_row.payload_json,
                        )
                        _first_line = _payload_excerpt.splitlines()[0] if _payload_excerpt else ""
                        _summary = (_first_line or _payload_excerpt)[:400]
                        await bindings.record_experience(
                            verdict=quorum,
                            investigation_id=investigation_id,
                            outcome_id=str(outcome_id),
                            summary=_summary,
                            body=_payload_excerpt,
                        )
                    except (OSError, TimeoutError, RuntimeError, ValueError, SQLAlchemyError) as exc:
                        _log.warning(
                            "investigation_emit EXPERIENCE_WRITE FAILED outcome=%s err=%s: %s",
                            outcome_id, type(exc).__name__, exc,
                        )
                approved = quorum.new_state == bindings.approved_state
            except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "investigation_emit DRAFT_REVIEW failed outcome=%s err=%s",
                    outcome_id, exc,
                )
                approved = False

            # Dispatch only when approved by quorum. The dispatcher itself
            # refuses draft/rejected outcomes; checking here avoids the
            # redundant DB load + log line for the common still-DRAFT path.
            if approved:
                # Bridge (RFC-13 Phase 4): a quorum-approved finding confirms
                # the proposing branch's discoveries on the shared ledger.
                # Without this the outcome-review quorum and the ledger oracle
                # stay disconnected -- no discovery ever becomes confirmed, so
                # confirmed-trust phases (poc_development) never activate and
                # replan requests never ratify.
                try:
                    if outcome_row is not None and investigation_id:
                        confirmed_ids = await LedgerService().confirm_branch_discoveries(
                            str(investigation_id), outcome_row.branch_id,
                        )
                        if confirmed_ids:
                            _log.info(
                                "investigation_emit CONFIRM outcome_id=%s "
                                "branch=%s discoveries=%s",
                                outcome_id, outcome_row.branch_id, confirmed_ids,
                            )
                except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                    _log.warning(
                        "investigation_emit CONFIRM failed outcome_id=%s err=%s",
                        outcome_id, exc,
                    )
                dispatcher = bindings.outcome_dispatcher_cls(knowledge=ServiceFactory().knowledge)
                try:
                    dispatch_result = await dispatcher.dispatch(str(outcome_id))
                    dispatch_status = dispatch_result.dispatch_status.value
                    dispatch_target = dispatch_result.dispatch_target
                    dispatch_reason = dispatch_result.reason
                    _log.info(
                        "investigation_emit DISPATCH outcome_id=%s status=%s target=%s",
                        outcome_id, dispatch_status, dispatch_target,
                    )
                except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                    dispatch_status = "failed"
                    dispatch_reason = f"{type(exc).__name__}: {exc}"
                    _log.warning(
                        "investigation_emit DISPATCH ERROR outcome_id=%s err=%s",
                        outcome_id, exc,
                    )

        extraction_count: int | None = None
        extraction_reason: str | None = None
        if outcome_id and final_status == InvestigationStatus.COMPLETED.value:
            try:
                extraction_result = await _run_pattern_extraction(str(outcome_id))
                extraction_count = extraction_result.extracted_count
                extraction_reason = extraction_result.skipped_reason or None
                _log.info(
                    "investigation_emit EXTRACT outcome_id=%s count=%d reason=%s",
                    outcome_id, extraction_count, extraction_reason,
                )
            except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                extraction_count = 0
                extraction_reason = f"{type(exc).__name__}: {exc}"
                _log.warning(
                    "investigation_emit EXTRACT ERROR outcome_id=%s err=%s",
                    outcome_id, exc,
                )

        # Multi-persona deliberation synthesis trigger. When this branch
        # finishes with a terminal outcome AND every other persona branch
        # in this investigation has also finished with a terminal outcome,
        # enqueue a synthesis task that consolidates all persona verdicts
        # into one final outcome. Idempotent -- synthesis dedupes itself by
        # checking inv.primary_outcome_id before producing a new one.
        # fix Phase-C -- synthesis trigger goes through the finalize chokepoint.
        # _maybe_trigger_synthesis covered only one of the four trigger conditions
        # (all_outcomes). The finalize chokepoint additionally catches the other
        # three (rejected_quorum, wall_clock_idle_grace, all_terminal_no_outcome)
        # which previously raced across three separate reaper paths.
        # fix -- fire on a fresh submit (outcome_id) OR on any terminal
        # completion. Under the dispatch hub a branch reaches this state
        # via hub_stalled / branch_already_terminal with outcome_id=None
        # even though it already submitted into the shared canonical
        # panel during its phase loop, so gating on outcome_id alone
        # skipped synthesis for every multi-phase investigation and left
        # the raw last-writer answer as the headline. _maybe_trigger_synthesis
        # self-gates on panel completeness + the panel_summary idempotency
        # marker, so calling it on a terminal emit with no fresh outcome_id
        # is safe (it no-ops until every expected branch has contributed).
        if (
            outcome_id is not None
            or final_status == InvestigationStatus.COMPLETED.value
        ):
            try:
                await _maybe_trigger_synthesis(investigation_id)
            except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "investigation_emit SYNTHESIS_TRIGGER FAILED inv=%s err=%s",
                    investigation_id, exc,
                )

        # Adversarial verifier trigger -- fires for EVERY investigation that
        # lands in a terminal state with a canonical outcome, not just the
        # multi-branch synthesis case. Single-branch variant_hunts and
        # MASVS per-control audits previously never triggered verifier
        # because the only enqueue site lived inside _maybe_trigger_synthesis
        # which gated on len(branches) >= 2. _maybe_trigger_verifier
        # self-gates on inv.status terminal + canonical outcome present
        # + no prior verifier_report -- same idempotency contract as the
        # synthesis trigger, fires from the same emit chokepoint so cron
        # sweeps never need to re-enqueue.
        try:
            await _maybe_trigger_verifier(investigation_id)
        except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
            _log.warning(
                "investigation_emit VERIFIER_TRIGGER FAILED inv=%s err=%s",
                investigation_id, exc,
            )

        # RFC #149 auto-patch trigger. Fires ONLY when the module bound
        # a patcher task AND the operator has enabled the platform
        # ``autopatch_enabled`` flag AND the canonical outcome carries
        # a confirmed verifier verdict with no prior ``patch_report``.
        # Default OFF: this call short-circuits with no-op on every
        # existing deployment (byte-identical to pre-#149 flow).
        if bindings.patcher_task_fn is not None:
            try:
                await _maybe_trigger_patcher(investigation_id)
            except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "investigation_emit PATCHER_TRIGGER FAILED inv=%s err=%s",
                    investigation_id, exc,
                )

        # Post-completion proposers \u2014 best-effort. PatternProposer drafts
        # reusable patterns (YARA templates / unpacker recipes / family
        # fingerprints / config-extractor templates) from accepted
        # outcomes. PlaybookProposer drafts a playbook when there's a
        # strong family fingerprint + a tool-recipe pattern to derive
        # steps from. Both write rows with status='draft' / 'proposed'
        # so the operator reviews them before activation; never
        # auto-promoted.
        if hooks.propose_pattern is not None:
            try:
                await hooks.propose_pattern(investigation_id)
            except (OSError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "investigation_emit PATTERN_PROPOSER FAILED inv=%s err=%s",
                    investigation_id, exc,
                )
        if hooks.propose_playbook is not None:
            try:
                await hooks.propose_playbook(investigation_id)
            except (OSError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "investigation_emit PLAYBOOK_PROPOSER FAILED inv=%s err=%s",
                    investigation_id, exc,
                )

        # Independent of outcome_id: call finalize. Cheap when no trigger
        # fires (single SELECT + branch/outcome aggregate, no action).
        try:
            result = await bindings.finalize(investigation_id)
            if result.trigger not in ("no_trigger", "not_running"):
                _log.info(
                    "investigation_emit FINALIZE inv=%s trigger=%s action=%s",
                    investigation_id, result.trigger, result.action_taken,
                )
        except (ImportError, SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            # fix §350 -- finalize is best-effort because the emit terminal
            # already wrote the cursor; the traceback surfaces a structural
            # finalize regression (handler crash, DB unreachable) on every
            # occurrence instead of just the class name.
            _log.warning(
                "investigation_emit FINALIZE failed inv=%s err=%s",
                investigation_id, exc,
                exc_info=True,
            )
        _log.info(
            "investigation_emit DONE investigation_id=%s exit_reason=%s final_status=%s outcome_id=%s",
            investigation_id, exit_reason, final_status, outcome_id,
        )

        return StateResult(
            next_state=RESERVED_SUCCEEDED,
            output={
                "investigation_id": investigation_id,
                "status": final_status,
                "exit_reason": exit_reason,
                "outcome_id": outcome_id,
                "last_turn_idx": input.get("last_turn_idx"),
                "last_action": input.get("last_action"),
                "dispatch_status": dispatch_status,
                "dispatch_target": dispatch_target,
                "dispatch_reason": dispatch_reason,
                "pattern_extraction_count": extraction_count,
                "pattern_extraction_reason": extraction_reason,
            },
        )


    async def _maybe_trigger_synthesis(investigation_id: str) -> None:
        """Enqueue the synthesis task if every active persona branch has
        submitted a terminal outcome AND no synthesis is already done.

        Idempotency: synthesis sets inv.primary_outcome_id to its own
        outcome id. Subsequent triggers that find primary_outcome_id
        already populated by a synthesis-kind outcome exit early.

        Race-safe: when two sibling branches finish at the same moment,
        both may call this and both may enqueue the synthesis task. The
        synthesis task itself dedupes by checking primary_outcome_id at
        its own start, so the second one becomes a no-op.
        """
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(bindings.inv_model).where(
                    bindings.inv_model.id == investigation_id,
                )
            )).first()
            if inv is None:
                return
            # Skip only when the primary outcome row IS already a synthesis
            # output. Without this distinction, the legacy 'first terminal
            # wins primary_outcome_id' path (investigation_emit body line
            # ~170) blocks synthesis forever, because primary_outcome_id
            # gets set on the first persona's submission before siblings
            # exist. Real synthesis outcomes carry a 'panel_summary' field
            # populated by SynthesisAgent -- use that as the unique marker.
            if inv.primary_outcome_id:
                primary_outcome = (await uow.session.exec(
                    _select(bindings.outcome_model).where(
                        bindings.outcome_model.id == inv.primary_outcome_id,
                    )
                )).first()
                if primary_outcome is not None:
                    try:
                        primary_payload = json.loads(primary_outcome.payload_json or "{}")
                    except (ValueError, TypeError):
                        primary_payload = {}
                    if "panel_summary" in primary_payload:
                        # Real synthesis already ran -- nothing to do.
                        return

            # Per D-101: ONE canonical outcome row, panel_contributions[]
            # tracks each persona's submission. Synthesis fires when every
            # branch that's expected to submit (status ACTIVE or COMPLETED;
            # PAUSED/MERGED/ABANDONED don't contribute) has at least one
            # entry in panel_contributions. Without this check the trigger
            # relied on per-branch outcome rows that no longer exist --
            # synthesis NEVER fired in the new architecture, leaving the
            # investigation status stuck at RUNNING forever.

            canonical = (await uow.session.exec(
                _select(bindings.outcome_model)
                .where(bindings.outcome_model.investigation_id == investigation_id)
                .order_by(bindings.outcome_model.created_at.asc())
                .limit(1),
            )).first()
            if canonical is None:
                return  # no terminal submissions yet
            try:
                canonical_payload = json.loads(canonical.payload_json or "{}")
            except (ValueError, TypeError):
                canonical_payload = {}
            contributions = canonical_payload.get("panel_contributions") or []
            contributed_branch_ids = {
                (c.get("branch_id") or "") for c in contributions if isinstance(c, dict)
            }
            contributed_branch_ids.discard("")

            branches = (await uow.session.exec(
                _select(bindings.branch_model).where(
                    bindings.branch_model.investigation_id == investigation_id,
                )
            )).all()
            if len(branches) < 2:
                # Single-branch investigation -- no panel to synthesise.
                return
            expected_branch_ids = {
                b.id for b in branches
                if b.status in (BranchStatus.ACTIVE.value, BranchStatus.COMPLETED.value)
            }
            missing = expected_branch_ids - contributed_branch_ids
            if missing:
                _log.info(
                    "investigation_emit SYNTHESIS_WAIT inv=%s contributed=%d expected=%d missing=%s",
                    investigation_id, len(contributed_branch_ids),
                    len(expected_branch_ids), sorted(missing)[:3],
                )
                return
            team_id = inv.team_id

        task_queue = bindings.task_queue_factory()
        await task_queue.submit(
            track=bindings.track,
            fn=bindings.synthesis_task_fn,
            kwargs={"investigation_id": investigation_id},
            user_id="system",
            group_id=f"{bindings.track}_synthesis",
            team_id=team_id,
        )
        _log.info(
            "investigation_emit SYNTHESIS queued investigation_id=%s",
            investigation_id,
        )


    async def _maybe_trigger_verifier(investigation_id: str) -> None:
        """Enqueue the adversarial claim verifier when the investigation
        is in a terminal state and has a canonical outcome the verifier
        can chew on.

        Independent of :func:`_maybe_trigger_synthesis`: synthesis only
        fires for multi-branch panel investigations once every persona
        has contributed. The verifier should run on EVERY investigation
        that lands a claim, including single-branch audits and variant
        hunts -- those skip synthesis entirely but still produce findings
        that benefit from adversarial probing.

        Idempotent on three levels:
          1. ``inv.status`` must be terminal -- we never verify a moving
             target (this hook also fires from the partial-branch emit
             call, where the investigation is still RUNNING; bail).
          2. A canonical outcome row must exist -- nothing to verify
             without one.
          3. ``verifier_report`` must not already be present on the
             payload -- :class:`ClaimVerifierAgent` re-asserts the same
             gate, but checking here saves a queue submission +
             worker tick.

        Race-safe against synthesis: when synthesis fires too, both
        tasks load the canonical outcome, modify the payload, and save.
        Last writer wins on the payload field but each writes a
        different key (``panel_summary`` vs ``verifier_report``), so
        the only true collision is one overwriting the other's NEW
        field -- handled at the agent layer by re-reading + merging.
        """
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(bindings.inv_model).where(
                    bindings.inv_model.id == investigation_id,
                )
            )).first()
            if inv is None:
                return
            if inv.status not in (
                InvestigationStatus.COMPLETED.value,
                InvestigationStatus.FAILED.value,
            ):
                return  # still running -- sibling branches not done yet
            canonical = (await uow.session.exec(
                _select(bindings.outcome_model)
                .where(bindings.outcome_model.investigation_id == investigation_id)
                .order_by(bindings.outcome_model.created_at.asc())
                .limit(1),
            )).first()
            if canonical is None:
                return  # nothing to verify
            try:
                payload = json.loads(canonical.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            if payload.get("verifier_report"):
                return  # already verified -- agent gate would skip too
            team_id = inv.team_id

        task_queue = bindings.task_queue_factory()
        await task_queue.submit(
            track=bindings.track,
            fn=bindings.verifier_task_fn,
            kwargs={"investigation_id": investigation_id},
            user_id="system",
            group_id=f"{bindings.track}_claim_verifier",
            team_id=team_id,
        )
        _log.info(
            "investigation_emit VERIFIER queued investigation_id=%s",
            investigation_id,
        )


    async def _maybe_trigger_patcher(investigation_id: str) -> None:
        """Enqueue :class:`PatchingService` when the operator has enabled
        ``platform.autopatch_enabled`` AND the claim verifier just wrote
        a confirmed verdict on the canonical outcome.

        Fires from the same emit chokepoint the verifier does, and only
        after :func:`_maybe_trigger_verifier` above -- so the verifier
        task has already been queued by the time this runs. The gate
        that keeps the patcher from firing before the verifier finishes
        is the ``verifier_report`` presence check below: a race where
        the operator sees the emit tick before the verifier task
        completes simply skips this fire; the NEXT emit tick (fired by
        the verifier task's own outcome update at commit time) picks
        the trigger up idempotently.

        Idempotent on four levels:
          1. Module bound a ``patcher_task_fn`` (short-circuit above).
          2. ``inv.status`` is terminal (COMPLETED / FAILED).
          3. Canonical outcome carries a ``verifier_report`` with
             ``verdict == 'confirmed'``.
          4. No prior ``patch_report`` on the payload (retry safety).

        Config-gated on ``platform.autopatch_enabled`` -- read once per
        fire through :class:`PatchingService.is_enabled` so the
        registry cache handles the hot path and a PUT /config flip
        lands on the next terminal investigation.
        """
        # Deferred import breaks the otherwise-inevitable cycle from
        # platform.workflows -> platform.services.patching ->
        # storage.db_models -> platform.workflows. The corresponding
        # PLC0415 suppression lives in pyproject.toml's per-file-ignores
        # for this file (repo policy is per-file-ignores, not inline noqa).
        from aila.config import get_settings
        from aila.platform.config import build_platform_settings
        from aila.platform.services.patching import PatchingService

        try:
            platform_settings = build_platform_settings(get_settings())
        except (OSError, RuntimeError, ValueError) as exc:
            _log.warning(
                "investigation_emit PATCHER settings build failed inv=%s err=%s",
                investigation_id, exc,
            )
            return
        patching_service = PatchingService(platform_settings)
        if not await patching_service.is_enabled():
            return  # operator opt-out -- default OFF

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(bindings.inv_model).where(
                    bindings.inv_model.id == investigation_id,
                )
            )).first()
            if inv is None:
                return
            if inv.status not in (
                InvestigationStatus.COMPLETED.value,
                InvestigationStatus.FAILED.value,
            ):
                return  # verifier itself gates on terminal; mirror it
            canonical = (await uow.session.exec(
                _select(bindings.outcome_model)
                .where(bindings.outcome_model.investigation_id == investigation_id)
                .order_by(bindings.outcome_model.created_at.asc())
                .limit(1),
            )).first()
            if canonical is None:
                return
            try:
                payload = json.loads(canonical.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            vr = payload.get("verifier_report") or {}
            if not isinstance(vr, dict) or vr.get("verdict") != "confirmed":
                # Verifier hasn't run yet, or verdict is refuted /
                # inconclusive -- no patch to synthesise.
                return
            if payload.get("patch_report"):
                return  # already patched -- task-side agent also gates
            team_id = inv.team_id

        task_queue = bindings.task_queue_factory()
        await task_queue.submit(
            track=bindings.track,
            fn=bindings.patcher_task_fn,
            kwargs={"investigation_id": investigation_id},
            user_id="system",
            group_id=f"{bindings.track}_auto_patch",
            team_id=team_id,
        )
        _log.info(
            "investigation_emit PATCHER queued investigation_id=%s",
            investigation_id,
        )


    async def _run_pattern_extraction(outcome_id: str) -> Any:
        """Bridge between investigation_emit and PatternExtractor.

        Resolves team_id from the outcome's investigation row, constructs the
        extractor with platform LLM client + PatternStore, and runs one pass.
        Errors propagate to the caller's try/except for status logging.
        """

        async with UnitOfWork() as uow:
            outcome = (await uow.session.exec(
                _select(bindings.outcome_model).where(
                    bindings.outcome_model.id == outcome_id,
                ),
            )).first()
            if outcome is None:
                raise RuntimeError(f"outcome {outcome_id} disappeared before extraction")
            inv = (await uow.session.exec(
                _select(bindings.inv_model).where(
                    bindings.inv_model.id == outcome.investigation_id,
                ),
            )).first()
            team_id = inv.team_id if inv is not None else None

        services = ServiceFactory()
        store = bindings.pattern_store_factory()
        extractor = bindings.pattern_extractor_cls(
            llm_client=services.llm_client,
            pattern_store=store,
        )
        return await extractor.extract(outcome_id=outcome_id, team_id=team_id)

    return _handler

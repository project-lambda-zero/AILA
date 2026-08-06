"""Investigation loop state factory (RFC-02 Phase 4b).

Extracted from the vr and malware loop states (89% identical). The
bounded turn loop -- per-turn liveness poll (inv status, branch status,
cursor SSOT, cancellation token), researcher run_turn, tool dispatch,
and terminal / cap handling -- is platform-owned. The module binds its
record models, researcher factory, tool-executor factory, per-task
max-turns reader, and researcher-error type. ``run_turn`` comes from the
module researcher the factory builds; the platform never names a module.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sqlmodel import select as _select

from aila.platform.agents.turn_helpers import (
    decode_case_state,
    encode_case_state,
)
from aila.platform.contracts.enums import BranchStatus, InvestigationStatus
from aila.platform.llm.cancellation import (
    LLMCancelledError,
    get_cancellation_token,
)
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)
from aila.platform.workflows.types import (
    RESERVED_PAUSED,
    RESERVED_TERMINAL_STATES,
    StateResult,
)
from aila.storage.db_models import WorkflowStateCursor

_log = logging.getLogger(__name__)

__all__ = ["state_investigation_loop"]

# RFC-13 (#12) escalation ceiling. The tool_executor's HARD-BLOCK guard
# refuses to re-dispatch an identical failing tool call, but the agent is
# free to reissue the same command over and over -- burning a turn per
# reissue and never escaping the loop. Track consecutive HARD-BLOCKED
# tool_run turns per branch in ``case_state.observables`` and exit the
# loop cleanly with ``exit_reason='tool_loop_blocked'`` once the streak
# reaches this ceiling. A successful tool call OR any non-tool_run turn
# resets the streak to 0.
_MAX_HARD_BLOCK_STREAK: int = 3
_HARD_BLOCK_STREAK_KEY: str = "_tool_hard_block_streak"
_HARD_BLOCK_MARKER: str = "HARD-BLOCKED"


async def _is_loop_alive(
    inv_model: Any, branch_model: Any, investigation_id: str, branch_id: str,
) -> tuple[bool, str]:
    """Return ``(alive, exit_reason)`` for the polling sites in the loop.

    Phase B (cutover): the loop's terminal check used to read only
    ``inv.status`` via a fresh UoW every turn (per §287). Two failures
    that pattern produced:

      * Operator paused a SPECIFIC branch (not the whole investigation).
        ``inv.status`` stayed RUNNING; the loop kept ticking on a
        branch the operator had paused. (§288)
      * The cursor SSOT (Phase B) flips ``__paused__`` atomically with
        ``inv.status``; reading the cursor is the canonical check and
        the same UoW already holds it.

    This helper performs ONE UoW + ONE query that returns three signals:
      * cursor.current_state for the branch_id (the SSOT)
      * branch.status (per-branch pause / abandon)
      * inv.status (parent pause / terminal)

    Alive when:
      * cursor exists AND current_state != '__paused__' AND
        not in {SUCCEEDED, FAILED, CANCELLED, CRASHED}
      * branch.status not in dead states
      * inv.status == RUNNING
    """

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(inv_model).where(
                inv_model.id == investigation_id,
            )
        )).first()
        if inv is None:
            return False, "inv_not_found"
        if inv.status != InvestigationStatus.RUNNING.value:
            return False, f"inv_status_flipped:{inv.status}"

        # Branch-level pause / abandon -- §288 closes this.
        branch = (await uow.session.exec(
            _select(branch_model).where(
                branch_model.id == branch_id,
            )
        )).first()
        if branch is None:
            return False, "branch_not_found"
        if branch.status != BranchStatus.ACTIVE.value:
            return False, f"branch_status_flipped:{branch.status}"

        # Cursor SSOT -- pause writes __paused__ here. Look up by the
        # denormalised ``branch_id`` COLUMN (migration 101), not by primary
        # key: the cursor PK is ``run_id`` (the ARQ task uuid), so
        # ``session.get(_, branch_id)`` always missed and this SSOT check
        # was dead. Take the most-recent cursor for the branch; pause flips
        # every cursor of the investigation to __paused__.
        cursor_state = (await uow.session.exec(
            _select(WorkflowStateCursor.current_state)
            .where(WorkflowStateCursor.branch_id == branch_id)
            .order_by(WorkflowStateCursor.updated_at.desc())
            .limit(1)
        )).first()
        if cursor_state is not None:
            if cursor_state == RESERVED_PAUSED:
                return False, "cursor_paused"
            if cursor_state in RESERVED_TERMINAL_STATES:
                return False, f"cursor_terminal:{cursor_state}"

    # Phase B.5 -- per-investigation cancellation token. Process-local;
    # cross-process synchronization is via the cursor SSOT (which the
    # block above already checked). The token catches the case where
    # pause was triggered AFTER the cursor read above but BEFORE this
    # turn's LLM call: same-process pause flips the token immediately,
    # so the next turn's alive check exits clean instead of paying
    # the LLM cost.
    try:
        if get_cancellation_token(investigation_id).is_cancelled():
            return False, "cancellation_token_set"
    except (ImportError, AttributeError, RuntimeError, ValueError, TypeError) as exc:
        _log.warning(
            "loop_alive cancellation_token check failed reason=%s",
            exc,
            exc_info=True,
        )

    return True, "alive"


async def _update_hard_block_streak(
    branch_model: Any, branch_id: str, *, bump: bool,
) -> int:
    """Increment or reset the branch's consecutive HARD-BLOCK streak.

    Persists the counter under ``_tool_hard_block_streak`` inside
    ``case_state.observables`` so it survives an auto_continue re-
    enqueue (belt-and-braces -- ``tool_loop_blocked`` is already a
    non-continue reason). Returns the new streak value; the caller
    compares against ``_MAX_HARD_BLOCK_STREAK`` to decide whether to
    break the turn loop.
    """
    async with UnitOfWork() as uow:
        branch = (await uow.session.exec(
            _select(branch_model).where(branch_model.id == branch_id)
        )).first()
        if branch is None:
            return 0
        case_state = decode_case_state(branch.case_state_json)
        if bump:
            current = int(
                case_state.observables.get(_HARD_BLOCK_STREAK_KEY, 0) or 0
            )
            new_value = current + 1
        else:
            new_value = 0
        # Skip the write when a reset would be a no-op; avoids a needless
        # row update per non-tool_run turn on branches that never hit
        # HARD-BLOCK.
        prior = case_state.observables.get(_HARD_BLOCK_STREAK_KEY)
        if prior == new_value:
            return new_value
        if new_value == 0 and prior is None:
            return 0
        case_state.observables[_HARD_BLOCK_STREAK_KEY] = new_value
        branch.case_state_json = encode_case_state(case_state)
        uow.session.add(branch)
        await uow.session.commit()
    return new_value


async def _write_phase_directive(
    branch_model: Any, branch_id: str, directive: str | None,
    *, strategy_family: str | None = None,
) -> None:
    """Write the phase regime (mission + optional prompt family) to observables.

    The render layer surfaces ``_directive.*`` observables in the next-turn
    prompt (reserved keys, never evicted), so a phase-scoped loop tells the
    shared expert agent this phase's objective and exit criteria without a
    phase-specific system prompt. ``strategy_family``, when set, is written
    to ``_directive.phase_strategy_family`` so the turn runner selects this
    phase's prompt family instead of the investigation-level one. Overwritten
    at each phase entry; stripped at fork so children start on a clean slate.
    """
    if directive is None and strategy_family is None:
        return
    async with UnitOfWork() as uow:
        branch = (await uow.session.exec(
            _select(branch_model).where(branch_model.id == branch_id)
        )).first()
        if branch is None:
            return
        case_state = decode_case_state(branch.case_state_json)
        if directive is not None:
            case_state.observables["_directive.phase_mission"] = directive
        if strategy_family is not None:
            case_state.observables["_directive.phase_strategy_family"] = (
                strategy_family
            )
        branch.case_state_json = encode_case_state(case_state)
        uow.session.add(branch)
        await uow.session.commit()


def state_investigation_loop(
    bindings: InvestigationStateBindings,
    hooks: InvestigationStateHooks,
    *,
    next_state: str = "investigation_emit",
    phase_directive: str | None = None,
    phase_max_turns: int | None = None,
    phase_allowed_servers: tuple[str, ...] | None = None,
    phase_strategy_family: str | None = None,
) -> Callable[[dict[str, Any], Any], Awaitable[StateResult]]:
    """Build the loop-state handler bound to *bindings* + *hooks*.

    *next_state* is the transition taken when the loop exits (default
    ``investigation_emit`` -- the single-loop V1 shape). A phase-graph node
    passes the next phase or a router state, so the same loop body serves
    every phase. *phase_max_turns* in the state input overrides the
    module turn cap for a phase-scoped loop; absent, the V1 cap applies.
    *phase_directive*, when set, is written to the branch case state as the
    ``_directive.phase_mission`` observable at phase entry so the agent's
    next turn sees this phase's objective; None preserves V1 behavior.
    *phase_max_turns*, when set, caps this phase's loop (takes precedence
    over the ``phase_max_turns`` state input and the module reader).
    *phase_allowed_servers*, when set, restricts this phase's tool dispatch
    to that server allowlist on top of the module's own allowlist.
    *phase_strategy_family*, when set, overrides the prompt family the turn
    runner selects for this phase (via the ``_directive.phase_strategy_family``
    observable); None keeps the investigation-level family.
    """
    del hooks  # loop takes no optional hooks today
    _phase_servers = (
        frozenset(phase_allowed_servers)
        if phase_allowed_servers is not None
        else None
    )

    async def _handler(input: dict[str, Any], services: Any) -> StateResult:
        """Run turns until terminal / max / status flips out of RUNNING.

        The ARQ task wrapping this state can be configured for a long
        timeout (1+ hour) since each turn is a single LLM round trip.
        Operator-initiated pause flips investigation.status; the loop polls
        that between turns and stops cleanly.
        """
        investigation_id = str(input.get("investigation_id") or "")
        branch_id = str(input.get("branch_id") or "")
        if not investigation_id or not branch_id:
            raise ValueError("investigation_loop: missing investigation_id or branch_id")

        if phase_directive or phase_strategy_family:
            await _write_phase_directive(
                bindings.branch_model, branch_id, phase_directive,
                strategy_family=phase_strategy_family,
            )

        max_turns = int(
            phase_max_turns
            or input.get("phase_max_turns")
            or input.get("max_turns")
            or await bindings.max_turns_reader()
        )

        # fix §289 -- strict input validation. cve_intel + applicable_patterns
        # flow through state input dicts and the workflow engine persists
        # them as JSON; a corrupted resume (e.g. a hand-edited state row
        # turning the list into a string, or a non-JSON-safe value sneaking
        # in) used to silently degrade via \`input.get(...) or []\`, dropping
        # CVE intel and pattern context without any signal. Loud rejection
        # surfaces the corruption at task entry where the operator can
        # correlate it against the responsible state transition.
        raw_cve_intel = input.get("cve_intel")
        if raw_cve_intel is None:
            raw_cve_intel = []
        if not isinstance(raw_cve_intel, list):
            raise ValueError(
                f"investigation_loop: cve_intel must be a list, got "
                f"{type(raw_cve_intel).__name__}: {raw_cve_intel!r:.200}",
            )
        raw_patterns = input.get("applicable_patterns")
        if raw_patterns is None:
            raw_patterns = []
        if not isinstance(raw_patterns, list):
            raise ValueError(
                f"investigation_loop: applicable_patterns must be a list, got "
                f"{type(raw_patterns).__name__}: {raw_patterns!r:.200}",
            )
        # RFC-12 read loop: setup resolved prior knowledge for the RETRIEVED
        # prompt tier and threaded it through the state input. Same strict
        # validation as cve_intel + applicable_patterns so a corrupted resume
        # surfaces loudly rather than silently dropping the tier.
        raw_retrieved = input.get("retrieved_knowledge")
        if raw_retrieved is None:
            raw_retrieved = []
        if not isinstance(raw_retrieved, list):
            raise ValueError(
                f"investigation_loop: retrieved_knowledge must be a list, got "
                f"{type(raw_retrieved).__name__}: {raw_retrieved!r:.200}",
            )

        engine = CyberReasoningEngine(services.llm_client)
        researcher = bindings.researcher_factory(
            engine, investigation_id, branch_id, raw_cve_intel, raw_patterns,
            raw_retrieved,
        )
        executor = bindings.executor_factory()

        last_turn_idx = 0
        last_outcome_id: str | None = None
        last_action = ""
        exit_reason = "max_turns"

        for turn_attempt in range(1, max_turns + 1):
            # fix §287 + §288 -- single UoW polls inv.status, branch.status,
            # AND cursor.current_state (Phase B SSOT). Operator pauses at
            # any of the three layers are visible.
            alive, alive_reason = await _is_loop_alive(
                bindings.inv_model, bindings.branch_model,
                investigation_id, branch_id,
            )
            if not alive:
                exit_reason = alive_reason
                _log.info(
                    "investigation_loop EXIT investigation_id=%s branch_id=%s "
                    "reason=%s after_turn=%d",
                    investigation_id, branch_id, exit_reason, last_turn_idx,
                )
                break

            # On-demand specialists (mid-run spawn). A request_specialist
            # ratified AFTER setup ran must still spawn -- setup does not
            # re-run on auto-continue, so a setup-only spawn never fires for
            # the real use case (the agent requests a specialist mid-
            # investigation). Poll each live turn so a request ratified by a
            # sibling this turn spawns the matching specialist on the next
            # turn. Idempotent per persona_voice; a single cheap query when
            # nothing new is ratified. None when the module has no specialist
            # support.
            if bindings.specialist_spawn_fn is not None:
                await bindings.specialist_spawn_fn(investigation_id)

            try:
                result = await researcher.run_turn()
            except LLMCancelledError:
                # #44: the run was cancelled mid-LLM-retry (a pause landed while
                # the provider call was backing off). Route to the same clean
                # exit as the turn-boundary poll below rather than letting the
                # exception escape and finalise the workflow as FAILED.
                exit_reason = "cancellation_token_set"
                _log.info(
                    "investigation_loop EXIT investigation_id=%s branch_id=%s "
                    "reason=%s after_turn=%d cancelled_mid_retry=1",
                    investigation_id, branch_id, exit_reason, last_turn_idx,
                )
                break
            except bindings.researcher_error as exc:
                tag = "researcher_error_retryable" if getattr(exc, "retryable", False) else "researcher_error"
                exit_reason = f"{tag}:{exc}"
                _log.warning(
                    "investigation_loop ERROR investigation_id=%s after_turn=%d retryable=%s err=%s",
                    investigation_id, last_turn_idx, getattr(exc, "retryable", False), exc,
                )
                break

            last_turn_idx = result.turn
            last_action = result.decision.action
            last_outcome_id = result.outcome_id

            if result.decision.action == "tool_run":
                tool_outcome = await executor.execute(
                    investigation_id=investigation_id,
                    branch_id=branch_id,
                    command_raw=result.decision.command or "",
                    at_turn=result.turn,
                    phase_allowed_servers=_phase_servers,
                )
                _log.info(
                    "investigation_loop TOOL inv=%s turn=%d server=%s tool=%s success=%s",
                    investigation_id, result.turn,
                    tool_outcome.server_id, tool_outcome.tool_name,
                    tool_outcome.success,
                )
                # RFC-13 (#12): the tool_executor's HARD-BLOCK guard sets
                # ``success=False`` and includes the literal string
                # ``HARD-BLOCKED`` in ``error`` when it refuses an
                # identical repeat call. Any other failure (bridge error,
                # error envelope, malformed command) is NOT a hard block
                # and MUST NOT escalate here -- it resets the streak so
                # unrelated transient failures don't bank toward the cap.
                is_hard_block = (
                    not tool_outcome.success
                    and _HARD_BLOCK_MARKER in (tool_outcome.error or "")
                )
                streak = await _update_hard_block_streak(
                    bindings.branch_model, branch_id, bump=is_hard_block,
                )
                if is_hard_block and streak >= _MAX_HARD_BLOCK_STREAK:
                    exit_reason = "tool_loop_blocked"
                    _log.warning(
                        "investigation_loop EXIT investigation_id=%s branch_id=%s "
                        "reason=%s streak=%d after_turn=%d",
                        investigation_id, branch_id, exit_reason, streak,
                        result.turn,
                    )
                    break
            else:
                # Non-tool_run turn: clear any accumulated streak so
                # HARD-BLOCK escalation requires CONSECUTIVE offenses.
                await _update_hard_block_streak(
                    bindings.branch_model, branch_id, bump=False,
                )

            if result.terminal:
                exit_reason = "terminal_submit"
                _log.info(
                    "investigation_loop TERMINAL investigation_id=%s turn=%d outcome_id=%s",
                    investigation_id, last_turn_idx, last_outcome_id,
                )
                break

            if turn_attempt == max_turns:
                exit_reason = "max_turns"
                _log.info(
                    "investigation_loop CAP investigation_id=%s reached max_turns=%d",
                    investigation_id, max_turns,
                )

        # Feed the hub-level budget guard (RFC-13): when a phase loop exits
        # on the turn cap AND the branch's cumulative turns have reached the
        # overall investigation cap, tell the dispatch hub the budget is
        # exhausted so it emits instead of activating another phase inside
        # this task. The hub reads ``_budget_exhausted`` (phase_graph). Only
        # set on the max_turns exit -- terminal_submit / errors keep their
        # own routing. Redundant with the re-enqueue cap and
        # MAX_STEPS_PER_JOB, but enforces the overall cap WITHIN a single
        # hub walk rather than only across re-enqueues.
        budget_exhausted = False
        if exit_reason == "max_turns":
            overall_cap = int(await bindings.max_turns_reader())
            async with UnitOfWork() as uow:
                _b = (await uow.session.exec(
                    _select(bindings.branch_model).where(
                        bindings.branch_model.id == branch_id,
                    )
                )).first()
                cumulative_turns = (
                    int(_b.turn_count) if _b is not None else last_turn_idx
                )
            budget_exhausted = cumulative_turns >= overall_cap

        return StateResult(
            next_state=next_state,
            output={
                **input,
                "branch_id": branch_id,
                "exit_reason": exit_reason,
                "last_turn_idx": last_turn_idx,
                "last_action": last_action,
                "outcome_id": last_outcome_id,
                "_budget_exhausted": budget_exhausted,
            },
        )

    return _handler

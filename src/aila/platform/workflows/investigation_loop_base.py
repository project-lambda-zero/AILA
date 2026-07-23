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

        # Cursor SSOT -- Phase B's pause writes __paused__ here.
        cursor = await uow.session.get(WorkflowStateCursor, branch_id)
        if cursor is not None:
            if cursor.current_state == RESERVED_PAUSED:
                return False, "cursor_paused"
            if cursor.current_state in RESERVED_TERMINAL_STATES:
                return False, f"cursor_terminal:{cursor.current_state}"

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


def state_investigation_loop(
    bindings: InvestigationStateBindings,
    hooks: InvestigationStateHooks,
) -> Callable[[dict[str, Any], Any], Awaitable[StateResult]]:
    """Build the loop-state handler bound to *bindings* + *hooks*."""
    del hooks  # loop takes no optional hooks today

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

        max_turns = int(input.get("max_turns") or await bindings.max_turns_reader())

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

        engine = CyberReasoningEngine(services.llm_client)
        researcher = bindings.researcher_factory(
            engine, investigation_id, branch_id, raw_cve_intel, raw_patterns,
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
                )
                _log.info(
                    "investigation_loop TOOL inv=%s turn=%d server=%s tool=%s success=%s",
                    investigation_id, result.turn,
                    tool_outcome.server_id, tool_outcome.tool_name,
                    tool_outcome.success,
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

        return StateResult(
            next_state="investigation_emit",
            output={
                **input,
                "branch_id": branch_id,
                "exit_reason": exit_reason,
                "last_turn_idx": last_turn_idx,
                "last_action": last_action,
                "outcome_id": last_outcome_id,
            },
        )

    return _handler

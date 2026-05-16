"""Investigation loop state (M3.R-7).

Drives ``HonestVulnResearcher.run_turn`` in a loop until one of:
  * A turn returns ``terminal=True`` (engine emitted submit; outcome
    already persisted)
  * Hits the per-loop max_turns cap
  * Investigation status changes from RUNNING (operator paused, cost
    budget exhausted, MCP failure)

On any exit reason the loop forwards the terminating turn's metadata to
the emit state for finalization. The loop itself does NOT mark the
investigation COMPLETED — that's emit's job.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.agents import (
    HonestVulnResearcher,
    VulnResearcherError,
)
from aila.modules.vr.agents.tool_executor import ToolExecutor
from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import VRInvestigationRecord
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

__all__ = ["state_investigation_loop"]

_log = logging.getLogger(__name__)

# Hard upper bound on turns per single loop entry. Configurable per-
# strategy in a future commit; v0.3 v1 ships a single cap. Operator
# pauses + budget exhaustion break out earlier.
_DEFAULT_MAX_TURNS = 25


async def _investigation_status(investigation_id: str) -> str | None:
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            )
        )).first()
        return inv.status if inv else None


async def state_investigation_loop(input: dict[str, Any], services: Any) -> StateResult:
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

    max_turns = int(input.get("max_turns") or _DEFAULT_MAX_TURNS)

    engine = CyberReasoningEngine(services.llm_client)
    researcher = HonestVulnResearcher(
        reasoning_engine=engine,
        investigation_id=investigation_id,
        branch_id=branch_id,
    )
    executor = ToolExecutor(
        ida=IDABridgeTool(),
        audit_mcp=AuditMcpBridgeTool(),
    )

    last_turn_idx = 0
    last_outcome_id: str | None = None
    last_action = ""
    exit_reason = "max_turns"

    for turn_attempt in range(1, max_turns + 1):
        status = await _investigation_status(investigation_id)
        if status != InvestigationStatus.RUNNING.value:
            exit_reason = f"status_flipped:{status}"
            _log.info(
                "investigation_loop EXIT investigation_id=%s reason=%s after_turn=%d",
                investigation_id, exit_reason, last_turn_idx,
            )
            break

        try:
            result = await researcher.run_turn()
        except VulnResearcherError as exc:
            exit_reason = f"researcher_error:{exc}"
            _log.warning(
                "investigation_loop ERROR investigation_id=%s after_turn=%d err=%s",
                investigation_id, last_turn_idx, exc,
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
            "exit_reason": exit_reason,
            "last_turn_idx": last_turn_idx,
            "last_action": last_action,
            "outcome_id": last_outcome_id,
        },
    )

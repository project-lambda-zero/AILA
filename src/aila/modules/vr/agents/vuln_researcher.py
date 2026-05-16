"""HonestVulnResearcher — single-turn reasoning agent (M3.R-2).

Per the M3.R-1 schema lesson and the no-overengineering rule: this
agent runs ONE turn against the platform's existing
``CyberReasoningEngine``. The workflow state machine (M3.R-7) drives
the loop; the agent itself owns no loop, no tool execution, no
branching. Each of those is a separate later milestone.

What this commit ships:
  1. ``HonestVulnResearcher.run_turn()`` — load branch state, build
     prompt context, call engine.decide_next_turn, absorb decision,
     persist message + updated branch state.
  2. ``run_turn`` returns a ``VulnResearcherTurnResult`` describing
     what happened (action chosen, terminal yes/no, message id).
  3. Tool calls are RECORDED as messages but NOT executed (M3.R-3 wires
     MCP adapters). Submit actions DO get persisted as VROutcome rows.

What this commit does NOT do:
  - Branching: only the primary branch is touched (M3.R-5).
  - Persona voicing: ignores branch.persona_voice (M3.R-5).
  - Cost tracking: turn count goes up but $ costs stay at 0 until the
    cost_tracker service ships (separate small commit).
  - Tool execution: tool_run decisions become tool_call messages but no
    real MCP call. M3.R-3 adapters convert the message into a real call.
  - Operator messaging interleave: operator messages stored in DB but
    agent does NOT incorporate them into context. M3.R-6 adds that.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.agents.mcp_adapters import (
    KNOWN_TOOLS,
    specialized_tools,
)
from aila.modules.vr.contracts import (
    OutcomeConfidence,
    OutcomeKind,
    PayloadKind,
    SenderKind,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningContract,
    ReasoningTurnDecision,
)
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.uow import UnitOfWork

__all__ = [
    "HonestVulnResearcher",
    "VulnResearcherError",
    "VulnResearcherTurnResult",
]

_log = logging.getLogger(__name__)


_PROMPT_DIR = Path(__file__).parent / "prompts"


@dataclass
class VulnResearcherTurnResult:
    """What one ``run_turn`` produced.

    ``terminal`` is True when the engine chose ``submit`` — caller
    (workflow state) should stop calling run_turn for this branch.
    """

    investigation_id: str
    branch_id: str
    turn: int
    decision: ReasoningTurnDecision
    message_id: str
    outcome_id: str | None = None
    terminal: bool = False


class VulnResearcherError(Exception):
    """Raised on fatal agent failures (branch not found, prompt missing, etc.)."""


class HonestVulnResearcher:
    """Single-branch reasoning agent.

    Construction takes the reasoning engine + identifiers. The engine
    can be swapped for a fake in tests (tests inject a stub with the
    same ``decide_next_turn`` + ``absorb`` shape).
    """

    def __init__(
        self,
        reasoning_engine: CyberReasoningEngine,
        investigation_id: str,
        branch_id: str,
    ) -> None:
        self._engine = reasoning_engine
        self.investigation_id = investigation_id
        self.branch_id = branch_id

    async def run_turn(self) -> VulnResearcherTurnResult:
        """Run one turn for this branch and write the result to the DB.

        On a ``submit`` decision, also writes a VRInvestigationOutcomeRecord
        and returns ``terminal=True`` so the workflow state knows to
        stop driving the branch.
        """
        inv, branch = await self._load()

        case_state = _decode_case_state(branch.case_state_json)
        turn_number = branch.turn_count + 1

        pending_operator_messages = await self._consume_pending_operator_messages(
            turn_number,
        )

        system_prompt = _load_prompt(inv.strategy_family)
        user_prompt = self._build_user_prompt(
            inv=inv,
            branch=branch,
            case_state=case_state,
            turn=turn_number,
            pending_operator_messages=pending_operator_messages,
        )

        try:
            decision = await self._engine.decide_next_turn(
                task_type=inv.strategy_family,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        except RuntimeError as exc:
            raise VulnResearcherError(
                f"engine.decide_next_turn failed for investigation_id="
                f"{self.investigation_id} branch_id={self.branch_id}: {exc}",
            ) from exc

        new_case_state = self._engine.absorb(case_state, decision)

        payload_kind, payload = _decision_to_message_payload(decision)
        terminal = decision.action == "submit"
        outcome_id: str | None = None

        async with UnitOfWork() as uow:
            msg = VRInvestigationMessageRecord(
                investigation_id=self.investigation_id,
                branch_id=self.branch_id,
                sender_kind=SenderKind.ENGINE.value,
                sender_id="engine",
                payload_kind=payload_kind.value,
                payload_json=json.dumps(payload),
                at_turn=turn_number,
                evidence_refs_json="[]",
            )
            uow.session.add(msg)

            branch_row = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == self.branch_id,
                )
            )).first()
            if branch_row is None:
                raise VulnResearcherError(
                    f"branch {self.branch_id} disappeared during turn",
                )
            branch_row.turn_count = turn_number
            branch_row.case_state_json = _encode_case_state(new_case_state)
            branch_row.updated_at = utc_now()
            uow.session.add(branch_row)

            if terminal:
                outcome_kind = _terminal_outcome_kind(decision)
                outcome_row = VRInvestigationOutcomeRecord(
                    investigation_id=self.investigation_id,
                    branch_id=self.branch_id,
                    outcome_kind=outcome_kind.value,
                    payload_json=json.dumps(_outcome_payload(decision)),
                    confidence=_to_outcome_confidence(decision).value,
                    evidence_refs_json="[]",
                )
                uow.session.add(outcome_row)
                await uow.session.flush()
                outcome_id = outcome_row.id

            await uow.session.commit()
            await uow.session.refresh(msg)

        _log.info(
            "vuln_researcher TURN inv=%s branch=%s turn=%d action=%s terminal=%s",
            self.investigation_id, self.branch_id, turn_number,
            decision.action, terminal,
        )

        return VulnResearcherTurnResult(
            investigation_id=self.investigation_id,
            branch_id=self.branch_id,
            turn=turn_number,
            decision=decision,
            message_id=msg.id,
            outcome_id=outcome_id,
            terminal=terminal,
        )

    async def _load(self) -> tuple[VRInvestigationRecord, VRInvestigationBranchRecord]:
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                )
            )).first()
            if inv is None:
                raise VulnResearcherError(
                    f"investigation {self.investigation_id} not found",
                )
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == self.branch_id,
                )
            )).first()
            if branch is None:
                raise VulnResearcherError(
                    f"branch {self.branch_id} not found",
                )
            if branch.investigation_id != self.investigation_id:
                raise VulnResearcherError(
                    f"branch {self.branch_id} does not belong to investigation "
                    f"{self.investigation_id}",
                )
            return inv, branch

    def _build_user_prompt(
        self,
        *,
        inv: VRInvestigationRecord,
        branch: VRInvestigationBranchRecord,
        case_state: ReasoningCaseState,
        turn: int,
        pending_operator_messages: list[dict[str, Any]] | None = None,
    ) -> str:
        """Render the per-turn user prompt.

        Compact + structured. Includes the investigation question,
        target reference, current case state model, turn counter, and
        any pending operator messages (M3.R-6) consumed at this turn.
        MCP tool results land in case_state.observables and surface via
        render_case_model.
        """
        case_model = self._engine.render_case_model(case_state)
        secondary_refs = json.loads(inv.secondary_target_refs_json or "[]")
        secondary_str = (
            ", ".join(str(r) for r in secondary_refs) if secondary_refs else "(none)"
        )

        operator_section = _render_operator_messages_section(
            pending_operator_messages or [],
        )

        return (
            f"# Investigation\n\n"
            f"Title: {inv.title}\n"
            f"Question: {inv.initial_question}\n"
            f"Primary target: {inv.target_id}\n"
            f"Secondary targets: {secondary_str}\n"
            f"Strategy: {inv.strategy_family}\n"
            f"Turn: {turn}\n"
            f"Branch: {branch.id} (persona: {branch.persona_voice or 'none'})\n"
            f"\n"
            f"# Current case state\n\n"
            f"{case_model}\n"
            f"\n"
            f"{operator_section}"
            f"{_render_available_tools_section()}"
            f"# Instruction\n\n"
            f"Produce the next reasoning turn as a JSON object per the "
            f"system prompt schema."
        )

    async def _consume_pending_operator_messages(
        self,
        turn_number: int,
    ) -> list[dict[str, Any]]:
        """Read + consume operator messages with at_turn IS NULL.

        Stamps at_turn=turn_number so subsequent turns don't re-read
        them. Returns the consumed messages' text + intent for prompt
        rendering. Engine messages are ignored — they're already in
        case_state via prior absorb() calls.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(
                    VRInvestigationMessageRecord.branch_id == self.branch_id,
                    VRInvestigationMessageRecord.sender_kind == SenderKind.OPERATOR.value,
                    VRInvestigationMessageRecord.at_turn.is_(None),
                )
                .order_by(VRInvestigationMessageRecord.created_at.asc())
            )).all()

            if not rows:
                return []

            consumed: list[dict[str, Any]] = []
            for row in rows:
                try:
                    payload = json.loads(row.payload_json or "{}")
                except json.JSONDecodeError:
                    payload = {}
                text = str(payload.get("text", "")).strip()
                consumed.append({
                    "id": row.id,
                    "text": text,
                    "intent": row.operator_intent or "unclassified",
                    "sender_id": row.sender_id,
                })
                row.at_turn = turn_number
                uow.session.add(row)
            await uow.commit()
            return consumed


def _render_operator_messages_section(messages: list[dict[str, Any]]) -> str:
    """Render pending operator messages as a markdown block for the prompt.

    Returns "" when no messages — caller concatenates unconditionally.
    Each message is shown with its intent classification (defaults to
    'unclassified' when the message_classifier hasn't tagged it yet).
    """
    if not messages:
        return ""
    lines: list[str] = ["# Operator messages (new — consider before acting)\n"]
    for entry in messages:
        intent = entry.get("intent") or "unclassified"
        text = entry.get("text") or ""
        lines.append(f"- [intent: {intent}] {text}")
    lines.append("")  # trailing blank for spacing before next section
    return "\n".join(lines) + "\n"


def _render_available_tools_section() -> str:
    """Render the catalog of MCP tools the engine may invoke this turn.

    Organized per MCP server. Tools with custom adapters (structured
    payloads) are marked ``[structured]`` so the engine knows which
    calls return high-fidelity rendering; everything else returns a
    bounded TEXT payload via the generic fallback. The catalog is
    derived from ``KNOWN_TOOLS`` + ``specialized_tools()`` so adding a
    new tool only requires updating the registry.
    """
    specialized = set(specialized_tools())
    parts: list[str] = ["# Available tools\n"]
    for server in sorted(KNOWN_TOOLS):
        tool_names = sorted(KNOWN_TOOLS[server])
        parts.append(f"\n## {server} ({len(tool_names)} tools)\n\n")
        for name in tool_names:
            full = f"{server}.{name}"
            marker = " [structured]" if full in specialized else ""
            parts.append(f"- `{full}`{marker}\n")
        parts.append("\n")
    return "".join(parts)



def _decode_case_state(raw_json: str | None) -> ReasoningCaseState:
    if not raw_json:
        return ReasoningCaseState()
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return ReasoningCaseState()
    try:
        return ReasoningCaseState.model_validate(data)
    except (ValueError, TypeError):
        return ReasoningCaseState()


def _encode_case_state(state: ReasoningCaseState) -> str:
    return json.dumps(state.model_dump(mode="json"))


def _decision_to_message_payload(
    decision: ReasoningTurnDecision,
) -> tuple[PayloadKind, dict[str, Any]]:
    """Map a ReasoningTurnDecision into a typed message payload.

    The mapping is intentionally narrow for v0.3 v1:
      - tool_run    → TOOL_CALL payload with command/script_content
      - submit      → OUTCOME_PENDING payload with answer + confidence
      - everything else → TEXT payload with reasoning + expected_observation
    Richer payload kinds (graph_view, taint_flow, etc.) land in M3.R-3
    when MCP adapters produce them.
    """
    if decision.action == "tool_run":
        return PayloadKind.TOOL_CALL, {
            "command": decision.command or "",
            "script_content": decision.script_content or "",
            "reasoning": decision.reasoning,
            "expected_observation": decision.expected_observation,
        }
    if decision.action == "submit":
        return PayloadKind.OUTCOME_PENDING, {
            "answer": decision.answer or "",
            "confidence": (
                decision.confidence if decision.confidence else "unknown"
            ),
            "reasoning": decision.reasoning,
            "provenance": decision.provenance.model_dump(mode="json"),
        }
    return PayloadKind.TEXT, {
        "text": decision.reasoning,
        "expected_observation": decision.expected_observation,
    }


def _terminal_outcome_kind(decision: ReasoningTurnDecision) -> OutcomeKind:
    """Pick a terminal outcome kind from a submit decision.

    v0.3 v1 has a tiny dispatch: confidence >= strong + contract suggests
    DirectFinding -> DirectFinding; otherwise AssessmentReport. Real
    routing logic lands in M3.R-4 outcome_router.
    """
    if decision.confidence in {"strong", "exact"}:
        return OutcomeKind.DIRECT_FINDING
    return OutcomeKind.ASSESSMENT_REPORT


def _to_outcome_confidence(decision: ReasoningTurnDecision) -> OutcomeConfidence:
    if decision.confidence:
        return OutcomeConfidence(decision.confidence)
    return OutcomeConfidence.UNKNOWN


def _outcome_payload(decision: ReasoningTurnDecision) -> dict[str, Any]:
    return {
        "answer": decision.answer or "",
        "reasoning": decision.reasoning,
        "provenance": decision.provenance.model_dump(mode="json"),
        "contract": (
            decision.contract.model_dump(mode="json") if decision.contract else None
        ),
    }


def _load_prompt(strategy_family: str) -> str:
    """Load the system prompt for a strategy family.

    v0.3 v1 ships only ``system_audit.md``; other strategy families
    fall through to it for now. Per-family prompts land as needed.
    """
    candidate = _PROMPT_DIR / f"system_{strategy_family.rsplit('.', 1)[-1]}.md"
    if not candidate.exists():
        candidate = _PROMPT_DIR / "system_audit.md"
    if not candidate.exists():
        raise VulnResearcherError(f"prompt file missing: {candidate}")
    return candidate.read_text(encoding="utf-8")


# Resolves Pydantic forward refs when this module is imported standalone.
ReasoningContract.model_rebuild()

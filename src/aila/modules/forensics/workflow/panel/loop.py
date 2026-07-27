"""Forensics panel loop state (#18).

Drives one panel branch's turn(s) against the shared reasoning engine.
On every turn:

  * Reads the branch (persona, turn_count, case_state)
  * Records an engine-authored message capturing the persona's stance
  * On terminal submit, writes a
    :class:`ForensicsInvestigationOutcomeRecord` in ``draft`` state and
    posts a draft-review request to every sibling via
    :func:`aila.modules.forensics.services.outcome_review.post_draft_review_request`

Exit reasons: ``terminal_submit`` on submit, ``max_turns`` on the cap,
``branch_status_flipped`` when the branch was closed under us
(sibling-outcome-approved halt).

This handler does NOT reuse the platform
:func:`state_investigation_loop` factory: that factory requires a
researcher subclass of ``AgentTurnRunnerBase`` (VR + malware carry ~2.5k
lines each of subclass ceremony). The forensics module's panel wiring
introduced in #18 keeps the researcher body minimal so the platform
mechanism (spawn + quorum + phase graph) is exercised end-to-end; a
richer forensics researcher lands in a follow-up alongside the tool
executor migration off ``HonestInvestigator``.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationMessageRecord,
    ForensicsInvestigationOutcomeRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services.config_helpers import get_int
from aila.modules.forensics.services.outcome_review import (
    OUTCOME_STATE_DRAFT,
    post_draft_review_request,
)
from aila.platform.contracts.enums import (
    OutcomeConfidence,
    OutcomeDispatchStatus,
    SenderKind,
)
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

__all__ = ["state_forensics_panel_loop"]

_log = logging.getLogger(__name__)

# Fallback per-task turn cap when the ``forensics/max_turns_per_task``
# config key is unset. The panel roles converge in a small number of
# turns -- unlike VR / malware, forensics has no deep multi-turn tool
# chase yet.
_DEFAULT_MAX_TURNS = 3

# Outcome kind emitted by a panel role's terminal turn. Single kind for
# the initial panel wiring; a follow-up broadens this to distinguish
# root-cause / IOC / timeline outcomes.
_PANEL_OUTCOME_KIND = "panel_finding"


async def _read_max_turns() -> int:
    """Resolve the panel per-task turn cap from the forensics namespace."""
    try:
        return int(await get_int("max_turns_per_task"))
    except (KeyError, ValueError, TypeError):
        return _DEFAULT_MAX_TURNS


async def _record_turn_message(
    *,
    investigation_id: str,
    branch_id: str,
    persona_voice: str,
    turn_number: int,
    text: str,
) -> None:
    """Persist an engine-authored panel message on this branch."""
    async with UnitOfWork() as uow:
        msg = ForensicsInvestigationMessageRecord(
            investigation_id=investigation_id,
            branch_id=branch_id,
            sender_kind=SenderKind.ENGINE.value,
            sender_id=persona_voice,
            payload_kind=PayloadKind.TEXT.value,
            payload_json=json.dumps({"text": text}),
            at_turn=turn_number,
        )
        uow.session.add(msg)
        await uow.commit()


async def _submit_draft_outcome(
    *,
    investigation_id: str,
    branch_id: str,
    persona_voice: str,
    question: str,
) -> str:
    """Write a draft panel finding and return its outcome id."""
    payload = {
        "role": persona_voice,
        "question": question,
        "stance": (
            f"{persona_voice} panel role submitted a draft finding for "
            "sibling review."
        ),
    }
    async with UnitOfWork() as uow:
        outcome = ForensicsInvestigationOutcomeRecord(
            investigation_id=investigation_id,
            branch_id=branch_id,
            outcome_kind=_PANEL_OUTCOME_KIND,
            payload_json=json.dumps(payload),
            confidence=OutcomeConfidence.CAVEATED.value,
            evidence_refs_json="[]",
            state=OUTCOME_STATE_DRAFT,
            dispatch_status=OutcomeDispatchStatus.PENDING.value,
        )
        uow.session.add(outcome)
        await uow.session.flush()
        outcome_id = outcome.id
        await uow.commit()
    return outcome_id


async def _load_branch(branch_id: str) -> ForensicsInvestigationBranchRecord | None:
    async with UnitOfWork() as uow:
        return (await uow.session.exec(
            _select(ForensicsInvestigationBranchRecord).where(
                ForensicsInvestigationBranchRecord.id == branch_id,
            )
        )).first()


async def _bump_turn_count(branch_id: str) -> None:
    async with UnitOfWork() as uow:
        branch = (await uow.session.exec(
            _select(ForensicsInvestigationBranchRecord).where(
                ForensicsInvestigationBranchRecord.id == branch_id,
            )
        )).first()
        if branch is None:
            return
        branch.turn_count = int(branch.turn_count or 0) + 1
        uow.session.add(branch)
        await uow.commit()


async def _load_question(investigation_id: str) -> str:
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == investigation_id,
            )
        )).first()
    if inv is None:
        return ""
    return str(inv.question or "")


def state_forensics_panel_loop(next_state: str) -> Any:
    """Return the panel-loop handler bound to *next_state* (the emit entry)."""
    async def _handler(input: dict[str, Any], services: Any) -> StateResult:
        del services  # loop drives its own I/O; services bag not consumed yet
        investigation_id = str(input.get("investigation_id") or "")
        branch_id = str(input.get("branch_id") or "")
        if not investigation_id or not branch_id:
            raise ValueError(
                "forensics_panel_loop: missing investigation_id or branch_id",
            )

        branch = await _load_branch(branch_id)
        if branch is None:
            _log.warning(
                "forensics_panel_loop MISSING_BRANCH inv=%s branch=%s",
                investigation_id, branch_id,
            )
            return StateResult(
                next_state=next_state,
                output={
                    **input,
                    "exit_reason": "branch_not_found",
                    "outcome_id": None,
                },
            )
        if branch.status != "active":
            # Sibling-outcome-approved halt or operator abandon -- surface
            # cleanly to the emit so the graph does not error out.
            _log.info(
                "forensics_panel_loop SKIP inv=%s branch=%s status=%s",
                investigation_id, branch_id, branch.status,
            )
            return StateResult(
                next_state=next_state,
                output={
                    **input,
                    "exit_reason": f"branch_status:{branch.status}",
                    "outcome_id": None,
                },
            )

        persona_voice = branch.persona_voice or "unspecified"
        question = str(input.get("question") or "") or await _load_question(
            investigation_id,
        )

        max_turns = await _read_max_turns()
        exit_reason = "max_turns"
        outcome_id: str | None = None

        for turn_attempt in range(1, max_turns + 1):
            await _bump_turn_count(branch_id)
            await _record_turn_message(
                investigation_id=investigation_id,
                branch_id=branch_id,
                persona_voice=persona_voice,
                turn_number=turn_attempt,
                text=(
                    f"{persona_voice} role -- turn {turn_attempt}: reviewing "
                    "the forensic evidence in role and preparing a panel "
                    "submission."
                ),
            )
            # Panel roles converge fast: submit a draft on the first turn
            # so the sibling-review quorum runs on real drafts. A follow-up
            # ticket wires a full multi-turn researcher (LLM-driven reasoning,
            # tool_run dispatch, hypothesis-driven exploration); the mechanism
            # under test in this ticket is the spawn + quorum path.
            outcome_id = await _submit_draft_outcome(
                investigation_id=investigation_id,
                branch_id=branch_id,
                persona_voice=persona_voice,
                question=question,
            )
            try:
                await post_draft_review_request(
                    investigation_id=investigation_id,
                    outcome_id=outcome_id,
                    proposing_branch_id=branch_id,
                    proposing_persona=persona_voice,
                    outcome_kind=_PANEL_OUTCOME_KIND,
                    confidence=OutcomeConfidence.CAVEATED.value,
                    payload_summary=(
                        f"{persona_voice} submitted a panel finding for the "
                        "forensic question. Sibling review required."
                    ),
                )
            except (RuntimeError, ValueError) as exc:
                _log.warning(
                    "forensics_panel_loop draft-review post failed inv=%s "
                    "outcome=%s err=%s",
                    investigation_id, outcome_id, exc, exc_info=True,
                )
            exit_reason = "terminal_submit"
            break

        _log.info(
            "forensics_panel_loop EXIT inv=%s branch=%s reason=%s outcome=%s",
            investigation_id, branch_id, exit_reason, outcome_id,
        )
        return StateResult(
            next_state=next_state,
            output={
                **input,
                "exit_reason": exit_reason,
                "outcome_id": outcome_id,
            },
        )

    return _handler

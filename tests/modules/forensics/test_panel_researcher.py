"""Forensics panel branches run real turns on the shared agent substrate.

The panel researcher drives the platform turn runner against the test
database. Only the provider call and the analyzer transport (SSH command and
script execution) are replaced. Covered: an analyzer action recorded as an
investigation step and fed back into the branch's next prompt, the persona
system prompt, the draft-review gate, sibling approval recording the answer
on the investigation, a rejected draft reopening submission, and the cost
ceiling stopping a turn before the provider call.
"""
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.forensics.agents.panel_actions import PanelActionDispatcher
from aila.modules.forensics.agents.panel_researcher import (
    COST_CEILING_ERROR_PREFIX,
    ForensicsPanelResearcher,
    ForensicsPanelResearcherError,
)
from aila.modules.forensics.db_models import (
    AgentStepRecord,
    AnswerCandidateRecord,
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationOutcomeRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services import analyzer_actions
from aila.modules.forensics.workflow.panel import emit as panel_emit
from aila.modules.forensics.workflow.panel.emit import (
    _close_branch_after_loop,
    _reopen_reviewers_for_draft,
)
from aila.platform.contracts.reasoning import EvidenceProvenance, ReasoningTurnDecision
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord

pytestmark = pytest.mark.usefixtures("test_db")

_SHELL = "grep -i runonce /evidence/registry.txt"
_TOOL_RUN = json.dumps({"tool": "analyzer.run_command", "args": {"command": _SHELL}})
_STDOUT = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce updater.exe"


class _Panel:
    """Seeded project, analyzer system, running investigation, and three branches."""

    def __init__(self, suffix: str, project_id: str, inv_id: str, branches: dict[str, str]) -> None:
        self.suffix = suffix
        self.project_id = project_id
        self.inv_id = inv_id
        self.branches = branches


async def _seed_panel() -> _Panel:
    suffix = uuid4().hex[:8]
    project_id = f"proj-{suffix}"
    inv_id = f"inv-{suffix}"
    async with async_session_scope() as session:
        system = ManagedSystemRecord(
            name=f"analyzer-{suffix}", host=f"analyzer-{suffix}.test", username="examiner",
        )
        session.add(system)
        await session.flush()
        session.add(ForensicsProjectRecord(
            id=project_id,
            name=f"panel-{suffix}",
            system_id=system.id,
            evidence_directory="/evidence",
            analyzer_os="linux",
        ))
        await session.flush()
        session.add(InvestigationRunRecord(
            id=inv_id, project_id=project_id, question="How did the implant persist?",
            status="running",
        ))
        await session.flush()
        branches: dict[str, str] = {}
        for persona, fork_reason in (("halvar", "primary"), ("maddie", "persona"), ("renzo", "persona")):
            branch = ForensicsInvestigationBranchRecord(
                investigation_id=inv_id,
                status="active",
                persona_voice=persona,
                fork_reason=fork_reason,
                fork_at_turn=0,
                case_state_json="{}",
                turn_count=0,
                branch_cost_usd=0.0,
            )
            session.add(branch)
            await session.flush()
            branches[persona] = branch.id
        await session.commit()
    return _Panel(suffix, project_id, inv_id, branches)


class _Provider:
    """Scripted provider: returns queued decisions and records each prompt pair."""

    def __init__(self) -> None:
        self.queue: list[ReasoningTurnDecision] = []
        self.prompts: list[dict[str, str]] = []

    def engine(self) -> CyberReasoningEngine:
        engine = CyberReasoningEngine(None)  # type: ignore[arg-type]

        async def decide_next_turn(**kwargs: Any) -> ReasoningTurnDecision:
            self.prompts.append({
                "system": str(kwargs.get("system_prompt") or ""),
                "user": str(kwargs.get("user_prompt") or ""),
            })
            return self.queue.pop(0)

        engine.decide_next_turn = decide_next_turn  # type: ignore[method-assign]
        return engine


@pytest.fixture
def analyzer(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    """Replace the analyzer transport; record (shell command, integration) per call."""
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_command(
        *, settings: Any, integration: dict[str, Any], investigation_id: str, command: str,
    ) -> dict[str, Any]:
        calls.append((command, integration))
        return {"stdout": _STDOUT, "stderr": "", "exit_code": 0}

    monkeypatch.setattr(analyzer_actions, "execute_command", fake_command)
    return calls


async def _turn(
    provider: _Provider,
    panel: _Panel,
    persona: str,
    decision: ReasoningTurnDecision,
    dispatch: Callable[..., Awaitable[Any]] | None = None,
) -> Any:
    provider.queue.append(decision)
    researcher = ForensicsPanelResearcher(
        reasoning_engine=provider.engine(),
        investigation_id=panel.inv_id,
        branch_id=panel.branches[persona],
    )
    result = await researcher.run_turn()
    if dispatch is not None and not result.terminal:
        await dispatch(
            investigation_id=panel.inv_id,
            branch_id=panel.branches[persona],
            decision=result.decision,
            at_turn=result.turn,
            phase_allowed_servers=None,
        )
    return result


def _submit(answer: str) -> ReasoningTurnDecision:
    return ReasoningTurnDecision(
        reasoning="the RunOnce value launches updater.exe at logon",
        action="submit",
        answer=answer,
        confidence="strong",
        provenance=EvidenceProvenance(
            primary_artifact="/evidence/registry.txt",
            corroboration=["/evidence/prefetch/UPDATER.EXE-1A2B3C4D.pf"],
        ),
    )


def _vote(outcome_id: str, vote: str, comment: str) -> ReasoningTurnDecision:
    return ReasoningTurnDecision(
        reasoning=f"re-checked the cited registry value: {vote}",
        action="submit_outcome_review",
        review_outcome_id=outcome_id,
        review_vote=vote,  # type: ignore[arg-type]
        review_comment=comment,
    )


async def _outcomes(inv_id: str) -> list[ForensicsInvestigationOutcomeRecord]:
    async with async_session_scope() as session:
        return list((await session.exec(
            select(ForensicsInvestigationOutcomeRecord)
            .where(ForensicsInvestigationOutcomeRecord.investigation_id == inv_id)
            .order_by(ForensicsInvestigationOutcomeRecord.created_at),
        )).all())


async def test_analyzer_action_is_recorded_and_fed_into_the_next_prompt(
    analyzer: list[tuple[str, dict[str, Any]]],
) -> None:
    panel = await _seed_panel()
    provider = _Provider()
    dispatcher = PanelActionDispatcher()

    await _turn(
        provider, panel, "halvar",
        ReasoningTurnDecision(reasoning="check autoruns", action="tool_run", command=_TOOL_RUN),
        dispatch=dispatcher,
    )
    await _turn(
        provider, panel, "halvar",
        ReasoningTurnDecision(reasoning="correlate with prefetch", action="reasoning"),
    )

    assert [cmd for cmd, _ in analyzer] == [_SHELL]
    assert analyzer[0][1]["host"] == f"analyzer-{panel.suffix}.test"
    async with async_session_scope() as session:
        steps = (await session.exec(
            select(AgentStepRecord).where(AgentStepRecord.investigation_id == panel.inv_id),
        )).all()
    assert [(s.action, s.command, s.stdout, s.exit_code) for s in steps] == [
        ("tool_run", _SHELL, _STDOUT, 0),
    ]
    assert json.loads(steps[0].reasoning)["panel"]["persona_voice"] == "halvar"
    assert "Your voice: HALVAR" in provider.prompts[0]["system"]
    assert _STDOUT in provider.prompts[1]["user"]


async def test_sibling_approvals_record_the_answer_on_the_investigation() -> None:
    panel = await _seed_panel()
    provider = _Provider()
    answer = "RunOnce value launching updater.exe"

    first = await _turn(provider, panel, "halvar", _submit(answer))
    assert first.terminal
    draft = (await _outcomes(panel.inv_id))[0]
    assert draft.state == "draft"

    blocked = await _turn(provider, panel, "maddie", _submit("a scheduled task"))
    assert not blocked.terminal
    assert len(await _outcomes(panel.inv_id)) == 1
    assert "Draft answers awaiting your vote" in provider.prompts[-1]["user"]

    await _turn(provider, panel, "maddie", _vote(draft.id, "approve", "value present at the cited key"))
    assert (await _outcomes(panel.inv_id))[0].state == "draft"
    await _turn(provider, panel, "renzo", _vote(draft.id, "approve", "prefetch run time follows logon"))

    async with async_session_scope() as session:
        inv = (await session.exec(
            select(InvestigationRunRecord).where(InvestigationRunRecord.id == panel.inv_id),
        )).one()
        candidates = (await session.exec(
            select(AnswerCandidateRecord).where(AnswerCandidateRecord.investigation_id == panel.inv_id),
        )).all()
    assert (await _outcomes(panel.inv_id))[0].state == "dispatched"
    assert (inv.final_answer, inv.confidence, inv.primary_outcome_id) == (answer, "strong", draft.id)
    assert [(c.answer_text, c.primary_artifact_id) for c in candidates] == [
        (answer, "/evidence/registry.txt"),
    ]


async def test_rejected_draft_reopens_reviewers_and_bounds_repeat_proposals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panel = await _seed_panel()
    provider = _Provider()
    enqueued: list[dict[str, Any]] = []

    class _Queue:
        async def submit(self, **kwargs: Any) -> SimpleNamespace:
            enqueued.append(kwargs)
            return SimpleNamespace(task_id=f"review-{len(enqueued)}")

    monkeypatch.setattr(panel_emit, "default_task_queue", lambda: _Queue())

    await _turn(provider, panel, "halvar", _submit("RunOnce value launching updater.exe"))
    await _close_branch_after_loop(panel.branches["halvar"], "terminal_submit")
    draft = (await _outcomes(panel.inv_id))[0]
    await _turn(
        provider, panel, "maddie",
        _vote(draft.id, "reject", "the RunOnce value was deleted before the first prefetch run"),
    )
    second = await _turn(provider, panel, "renzo", _submit("scheduled task UpdaterTask"))
    await _close_branch_after_loop(panel.branches["renzo"], "terminal_submit")

    outcomes = await _outcomes(panel.inv_id)
    assert second.terminal
    assert [(o.state, o.branch_id) for o in outcomes] == [
        ("rejected", panel.branches["halvar"]),
        ("draft", panel.branches["renzo"]),
    ]
    reactivated = await _reopen_reviewers_for_draft(panel.inv_id, second.outcome_id, panel.branches["renzo"])
    assert reactivated == [panel.branches["halvar"]]
    assert [call["kwargs"]["branch_id"] for call in enqueued] == [panel.branches["halvar"]]

    # The first proposer can review the successor but cannot start an
    # unbounded sequence of its own rejected proposals.
    repeat = await _turn(provider, panel, "halvar", _submit("another RunOnce theory"))
    assert not repeat.terminal
    assert len(await _outcomes(panel.inv_id)) == 2

    await _turn(provider, panel, "halvar", _vote(second.outcome_id, "approve", "task XML verified"))
    await _turn(provider, panel, "maddie", _vote(second.outcome_id, "approve", "task run corroborated"))
    assert (await _outcomes(panel.inv_id))[1].state == "dispatched"
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, panel.inv_id)
        assert inv is not None and inv.final_answer == "scheduled task UpdaterTask"


async def test_cost_ceiling_stops_the_turn_before_the_provider_call() -> None:
    panel = await _seed_panel()
    provider = _Provider()
    async with async_session_scope() as session:
        session.add(LLMCostRecord(
            run_id=panel.inv_id, model_id="test-model", task_type="forensics_freeflow",
            cost_usd=10_000.0,
        ))
        await session.commit()

    with pytest.raises(ForensicsPanelResearcherError, match=COST_CEILING_ERROR_PREFIX):
        await _turn(provider, panel, "halvar", ReasoningTurnDecision(reasoning="x"))
    assert provider.prompts == []


async def test_unsupported_tool_run_fails_the_step_without_reaching_the_analyzer(
    analyzer: list[tuple[str, dict[str, Any]]],
) -> None:
    panel = await _seed_panel()
    dispatcher = PanelActionDispatcher()
    bad = json.dumps({"tool": "rea.analyze", "args": {"command": _SHELL}})

    result = await dispatcher(
        investigation_id=panel.inv_id,
        branch_id=panel.branches["renzo"],
        decision=ReasoningTurnDecision(reasoning="x", action="tool_run", command=bad),
        at_turn=1,
        phase_allowed_servers=None,
    )
    nothing = await dispatcher(
        investigation_id=panel.inv_id,
        branch_id=panel.branches["renzo"],
        decision=ReasoningTurnDecision(reasoning="thinking", action="reasoning"),
        at_turn=2,
        phase_allowed_servers=None,
    )

    assert analyzer == []
    assert result is not None and not result.success
    assert "analyzer.run_command" in result.error
    assert nothing is None
    async with async_session_scope() as session:
        steps = (await session.exec(
            select(AgentStepRecord).where(AgentStepRecord.investigation_id == panel.inv_id),
        )).all()
    assert [(s.action, s.exit_code) for s in steps] == [("tool_run", 1)]

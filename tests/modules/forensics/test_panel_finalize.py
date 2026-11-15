"""Forensics panel settlement and write-up reconstruction behavior."""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.forensics.db_models import (
    AgentStepRecord,
    AnswerCandidateRecord,
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationOutcomeRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
    WriteUpRecord,
)
from aila.modules.forensics.workflow.panel import finalize as panel_finalize
from aila.modules.forensics.workflow.panel.emit import _close_branch_after_loop
from aila.modules.forensics.workflow.panel.writeup import (
    _state_load_panel_writeup,
    run_forensics_panel_writeup,
)
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.workflows.types import RESERVED_SUCCEEDED
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord

pytestmark = pytest.mark.usefixtures("test_db")


class _Queue:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def submit(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        return SimpleNamespace(task_id=f"writeup-{len(self.calls)}")


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> _Queue:
    recorder = _Queue()
    monkeypatch.setattr(panel_finalize, "default_task_queue", lambda: recorder)
    return recorder


async def _seed(*, branch_statuses: tuple[str, ...] = ("completed", "completed")) -> dict[str, Any]:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        system = ManagedSystemRecord(
            name=f"analyzer-{suffix}", host=f"analyzer-{suffix}.test", username="examiner",
        )
        session.add(system)
        await session.flush()
        project = ForensicsProjectRecord(
            name=f"panel-{suffix}", system_id=system.id,
            evidence_directory="/evidence", team_id="team-panel",
        )
        session.add(project)
        await session.flush()
        inv = InvestigationRunRecord(
            project_id=project.id, team_id=project.team_id,
            question="How did the implant persist?", status="running",
        )
        session.add(inv)
        await session.flush()
        branches = []
        for index, status in enumerate(branch_statuses):
            branch = ForensicsInvestigationBranchRecord(
                investigation_id=inv.id, status=status,
                persona_voice=("halvar", "maddie", "renzo")[index],
                case_state_json=json.dumps({"observables": {"registry": "RunOnce"}}),
            )
            session.add(branch)
            await session.flush()
            branches.append(branch.id)
        session.add(AgentStepRecord(
            investigation_id=inv.id, team_id=inv.team_id, step_number=1,
            action="tool_run", command="grep RunOnce /evidence/registry.txt",
            stdout="updater.exe", exit_code=0,
            reasoning=json.dumps({
                "reasoning": "RunOnce launches updater.exe",
                "provenance": {"primary_artifact": "/evidence/registry.txt"},
                "panel": {"persona_voice": "halvar"},
            }),
        ))
        await session.commit()
        ids = {"project_id": project.id, "inv_id": inv.id, "branches": branches}
    return ids


async def _add_outcome(
    ids: dict[str, Any], state: str, *, answer: str = "RunOnce launches updater.exe",
) -> str:
    async with async_session_scope() as session:
        outcome = ForensicsInvestigationOutcomeRecord(
            investigation_id=ids["inv_id"], branch_id=ids["branches"][0],
            outcome_kind="forensic_answer", confidence="strong", state=state,
            payload_json=json.dumps({
                "answer": answer,
                "provenance": {
                    "primary_artifact": "/evidence/registry.txt",
                    "corroboration": ["/evidence/prefetch/UPDATER.EXE.pf"],
                },
                "contract": {"answer_format": "persistence mechanism"},
            }),
        )
        session.add(outcome)
        await session.commit()
        return outcome.id


async def test_last_branch_settles_approved_answer_and_enqueues_writeup_once(
    queue: _Queue,
) -> None:
    ids = await _seed()
    outcome_id = await _add_outcome(ids, "approved")

    first = await panel_finalize.finalize_panel_investigation(ids["inv_id"])
    second = await panel_finalize.finalize_panel_investigation(ids["inv_id"])

    assert (first.status, first.writeup_task_id) == ("completed", "writeup-1")
    assert not second.finalized
    assert [c["fn"] for c in queue.calls] == [run_forensics_panel_writeup]
    assert queue.calls[0]["kwargs"] == {"investigation_id": ids["inv_id"]}
    assert queue.calls[0]["team_id"] == "team-panel"
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, ids["inv_id"])
        candidates = (await session.exec(
            select(AnswerCandidateRecord).where(
                AnswerCandidateRecord.investigation_id == ids["inv_id"],
            ),
        )).all()
    assert inv is not None
    assert (inv.final_answer, inv.confidence, inv.primary_outcome_id) == (
        "RunOnce launches updater.exe", "strong", outcome_id,
    )
    assert inv.stopped_at is not None
    assert len(candidates) == 1


async def test_active_branch_defers_settlement(queue: _Queue) -> None:
    ids = await _seed(branch_statuses=("completed", "active"))
    await _add_outcome(ids, "draft")

    result = await panel_finalize.finalize_panel_investigation(ids["inv_id"])

    assert not result.finalized
    assert queue.calls == []
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, ids["inv_id"])
        assert inv is not None and inv.status == "running"


async def test_cost_ceiling_produces_budget_exhausted_answer(queue: _Queue) -> None:
    ids = await _seed()
    async with async_session_scope() as session:
        session.add(LLMCostRecord(
            run_id=ids["inv_id"], model_id="test-model",
            task_type="forensics_freeflow", cost_usd=10_000.0,
        ))
        await session.commit()

    result = await panel_finalize.finalize_panel_investigation(ids["inv_id"])

    assert result.status == "exhausted"
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, ids["inv_id"])
        assert inv is not None
        assert inv.final_answer is not None and inv.final_answer.startswith("<budget_exhausted:")
        assert inv.confidence == "caveated"
    assert len(queue.calls) == 1


async def test_rejected_answer_fails_with_the_rejected_claim(queue: _Queue) -> None:
    ids = await _seed()
    await _add_outcome(ids, "rejected", answer="Scheduled task UpdaterTask")

    result = await panel_finalize.finalize_panel_investigation(ids["inv_id"])

    assert result.status == "failed"
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, ids["inv_id"])
        assert inv is not None
        assert "Panel rejected" in (inv.final_answer or "")
        assert "Scheduled task UpdaterTask" in (inv.final_answer or "")


async def test_unvoted_draft_exhausts_instead_of_claiming_completion(queue: _Queue) -> None:
    ids = await _seed()
    await _add_outcome(ids, "draft")

    result = await panel_finalize.finalize_panel_investigation(ids["inv_id"])

    assert result.status == "exhausted"
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, ids["inv_id"])
        assert inv is not None and "quorum" in (inv.final_answer or "")


async def test_loop_exit_closes_only_branch_owned_states() -> None:
    ids = await _seed(branch_statuses=("active", "paused"))

    await _close_branch_after_loop(ids["branches"][0], "terminal_submit")
    await _close_branch_after_loop(ids["branches"][1], "inv_status_flipped:paused")

    async with async_session_scope() as session:
        first = await session.get(ForensicsInvestigationBranchRecord, ids["branches"][0])
        second = await session.get(ForensicsInvestigationBranchRecord, ids["branches"][1])
        assert first is not None and first.status == "completed"
        assert first.closed_reason == "terminal_submit"
        assert second is not None and second.status == "paused"
        assert second.closed_at is None


async def test_writeup_input_reuses_panel_steps_and_is_idempotent() -> None:
    ids = await _seed()
    outcome_id = await _add_outcome(ids, "dispatched")
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, ids["inv_id"])
        assert inv is not None
        inv.primary_outcome_id = outcome_id
        inv.status = "completed"
        inv.final_answer = "RunOnce launches updater.exe"
        inv.confidence = "strong"
        session.add(inv)
        await session.commit()

    loaded = await _state_load_panel_writeup({"investigation_id": ids["inv_id"]}, None)

    assert loaded.next_state == "promotion"
    assert loaded.output["answer"] == "RunOnce launches updater.exe"
    assert loaded.output["observables"] == {"registry": "RunOnce"}
    assert loaded.output["contract"] == {"answer_format": "persistence mechanism"}
    assert loaded.output["steps"][0]["reasoning"] == "RunOnce launches updater.exe"
    assert loaded.output["steps"][0]["panel"] == {"persona_voice": "halvar"}

    async with async_session_scope() as session:
        session.add(WriteUpRecord(
            project_id=ids["project_id"], investigation_id=ids["inv_id"],
            title="Persistence write-up", content_markdown="done",
        ))
        await session.commit()
        writeup_id = (await session.exec(
            select(WriteUpRecord.id).where(WriteUpRecord.investigation_id == ids["inv_id"]),
        )).one()
    repeated = await _state_load_panel_writeup({"investigation_id": ids["inv_id"]}, None)
    assert repeated.next_state == RESERVED_SUCCEEDED
    assert repeated.output["writeup_id"] == writeup_id

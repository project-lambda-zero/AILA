"""Forensics investigator and freeflow stop on paused and terminal statuses (#352).

``HonestInvestigator.investigate`` reads the persisted investigation status at
every turn boundary. A paused, completed, exhausted, or failed row ends the loop
before the next provider or tool call and returns a non-cancelled
``stopped_status`` result with no cancellation event. A cancelled row keeps its
cancelled result. ``state_freeflow`` consumes a stopped result without the
zero-step failure path and leaves the persisted status untouched.

Only the provider call, the prompt-store lookup, the SSH-backed tool methods,
and the snapshot sink are replaced. Investigation rows, steps, and status
writes run against the test database.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.forensics.agents import investigator as investigator_module
from aila.modules.forensics.agents.investigator import HonestInvestigator
from aila.modules.forensics.db_models import (
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.workflow.states import freeflow as freeflow_module
from aila.modules.forensics.workflow.states.freeflow import state_freeflow
from aila.platform.contracts.reasoning import ReasoningTurnDecision
from aila.platform.llm.errors import BudgetExceededError, LLMError
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.prompts import LoadedPrompt
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.storage.database import async_session_scope

pytestmark = pytest.mark.usefixtures("test_db")

_STOP_STATUSES = ["paused", "completed", "exhausted", "failed"]
_ALL_STOP_STATUSES = [*_STOP_STATUSES, "cancelled"]
_COMMAND = json.dumps({"tool": "run_command", "args": {"command": "uname -a"}})

Decide = Callable[[int], Awaitable[ReasoningTurnDecision]]


class _Emitter:
    def __init__(self) -> None:
        self.stages: list[str] = []

    async def emit(self, stream: str, message: str, meta: dict[str, Any] | None = None) -> None:
        self.stages.append(str((meta or {}).get("stage", "")))


class _Graphs:
    """Inert snapshot sink; graph persistence is not under test."""

    async def save_snapshot(self, **_kwargs: Any) -> None:
        return None


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Ledger of provider calls and tool executions for one test."""
    ledger: dict[str, list[Any]] = {"provider": [], "tools": []}

    async def fake_command(self: HonestInvestigator, command: str) -> dict[str, Any]:
        ledger["tools"].append(command)
        return {"stdout": "", "stderr": "", "exit_code": 0}

    async def fake_script(self: HonestInvestigator, script_content: str) -> dict[str, Any]:
        ledger["tools"].append(script_content)
        return {"stdout": "", "stderr": "", "exit_code": 0}

    async def fake_prompt(analyzer_os: str, *, investigation_id: str) -> LoadedPrompt:
        return LoadedPrompt(body="system prompt", version=None)

    monkeypatch.setattr(HonestInvestigator, "_execute_command", fake_command)
    monkeypatch.setattr(HonestInvestigator, "_execute_script", fake_script)
    monkeypatch.setattr(investigator_module, "_resolve_freeflow_prompt", fake_prompt)
    return ledger


def _reason() -> ReasoningTurnDecision:
    return ReasoningTurnDecision(reasoning="correlate the timeline", action="reasoning")


def _tool() -> ReasoningTurnDecision:
    return ReasoningTurnDecision(reasoning="inspect the host", action="tool_run", command=_COMMAND)


def _always(decision: ReasoningTurnDecision) -> Decide:
    async def decide(_call_number: int) -> ReasoningTurnDecision:
        return decision

    return decide


def _flip_on_first_call(inv_id: str, status: str, decision: ReasoningTurnDecision) -> Decide:
    """Simulate the lifecycle writing ``status`` while turn 1's provider call is in flight."""

    async def decide(call_number: int) -> ReasoningTurnDecision:
        if call_number == 1:
            await _force_status(inv_id, status)
        return decision

    return decide


def _breach_cost_then_hold_until_cancelled(inv_id: str) -> Decide:
    """Accrue spend that crosses the cap during turn 1, then hold until the monitor flips the row."""

    async def decide(call_number: int) -> ReasoningTurnDecision:
        if call_number == 1:
            async with async_session_scope() as session:
                session.add(LLMCostRecord(
                    run_id=inv_id,
                    model_id="test-model",
                    task_type="forensics_freeflow",
                    cost_usd=2.0,
                ))
                await session.commit()
            async with asyncio.timeout(10):
                while (await _persisted(inv_id))[0] != "cancelled":
                    await asyncio.sleep(0.01)
        return _reason()

    return decide


def _engine(calls: dict[str, list[Any]], decide: Decide) -> CyberReasoningEngine:
    """Real reasoning engine whose only replaced method is the provider call."""
    engine = CyberReasoningEngine(None)  # type: ignore[arg-type]

    async def decide_next_turn(**_kwargs: Any) -> ReasoningTurnDecision:
        calls["provider"].append(len(calls["provider"]) + 1)
        return await decide(len(calls["provider"]))

    engine.decide_next_turn = decide_next_turn  # type: ignore[method-assign]
    return engine


def _flip_after_running(monkeypatch: pytest.MonkeyPatch, inv_id: str, status: str) -> None:
    """Simulate the lifecycle writing ``status`` right after the pending-to-running setup."""
    original = HonestInvestigator._set_status

    async def set_then_flip(self: HonestInvestigator, status_value: str) -> None:
        await original(self, status_value)
        if status_value == "running":
            await _force_status(inv_id, status)

    monkeypatch.setattr(HonestInvestigator, "_set_status", set_then_flip)


def _investigator(engine: CyberReasoningEngine, project_id: str, inv_id: str) -> HonestInvestigator:
    return HonestInvestigator(
        settings=None,  # type: ignore[arg-type]
        reasoning_engine=engine,
        reasoning_graphs=_Graphs(),  # type: ignore[arg-type]
        run_id=f"run-{inv_id}",
        integration={},
        project_id=project_id,
        investigation_id=inv_id,
        analyzer_os="linux",
    )


def _services(engine: CyberReasoningEngine, emitter: _Emitter) -> SimpleNamespace:
    return SimpleNamespace(
        settings=None,
        reasoning_engine=engine,
        reasoning_graphs=_Graphs(),
        run_id="run-freeflow",
        integration={},
        emitter=emitter,
    )


def _freeflow_input(project_id: str, inv_id: str, max_attempts: int) -> dict[str, Any]:
    return {
        "investigation_id": inv_id,
        "project_id": project_id,
        "question": "what happened",
        "max_attempts": max_attempts,
        "analyzer_os": "linux",
    }


async def _seed(status: str) -> tuple[str, str]:
    suffix = uuid4().hex[:8]
    project_id = f"proj-{suffix}"
    inv_id = f"inv-{suffix}"
    async with async_session_scope() as session:
        session.add(ForensicsProjectRecord(
            id=project_id,
            name=f"test-{suffix}",
            system_id=0,
            evidence_directory="/evidence",
            analyzer_os="linux",
        ))
        await session.flush()
        session.add(InvestigationRunRecord(
            id=inv_id,
            project_id=project_id,
            question="what happened",
            status=status,
        ))
        await session.commit()
    return project_id, inv_id


async def _force_status(inv_id: str, status: str) -> None:
    async with async_session_scope() as session:
        row = (await session.exec(
            select(InvestigationRunRecord).where(InvestigationRunRecord.id == inv_id)
        )).first()
        assert row is not None
        row.status = status
        session.add(row)
        await session.commit()


async def _persisted(inv_id: str) -> tuple[str, str | None]:
    async with async_session_scope() as session:
        row = (await session.exec(
            select(InvestigationRunRecord).where(InvestigationRunRecord.id == inv_id)
        )).first()
        assert row is not None
        return row.status, row.final_answer


# ---------------------------------------------------------------- investigator


async def test_running_investigation_takes_every_turn_and_setup_reaches_running(
    calls: dict[str, list[Any]],
) -> None:
    project_id, inv_id = await _seed("pending")
    engine = _engine(calls, _always(_tool()))

    result = await _investigator(engine, project_id, inv_id).investigate(
        question="what happened", max_attempts=2, emitter=_Emitter(),
    )

    assert len(calls["provider"]) == 2
    assert calls["tools"] == [_COMMAND, _COMMAND]
    assert "stopped_status" not in result
    assert not result.get("cancelled")
    assert result["attempts_used"] == 2
    status, _ = await _persisted(inv_id)
    assert status == "running"


@pytest.mark.parametrize("status", _STOP_STATUSES)
async def test_stop_status_before_first_turn_makes_no_provider_or_tool_call(
    status: str, calls: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, inv_id = await _seed("pending")
    _flip_after_running(monkeypatch, inv_id, status)
    engine = _engine(calls, _always(_tool()))
    emitter = _Emitter()

    result = await _investigator(engine, project_id, inv_id).investigate(
        question="what happened", max_attempts=3, emitter=emitter,
    )

    assert calls["provider"] == []
    assert calls["tools"] == []
    assert result["stopped_status"] == status
    assert result["cancelled"] is False
    assert result["answer"] is None
    assert result["steps"] == []
    assert "cancelled" not in emitter.stages
    persisted_status, _ = await _persisted(inv_id)
    assert persisted_status == status


async def test_cancel_before_first_turn_keeps_cancelled_result_and_event(
    calls: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, inv_id = await _seed("pending")
    _flip_after_running(monkeypatch, inv_id, "cancelled")
    engine = _engine(calls, _always(_tool()))
    emitter = _Emitter()

    result = await _investigator(engine, project_id, inv_id).investigate(
        question="what happened", max_attempts=3, emitter=emitter,
    )

    assert calls["provider"] == []
    assert calls["tools"] == []
    assert result["cancelled"] is True
    assert result["answer"] == "Cancelled by analyst."
    assert "stopped_status" not in result
    assert "cancelled" in emitter.stages


@pytest.mark.parametrize("status", _ALL_STOP_STATUSES)
async def test_redispatched_stopped_row_keeps_its_status_and_runs_no_turn(
    status: str, calls: dict[str, list[Any]],
) -> None:
    project_id, inv_id = await _seed(status)
    engine = _engine(calls, _always(_tool()))

    result = await _investigator(engine, project_id, inv_id).investigate(
        question="what happened", max_attempts=3, emitter=_Emitter(),
    )

    assert calls["provider"] == []
    assert calls["tools"] == []
    assert result["attempts_used"] == 0
    assert result["cancelled"] is (status == "cancelled")
    assert (await _persisted(inv_id))[0] == status


async def test_status_write_never_leaves_cancelled(calls: dict[str, list[Any]]) -> None:
    project_id, inv_id = await _seed("cancelled")
    investigator = _investigator(_engine(calls, _always(_reason())), project_id, inv_id)

    await investigator._set_status("running")

    assert (await _persisted(inv_id))[0] == "cancelled"


@pytest.mark.parametrize("status", _STOP_STATUSES)
async def test_stop_status_set_during_turn_blocks_the_next_provider_call(
    status: str, calls: dict[str, list[Any]],
) -> None:
    project_id, inv_id = await _seed("pending")
    engine = _engine(calls, _flip_on_first_call(inv_id, status, _reason()))
    emitter = _Emitter()

    result = await _investigator(engine, project_id, inv_id).investigate(
        question="what happened", max_attempts=3, emitter=emitter,
    )

    assert len(calls["provider"]) == 1
    assert calls["tools"] == []
    assert result["stopped_status"] == status
    assert result["cancelled"] is False
    assert result["attempts_used"] == 1
    assert "cancelled" not in emitter.stages
    persisted_status, _ = await _persisted(inv_id)
    assert persisted_status == status


# ------------------------------------------------------------------- freeflow


@pytest.mark.parametrize("status", _ALL_STOP_STATUSES)
async def test_freeflow_preserves_status_stopped_before_first_turn(
    status: str, calls: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, inv_id = await _seed("pending")
    _flip_after_running(monkeypatch, inv_id, status)
    engine = _engine(calls, _always(_reason()))

    await state_freeflow(
        _freeflow_input(project_id, inv_id, max_attempts=3),
        _services(engine, _Emitter()),
    )

    assert calls["provider"] == []
    assert (await _persisted(inv_id))[0] == status


@pytest.mark.parametrize("status", _STOP_STATUSES)
async def test_freeflow_preserves_status_stopped_mid_investigation(
    status: str, calls: dict[str, list[Any]],
) -> None:
    project_id, inv_id = await _seed("pending")
    engine = _engine(calls, _flip_on_first_call(inv_id, status, _reason()))

    await state_freeflow(
        _freeflow_input(project_id, inv_id, max_attempts=3),
        _services(engine, _Emitter()),
    )

    assert len(calls["provider"]) == 1
    assert calls["tools"] == []
    assert (await _persisted(inv_id))[0] == status


async def test_freeflow_cost_ceiling_still_exhausts_the_investigation(
    calls: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, inv_id = await _seed("pending")

    async def cap_one_dollar() -> float:
        return 1.0

    monkeypatch.setattr(freeflow_module, "_read_freeflow_max_cost_usd", cap_one_dollar)
    monkeypatch.setattr(freeflow_module, "_COST_MONITOR_POLL_SECONDS", 0.01)
    engine = _engine(calls, _breach_cost_then_hold_until_cancelled(inv_id))

    await state_freeflow(
        _freeflow_input(project_id, inv_id, max_attempts=3),
        _services(engine, _Emitter()),
    )

    assert len(calls["provider"]) == 1
    assert calls["tools"] == []
    status, final_answer = await _persisted(inv_id)
    assert status == "exhausted"
    assert final_answer is not None
    assert final_answer.startswith("<budget_exhausted:")


@pytest.mark.parametrize(
    "error",
    [LLMError("provider rejected the request"), BudgetExceededError("provider rejected the request")],
    ids=["llm_error", "budget_exceeded"],
)
async def test_freeflow_provider_failure_fails_the_investigation(
    error: Exception, calls: dict[str, list[Any]],
) -> None:
    project_id, inv_id = await _seed("pending")

    async def raise_error(_call_number: int) -> ReasoningTurnDecision:
        raise error

    engine = _engine(calls, raise_error)
    emitter = _Emitter()

    with pytest.raises(type(error)):
        await state_freeflow(
            _freeflow_input(project_id, inv_id, max_attempts=3),
            _services(engine, emitter),
        )

    assert len(calls["provider"]) == 1
    assert emitter.stages.count("agent_failed") == 1
    status, final_answer = await _persisted(inv_id)
    assert status == "failed"
    assert final_answer == "provider rejected the request"

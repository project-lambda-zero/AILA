"""Dispatch-hub graph run through the real DurableStateMachine (RFC-13 Phase 4)."""
from __future__ import annotations

from typing import Any

from aila.platform.services.ledger import LedgerService
from aila.platform.workflows import DurableStateMachine, StateResult
from aila.platform.workflows.phase_graph import (
    DISPATCH_STATE,
    PhaseSpec,
    build_dispatch_workflow,
)
from aila.platform.workflows.types import RESERVED_SUCCEEDED
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor

_DEF_ID = "test.hub.v1"


async def _svc(run_id: str) -> Any:
    del run_id
    return object()


def _make_wf(phases: tuple[PhaseSpec, ...], ran: list[str]) -> Any:
    def setup_builder(next_state: str) -> Any:
        async def _h(state_input: dict[str, Any], services: Any) -> StateResult:
            del services
            return StateResult(next_state=next_state, output={**state_input})
        return _h

    def loop_builder(phase: PhaseSpec, next_state: str) -> Any:
        async def _h(state_input: dict[str, Any], services: Any) -> StateResult:
            del services
            ran.append(phase.name)
            return StateResult(next_state=next_state, output={**state_input})
        return _h

    async def emit_handler(state_input: dict[str, Any], services: Any) -> StateResult:
        del services
        return StateResult(next_state=RESERVED_SUCCEEDED, output={**state_input})

    return build_dispatch_workflow(
        _DEF_ID, phases,
        services_factory=_svc,
        setup_builder=setup_builder,
        loop_builder=loop_builder,
        emit_handler=emit_handler,
    )


async def _always(state_input: dict[str, Any]) -> tuple[bool, str]:
    del state_input
    return True, "always"


async def _never(state_input: dict[str, Any]) -> tuple[bool, str]:
    del state_input
    return False, "never"


async def test_hub_runs_setup_phase_hub_phase_emit(workflow_run_id: str) -> None:
    ran: list[str] = []
    phases = (
        PhaseSpec(name="phaseA", condition=_always),
        PhaseSpec(name="phaseB", condition=_always),
    )
    wf = _make_wf(phases, ran)
    out = await DurableStateMachine.execute(
        workflow_run_id, wf, {"investigation_id": workflow_run_id},
    )
    assert ran == ["phaseA", "phaseB"]
    assert set(out["_dispatch_visited"]) == {"phaseA", "phaseB"}


async def test_budget_cut_emits_truncated(workflow_run_id: str) -> None:
    ran: list[str] = []
    phases = (PhaseSpec(name="phaseA", condition=_always),)
    wf = _make_wf(phases, ran)
    out = await DurableStateMachine.execute(
        workflow_run_id, wf,
        {"investigation_id": workflow_run_id, "_budget_exhausted": True},
    )
    assert out.get("budget_truncated") is True
    assert ran == []


async def test_stall_raises_replan(workflow_run_id: str) -> None:
    ran: list[str] = []
    phases = (PhaseSpec(name="blocked", condition=_never),)
    wf = _make_wf(phases, ran)
    out = await DurableStateMachine.execute(
        workflow_run_id, wf, {"investigation_id": workflow_run_id},
    )
    assert out.get("stalled") is True
    requests = await LedgerService().read_general(
        workflow_run_id, kinds=["request"],
    )
    assert any((r["payload"] or {}).get("intent") == "replan" for r in requests)
    assert ran == []


async def test_resume_preserves_visited_set(workflow_run_id: str) -> None:
    ran: list[str] = []
    phases = (
        PhaseSpec(name="phaseA", condition=_always),
        PhaseSpec(name="phaseB", condition=_always),
    )
    wf = _make_wf(phases, ran)
    # Simulate a pause after phaseA: stage a cursor at the hub with phaseA
    # already visited. Resume must not re-run phaseA.
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state=DISPATCH_STATE,
                state_input={
                    "investigation_id": workflow_run_id,
                    "_dispatch_visited": ["phaseA"],
                },
                retries_in_state=0,
                definition_id=_DEF_ID,
                version=1,
            )
        )
        await session.commit()
    out = await DurableStateMachine.execute(workflow_run_id, wf, {"ignored": True})
    assert ran == ["phaseB"]  # phaseA was visited before the pause
    assert set(out["_dispatch_visited"]) == {"phaseA", "phaseB"}

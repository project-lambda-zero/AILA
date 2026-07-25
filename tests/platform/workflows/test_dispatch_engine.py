"""Dispatch-hub graph run through the real DurableStateMachine (RFC-13 Phase 4)."""
from __future__ import annotations

from typing import Any

from aila.platform.services.ledger import LedgerService, make_discovery_condition
from aila.platform.services.oracle import Oracle
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


def _make_loop_wf(
    phases: tuple[PhaseSpec, ...],
    ran: list[str],
    recon_hook,
) -> Any:
    """A hub whose ``recon`` loop runs *recon_hook* (simulating an agent's
    ledger activity) before looping back to the hub."""
    def setup_builder(next_state: str) -> Any:
        async def _h(state_input: dict[str, Any], services: Any) -> StateResult:
            del services
            return StateResult(next_state=next_state, output={**state_input})
        return _h

    def loop_builder(phase: PhaseSpec, next_state: str) -> Any:
        async def _h(state_input: dict[str, Any], services: Any) -> StateResult:
            del services
            ran.append(phase.name)
            if phase.name == "recon":
                await recon_hook(state_input["investigation_id"])
            return StateResult(next_state=next_state, output={**state_input})
        return _h

    async def emit_handler(state_input: dict[str, Any], services: Any) -> StateResult:
        del services
        return StateResult(next_state=RESERVED_SUCCEEDED, output={**state_input})

    return build_dispatch_workflow(
        "test.hub.loop.v1", phases,
        services_factory=_svc,
        setup_builder=setup_builder,
        loop_builder=loop_builder,
        emit_handler=emit_handler,
    )


async def test_full_loop_ratified_request_activates_confirmed_phase(
    workflow_run_id: str,
) -> None:
    """End-to-end through the DurableStateMachine: recon posts a discovery +
    a request, a sibling ratifies it, the hub applies the ratified request
    (confirming the discovery) on its next visit, and the confirmed-trust
    ``deep`` phase then activates. This exercises the ledger -> oracle -> hub
    wiring in the running engine, not the router in isolation."""
    ran: list[str] = []
    svc = LedgerService()
    oracle = Oracle()

    async def recon_hook(inv: str) -> None:
        discovery = await svc.append_general(inv, "b1", "discovery", {"packed": True})
        request = await svc.append_general(
            inv, "b1", "request",
            {"intent": "activate_phase", "discovery_id": discovery},
        )
        await oracle.record_decision(inv, request, "b2", approve=True)

    phases = (
        PhaseSpec(name="recon", condition=_always),
        PhaseSpec(
            name="deep",
            condition=make_discovery_condition("discovery"),
            trust="confirmed",
        ),
    )
    wf = _make_loop_wf(phases, ran, recon_hook)
    await DurableStateMachine.execute(
        workflow_run_id, wf, {"investigation_id": workflow_run_id},
    )
    assert ran == ["recon", "deep"]


async def test_full_loop_unratified_request_does_not_activate_confirmed_phase(
    workflow_run_id: str,
) -> None:
    """Same graph, but the request is never ratified. The confirmed-trust
    ``deep`` phase must NOT activate -- proving the hub-apply of a ratified
    request is load-bearing, not incidental."""
    ran: list[str] = []
    svc = LedgerService()

    async def recon_hook(inv: str) -> None:
        discovery = await svc.append_general(inv, "b1", "discovery", {"packed": True})
        await svc.append_general(
            inv, "b1", "request",
            {"intent": "activate_phase", "discovery_id": discovery},
        )
        # No approval -- the request stays unratified.

    phases = (
        PhaseSpec(name="recon", condition=_always),
        PhaseSpec(
            name="deep",
            condition=make_discovery_condition("discovery"),
            trust="confirmed",
        ),
    )
    wf = _make_loop_wf(phases, ran, recon_hook)
    out = await DurableStateMachine.execute(
        workflow_run_id, wf, {"investigation_id": workflow_run_id},
    )
    assert ran == ["recon"]  # deep never activated -- discovery unconfirmed
    assert out.get("stalled") is True

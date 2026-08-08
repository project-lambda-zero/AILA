"""Dispatch-hub graph run through the real DurableStateMachine (RFC-13 Phase 4)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.services.ledger import (
    InvestigationLedgerRecord,
    LedgerService,
    make_discovery_condition,
)
from aila.platform.services.oracle import Oracle
from aila.platform.workflows import DurableStateMachine, StateResult
from aila.platform.workflows.investigation_emit_base import (
    _NON_CONTINUE_EXIT_REASONS,
    resolve_final_status,
)
from aila.platform.workflows.phase_graph import (
    DISPATCH_STATE,
    DispatchEscalationModels,
    PhaseSpec,
    _is_live_replan_request,
    build_dispatch_workflow,
)
from aila.platform.workflows.types import RESERVED_SUCCEEDED
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor

_DEF_ID = "test.hub.v1"


async def _svc(run_id: str) -> Any:
    del run_id
    return object()


def _make_wf(
    phases: tuple[PhaseSpec, ...],
    ran: list[str],
    *,
    escalation_models: DispatchEscalationModels | None = None,
) -> Any:
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
        escalation_models=escalation_models,
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


# -- RFC-13 #68 stall-to-escalation ------------------------------------------


async def _seed_old_replan(
    investigation_id: str, age_seconds: float, *, status: str | None = None,
) -> None:
    """Pre-write an OLD unratified replan row so the hub's stall handler
    finds an aged idempotency-keyed duplicate on its own append attempt.

    Uses the exact idempotency key the hub itself computes for the
    empty-visited-set case (``replan:``), so ``append_general`` on the
    hub side is a no-op and the row this test inserted survives with
    its backdated ``created_at``. ``status`` sets the ledger row's status
    column -- pass ``"superseded"`` to model a re-enqueue reset.
    """
    backdated = datetime.now(UTC) - timedelta(seconds=age_seconds)
    async with async_session_scope() as session:
        session.add(
            InvestigationLedgerRecord(
                investigation_id=investigation_id,
                author_branch_id="__hub__",
                kind="request",
                payload_json=json.dumps({
                    "intent": "replan",
                    "reason": "pre-existing aged replan (test seed)",
                    "blocked": ["blocked"],
                }),
                idempotency_key="replan:",
                status=status,
                created_at=backdated,
            )
        )
        await session.commit()


async def test_stall_timed_out_escalates_and_emits_hub_stalled_timeout(
    workflow_run_id: str, monkeypatch,
) -> None:
    """An unratified replan aged past ``platform.dispatch_replan_timeout_s``
    causes the hub to emit ``hub_stalled_timeout`` (distinct from the
    within-window ``hub_stalled``) AND call ``post_dispatch_stall_escalation``
    with the configured escalation_models. Default window is 1800s; we
    seed a replan aged 3600s so age > window unconditionally."""
    ran: list[str] = []
    calls: list[dict[str, Any]] = []

    async def _spy(
        *, investigation_id: str, blocked_phases: list[str],
        replan_age_s: float, message_model: Any, branch_model: Any,
    ) -> str | None:
        calls.append({
            "investigation_id": investigation_id,
            "blocked_phases": list(blocked_phases),
            "replan_age_s": replan_age_s,
            "message_model": message_model,
            "branch_model": branch_model,
        })
        return "spy-msg-id"

    monkeypatch.setattr(
        "aila.platform.agents.auto_steering.post_dispatch_stall_escalation",
        _spy,
    )

    class _FakeMessageModel:
        pass

    class _FakeBranchModel:
        pass

    await _seed_old_replan(workflow_run_id, age_seconds=3600.0)

    phases = (PhaseSpec(name="blocked", condition=_never),)
    wf = _make_wf(
        phases, ran,
        escalation_models=DispatchEscalationModels(
            message_model=_FakeMessageModel,
            branch_model=_FakeBranchModel,
        ),
    )
    out = await DurableStateMachine.execute(
        workflow_run_id, wf, {"investigation_id": workflow_run_id},
    )

    assert out.get("stalled") is True
    assert out.get("exit_reason") == "hub_stalled_timeout"
    assert out.get("blocked_phases") == ["blocked"]
    assert out.get("replan_age_s", 0) >= 3600.0
    assert ran == []

    assert len(calls) == 1, calls
    call = calls[0]
    assert call["investigation_id"] == workflow_run_id
    assert call["blocked_phases"] == ["blocked"]
    assert call["replan_age_s"] >= 3600.0
    assert call["message_model"] is _FakeMessageModel
    assert call["branch_model"] is _FakeBranchModel


async def test_stall_timed_out_without_escalation_models_still_flips_status(
    workflow_run_id: str, monkeypatch,
) -> None:
    """The STALLED terminal-status flip must NOT be gated on
    ``escalation_models``: when a module has not (yet) bound its record
    types, the hub still emits ``hub_stalled_timeout`` so the operator
    sees the stall in the investigation status column. The escalation
    post is simply skipped (verified via the spy never firing)."""
    ran: list[str] = []
    calls: list[dict[str, Any]] = []

    async def _spy(**kwargs: Any) -> str | None:
        calls.append(kwargs)
        return None

    monkeypatch.setattr(
        "aila.platform.agents.auto_steering.post_dispatch_stall_escalation",
        _spy,
    )

    await _seed_old_replan(workflow_run_id, age_seconds=3600.0)

    phases = (PhaseSpec(name="blocked", condition=_never),)
    wf = _make_wf(phases, ran, escalation_models=None)
    out = await DurableStateMachine.execute(
        workflow_run_id, wf, {"investigation_id": workflow_run_id},
    )

    assert out.get("exit_reason") == "hub_stalled_timeout"
    assert out.get("stalled") is True
    assert calls == []  # escalation post skipped, terminal flip preserved


def test_hub_stalled_timeout_is_terminal_and_maps_to_stalled() -> None:
    """Contract assertions the emit-state relies on: ``hub_stalled_timeout``
    is in the non-continue set (so auto_continue never re-enqueues on it)
    and ``resolve_final_status`` maps it to ``InvestigationStatus.STALLED``.
    The plain ``hub_stalled`` reason must still fall through to COMPLETED
    so within-window stalls preserve their historical behavior."""
    assert "hub_stalled_timeout" in _NON_CONTINUE_EXIT_REASONS
    assert "hub_stalled" in _NON_CONTINUE_EXIT_REASONS  # unchanged
    assert resolve_final_status("hub_stalled_timeout") == (
        InvestigationStatus.STALLED.value
    )
    assert resolve_final_status("hub_stalled") == (
        InvestigationStatus.COMPLETED.value
    )
    assert InvestigationStatus.STALLED.value == "stalled"


def test_is_live_replan_request_skips_superseded() -> None:
    """``_is_live_replan_request`` counts an open replan request but ignores
    one marked ``status='superseded'`` (the re-enqueue reset flag) and any
    non-replan / non-request row. This is the guard that stops an aged
    superseded replan from tripping ``hub_stalled_timeout``."""
    live = {"id": 1, "kind": "request", "payload": {"intent": "replan"}}
    superseded = {**live, "id": 2, "status": "superseded"}
    assert _is_live_replan_request(live) is True
    assert _is_live_replan_request(superseded) is False
    assert _is_live_replan_request(
        {"id": 3, "kind": "request", "payload": {"intent": "other"}},
    ) is False
    assert _is_live_replan_request(
        {"id": 4, "kind": "discovery", "payload": {}},
    ) is False


async def test_superseded_aged_replan_does_not_time_out(
    workflow_run_id: str, monkeypatch,
) -> None:
    """Regression: a re-enqueued investigation must not instantly re-stall on
    an hours-old unratified replan. An aged replan marked
    ``status='superseded'`` (by ``supersede_unratified_replan_requests`` on
    the re-enqueue path) is skipped by ``_is_live_replan_request``, so the
    hub emits the within-window ``hub_stalled`` (which resolves to COMPLETED)
    rather than the terminal ``hub_stalled_timeout`` (STALLED), and posts no
    operator escalation. The sibling test with an un-superseded aged replan
    proves the same seed WOULD otherwise time out."""
    ran: list[str] = []
    calls: list[dict[str, Any]] = []

    async def _spy(**kwargs: Any) -> str | None:
        calls.append(kwargs)
        return "spy-msg-id"

    monkeypatch.setattr(
        "aila.platform.agents.auto_steering.post_dispatch_stall_escalation",
        _spy,
    )

    await _seed_old_replan(
        workflow_run_id, age_seconds=3600.0, status="superseded",
    )

    class _FakeMessageModel:
        pass

    class _FakeBranchModel:
        pass

    phases = (PhaseSpec(name="blocked", condition=_never),)
    wf = _make_wf(
        phases, ran,
        escalation_models=DispatchEscalationModels(
            message_model=_FakeMessageModel,
            branch_model=_FakeBranchModel,
        ),
    )
    out = await DurableStateMachine.execute(
        workflow_run_id, wf, {"investigation_id": workflow_run_id},
    )

    assert out.get("exit_reason") == "hub_stalled"
    assert out.get("exit_reason") != "hub_stalled_timeout"
    # hub_stalled (within-window) resolves to COMPLETED, NOT the terminal
    # STALLED that hub_stalled_timeout would have produced.
    assert resolve_final_status(out.get("exit_reason", "")) == (
        InvestigationStatus.COMPLETED.value
    )
    assert resolve_final_status(out.get("exit_reason", "")) != (
        InvestigationStatus.STALLED.value
    )
    assert calls == []  # not timed out -> no escalation posted

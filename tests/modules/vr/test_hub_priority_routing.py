"""VR dispatch-hub priority routing + discovery-gated specialized phases (#245).

Covers the three routing changes the phase-graph PoC feedback work introduced:

* a confirmed finding routes the hub to the priority-100 exploit-verification
  phase ahead of the priority-10 generic audit sweeps;
* a specialized audit phase activates only when a shared-ledger discovery
  names its vulnerability class (keyword-gated), and a ratified replan waives
  that keyword gate;
* ``build_dispatch_workflow`` binds a ``PhaseSpec.handler`` phase's custom
  state handler instead of the module loop builder.
"""
from __future__ import annotations

import uuid

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.workflow.definitions_hub import (
    _AUTH_BYPASS_KEYWORDS,
    _BINARY_KINDS,
    _DESERIALIZATION_KEYWORDS,
    _INJECTION_KEYWORDS,
    _KERNEL_DRIVER_KEYWORDS,
    _SOURCE_KINDS,
    VR_HUB_PHASES,
    _make_specialized_phase_condition,
)
from aila.platform.services.ledger import LedgerService
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.phase_graph import (
    PhaseSpec,
    build_dispatch_workflow,
    make_dispatch_router,
)
from aila.platform.workflows.types import RESERVED_SUCCEEDED, StateResult


async def _seed_source_repo(inv: str) -> None:
    """Create a workspace + source_repo target + investigation for *inv*.

    A specialized/baseline audit condition reads the investigation's primary
    target kind, so the row must exist for the source-scoped phases to be
    kind-eligible.
    """
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="prio-ws", slug=f"prio-ws-{inv[:8]}", description="",
            theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name="prio target", kind="source_repo",
            descriptor_json="{}", primary_language="python",
            secondary_languages_json="[]", tags_json="[]",
            mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.flush()
        uow.session.add(VRInvestigationRecord(
            id=inv, target_id=target.id, team_id="admin",
            kind="discovery", title="prio inv", initial_question="test",
            status="running", auto_pilot=False,
            strategy_family="vulnerability_research.discovery_research",
            cost_budget_usd=50.0,
        ))
        await uow.session.commit()


async def test_confirmed_finding_routes_to_exploit_before_baseline(test_db) -> None:
    del test_db
    inv = str(uuid.uuid4())
    await _seed_source_repo(inv)
    svc = LedgerService()
    # A confirmed (quorum-approved) taint-path discovery. It is not a recon
    # hypothesis, so the exploit phases' payload_exclude keeps it.
    disc = await svc.append_general(
        inv, "b1", "discovery",
        {"source": "taint_confirmed", "claim": "reachable OOB write in decoder"},
    )
    await svc.append_general(
        inv, "b2", "decision", {"approved": True, "target": disc},
    )
    router = make_dispatch_router(VR_HUB_PHASES)
    # No branch capability -> every phase is eligible, so priority (not the
    # capability filter) decides. recon is already visited. The confirmed
    # finding must open poc_development (priority 100) ahead of the generic
    # source_audit / taint_analysis sweeps (priority 10).
    state = {"investigation_id": inv, "_dispatch_visited": ["recon"]}
    result = await router(state, None)
    assert result.next_state == "poc_development"


async def test_specialized_phase_gates_on_named_discovery(test_db) -> None:
    del test_db
    inv = str(uuid.uuid4())
    await _seed_source_repo(inv)
    svc = LedgerService()
    await svc.append_general(
        inv, "b1", "discovery",
        {
            "source": "recon_hypothesis",
            "claim": "SQL injection via string concatenation in UserRepository",
            "why_plausible": "raw query built from the request parameter",
            "kill_criterion": "no parameterized statement on the path",
        },
    )
    inj = _make_specialized_phase_condition(_SOURCE_KINDS, _INJECTION_KEYWORDS)
    deser = _make_specialized_phase_condition(_SOURCE_KINDS, _DESERIALIZATION_KEYWORDS)
    auth = _make_specialized_phase_condition(_SOURCE_KINDS, _AUTH_BYPASS_KEYWORDS)
    state = {"investigation_id": inv}
    inj_ok, _r = await inj(state)
    deser_ok, _r2 = await deser(state)
    auth_ok, _r3 = await auth(state)
    assert inj_ok is True
    assert deser_ok is False
    assert auth_ok is False


async def test_specialized_phase_false_without_matching_discovery(test_db) -> None:
    del test_db
    inv = str(uuid.uuid4())
    await _seed_source_repo(inv)
    svc = LedgerService()
    # A discovery that names no injection/deser keyword.
    await svc.append_general(
        inv, "b1", "discovery",
        {"source": "recon_hypothesis", "claim": "the module exposes a health endpoint"},
    )
    inj = _make_specialized_phase_condition(_SOURCE_KINDS, _INJECTION_KEYWORDS)
    state = {"investigation_id": inv}
    ok, _r = await inj(state)
    assert ok is False
    # A ratified replan waives the keyword gate: kind alone activates.
    relaxed, reason = await inj({**state, "_dispatch_replan_relax": True})
    assert relaxed is True
    assert "replan relax" in reason


async def test_specialized_phase_false_on_kind_mismatch(test_db) -> None:
    del test_db
    inv = str(uuid.uuid4())
    await _seed_source_repo(inv)
    svc = LedgerService()
    await svc.append_general(
        inv, "b1", "discovery",
        {"source": "recon_hypothesis", "claim": "IOCTL handler in the driver"},
    )
    # kernel_driver keywords apply only to binary kinds; a source_repo target
    # never activates the kernel phase even when a discovery names its class.
    kern = _make_specialized_phase_condition(_BINARY_KINDS, _KERNEL_DRIVER_KEYWORDS)
    ok, _r = await kern({"investigation_id": inv})
    assert ok is False


def test_dispatch_handler_field_binds_custom_state() -> None:
    sentinel = object()

    def _custom(next_state: str):
        async def _h(state_input, services):  # noqa: ANN001, ANN202
            del services
            return StateResult(next_state=next_state, output={**state_input})
        _h.__dict__["_algo_marker"] = sentinel
        return _h

    loop_calls: list[str] = []

    def _loop_builder(phase: PhaseSpec, next_state: str):
        loop_calls.append(phase.name)

        async def _h(state_input, services):  # noqa: ANN001, ANN202
            del services
            return StateResult(next_state=next_state, output={**state_input})
        return _h

    def _setup_builder(next_state: str):
        async def _h(state_input, services):  # noqa: ANN001, ANN202
            del services
            return StateResult(next_state=next_state, output={**state_input})
        return _h

    async def _emit(state_input, services):  # noqa: ANN001, ANN202
        del services
        return StateResult(next_state=RESERVED_SUCCEEDED, output={**state_input})

    async def _svc(run_id: str):  # noqa: ANN202
        del run_id
        return object()

    phases = (
        PhaseSpec(name="algo_verify", handler=_custom),
        PhaseSpec(name="loop_phase", catch_all=True),
    )
    wf = build_dispatch_workflow(
        "test.vr.handler.v1", phases,
        services_factory=_svc,
        setup_builder=_setup_builder,
        loop_builder=_loop_builder,
        emit_handler=_emit,
    )
    # The handler phase binds phase.handler(DISPATCH_STATE); the loop phase
    # falls back to the module loop builder.
    assert wf.states["algo_verify"].handler.__dict__.get("_algo_marker") is sentinel
    assert "loop_phase" in loop_calls
    assert "algo_verify" not in loop_calls

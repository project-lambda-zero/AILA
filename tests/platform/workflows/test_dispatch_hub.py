"""Pure unit tests for the discovery-driven dispatch hub (RFC-13 Phase 0).

No DB, no engine: the hub handler and the builder are exercised directly.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.platform.workflows.phase_graph import (
    DISPATCH_STATE,
    EMIT_STATE,
    SETUP_STATE,
    PhaseSpec,
    build_dispatch_workflow,
    make_dispatch_router,
)
from aila.platform.workflows.types import RESERVED_SUCCEEDED, StateResult


async def _never(state_input: dict[str, Any]) -> tuple[bool, str]:
    del state_input
    return False, "never"


def _needs(flag: str):
    async def _cond(state_input: dict[str, Any]) -> tuple[bool, str]:
        return bool(state_input.get(flag)), flag

    return _cond


# --- make_dispatch_router ---------------------------------------------------


async def test_activates_first_unconditional() -> None:
    hub = make_dispatch_router((PhaseSpec("a"), PhaseSpec("b")))
    r = await hub({}, None)
    assert r.next_state == "a"
    assert r.output["_dispatch_visited"] == ["a"]


async def test_skips_visited() -> None:
    hub = make_dispatch_router((PhaseSpec("a"), PhaseSpec("b")))
    r = await hub({"_dispatch_visited": ["a"]}, None)
    assert r.next_state == "b"
    assert set(r.output["_dispatch_visited"]) == {"a", "b"}


async def test_emits_when_none_eligible() -> None:
    hub = make_dispatch_router((PhaseSpec("a", condition=_never),))
    assert (await hub({}, None)).next_state == EMIT_STATE


async def test_condition_gates_activation() -> None:
    hub = make_dispatch_router((PhaseSpec("a", condition=_needs("packed")),))
    assert (await hub({}, None)).next_state == EMIT_STATE
    assert (await hub({"packed": True}, None)).next_state == "a"


async def test_capability_filter() -> None:
    phases = (
        PhaseSpec("shared"),
        PhaseSpec("re_phase", capability="re"),
        PhaseSpec("crypto_phase", capability="crypto"),
    )
    hub = make_dispatch_router(phases)
    # RE branch, shared already visited -> takes the re phase.
    r = await hub(
        {"_branch_capability": "re", "_dispatch_visited": ["shared"]}, None,
    )
    assert r.next_state == "re_phase"
    # Crypto branch skips the re phase, takes the crypto phase.
    r2 = await hub(
        {"_branch_capability": "crypto", "_dispatch_visited": ["shared", "re_phase"]},
        None,
    )
    assert r2.next_state == "crypto_phase"
    # No branch capability -> no filtering, takes the next declared phase.
    r3 = await hub({"_dispatch_visited": ["shared"]}, None)
    assert r3.next_state == "re_phase"


async def test_budget_exhausted_emits_truncated() -> None:
    hub = make_dispatch_router((PhaseSpec("a"),))
    r = await hub({"_budget_exhausted": True}, None)
    assert r.next_state == EMIT_STATE
    assert r.output["budget_truncated"] is True


async def test_chaining_discovery_enables_later_phase() -> None:
    hub = make_dispatch_router(
        (PhaseSpec("a"), PhaseSpec("b", condition=_needs("found"))),
    )
    assert (await hub({}, None)).next_state == "a"
    # After phase a posts its discovery, the next hub visit enables b.
    r = await hub({"_dispatch_visited": ["a"], "found": True}, None)
    assert r.next_state == "b"
    # Without the discovery, the hub emits.
    assert (await hub({"_dispatch_visited": ["a"]}, None)).next_state == EMIT_STATE


# --- PhaseSpec validation ---------------------------------------------------


def test_phasespec_rejects_bad_trust() -> None:
    with pytest.raises(ValueError, match="trust must be"):
        PhaseSpec("x", trust="bogus")


def test_phasespec_default_trust_confirmed() -> None:
    assert PhaseSpec("x").trust == "confirmed"


# --- build_dispatch_workflow ------------------------------------------------


async def _fake_services(run_id: str) -> Any:
    del run_id
    return object()


def _setup_builder(next_state: str):
    async def _h(state_input: dict[str, Any], services: Any) -> StateResult:
        del services
        return StateResult(next_state=next_state, output={**state_input})

    return _h


def _make_loop_builder(calls: list[tuple[str, str]]):
    def _lb(phase: PhaseSpec, next_state: str):
        calls.append((phase.name, next_state))

        async def _h(state_input: dict[str, Any], services: Any) -> StateResult:
            del services
            return StateResult(next_state=next_state, output={**state_input})

        return _h

    return _lb


async def _emit(state_input: dict[str, Any], services: Any) -> StateResult:
    del state_input, services
    return StateResult(next_state=RESERVED_SUCCEEDED, output={})


def test_build_dispatch_structure() -> None:
    calls: list[tuple[str, str]] = []
    phases = (PhaseSpec("a"), PhaseSpec("b", condition=_needs("x")))
    wf = build_dispatch_workflow(
        "test.dispatch.v1",
        phases,
        services_factory=_fake_services,
        setup_builder=_setup_builder,
        loop_builder=_make_loop_builder(calls),
        emit_handler=_emit,
    )
    assert wf.start_state == SETUP_STATE
    assert {SETUP_STATE, DISPATCH_STATE, "a", "b", EMIT_STATE} <= set(wf.states)
    # Every phase loops back to the hub, not to a static next.
    assert ("a", DISPATCH_STATE) in calls
    assert ("b", DISPATCH_STATE) in calls


def test_build_dispatch_rejects_empty() -> None:
    with pytest.raises(ValueError, match="at least one phase"):
        build_dispatch_workflow(
            "test.empty.v1",
            (),
            services_factory=_fake_services,
            setup_builder=_setup_builder,
            loop_builder=_make_loop_builder([]),
            emit_handler=_emit,
        )


async def test_setup_routes_to_hub() -> None:
    wf = build_dispatch_workflow(
        "test.dispatch.v2",
        (PhaseSpec("a"),),
        services_factory=_fake_services,
        setup_builder=_setup_builder,
        loop_builder=_make_loop_builder([]),
        emit_handler=_emit,
    )
    setup = wf.states[SETUP_STATE].handler
    r = await setup({}, None)
    assert r.next_state == DISPATCH_STATE

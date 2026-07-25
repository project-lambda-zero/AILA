"""Tests for the phase-graph substrate (a graph of loops over the engine)."""
from __future__ import annotations

from typing import Any

import pytest

from aila.platform.workflows.phase_graph import (
    EMIT_STATE,
    SETUP_STATE,
    PhaseGraphSpec,
    PhaseSpec,
    build_phase_workflow,
    make_gate_state,
    make_router_state,
)
from aila.platform.workflows.types import RESERVED_SUCCEEDED, StateResult


async def _fake_services(run_id: str) -> Any:
    del run_id
    return object()


def _setup_builder(next_state: str):
    async def _h(state_input: dict[str, Any], services: Any) -> StateResult:
        del services
        return StateResult(next_state=next_state, output={**state_input})

    return _h


def _make_loop_builder(calls: list[tuple[str, str]]):
    def _loop_builder(phase: PhaseSpec, next_state: str):
        calls.append((phase.name, next_state))

        async def _h(state_input: dict[str, Any], services: Any) -> StateResult:
            del services
            return StateResult(next_state=next_state, output={**state_input})

        return _h

    return _loop_builder


async def _emit_handler(state_input: dict[str, Any], services: Any) -> StateResult:
    del services, state_input
    return StateResult(next_state=RESERVED_SUCCEEDED, output={})


async def _gate_allow(state_input: dict[str, Any]) -> tuple[bool, str]:
    return bool(state_input.get("ok", True)), "checked"


async def _router(state_input: dict[str, Any]) -> str:
    return str(state_input.get("target", "phase_b"))


def _build() -> tuple[Any, list[tuple[str, str]]]:
    calls: list[tuple[str, str]] = []
    spec = PhaseGraphSpec(
        start="phase_a",
        phases=(
            PhaseSpec(name="phase_a", router=_router),
            PhaseSpec(name="phase_b", entry_gate=_gate_allow, next=EMIT_STATE),
        ),
    )
    wf = build_phase_workflow(
        "test.phasegraph.v1",
        spec,
        services_factory=_fake_services,
        setup_builder=_setup_builder,
        loop_builder=_make_loop_builder(calls),
        emit_handler=_emit_handler,
    )
    return wf, calls


def test_build_produces_expected_states() -> None:
    wf, _ = _build()
    assert wf.start_state == SETUP_STATE
    assert set(wf.states) >= {
        SETUP_STATE,
        "phase_a",
        "phase_a__route",
        "phase_b",
        "phase_b__loop",
        EMIT_STATE,
    }


def test_loop_builder_receives_phase_and_next() -> None:
    _, calls = _build()
    assert ("phase_a", "phase_a__route") in calls
    assert ("phase_b", EMIT_STATE) in calls


async def test_setup_routes_to_start_phase() -> None:
    wf, _ = _build()
    setup = wf.states[SETUP_STATE].handler
    result = await setup({"investigation_id": "i1"}, None)
    assert result.next_state == "phase_a"


async def test_gate_allows_and_denies() -> None:
    gate = make_gate_state(_gate_allow, on_pass="phase_b__loop", on_fail=EMIT_STATE)
    allowed = await gate({"ok": True}, None)
    assert allowed.next_state == "phase_b__loop"
    assert allowed.output["gate_allowed"] is True
    denied = await gate({"ok": False}, None)
    assert denied.next_state == EMIT_STATE
    assert denied.output["gate_allowed"] is False


async def test_router_returns_choice() -> None:
    router = make_router_state(_router)
    result = await router({"target": "config_extract"}, None)
    assert result.next_state == "config_extract"


def test_phasespec_rejects_next_and_router() -> None:
    with pytest.raises(ValueError, match="both next and router"):
        PhaseSpec(name="x", next="y", router=_router)


def test_graphspec_rejects_bad_start() -> None:
    with pytest.raises(ValueError, match="names no declared phase"):
        PhaseGraphSpec(start="missing", phases=(PhaseSpec(name="a"),))


def test_graphspec_rejects_duplicate_phases() -> None:
    with pytest.raises(ValueError, match="duplicate phase"):
        PhaseGraphSpec(start="a", phases=(PhaseSpec(name="a"), PhaseSpec(name="a")))

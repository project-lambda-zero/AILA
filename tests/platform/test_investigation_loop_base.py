"""Platform investigation loop state factory (RFC-02 Phase 4b).

Exercises ``state_investigation_loop`` through VR record models with stub
researcher / executor bindings so the platform turn loop (liveness poll,
run_turn, tool dispatch, terminal / cap handling) is verified in
isolation.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.investigation_loop_base import (
    state_investigation_loop,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)


class _StubError(Exception):
    pass


def _result(turn: int, action: str, terminal: bool,
            outcome_id: str | None = None, command: str | None = None):
    return SimpleNamespace(
        turn=turn,
        decision=SimpleNamespace(action=action, command=command),
        terminal=terminal,
        outcome_id=outcome_id,
    )


class _StubResearcher:
    def __init__(self, results: list[Any]) -> None:
        self._it = iter(results)

    async def run_turn(self):
        return next(self._it)


class _StubExecutor:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def execute(self, **kwargs: object):
        self.calls.append(kwargs)
        return SimpleNamespace(server_id="s", tool_name="t", success=True)


async def _reader(n: int) -> int:
    return n


def _handler(researcher: Any, executor: Any):
    bindings = InvestigationStateBindings(
        inv_model=VRInvestigationRecord,
        branch_model=VRInvestigationBranchRecord,
        researcher_factory=lambda *a: researcher,
        executor_factory=lambda: executor,
        max_turns_reader=lambda: _reader(5),
        researcher_error=_StubError,
    )
    return state_investigation_loop(bindings, InvestigationStateHooks())


async def _seed(status: InvestigationStatus, branch_status: str = "active") -> tuple[str, str]:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(name="lb", slug="lb", description="",
                               theme="custom", team_id="admin")
        uow.session.add(ws)
        await uow.session.flush()
        tgt = VRTargetRecord(
            workspace_id=ws.id, team_id="admin", display_name="t",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/x.apk"}),  # noqa: S108
            primary_language=None, secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(tgt)
        await uow.session.flush()
        inv = VRInvestigationRecord(
            target_id=tgt.id, team_id="admin", kind="variant_hunt", title="t",
            initial_question="q", status=status.value, auto_pilot=False,
            strategy_family="vulnerability_research.variant_hunt",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        br = VRInvestigationBranchRecord(
            investigation_id=inv.id, status=branch_status, turn_count=0,
            fork_reason="primary", persona_voice="halvar",
        )
        uow.session.add(br)
        await uow.session.commit()
        return inv.id, br.id


@pytest.mark.usefixtures("test_db")
async def test_terminal_submit_exits() -> None:
    inv_id, br_id = await _seed(InvestigationStatus.RUNNING)
    researcher = _StubResearcher([_result(1, "reason", terminal=True, outcome_id="o1")])
    handler = _handler(researcher, _StubExecutor())

    result = await handler(
        {"investigation_id": inv_id, "branch_id": br_id, "max_turns": 5},
        SimpleNamespace(llm_client=None),
    )

    assert result.next_state == "investigation_emit"
    assert result.output["exit_reason"] == "terminal_submit"
    assert result.output["outcome_id"] == "o1"


@pytest.mark.usefixtures("test_db")
async def test_max_turns_cap() -> None:
    inv_id, br_id = await _seed(InvestigationStatus.RUNNING)
    researcher = _StubResearcher([
        _result(i, "reason", terminal=False) for i in range(1, 4)
    ])
    handler = _handler(researcher, _StubExecutor())

    result = await handler(
        {"investigation_id": inv_id, "branch_id": br_id, "max_turns": 3},
        SimpleNamespace(llm_client=None),
    )

    assert result.next_state == "investigation_emit"
    assert result.output["exit_reason"] == "max_turns"
    assert result.output["last_turn_idx"] == 3


@pytest.mark.usefixtures("test_db")
async def test_paused_investigation_exits_before_turn() -> None:
    inv_id, br_id = await _seed(InvestigationStatus.PAUSED)
    researcher = _StubResearcher([_result(1, "reason", terminal=True)])
    handler = _handler(researcher, _StubExecutor())

    result = await handler(
        {"investigation_id": inv_id, "branch_id": br_id, "max_turns": 5},
        SimpleNamespace(llm_client=None),
    )

    assert result.next_state == "investigation_emit"
    assert result.output["exit_reason"].startswith("inv_status_flipped")


@pytest.mark.usefixtures("test_db")
async def test_tool_run_dispatches_to_executor() -> None:
    inv_id, br_id = await _seed(InvestigationStatus.RUNNING)
    researcher = _StubResearcher([
        _result(1, "tool_run", terminal=False, command="ida.decompile main"),
        _result(2, "reason", terminal=True, outcome_id="o2"),
    ])
    executor = _StubExecutor()
    handler = _handler(researcher, executor)

    result = await handler(
        {"investigation_id": inv_id, "branch_id": br_id, "max_turns": 5},
        SimpleNamespace(llm_client=None),
    )

    assert result.output["exit_reason"] == "terminal_submit"
    assert len(executor.calls) == 1
    assert executor.calls[0]["command_raw"] == "ida.decompile main"

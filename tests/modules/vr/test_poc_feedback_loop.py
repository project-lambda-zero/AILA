"""Post-submit PoC feedback loop on DIRECT_FINDING dispatch (#245).

When an agent submits a PoC with a DIRECT_FINDING, the outcome dispatcher
compiles + runs it in the SSH sandbox and routes the result back:

* a reproduced crash stamps the finding (asan_report, crash_signature,
  poc_reliability) and writes NO feedback directive;
* a clean (non-reproducing) run writes a ``_directive.poc_feedback``
  observable onto the submitting branch so the next turn sees why the PoC
  did not land.

Both paths use an injected fake PoC runner + integration resolver so the
tests never touch SSH.
"""
from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any

from sqlmodel import select

from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules.vr.contracts import OutcomeDispatchStatus
from aila.modules.vr.db_models import (
    VRFindingRecord,
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.uow import UnitOfWork

_NONCRASH_RUN = {
    "status": "ready",
    "exit_code": 0,
    "crash_detected": False,
    "clean_exit": True,
    "timeout": False,
    "asan_report": False,
    "stderr_tail": "",
    "stdout_tail": "target handled the input cleanly",
    "isolator": "unshare",
}
_CRASH_RUN = {
    "status": "ready",
    "exit_code": 139,
    "crash_detected": True,
    "clean_exit": False,
    "timeout": False,
    "asan_report": True,
    "stderr_tail": (
        "ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
        "  #0 0x4011 in parse_header src/parse.c:42\n"
    ),
    "stdout_tail": "",
    "isolator": "unshare",
}


class _FakeKnowledge:
    async def store(self, **_kwargs: Any) -> None:
        return None

    async def promote_confirmed_finding_to_pool(self, **_kwargs: Any) -> None:
        return None


class _FakePoCRunner:
    """Records the action sequence; returns a canned run result."""

    def __init__(self, run_result: dict[str, Any]) -> None:
        self._run_result = run_result
        self.calls: list[str] = []

    async def forward(
        self, action: str | None = None, integration: Any = None, **_kwargs: Any,
    ) -> dict[str, Any]:
        del integration
        self.calls.append(action or "")
        if action == "compile_poc":
            return {
                "status": "ready", "language": "python",
                "script_path": "/tmp/aila_vr/run_test/poc.py",
                "run_dir": "/tmp/aila_vr/run_test",
            }
        if action == "run_poc":
            return self._run_result
        if action == "verify_reliability":
            return {
                "status": "ready", "crashes": 5, "total": 5, "reliability": "5/5",
            }
        return {"status": "error", "error": f"unknown action {action}"}


async def _fake_resolver(_investigation_id: str) -> dict[str, Any]:
    return {"host": "workstation", "username": "runner", "port": 22}


async def _seed(inv: str, branch_id: str) -> None:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="poc-ws", slug=f"poc-ws-{inv[:8]}", description="",
            theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name="poc target", kind="native_binary",
            descriptor_json="{}", primary_language="c",
            secondary_languages_json="[]", tags_json="[]",
            mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.flush()
        uow.session.add(VRInvestigationRecord(
            id=inv, target_id=target.id, team_id="admin",
            kind="discovery", title="poc inv", initial_question="test",
            status="running", auto_pilot=False,
            strategy_family="vulnerability_research.discovery_research",
            cost_budget_usd=50.0,
        ))
        # Flush the investigation before the branch: the branch FK
        # references vr_investigations and SQLAlchemy has no ORM
        # relationship to order the inserts itself.
        await uow.session.flush()
        uow.session.add(VRInvestigationBranchRecord(
            id=branch_id, investigation_id=inv,
        ))
        await uow.session.commit()


async def _load_finding(team_id: str = "admin") -> VRFindingRecord:
    async with UnitOfWork() as uow:
        return (await uow.session.exec(
            select(VRFindingRecord).where(VRFindingRecord.team_id == team_id),
        )).first()


async def _load_branch(branch_id: str) -> VRInvestigationBranchRecord:
    async with UnitOfWork() as uow:
        return (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == branch_id,
            ),
        )).first()


async def test_noncrash_poc_writes_feedback_directive(test_db) -> None:
    del test_db
    inv = str(uuid.uuid4())
    branch_id = str(uuid.uuid4())
    await _seed(inv, branch_id)
    runner = _FakePoCRunner(_NONCRASH_RUN)
    disp = OutcomeDispatcher(
        knowledge=_FakeKnowledge(),
        poc_runner=runner,
        integration_resolver=_fake_resolver,
    )
    payload = {
        "answer": "suspected overflow in parse_header",
        "poc_code": "import sys\nprint('run', sys.argv)\n",
        "poc_language": "python",
        "target_binary": "/tmp/aila_vr_targets/vuln",
    }
    outcome_row = SimpleNamespace(branch_id=branch_id)
    result = await disp._dispatch_direct_finding("oc-1", inv, payload, outcome_row)
    assert result.dispatch_status == OutcomeDispatchStatus.DISPATCHED
    assert runner.calls == ["compile_poc", "run_poc"]
    branch = await _load_branch(branch_id)
    case_state = json.loads(branch.case_state_json or "{}")
    feedback = case_state.get("observables", {}).get("_directive.poc_feedback")
    assert feedback is not None
    assert "without crashing" in feedback
    finding = await _load_finding()
    assert finding.poc_skip_reason == "poc_no_crash"


async def test_crash_poc_stamps_finding(test_db) -> None:
    del test_db
    inv = str(uuid.uuid4())
    branch_id = str(uuid.uuid4())
    await _seed(inv, branch_id)
    runner = _FakePoCRunner(_CRASH_RUN)
    disp = OutcomeDispatcher(
        knowledge=_FakeKnowledge(),
        poc_runner=runner,
        integration_resolver=_fake_resolver,
    )
    payload = {
        "answer": "heap overflow in parse_header",
        "poc_code": "int main(){return 0;}\n",
        "poc_language": "c",
        "target_binary": "/tmp/aila_vr_targets/vuln",
    }
    outcome_row = SimpleNamespace(branch_id=branch_id)
    await disp._dispatch_direct_finding("oc-2", inv, payload, outcome_row)
    assert runner.calls == ["compile_poc", "run_poc", "verify_reliability"]
    finding = await _load_finding()
    assert finding.poc_reliability == "5/5"
    assert "AddressSanitizer" in (finding.asan_report or "")
    assert finding.crash_signature is not None
    assert "AddressSanitizer" in finding.crash_signature
    # A reproduced crash needs no feedback directive.
    branch = await _load_branch(branch_id)
    case_state = json.loads(branch.case_state_json or "{}")
    assert "_directive.poc_feedback" not in case_state.get("observables", {})


async def test_no_workstation_skips_and_stamps_reason(test_db) -> None:
    del test_db
    inv = str(uuid.uuid4())
    branch_id = str(uuid.uuid4())
    await _seed(inv, branch_id)
    runner = _FakePoCRunner(_NONCRASH_RUN)

    async def _no_integration(_inv: str) -> None:
        return None

    disp = OutcomeDispatcher(
        knowledge=_FakeKnowledge(),
        poc_runner=runner,
        integration_resolver=_no_integration,
    )
    payload = {
        "answer": "overflow",
        "poc_code": "print('x')\n",
        "poc_language": "python",
        "target_binary": "/tmp/aila_vr_targets/vuln",
    }
    outcome_row = SimpleNamespace(branch_id=branch_id)
    await disp._dispatch_direct_finding("oc-3", inv, payload, outcome_row)
    # No workstation -> no compile/run attempted, finding records the reason.
    assert runner.calls == []
    finding = await _load_finding()
    assert finding.poc_skip_reason == "no_analysis_workstation_registered"

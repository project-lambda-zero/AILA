"""On-demand specialist path: request -> critic ratifies -> spawn.

Proves the mechanism deterministically (no live LLM): a core branch files a
``request_specialist`` ledger request, a distinct branch (the critic)
ratifies it, the oracle reports the ratified capability, and
``spawn_specialist_branch`` creates exactly one branch whose persona_voice
is the specialist name (which setup resolves back to _branch_capability).
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.services.ledger import LedgerPermissionError, LedgerService
from aila.platform.services.oracle import Oracle
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.persona_spawn import spawn_specialist_branch


class _FakeQueue:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def submit(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


async def _dummy_task(**_kwargs: object) -> None:
    return None


async def test_request_specialist_ratified_by_critic(test_db) -> None:
    del test_db
    inv = "inv-spec-req"
    svc = LedgerService()
    # A core branch files a specialist request.
    req_id = await svc.append_general(
        inv, "researcher-branch", "request",
        {"intent": "request_specialist", "target_capability": "binary-audit",
         "reason": "needs disassembly"},
    )
    oracle = Oracle()
    # Before any approval: not ratified.
    assert await oracle.ratified_specialist_capabilities(inv) == []
    # The proposing branch cannot approve its own request.
    with pytest.raises(LedgerPermissionError):
        await oracle.record_decision(
            inv, req_id, "researcher-branch", approve=True,
        )
    # A distinct branch (the critic) ratifies it.
    await oracle.record_decision(inv, req_id, "critic-branch", approve=True)
    assert await oracle.is_ratified(inv, req_id, quorum_k=1) is True
    assert await oracle.ratified_specialist_capabilities(inv) == ["binary-audit"]


async def _seed_primary() -> tuple[str, str]:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(name="sp", slug="sp", description="", theme="custom", team_id="admin")
        uow.session.add(ws)
        await uow.session.flush()
        tgt = VRTargetRecord(
            workspace_id=ws.id, team_id="admin", display_name="t", kind="native_binary",
            descriptor_json=json.dumps({"path": "/tmp/x"}),  # noqa: S108
            primary_language=None, secondary_languages_json="[]", tags_json="[]",
            mcp_handles_json="{}", status="active", capability_profile_json="{}",
        )
        uow.session.add(tgt)
        await uow.session.flush()
        inv = VRInvestigationRecord(
            target_id=tgt.id, team_id="admin", kind="discovery", title="t",
            initial_question="q", status="running", auto_pilot=False,
            strategy_family="vulnerability_research.discovery_research",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        primary = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", turn_count=0,
            fork_reason="primary", persona_voice="halvar",
        )
        uow.session.add(primary)
        await uow.session.flush()
        ids = (inv.id, primary.id)
        await uow.session.commit()
    return ids


async def _branches(inv_id: str) -> list[VRInvestigationBranchRecord]:
    async with UnitOfWork() as uow:
        return list((await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == inv_id),
        )).all())


async def test_spawn_specialist_branch_is_idempotent(test_db) -> None:
    del test_db
    inv_id, primary_id = await _seed_primary()
    queue = _FakeQueue()
    kwargs = dict(
        branch_model=VRInvestigationBranchRecord,
        inv_table="vr_investigations",
        task_fn=_dummy_task, track="vr", group_id="vr_specialist",
        task_queue=queue, strip_case_state=lambda raw: raw,
    )
    first = await spawn_specialist_branch(
        inv_id, primary_id, "admin", specialist_name="re", **kwargs,
    )
    second = await spawn_specialist_branch(
        inv_id, primary_id, "admin", specialist_name="re", **kwargs,
    )
    assert first == second  # idempotent: same branch, no duplicate
    re_branches = [
        b for b in await _branches(inv_id) if b.persona_voice == "re"
    ]
    assert len(re_branches) == 1
    assert re_branches[0].fork_reason == "specialist_request:re"
    assert re_branches[0].status == "active"
    # One enqueue for the first spawn; the idempotent second does not re-enqueue.
    assert len(queue.calls) == 1

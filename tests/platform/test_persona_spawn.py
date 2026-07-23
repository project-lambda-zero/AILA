"""Platform persona sibling spawn (RFC-02 Phase 3).

Exercises ``spawn_persona_siblings`` through the VR record models (the
function is model-agnostic; VR rows are convenient containers). Covers
the four resolutions: INSERT a branch for a persona with none,
reactivate the winner (turn_count reset, prior messages deleted),
abandon a duplicate, and enqueue one task per resolved branch.
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.branch import PersonaVoice
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.persona_spawn import spawn_persona_siblings


class _FakeQueue:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def submit(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


async def _dummy_task(**_kwargs: object) -> None:  # never invoked (queue faked)
    return None


async def _seed() -> tuple[str, str, str, str]:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="ps", slug="ps", description="", theme="custom", team_id="admin",
        )
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
            target_id=tgt.id, team_id="admin", kind="variant_hunt",
            title="t", initial_question="q", status="running",
            auto_pilot=False,
            strategy_family="vulnerability_research.variant_hunt",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        primary = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", turn_count=0,
            fork_reason="primary",
        )
        uow.session.add(primary)
        await uow.session.flush()
        # NOOR winner: abandoned with the higher turn_count + a message.
        noor_a = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="abandoned", turn_count=5,
            fork_reason="auto_deliberation:noor",
            persona_voice=PersonaVoice.NOOR.value,
        )
        uow.session.add(noor_a)
        await uow.session.flush()
        # NOOR duplicate: active but fewer turns -> abandoned as a dup.
        noor_b = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", turn_count=2,
            fork_reason="auto_deliberation:noor",
            persona_voice=PersonaVoice.NOOR.value,
        )
        uow.session.add(noor_b)
        await uow.session.flush()
        uow.session.add(VRInvestigationMessageRecord(
            investigation_id=inv.id, branch_id=noor_a.id,
            sender_kind="engine", payload_kind="tool_call",
        ))
        await uow.session.commit()
        return inv.id, primary.id, noor_a.id, noor_b.id


@pytest.mark.usefixtures("test_db")
async def test_spawn_inserts_reactivates_abandons_and_enqueues() -> None:
    inv_id, primary_id, noor_a, noor_b = await _seed()
    queue = _FakeQueue()

    result = await spawn_persona_siblings(
        inv_id, primary_id, "admin",
        siblings=(PersonaVoice.NOOR, PersonaVoice.MADDIE),
        branch_model=VRInvestigationBranchRecord,
        inv_table="vr_investigations",
        message_table="vr_investigation_messages",
        task_fn=_dummy_task,
        track="vr",
        group_id="vr_auto_deliberation",
        task_queue=queue,
        strip_case_state=lambda raw: raw,
    )

    # NOOR winner (noor_a) reactivated; noor_b abandoned; MADDIE inserted.
    assert result.reactivated == [noor_a]
    assert result.abandoned == [noor_b]
    assert len(result.inserted) == 1

    async with UnitOfWork() as uow:
        a = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.id == noor_a),
        )).first()
        b = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.id == noor_b),
        )).first()
        maddie = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == inv_id)
            .where(
                VRInvestigationBranchRecord.persona_voice
                == PersonaVoice.MADDIE.value,
            ),
        )).first()
        msg_count = len((await uow.session.exec(
            select(VRInvestigationMessageRecord)
            .where(VRInvestigationMessageRecord.branch_id == noor_a),
        )).all())

    assert a.status == "active"
    assert a.turn_count == 0
    assert msg_count == 0  # reactivation wiped the branch message history
    assert b.status == "abandoned"
    assert b.closed_reason == "duplicate_persona_cleanup"
    assert maddie is not None
    assert maddie.status == "active"
    assert maddie.parent_branch_id == primary_id

    # One enqueue per resolved branch (NOOR winner + MADDIE insert).
    assert len(queue.calls) == 2
    assert {c["track"] for c in queue.calls} == {"vr"}
    assert all(c["group_id"] == "vr_auto_deliberation" for c in queue.calls)
    assert all("branch_id" in c["kwargs"] for c in queue.calls)

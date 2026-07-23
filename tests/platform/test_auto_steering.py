"""Platform auto-steering injector (RFC-03 Phase 1).

Exercises ``maybe_post_auto_steering`` through VR record models. Rule 4
(audit_mcp kwarg rejection) derives its correction without a bridge
call, so the post + dedup path -- and the record-model parameterization
the platform lift introduced -- is verifiable end-to-end against the DB.
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.agents.auto_steering import maybe_post_auto_steering
from aila.platform.contracts.enums import InvestigationStatus, SenderKind
from aila.platform.uow import UnitOfWork

_REJECT_RESULT = {
    "status": "error",
    "error": "rejected: unexpected keyword argument 'foo'",
}


async def _seed() -> tuple[str, str]:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(name="as", slug="as", description="",
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
            initial_question="q", status=InvestigationStatus.RUNNING.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.variant_hunt",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        br = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", turn_count=1,
            fork_reason="primary", persona_voice="halvar",
            parent_branch_id=None,
        )
        uow.session.add(br)
        await uow.session.commit()
        return inv.id, br.id


@pytest.mark.usefixtures("test_db")
async def test_kwarg_rejection_posts_steering_then_dedupes() -> None:
    inv_id, br_id = await _seed()

    posted = await maybe_post_auto_steering(
        investigation_id=inv_id, branch_id=br_id,
        server_id="audit_mcp", tool_name="read_function",
        args={"foo": "bar"}, raw_result=_REJECT_RESULT,
        bridge_base_url="http://127.0.0.1:18822",
        message_model=VRInvestigationMessageRecord,
        branch_model=VRInvestigationBranchRecord,
    )

    assert posted is not None
    async with UnitOfWork() as uow:
        msg = (await uow.session.exec(
            select(VRInvestigationMessageRecord).where(
                VRInvestigationMessageRecord.id == posted,
            ),
        )).first()
    assert msg is not None
    assert msg.sender_kind == SenderKind.OPERATOR.value
    assert msg.sender_id == "auto_steering"
    assert msg.auto_steering_key.startswith("kwarg_rejected:read_function")

    # Second identical call is deduped by the unacked prior steering.
    again = await maybe_post_auto_steering(
        investigation_id=inv_id, branch_id=br_id,
        server_id="audit_mcp", tool_name="read_function",
        args={"foo": "bar"}, raw_result=_REJECT_RESULT,
        bridge_base_url="http://127.0.0.1:18822",
        message_model=VRInvestigationMessageRecord,
        branch_model=VRInvestigationBranchRecord,
    )
    assert again is None


@pytest.mark.usefixtures("test_db")
async def test_clean_result_posts_nothing() -> None:
    inv_id, br_id = await _seed()

    posted = await maybe_post_auto_steering(
        investigation_id=inv_id, branch_id=br_id,
        server_id="audit_mcp", tool_name="read_function",
        args={"name": "main"}, raw_result={"status": "ready", "content": "ok"},
        bridge_base_url="http://127.0.0.1:18822",
        message_model=VRInvestigationMessageRecord,
        branch_model=VRInvestigationBranchRecord,
    )

    assert posted is None

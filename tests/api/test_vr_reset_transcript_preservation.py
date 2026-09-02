"""req 26 (VR-58B8) -- reset archives the transcript instead of destroying it.

The reset handler used to hard-DELETE every message row and every outcome,
leaving findings the run produced orphaned (referenced by
``inv.linked_finding_ids_json`` but with no surviving outcome or transcript).

The fix soft-supersedes messages (they survive for display + audit, but
agent-context reads filter ``superseded_at IS NULL`` to see a fresh
slate), keeps message-bearing forked branches as FK parents for those
rows while GC-ing zero-message forks, archives outcomes the same way
(rows survive, stamped ``superseded_at``), and relinks the
investigation to the findings its archived run produced -- the
back-pointer survives, so nothing is orphaned. The finding rows
themselves are preserved.
"""
from __future__ import annotations

import json

import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRFindingRecord,
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts.message_base import active_messages
from aila.platform.contracts.outcome_base import active_outcomes
from aila.platform.uow import UnitOfWork

pytestmark = pytest.mark.asyncio


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _seed() -> dict[str, str]:
    """Seed inv + primary branch + a message-bearing fork + an empty fork +
    messages + an outcome + a finding the investigation links to."""
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="reset", slug="reset", description="", theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        tgt = VRTargetRecord(
            workspace_id=ws.id, team_id="admin", display_name="t",
            kind="native_binary",
            descriptor_json=json.dumps({"binary_path": "/dev/null"}),
            primary_language="c", secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(tgt)
        await uow.session.flush()
        finding = VRFindingRecord(
            team_id="admin", target_id=tgt.id, root_cause="seeded crash",
            crash_type="uaf",
        )
        uow.session.add(finding)
        await uow.session.flush()
        inv = VRInvestigationRecord(
            target_id=tgt.id, team_id="admin", kind="variant_hunt",
            title="t", initial_question="q",
            status=InvestigationStatus.PAUSED.value, auto_pilot=False,
            strategy_family="vulnerability_research.variant_hunt",
            cost_budget_usd=50.0,
            linked_finding_ids_json=json.dumps([finding.id]),
        )
        uow.session.add(inv)
        await uow.session.flush()
        primary = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", turn_count=7,
            fork_reason="primary",
        )
        uow.session.add(primary)
        await uow.session.flush()
        fork_with_msgs = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", turn_count=3,
            fork_reason="auto_deliberation:noor",
            parent_branch_id=primary.id,
        )
        empty_fork = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", turn_count=0,
            fork_reason="auto_deliberation:maddie",
            parent_branch_id=primary.id,
        )
        uow.session.add(fork_with_msgs)
        uow.session.add(empty_fork)
        await uow.session.flush()
        for br, kind in (
            (primary, "tool_call"),
            (primary, "text"),
            (fork_with_msgs, "tool_call"),
        ):
            uow.session.add(VRInvestigationMessageRecord(
                investigation_id=inv.id, branch_id=br.id,
                sender_kind="engine", payload_kind=kind,
            ))
        uow.session.add(VRInvestigationOutcomeRecord(
            investigation_id=inv.id, branch_id=primary.id,
            outcome_kind="direct_finding", confidence="high",
            state="dispatched", dispatch_status="dispatched",
            dispatch_target=f"vr_finding:{finding.id}",
        ))
        await uow.session.commit()
        return {
            "inv": inv.id, "finding": finding.id,
            "primary": primary.id, "fork_with_msgs": fork_with_msgs.id,
            "empty_fork": empty_fork.id,
        }


@pytest.mark.usefixtures("test_db")
async def test_reset_preserves_transcript_and_archives_outcomes(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ids = await _seed()
    inv_id = ids["inv"]

    resp = await async_client.post(
        f"/vr/investigations/{inv_id}/reset", headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text

    async with UnitOfWork() as uow:
        all_msgs = (await uow.session.exec(
            select(VRInvestigationMessageRecord).where(
                VRInvestigationMessageRecord.investigation_id == inv_id,
            ),
        )).all()
        active = (await uow.session.exec(
            active_messages(VRInvestigationMessageRecord).where(
                VRInvestigationMessageRecord.investigation_id == inv_id,
            ),
        )).all()
        outcomes = (await uow.session.exec(
            select(VRInvestigationOutcomeRecord).where(
                VRInvestigationOutcomeRecord.investigation_id == inv_id,
            ),
        )).all()
        active_oc = (await uow.session.exec(
            active_outcomes(VRInvestigationOutcomeRecord).where(
                VRInvestigationOutcomeRecord.investigation_id == inv_id,
            ),
        )).all()
        finding = (await uow.session.exec(
            select(VRFindingRecord).where(
                VRFindingRecord.id == ids["finding"],
            ),
        )).first()
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == inv_id,
            ),
        )).first()
        primary = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == ids["primary"],
            ),
        )).first()
        kept_fork = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == ids["fork_with_msgs"],
            ),
        )).first()
        gone_fork = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == ids["empty_fork"],
            ),
        )).first()

    # Transcript preserved (archive, not destroy): every seeded row survives
    # and carries a superseded_at stamp, but the investigation reads as a
    # clean slate through active_messages().
    assert len(all_msgs) == 3
    assert all(m.superseded_at is not None for m in all_msgs)
    assert active == []

    # Outcomes are archived, not cleared: the seeded row survives stamped
    # superseded_at, and the active-outcome read sees a clean slate.
    assert len(outcomes) == 1
    assert all(o.superseded_at is not None for o in outcomes)
    assert active_oc == []

    # The finding row is preserved and the investigation stays linked to it:
    # relinking means the back-pointer survives, so the archived outcome's
    # dispatch_target and the investigation's linked list both still reach
    # the finding -- nothing is orphaned.
    assert finding is not None
    assert json.loads(inv.linked_finding_ids_json) == [finding.id]
    assert inv.status == InvestigationStatus.CREATED.value

    # Root branch reset to turn 0; the message-bearing fork is kept (as the
    # FK parent for its superseded rows) and marked terminal; the empty fork
    # is GC'd.
    assert primary is not None
    assert primary.status == "active"
    assert primary.turn_count == 0
    assert kept_fork is not None
    assert kept_fork.status == "abandoned"
    assert kept_fork.closed_reason == "investigation_reset"
    assert gone_fork is None

from __future__ import annotations

import json
from typing import cast
from uuid import uuid4

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from aila.modules.vr.agents.vuln_researcher import HonestVulnResearcher
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.discovery_outcomes import project_discovery_outcomes
from aila.platform.services.ledger import InvestigationLedgerRecord, LedgerService
from aila.platform.uow import UnitOfWork


async def _seed_investigation() -> tuple[str, str]:
    suffix = uuid4().hex[:8]
    async with UnitOfWork() as uow:
        workspace = VRWorkspaceRecord(
            team_id=f"team-{suffix}", name="W", slug=f"w-{suffix}",
        )
        uow.session.add(workspace)
        await uow.session.flush()
        target = VRTargetRecord(
            team_id=workspace.team_id,
            workspace_id=workspace.id,
            display_name="target",
            kind="native_binary",
        )
        uow.session.add(target)
        await uow.session.flush()
        investigation = VRInvestigationRecord(
            team_id=workspace.team_id, target_id=target.id, title="investigation",
        )
        uow.session.add(investigation)
        await uow.session.flush()
        branch = VRInvestigationBranchRecord(investigation_id=investigation.id)
        uow.session.add(branch)
        await uow.session.flush()
        result = (investigation.id, branch.id)
        await uow.session.commit()
    return result


async def _discovery(
    investigation_id: str,
    branch_id: str,
    payload: dict[str, object],
) -> int:
    return await LedgerService().append_general(
        investigation_id, branch_id, "discovery", payload,
    )


async def _outcomes(investigation_id: str) -> list[VRInvestigationOutcomeRecord]:
    async with UnitOfWork() as uow:
        session = cast(AsyncSession, uow.session)
        return list((await session.exec(
            select(VRInvestigationOutcomeRecord)
            .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
            .order_by(VRInvestigationOutcomeRecord.id)
        )).all())


async def test_every_discovery_projects_once_without_active_hypothesis(test_db) -> None:
    del test_db
    investigation_id, branch_id = await _seed_investigation()
    first = await _discovery(investigation_id, branch_id, {
        "claim": "SQL injection in login", "source": "lateral_llm",
        "why_plausible": "The query concatenates request input.",
    })
    second = await _discovery(investigation_id, branch_id, {
        "title": "XSS in profile rendering", "source": "lateral_observation",
    })

    async with UnitOfWork() as uow:
        created = await project_discovery_outcomes(investigation_id, session=uow.session)
        assert await project_discovery_outcomes(investigation_id, session=uow.session) == []
        await uow.session.commit()

    assert created == [f"ledger-discovery-{first}", f"ledger-discovery-{second}"]
    outcomes = await _outcomes(investigation_id)
    assert [row.id for row in outcomes] == created
    for row in outcomes:
        payload = json.loads(row.payload_json)
        assert row.outcome_kind == "assessment_report"
        assert row.confidence == "unknown"
        assert row.state == "draft"
        assert row.dispatch_status == "pending"
        assert payload["review_state"] == "unverified"
        assert payload["ledger_discovery_id"] in {first, second}
    assert {json.loads(row.payload_json)["title"] for row in outcomes} == {
        "SQL injection in login", "XSS in profile rendering",
    }


async def test_only_explicit_confirmation_creates_direct_finding_draft(test_db) -> None:
    del test_db
    investigation_id, branch_id = await _seed_investigation()
    discovery_id = await _discovery(investigation_id, branch_id, {
        "claim": "Reachable overflow in decoder",
        "confirmed_by": "audit_mcp.read_function:src/decoder.c:88",
        "source": "taint_confirmed",
    })

    async with UnitOfWork() as uow:
        await project_discovery_outcomes(investigation_id, session=uow.session)
        await uow.session.commit()

    [row] = await _outcomes(investigation_id)
    payload = json.loads(row.payload_json)
    assert row.id == f"ledger-discovery-{discovery_id}"
    assert row.outcome_kind == "direct_finding"
    assert row.confidence == "strong"
    assert row.state == "draft"
    assert payload["review_state"] == "confirmed"
    assert json.loads(row.evidence_refs_json) == [
        "audit_mcp.read_function:src/decoder.c:88",
    ]


async def test_projection_does_not_stop_at_the_ledger_reader_default_limit(test_db) -> None:
    del test_db
    investigation_id, branch_id = await _seed_investigation()
    async with UnitOfWork() as uow:
        uow.session.add_all([
            InvestigationLedgerRecord(
                investigation_id=investigation_id,
                author_branch_id=branch_id,
                kind="discovery",
                payload_json=json.dumps({"claim": f"Candidate {index}"}),
            )
            for index in range(201)
        ])
        await uow.session.commit()
    async with UnitOfWork() as uow:
        created = await project_discovery_outcomes(investigation_id, session=uow.session)
        await uow.session.commit()
    assert len(created) == 201
    assert len(await _outcomes(investigation_id)) == 201


async def test_terminal_submit_does_not_merge_into_a_projected_outcome(test_db) -> None:
    del test_db
    investigation_id, branch_id = await _seed_investigation()
    async with UnitOfWork() as uow:
        canonical = VRInvestigationOutcomeRecord(
            investigation_id=investigation_id,
            branch_id=branch_id,
            outcome_kind="assessment_report",
            confidence="medium",
            payload_json=json.dumps({"canonical": True, "answer": "Original"}),
        )
        uow.session.add(canonical)
        await uow.session.flush()
        canonical_id = canonical.id
        await uow.session.commit()
    discovery_id = await _discovery(investigation_id, branch_id, {"claim": "Ledger candidate"})

    async with UnitOfWork() as uow:
        await project_discovery_outcomes(investigation_id, session=uow.session)
        merged_id = await HonestVulnResearcher._upsert_canonical_outcome(
            uow=uow,
            investigation_id=investigation_id,
            branch_id=branch_id,
            persona_voice="primary",
            new_outcome_kind="audit_memo",
            new_confidence="medium",
            new_payload={"answer": "Canonical close"},
            at_turn=2,
            action="terminal_submit",
        )
        await uow.session.commit()

    assert merged_id == canonical_id
    assert merged_id != f"ledger-discovery-{discovery_id}"

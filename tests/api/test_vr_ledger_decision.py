"""Operator vote on a VR ledger request via the X-Ray oracle panel.

POST /vr/investigations/{id}/ledger/requests/{request_id}/decision records a
decision entry as one of the investigation's branches. A branch cannot
ratify its own request, a branch from another investigation cannot vote,
and the decision shows up on the ledger GET with its target.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest
from httpx import AsyncClient

from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.services.ledger import LedgerService
from aila.platform.services.oracle import Oracle
from aila.platform.uow import UnitOfWork

pytestmark = pytest.mark.asyncio


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _seed() -> dict[str, str]:
    async with UnitOfWork() as uow:
        # Unique slug: the suite's test DB may keep rows from other tests,
        # and (team_id, slug) is unique.
        slug = f"ledger-{uuid4().hex[:12]}"
        ws = VRWorkspaceRecord(
            name=slug, slug=slug, description="", theme="custom",
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
        ids: dict[str, str] = {}
        for key in ("inv", "other_inv"):
            inv = VRInvestigationRecord(
                target_id=tgt.id, team_id="admin", kind="variant_hunt",
                title=key, initial_question="q",
                status=InvestigationStatus.RUNNING.value, auto_pilot=False,
                strategy_family="vulnerability_research.variant_hunt",
                cost_budget_usd=50.0,
            )
            uow.session.add(inv)
            await uow.session.flush()
            ids[key] = inv.id
        for key, inv_key in (
            ("author", "inv"), ("approver", "inv"), ("foreign", "other_inv"),
        ):
            br = VRInvestigationBranchRecord(
                investigation_id=ids[inv_key], status="active", turn_count=1,
                fork_reason=key,
            )
            uow.session.add(br)
            await uow.session.flush()
            ids[key] = br.id
        await uow.session.commit()
    request_id = await LedgerService().append_general(
        ids["inv"], ids["author"], "request", {"intent": "replan"},
    )
    ids["request"] = str(request_id)
    return ids


def _url(inv: str, request_id: str) -> str:
    return f"/vr/investigations/{inv}/ledger/requests/{request_id}/decision"


@pytest.mark.usefixtures("test_db")
async def test_operator_vote_ratifies_request(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ids = await _seed()
    resp = await async_client.post(
        _url(ids["inv"], ids["request"]),
        json={"approver_branch_id": ids["approver"], "approve": True, "reason": "warranted"},
        headers=_auth(admin_token),
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()["data"]
    assert data["approved"] is True
    assert data["ratified"] is True
    assert await Oracle().is_ratified(ids["inv"], int(ids["request"])) is True

    ledger = await async_client.get(
        f"/vr/investigations/{ids['inv']}/ledger", headers=_auth(admin_token),
    )
    assert ledger.status_code == 200, ledger.text
    decisions = [r for r in ledger.json()["data"] if r["kind"] == "decision"]
    assert len(decisions) == 1
    assert decisions[0]["decision_target"] == int(ids["request"])
    assert decisions[0]["decision_approved"] is True
    assert decisions[0]["author_branch_id"] == ids["approver"]
    requests = [r for r in ledger.json()["data"] if r["kind"] == "request"]
    assert requests[0]["decision_target"] is None
    assert requests[0]["decision_approved"] is None


@pytest.mark.usefixtures("test_db")
async def test_reject_vote_leaves_request_unratified(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ids = await _seed()
    resp = await async_client.post(
        _url(ids["inv"], ids["request"]),
        json={"approver_branch_id": ids["approver"], "approve": False},
        headers=_auth(admin_token),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["data"]["ratified"] is False


@pytest.mark.usefixtures("test_db")
async def test_author_cannot_ratify_own_request(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ids = await _seed()
    resp = await async_client.post(
        _url(ids["inv"], ids["request"]),
        json={"approver_branch_id": ids["author"], "approve": True},
        headers=_auth(admin_token),
    )
    assert resp.status_code == 409, resp.text
    assert await Oracle().is_ratified(ids["inv"], int(ids["request"])) is False


@pytest.mark.usefixtures("test_db")
async def test_foreign_branch_and_unknown_request_are_404(
    async_client: AsyncClient, admin_token: str,
) -> None:
    ids = await _seed()
    foreign = await async_client.post(
        _url(ids["inv"], ids["request"]),
        json={"approver_branch_id": ids["foreign"], "approve": True},
        headers=_auth(admin_token),
    )
    assert foreign.status_code == 404, foreign.text
    missing = await async_client.post(
        _url(ids["inv"], str(int(ids["request"]) + 999)),
        json={"approver_branch_id": ids["approver"], "approve": True},
        headers=_auth(admin_token),
    )
    assert missing.status_code == 404, missing.text

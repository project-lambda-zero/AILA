"""Hard-delete regressions for VR investigation LLM artifacts."""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from datetime import timedelta
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationOutcomeReviewRecord,
    VRInvestigationRecord,
    VRInvestigationTargetRecord,
    VRPatternRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts import utc_now
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.llm.idempotency_cache import LLMIdempotencyCache
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import AuditEventRecord

pytestmark = pytest.mark.asyncio


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _seed_delete_case() -> dict[str, str]:
    pattern_id = str(uuid4())
    async with UnitOfWork() as uow:
        workspace = VRWorkspaceRecord(
            name="delete-test",
            slug=f"delete-{uuid4().hex[:12]}",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(workspace)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=workspace.id,
            team_id="admin",
            display_name="synthetic target",
            kind="native_binary",
            descriptor_json="{}",
            primary_language="c",
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json="{}",
            status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.flush()

        investigation = VRInvestigationRecord(
            target_id=target.id,
            team_id="admin",
            kind="variant_hunt",
            title="synthetic investigation",
            initial_question="synthetic question",
            status="paused",
            auto_pilot=False,
            strategy_family="vulnerability_research.variant_hunt",
            cost_budget_usd=10.0,
        )
        uow.session.add(investigation)
        await uow.session.flush()

        branch = VRInvestigationBranchRecord(
            investigation_id=investigation.id,
            status="active",
            turn_count=1,
            fork_reason="primary",
        )
        uow.session.add(branch)
        await uow.session.flush()
        child_branch = VRInvestigationBranchRecord(
            investigation_id=investigation.id,
            status="active",
            turn_count=0,
            fork_reason="synthetic child",
            parent_branch_id=branch.id,
        )
        uow.session.add(child_branch)
        await uow.session.flush()

        message = VRInvestigationMessageRecord(
            investigation_id=investigation.id,
            branch_id=branch.id,
            sender_kind="engine",
            payload_kind="text",
        )
        outcome = VRInvestigationOutcomeRecord(
            investigation_id=investigation.id,
            branch_id=branch.id,
            outcome_kind="direct_finding",
            confidence="high",
            state="dispatched",
            dispatch_status="dispatched",
        )
        uow.session.add(message)
        uow.session.add(outcome)
        uow.session.add(
            VRInvestigationTargetRecord(
                investigation_id=investigation.id,
                target_id=target.id,
                role="primary",
            )
        )
        uow.session.add(
            VRPatternRecord(
                id=pattern_id,
                workspace_id=workspace.id,
                investigation_id=investigation.id,
                kind="exploitation_technique",
                summary="synthetic pattern",
                body="synthetic evidence",
                applicability_json="{}",
                confidence="medium",
                evidence_refs_json="[]",
                status="active",
                scope="workspace",
            )
        )
        await uow.session.flush()

        uow.session.add(
            VRInvestigationOutcomeReviewRecord(
                outcome_id=outcome.id,
                reviewer_branch_id=child_branch.id,
                reviewer_persona="reviewer",
                vote="approve",
            )
        )

        cache_keys = [uuid4().hex for _ in range(3)]
        uow.session.add(
            LLMIdempotencyCache(
                request_key=cache_keys[0],
                investigation_id=investigation.id,
                branch_id=branch.id,
                response_json="{}",
                expires_at=utc_now() + timedelta(days=7),
            )
        )
        uow.session.add(
            LLMIdempotencyCache(
                request_key=cache_keys[1],
                investigation_id=f"unrelated-{uuid4().hex[:12]}",
                branch_id=child_branch.id,
                response_json="{}",
                expires_at=utc_now() + timedelta(days=7),
            )
        )
        unrelated_investigation_id = f"unrelated-{uuid4().hex[:12]}"
        unrelated_branch_id = f"unrelated-{uuid4().hex[:12]}"
        uow.session.add(
            LLMIdempotencyCache(
                request_key=cache_keys[2],
                investigation_id=unrelated_investigation_id,
                branch_id=unrelated_branch_id,
                response_json="{}",
                expires_at=utc_now() + timedelta(days=7),
            )
        )

        cost_ids = [str(uuid4()) for _ in range(3)]
        uow.session.add(
            LLMCostRecord(
                id=cost_ids[0],
                run_id=investigation.id,
                investigation_id=investigation.id,
                branch_id=branch.id,
                model_id="synthetic-model",
                task_type="test",
                team_id="admin",
                cost_usd=0.25,
            )
        )
        uow.session.add(
            LLMCostRecord(
                id=cost_ids[1],
                run_id="legacy-run",
                investigation_id=None,
                branch_id=child_branch.id,
                model_id="synthetic-model",
                task_type="test",
                team_id="admin",
                cost_usd=0.50,
            )
        )
        uow.session.add(
            LLMCostRecord(
                id=cost_ids[2],
                run_id=unrelated_investigation_id,
                investigation_id=unrelated_investigation_id,
                branch_id=unrelated_branch_id,
                model_id="synthetic-model",
                task_type="test",
                team_id="admin",
                cost_usd=1.00,
            )
        )
        await uow.commit()

    return {
        "investigation_id": investigation.id,
        "branch_id": branch.id,
        "child_branch_id": child_branch.id,
        "message_id": message.id,
        "outcome_id": outcome.id,
        "pattern_id": pattern_id,
        "cache_key_direct": cache_keys[0],
        "cache_key_branch": cache_keys[1],
        "cache_key_unrelated": cache_keys[2],
        "cost_id_direct": cost_ids[0],
        "cost_id_branch": cost_ids[1],
        "cost_id_unrelated": cost_ids[2],
    }


async def _assert_rolled_back(ids: dict[str, str]) -> None:
    async with UnitOfWork() as uow:
        investigation = (
            await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == ids["investigation_id"],
                ),
            )
        ).first()
        branch = (
            await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == ids["branch_id"],
                ),
            )
        ).first()
        child_branch = (
            await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == ids["child_branch_id"],
                ),
            )
        ).first()
        messages = (
            await uow.session.exec(
                select(VRInvestigationMessageRecord).where(
                    VRInvestigationMessageRecord.id == ids["message_id"],
                ),
            )
        ).all()
        outcomes = (
            await uow.session.exec(
                select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == ids["outcome_id"],
                ),
            )
        ).all()
        pattern = (
            await uow.session.exec(
                select(VRPatternRecord).where(
                    VRPatternRecord.id == ids["pattern_id"],
                ),
            )
        ).first()
        joins = (
            await uow.session.exec(
                select(VRInvestigationTargetRecord).where(
                    VRInvestigationTargetRecord.investigation_id == ids["investigation_id"],
                ),
            )
        ).all()
        reviews = (
            await uow.session.exec(
                select(VRInvestigationOutcomeReviewRecord).where(
                    VRInvestigationOutcomeReviewRecord.outcome_id == ids["outcome_id"],
                ),
            )
        ).all()
        cache_rows = (
            await uow.session.exec(
                select(LLMIdempotencyCache).where(
                    LLMIdempotencyCache.request_key.in_(
                        [
                            ids["cache_key_direct"],
                            ids["cache_key_branch"],
                        ]
                    ),
                ),
            )
        ).all()
        costs = (
            await uow.session.exec(
                select(LLMCostRecord).where(
                    LLMCostRecord.id.in_(
                        [
                            ids["cost_id_direct"],
                            ids["cost_id_branch"],
                        ]
                    ),
                ),
            )
        ).all()
        audit_rows = (
            await uow.session.exec(
                select(AuditEventRecord).where(
                    AuditEventRecord.run_id == ids["investigation_id"],
                    AuditEventRecord.action == "investigation_deleted",
                ),
            )
        ).all()

    assert investigation is not None
    assert branch is not None
    assert child_branch is not None
    assert child_branch.parent_branch_id == ids["branch_id"]
    assert len(messages) == 1
    assert len(outcomes) == 1
    assert len(reviews) == 1
    assert pattern is not None
    assert pattern.investigation_id == ids["investigation_id"]
    assert len(joins) == 1
    assert {row.request_key for row in cache_rows} == {
        ids["cache_key_direct"],
        ids["cache_key_branch"],
    }
    assert {row.id for row in costs} == {ids["cost_id_direct"], ids["cost_id_branch"]}
    assert all(row.investigation_id == ids["investigation_id"] or row.id == ids["cost_id_branch"] for row in costs)
    assert all(row.branch_id in (ids["branch_id"], ids["child_branch_id"]) for row in costs)
    assert all(row.run_id != "_no_run" for row in costs)
    assert audit_rows == []


async def test_delete_investigation_cleans_cache_and_detaches_costs(
    async_client: AsyncClient,
    admin_token: str,
) -> None:
    ids = await _seed_delete_case()

    response = await async_client.delete(
        f"/vr/investigations/{ids['investigation_id']}",
        headers=_auth(admin_token),
    )

    assert response.status_code == 204, response.text
    async with UnitOfWork() as uow:
        investigation = (
            await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == ids["investigation_id"],
                ),
            )
        ).first()
        branches = (
            await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id.in_(
                        [
                            ids["branch_id"],
                            ids["child_branch_id"],
                        ]
                    ),
                ),
            )
        ).all()
        messages = (
            await uow.session.exec(
                select(VRInvestigationMessageRecord).where(
                    VRInvestigationMessageRecord.investigation_id == ids["investigation_id"],
                ),
            )
        ).all()
        outcomes = (
            await uow.session.exec(
                select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.investigation_id == ids["investigation_id"],
                ),
            )
        ).all()
        reviews = (
            await uow.session.exec(
                select(VRInvestigationOutcomeReviewRecord).where(
                    VRInvestigationOutcomeReviewRecord.outcome_id == ids["outcome_id"],
                ),
            )
        ).all()
        joins = (
            await uow.session.exec(
                select(VRInvestigationTargetRecord).where(
                    VRInvestigationTargetRecord.investigation_id == ids["investigation_id"],
                ),
            )
        ).all()
        pattern = (
            await uow.session.exec(
                select(VRPatternRecord).where(VRPatternRecord.id == ids["pattern_id"]),
            )
        ).first()
        cache_rows = (
            await uow.session.exec(
                select(LLMIdempotencyCache).where(
                    LLMIdempotencyCache.request_key.in_(
                        [
                            ids["cache_key_direct"],
                            ids["cache_key_branch"],
                            ids["cache_key_unrelated"],
                        ]
                    ),
                ),
            )
        ).all()
        cache_references = (
            await uow.session.exec(
                select(LLMIdempotencyCache).where(
                    or_(
                        LLMIdempotencyCache.investigation_id == ids["investigation_id"],
                        LLMIdempotencyCache.branch_id.in_(
                            [
                                ids["branch_id"],
                                ids["child_branch_id"],
                            ]
                        ),
                    )
                ),
            )
        ).all()
        costs = (
            await uow.session.exec(
                select(LLMCostRecord).where(
                    LLMCostRecord.id.in_(
                        [
                            ids["cost_id_direct"],
                            ids["cost_id_branch"],
                            ids["cost_id_unrelated"],
                        ]
                    ),
                ),
            )
        ).all()
        cost_references = (
            await uow.session.exec(
                select(LLMCostRecord).where(
                    or_(
                        LLMCostRecord.investigation_id == ids["investigation_id"],
                        LLMCostRecord.branch_id.in_(
                            [
                                ids["branch_id"],
                                ids["child_branch_id"],
                            ]
                        ),
                    )
                ),
            )
        ).all()
        audit_rows = (
            await uow.session.exec(
                select(AuditEventRecord).where(
                    AuditEventRecord.run_id == ids["investigation_id"],
                    AuditEventRecord.action == "investigation_deleted",
                ),
            )
        ).all()

    assert investigation is None
    assert branches == []
    assert messages == []
    assert outcomes == []
    assert reviews == []
    assert joins == []
    assert pattern is not None
    assert pattern.investigation_id is None
    assert {row.request_key for row in cache_rows} == {ids["cache_key_unrelated"]}
    assert cache_references == []
    assert cost_references == []
    costs_by_id = {row.id: row for row in costs}
    for cost_id in (ids["cost_id_direct"], ids["cost_id_branch"]):
        assert costs_by_id[cost_id].investigation_id is None
        assert costs_by_id[cost_id].branch_id is None
        assert costs_by_id[cost_id].run_id == "_no_run"
        assert costs_by_id[cost_id].team_id == "admin"
    assert costs_by_id[ids["cost_id_unrelated"]].run_id != "_no_run"
    assert costs_by_id[ids["cost_id_unrelated"]].cost_usd == 1.0
    assert sum(row.cost_usd for row in costs) == pytest.approx(1.75)
    assert len(audit_rows) == 1


async def test_delete_investigation_rolls_back_when_cache_purge_fails(
    async_client: AsyncClient,
    admin_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _seed_delete_case()
    vr_api_router = importlib.import_module("aila.modules.vr.api_router")
    original_purge = vr_api_router.purge_for_investigation

    async def purge_then_fail(
        session: AsyncSession,
        investigation_id: str,
        branch_ids: Sequence[str] = (),
    ) -> int:
        await original_purge(session, investigation_id, branch_ids)
        raise SQLAlchemyError("forced cache purge failure")

    monkeypatch.setattr(vr_api_router, "purge_for_investigation", purge_then_fail)

    response = await async_client.delete(
        f"/vr/investigations/{ids['investigation_id']}",
        headers=_auth(admin_token),
    )

    assert response.status_code == 500
    await _assert_rolled_back(ids)


async def test_delete_investigation_rolls_back_when_cost_detach_fails(
    async_client: AsyncClient,
    admin_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _seed_delete_case()
    original_flush = Session.flush

    def flush_then_fail(
        session: Session,
        objects: Sequence[object] | None = None,
    ) -> None:
        if any(isinstance(row, LLMCostRecord) for row in session.dirty):
            raise SQLAlchemyError("forced cost detach failure")
        original_flush(session, objects)

    monkeypatch.setattr(Session, "flush", flush_then_fail)

    response = await async_client.delete(
        f"/vr/investigations/{ids['investigation_id']}",
        headers=_auth(admin_token),
    )

    assert response.status_code == 500
    await _assert_rolled_back(ids)

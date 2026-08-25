"""req 9 / AC1 -- deterministic fuzz-proposal producer.

Exercises ``produce_fuzz_proposals`` end-to-end against a live VR
target row:

  * count > 0 for a non-empty FunctionRanking (bounded at 8),
  * every emitted proposal carries a non-empty ``harness_source`` and a
    ``harness_build_command`` that clears the accept-flow validator
    (``validate_harness_build_command`` returns ``None``),
  * ``investigation_id`` and ``outcome_id`` land as NULL (widened by
    migration 134_fuzz_proposal_nullable_ctx),
  * re-running the producer for the same target is idempotent -- prior
    producer-authored rows are wiped, so the row count does not grow.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.db_models.workspace import VRWorkspaceRecord
from aila.modules.vr.db_models.fuzz_proposal import (
    VRFuzzCampaignProposalRecord,
)
from aila.modules.vr.enrichment.contracts import (
    FunctionRanking,
    RankedFunction,
    RankingSource,
)
from aila.modules.vr.services.fuzz_proposal_producer import (
    produce_fuzz_proposals,
)
from aila.modules.vr.services.proposal_preparer import (
    validate_harness_build_command,
)
from aila.platform.uow import UnitOfWork

pytestmark = pytest.mark.asyncio


def _make_ranking(target_id: str) -> FunctionRanking:
    """Ten ranked functions -- producer must cap at 8."""
    top = [
        RankedFunction(
            name=f"parse_thing_{i}",
            score=max(0.05, 1.0 - i * 0.1),
            rank=i + 1,
            file_path=f"src/parse_{i}.c",
            line=100 + i,
            reasons=[f"blast_radius={200 - i * 10}", "tainted_from=recv"],
        )
        for i in range(10)
    ]
    return FunctionRanking(
        target_id=target_id,
        source=RankingSource.AUDIT_MCP_FUZZING_TARGETS,
        produced_at=datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC),
        total_candidates=42,
        top_k=top,
        notes="",
    )


async def _seed_target(team_id: str, slug: str) -> VRTargetRecord:
    capability = {
        "primary_language": "c",
        "applicable_fuzzing_engines": ["libfuzzer", "afl++"],
    }
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            team_id=team_id,
            name=f"ws-{slug}",
            slug=slug,
            theme="browser_engines",
        )
        uow.session.add(ws)
        await uow.session.commit()
        await uow.session.refresh(ws)
        row = VRTargetRecord(
            team_id=team_id,
            workspace_id=ws.id,
            display_name="producer-target",
            kind=TargetKind.SOURCE_REPO.value,
            primary_language="c",
            capability_profile_json=json.dumps(capability),
        )
        uow.session.add(row)
        await uow.session.commit()
        await uow.session.refresh(row)
    return row


@pytest.mark.usefixtures("test_db")
async def test_producer_writes_valid_proposals_and_is_idempotent() -> None:
    team_id = "team-a"

    target = await _seed_target(team_id=team_id, slug="producer-test")
    ranking = _make_ranking(target.id)

    # First run -- writes fresh proposals.
    async with UnitOfWork() as uow:
        first_count = await produce_fuzz_proposals(uow.session, target, ranking)
        await uow.session.commit()
    assert first_count > 0
    assert first_count <= 8

    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(VRFuzzCampaignProposalRecord).where(
                VRFuzzCampaignProposalRecord.target_id == target.id,
            ),
        )).all()

    assert len(rows) == first_count
    for row in rows:
        assert row.investigation_id is None
        assert row.outcome_id is None
        assert row.target_id == target.id
        assert row.workspace_id == target.workspace_id
        assert row.profile
        assert row.harness_language in {"c", "cpp", "rust", "go"}
        assert row.harness_source and len(row.harness_source) > 0
        assert "TODO: implement" not in row.harness_source
        assert row.harness_build_command
        assert validate_harness_build_command(row.harness_build_command) is None
        assert row.confidence in {"high", "medium", "low"}
        assert row.status == "pending"

    # Second run -- idempotent (wipes prior producer rows, count stays).
    async with UnitOfWork() as uow:
        second_count = await produce_fuzz_proposals(uow.session, target, ranking)
        await uow.session.commit()
    assert second_count == first_count

    async with UnitOfWork() as uow:
        again = (await uow.session.exec(
            select(VRFuzzCampaignProposalRecord).where(
                VRFuzzCampaignProposalRecord.target_id == target.id,
            ),
        )).all()
    assert len(again) == first_count


@pytest.mark.usefixtures("test_db")
async def test_producer_empty_ranking_writes_nothing() -> None:
    target = await _seed_target(team_id="team-a", slug="empty-rank")
    ranking = FunctionRanking(
        target_id=target.id,
        source=RankingSource.AUDIT_MCP_FUZZING_TARGETS,
        produced_at=datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC),
        total_candidates=0,
        top_k=[],
        notes="",
    )
    async with UnitOfWork() as uow:
        count = await produce_fuzz_proposals(uow.session, target, ranking)
        await uow.session.commit()
    assert count == 0

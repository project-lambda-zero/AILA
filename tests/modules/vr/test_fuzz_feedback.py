"""Fuzz-to-source-investigation feedback loop (#173/#148 feedback half).

register_crash now closes the wired-but-dead loop:

- A SECURITY_RELEVANT crash on a campaign that carries a
  ``source_investigation_id`` posts exactly one operator-steering
  message row to that investigation, keyed on
  ``fuzz_crash:<campaign_id>:<stack_hash>`` so the second POST of the
  same crash collapses via the auto_steering unique index (migration
  063) instead of double-posting.
- A LIKELY_HARMLESS crash on the same campaign posts NO steering --
  the reasoning loop only wakes up for security-relevant hits.
- A campaign with ``source_investigation_id=None`` posts NO steering
  and does NOT raise -- operator-initiated campaigns have no back-
  reference to feed and are a valid, common case.

These paths write real rows through the FuzzCampaignService +
UnitOfWork so the crash-write + feedback-write ordering is exercised
end to end; the feedback is best-effort and the crash is always
durably stored regardless.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.fuzz import (
    CrashSeverity,
    CrashTriageVerdict,
    FuzzEngineId,
    FuzzStrategyId,
    VRFuzzCampaignCreate,
    VRFuzzCrashCreate,
)
from aila.modules.vr.db_models import (
    VRFuzzCampaignRecord,
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.fuzz_service import FuzzCampaignService
from aila.platform.contracts.enums import BranchStatus, SenderKind
from aila.platform.uow import UnitOfWork


async def _seed_workspace_target(*, slug: str) -> tuple[str, str]:
    """Insert the minimum row set (workspace + target) a campaign FK
    can point at. Returns ``(workspace_id, target_id)``."""
    workspace_id = f"ws-{slug}-{uuid4().hex[:8]}"
    target_id = f"tgt-{slug}-{uuid4().hex[:8]}"
    async with UnitOfWork() as uow:
        uow.session.add(VRWorkspaceRecord(
            id=workspace_id,
            slug=slug,
            name=f"ws {slug}",
        ))
        uow.session.add(VRTargetRecord(
            id=target_id,
            workspace_id=workspace_id,
            display_name=f"target {slug}",
            kind="native_binary",
            primary_language="c",
        ))
        await uow.session.commit()
    return workspace_id, target_id


async def _seed_investigation_with_primary_branch(
    *, target_id: str,
) -> str:
    """Insert an investigation + its primary branch so the steering
    dedup helper's branch scan resolves. Returns the investigation id.
    """
    investigation_id = f"inv-{uuid4().hex[:8]}"
    async with UnitOfWork() as uow:
        uow.session.add(VRInvestigationRecord(
            id=investigation_id,
            target_id=target_id,
            title="feedback-test investigation",
        ))
        uow.session.add(VRInvestigationBranchRecord(
            investigation_id=investigation_id,
            status=BranchStatus.ACTIVE.value,
            fork_reason="primary",
        ))
        await uow.session.commit()
    return investigation_id


async def _make_campaign(
    *,
    workspace_id: str,
    target_id: str,
    source_investigation_id: str | None,
) -> str:
    """Create a campaign via the service so the source_investigation_id
    is plumbed through the same path production goes through."""
    svc = FuzzCampaignService()
    summary = await svc.create_campaign(
        VRFuzzCampaignCreate(
            target_id=target_id,
            workspace_id=workspace_id,
            name=f"feedback-{uuid4().hex[:6]}",
            engine_id=FuzzEngineId.LIBFUZZER,
            strategy_id=FuzzStrategyId.COVERAGE_GUIDED,
            source_investigation_id=source_investigation_id,
        ),
        team_id=None,
    )
    return summary.id


async def _count_fuzz_crash_steerings(investigation_id: str) -> int:
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(VRInvestigationMessageRecord).where(
                VRInvestigationMessageRecord.investigation_id == investigation_id,
                VRInvestigationMessageRecord.sender_kind == SenderKind.OPERATOR.value,
                VRInvestigationMessageRecord.sender_id == "auto_steering",
            )
        )).all()
    return sum(
        1 for r in rows
        if (r.auto_steering_key or "").startswith("fuzz_crash:")
    )


async def _confirm_campaign_source(campaign_id: str, expected: str | None) -> None:
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRFuzzCampaignRecord).where(
                VRFuzzCampaignRecord.id == campaign_id,
            )
        )).first()
    assert row is not None
    assert row.source_investigation_id == expected


@pytest.mark.asyncio
async def test_security_relevant_crash_posts_one_steering_and_dedups(
    test_db,
) -> None:
    """A SECURITY_RELEVANT crash on a linked campaign posts exactly one
    steering row; a second identical crash (same stack_hash) hits both
    the crash-side dedup AND the steering-side auto_steering_key dedup
    and produces NO second steering row."""
    workspace_id, target_id = await _seed_workspace_target(slug="fbk-a")
    investigation_id = await _seed_investigation_with_primary_branch(
        target_id=target_id,
    )
    campaign_id = await _make_campaign(
        workspace_id=workspace_id,
        target_id=target_id,
        source_investigation_id=investigation_id,
    )
    await _confirm_campaign_source(campaign_id, investigation_id)

    svc = FuzzCampaignService()
    crash_body = VRFuzzCrashCreate(
        campaign_id=campaign_id,
        stack_hash="deadbeef" * 4,
        crash_type="heap-buffer-overflow",
        severity=CrashSeverity.HIGH,
        reproducer_path="/tmp/does-not-exist/repro.bin",
        stack_trace="ParseHeader at parser.c:123",
    )
    first = await svc.register_crash(crash_body, team_id=None)
    assert first.triage_verdict == CrashTriageVerdict.SECURITY_RELEVANT

    assert await _count_fuzz_crash_steerings(investigation_id) == 1

    # Same stack_hash -> crash-side dedup returns the existing crash
    # AND the auto_steering unique index refuses a second steering.
    second = await svc.register_crash(crash_body, team_id=None)
    assert second.id == first.id
    assert await _count_fuzz_crash_steerings(investigation_id) == 1


@pytest.mark.asyncio
async def test_likely_harmless_crash_posts_no_steering(test_db) -> None:
    """A crash whose class matches ``out-of-memory`` triages as
    LIKELY_HARMLESS; the feedback path must skip it entirely so the
    reasoning loop is not woken up for noise."""
    workspace_id, target_id = await _seed_workspace_target(slug="fbk-b")
    investigation_id = await _seed_investigation_with_primary_branch(
        target_id=target_id,
    )
    campaign_id = await _make_campaign(
        workspace_id=workspace_id,
        target_id=target_id,
        source_investigation_id=investigation_id,
    )
    svc = FuzzCampaignService()
    result = await svc.register_crash(
        VRFuzzCrashCreate(
            campaign_id=campaign_id,
            stack_hash="cafeb0ba" * 4,
            crash_type="out-of-memory",
        ),
        team_id=None,
    )
    assert result.triage_verdict == CrashTriageVerdict.LIKELY_HARMLESS

    assert await _count_fuzz_crash_steerings(investigation_id) == 0


@pytest.mark.asyncio
async def test_unlinked_campaign_stores_crash_but_skips_feedback(
    test_db,
) -> None:
    """A campaign that has ``source_investigation_id=None`` (operator-
    initiated, no proposal upstream) is a valid, common state. A
    SECURITY_RELEVANT crash must still be durably stored, no steering
    must be posted, and no exception must escape the register_crash
    call."""
    workspace_id, target_id = await _seed_workspace_target(slug="fbk-c")
    # Independent investigation only used to prove no cross-talk to
    # an unrelated investigation exists when the campaign has no link.
    ghost_investigation_id = await _seed_investigation_with_primary_branch(
        target_id=target_id,
    )
    campaign_id = await _make_campaign(
        workspace_id=workspace_id,
        target_id=target_id,
        source_investigation_id=None,
    )
    await _confirm_campaign_source(campaign_id, None)

    svc = FuzzCampaignService()
    result = await svc.register_crash(
        VRFuzzCrashCreate(
            campaign_id=campaign_id,
            stack_hash="feedface" * 4,
            crash_type="use-after-free",
            severity=CrashSeverity.CRITICAL,
        ),
        team_id=None,
    )
    assert result.triage_verdict == CrashTriageVerdict.SECURITY_RELEVANT

    assert await _count_fuzz_crash_steerings(ghost_investigation_id) == 0

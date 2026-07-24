"""Tests for the platform outcome-dispatch claim (RFC-03 Phase 6b).

The claim closes the dispatch TOCTOU: two workers must never both dispatch
the same outcome. These tests seed a real VR outcome (the claim is generic
over the module record type) and assert the claim invariant -- exactly one
caller wins, a second loses, a guard refusal leaves the row unclaimed, and
a missing row reports not-found.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta
from uuid import uuid4

import pytest

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import OutcomeDispatchStatus
from aila.platform.services.outcome_dispatch import claim_outcome_for_dispatch
from aila.storage.database import session_scope


def _seed_outcome(
    dispatch_status: str = "pending",
    *,
    claimed_minutes_ago: float | None = None,
) -> str:
    """Seed the FK chain and one approved outcome; return the outcome id."""
    suffix = uuid4().hex[:8]
    ws_id = f"ws-{suffix}"
    tgt_id = f"tgt-{suffix}"
    inv_id = f"inv-{suffix}"
    branch_id = f"br-{suffix}"
    outcome_id = f"out-{suffix}"
    with session_scope() as sess:
        sess.add(VRWorkspaceRecord(id=ws_id, name="ws", slug=ws_id))
        sess.flush()
        sess.add(VRTargetRecord(
            id=tgt_id, workspace_id=ws_id,
            display_name="tgt", kind="native_binary",
        ))
        sess.flush()
        sess.add(VRInvestigationRecord(
            id=inv_id, target_id=tgt_id, title="seed", kind="discovery",
            strategy_family="vulnerability_research.discovery_research",
        ))
        sess.flush()
        sess.add(VRInvestigationBranchRecord(id=branch_id, investigation_id=inv_id))
        sess.flush()
        claimed_at = (
            None if claimed_minutes_ago is None
            else utc_now() - timedelta(minutes=claimed_minutes_ago)
        )
        sess.add(VRInvestigationOutcomeRecord(
            id=outcome_id, investigation_id=inv_id, branch_id=branch_id,
            outcome_kind="direct_finding", confidence="strong",
            state="approved", dispatch_status=dispatch_status,
            claimed_at=claimed_at,
        ))
        sess.commit()
    return outcome_id


def _read_dispatch_status(outcome_id: str) -> str:
    with session_scope() as sess:
        row = sess.get(VRInvestigationOutcomeRecord, outcome_id)
        assert row is not None
        return row.dispatch_status


@pytest.mark.asyncio
async def test_first_claim_wins(test_db) -> None:
    del test_db
    outcome_id = _seed_outcome()
    claim = await claim_outcome_for_dispatch(VRInvestigationOutcomeRecord, outcome_id)
    assert claim.found is True
    assert claim.won is True
    assert claim.outcome_kind == "direct_finding"
    assert claim.investigation_id is not None
    assert _read_dispatch_status(outcome_id) == OutcomeDispatchStatus.CLAIMED.value


@pytest.mark.asyncio
async def test_second_claim_loses(test_db) -> None:
    del test_db
    outcome_id = _seed_outcome()
    first = await claim_outcome_for_dispatch(VRInvestigationOutcomeRecord, outcome_id)
    second = await claim_outcome_for_dispatch(VRInvestigationOutcomeRecord, outcome_id)
    assert first.won is True
    assert second.found is True
    assert second.won is False
    assert second.skip_reason == "claim_in_progress"


@pytest.mark.asyncio
async def test_guard_refusal_leaves_row_pending(test_db) -> None:
    del test_db
    outcome_id = _seed_outcome()

    def _refuse(_row) -> str:
        return "not_dispatchable"

    claim = await claim_outcome_for_dispatch(
        VRInvestigationOutcomeRecord, outcome_id, guard=_refuse,
    )
    assert claim.found is True
    assert claim.won is False
    assert claim.skip_reason == "not_dispatchable"
    assert _read_dispatch_status(outcome_id) == OutcomeDispatchStatus.PENDING.value


@pytest.mark.asyncio
async def test_missing_outcome_reports_not_found(test_db) -> None:
    del test_db
    claim = await claim_outcome_for_dispatch(
        VRInvestigationOutcomeRecord, "does-not-exist",
    )
    assert claim.found is False
    assert claim.won is False


@pytest.mark.asyncio
async def test_concurrent_claims_single_winner(test_db) -> None:
    """Two claims raced against the same outcome: the FOR UPDATE lock lets
    exactly one win; the other observes CLAIMED and backs off."""
    del test_db
    outcome_id = _seed_outcome()
    results = await asyncio.wait_for(
        asyncio.gather(
            claim_outcome_for_dispatch(VRInvestigationOutcomeRecord, outcome_id),
            claim_outcome_for_dispatch(VRInvestigationOutcomeRecord, outcome_id),
        ),
        timeout=30,
    )
    winners = [r for r in results if r.won]
    assert len(winners) == 1
    assert _read_dispatch_status(outcome_id) == OutcomeDispatchStatus.CLAIMED.value


@pytest.mark.asyncio
async def test_stale_claim_is_reclaimed(test_db) -> None:
    """A CLAIMED row whose claimed_at is older than the reclaim window was
    stranded by a crashed dispatcher; the next attempt reclaims it."""
    del test_db
    outcome_id = _seed_outcome("claimed", claimed_minutes_ago=20)
    claim = await claim_outcome_for_dispatch(
        VRInvestigationOutcomeRecord, outcome_id,
    )
    assert claim.found is True
    assert claim.won is True
    assert _read_dispatch_status(outcome_id) == OutcomeDispatchStatus.CLAIMED.value


@pytest.mark.asyncio
async def test_fresh_claim_is_not_reclaimed(test_db) -> None:
    """A CLAIMED row with a recent claimed_at is held by a live dispatcher
    and must not be reclaimed."""
    del test_db
    outcome_id = _seed_outcome("claimed", claimed_minutes_ago=1)
    claim = await claim_outcome_for_dispatch(
        VRInvestigationOutcomeRecord, outcome_id,
    )
    assert claim.found is True
    assert claim.won is False
    assert claim.skip_reason == "claim_in_progress"


@pytest.mark.asyncio
async def test_dispatched_is_terminal(test_db) -> None:
    """A DISPATCHED row is terminal -- never reclaimed regardless of age."""
    del test_db
    outcome_id = _seed_outcome("dispatched")
    claim = await claim_outcome_for_dispatch(
        VRInvestigationOutcomeRecord, outcome_id,
    )
    assert claim.found is True
    assert claim.won is False
    assert claim.skip_reason == "already_dispatched"

"""#315 VR outcome list returns stored sibling-review vote counts and quorum K.

Before this fix the VR outcome projection never read ``vr_outcome_reviews``,
so ``approve_count``, ``reject_count``, ``request_edit_count``,
``abstain_count`` and ``quorum_k`` serialized as 0 for every outcome. These
tests drive the real list handler from ``create_vr_router`` against the
Postgres ``test_db`` fixture and assert:

- stored vote counts per outcome, with ``not_ready`` excluded from every field;
- zero counts for an outcome with no reviews, and quorum K still computed;
- quorum K from non-abandoned branches minus one (malware rule);
- an empty investigation returns no outcomes;
- a review inserted after an earlier read is reflected on the next read;
- one grouped SELECT over ``vr_outcome_reviews`` regardless of outcome count.

The slowapi limiter is disabled process-wide by the ``_disable_slowapi_limiter``
autouse fixture in ``tests/api/conftest.py``, so the endpoint runs its inner
closure directly.
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import event
from sqlalchemy.engine import Engine

from aila.api.auth import AuthContext
from aila.modules.vr.api_router import create_vr_router
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationOutcomeReviewRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.storage.database import async_session_scope

_LIST_PATH = "/investigations/{investigation_id}/outcomes"


class _Req:
    """Stand-in Request: the handlers ``del request`` immediately."""


def _endpoint(path: str, method: str):
    for route in create_vr_router().routes:
        if (
            getattr(route, "path", None) == path
            and method in getattr(route, "methods", set())
        ):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _auth(team_id: str) -> AuthContext:
    return AuthContext(
        user_id=f"u-{team_id}",
        role="analyst",
        auth_type="user",
        team_id=team_id,
    )


async def _seed_team() -> tuple[str, str]:
    suffix = uuid4().hex[:8]
    team_id = f"team-315-{suffix}"
    async with async_session_scope() as session:
        ws = VRWorkspaceRecord(team_id=team_id, name="W", slug=f"w-{suffix}")
        session.add(ws)
        await session.flush()
        target = VRTargetRecord(
            team_id=team_id, workspace_id=ws.id, display_name="t",
            kind="native_binary",
        )
        session.add(target)
        await session.flush()
        target_id = target.id
        await session.commit()
    return team_id, target_id


async def _seed_investigation(
    team_id: str, target_id: str, *, active: int, abandoned: int = 0,
) -> tuple[str, list[str]]:
    """Create one investigation with ``active`` live branches then ``abandoned``.

    Returns (investigation_id, active_branch_ids).
    """
    async with async_session_scope() as session:
        inv = VRInvestigationRecord(
            team_id=team_id, target_id=target_id, title="inv-315",
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id
        branches = [
            VRInvestigationBranchRecord(investigation_id=inv_id)
            for _ in range(active)
        ] + [
            VRInvestigationBranchRecord(
                investigation_id=inv_id, status="abandoned",
            )
            for _ in range(abandoned)
        ]
        session.add_all(branches)
        await session.flush()
        active_ids = [b.id for b in branches[:active]]
        await session.commit()
    return inv_id, active_ids


async def _seed_outcome(investigation_id: str, branch_id: str) -> str:
    async with async_session_scope() as session:
        oc = VRInvestigationOutcomeRecord(
            investigation_id=investigation_id,
            branch_id=branch_id,
            outcome_kind="direct_finding",
            confidence="strong",
        )
        session.add(oc)
        await session.flush()
        outcome_id = oc.id
        await session.commit()
    return outcome_id


async def _seed_review(outcome_id: str, reviewer_branch_id: str, vote: str) -> None:
    async with async_session_scope() as session:
        session.add(VRInvestigationOutcomeReviewRecord(
            outcome_id=outcome_id,
            reviewer_branch_id=reviewer_branch_id,
            reviewer_persona="persona-315",
            vote=vote,
        ))
        await session.commit()


async def _list(investigation_id: str, team_id: str) -> dict:
    list_outcomes = _endpoint(_LIST_PATH, "GET")
    envelope = await list_outcomes(
        request=_Req(), investigation_id=investigation_id, auth=_auth(team_id),
    )
    return {item.id: item for item in envelope.data}


async def test_vr_outcome_list_returns_stored_vote_counts_and_quorum(test_db) -> None:
    team_id, target_id = await _seed_team()
    # 6 live branches + 2 abandoned. Non-abandoned branch count minus one is 5,
    # so quorum K = compute_quorum(5) = 3. Counting abandoned branches would
    # give compute_quorum(7) = 4, so K == 3 also pins the abandoned exclusion.
    inv_id, br = await _seed_investigation(
        team_id, target_id, active=6, abandoned=2,
    )
    oa = await _seed_outcome(inv_id, br[0])
    ob = await _seed_outcome(inv_id, br[1])
    oc = await _seed_outcome(inv_id, br[2])

    # Outcome A: approve x2, reject x1, request_edit x1, abstain x1.
    await _seed_review(oa, br[1], "approve")
    await _seed_review(oa, br[2], "approve")
    await _seed_review(oa, br[3], "reject")
    await _seed_review(oa, br[4], "request_edit")
    await _seed_review(oa, br[5], "abstain")
    # Outcome B: not_ready x1 (must not appear in any field), approve x3, reject x1.
    await _seed_review(ob, br[0], "not_ready")
    await _seed_review(ob, br[2], "approve")
    await _seed_review(ob, br[3], "approve")
    await _seed_review(ob, br[4], "approve")
    await _seed_review(ob, br[5], "reject")

    items = await _list(inv_id, team_id)

    assert set(items) == {oa, ob, oc}
    a = items[oa]
    assert (a.approve_count, a.reject_count, a.request_edit_count, a.abstain_count) == (2, 1, 1, 1)
    assert a.quorum_k == 3
    b = items[ob]
    assert (b.approve_count, b.reject_count, b.request_edit_count, b.abstain_count) == (3, 1, 0, 0)
    assert b.quorum_k == 3


async def test_vr_outcome_without_reviews_has_zero_counts_and_quorum(test_db) -> None:
    team_id, target_id = await _seed_team()
    # 3 live branches -> 2 non-proposing -> compute_quorum(2) = 2.
    inv_id, br = await _seed_investigation(team_id, target_id, active=3)
    oc = await _seed_outcome(inv_id, br[0])

    items = await _list(inv_id, team_id)

    summary = items[oc]
    assert summary.approve_count == 0
    assert summary.reject_count == 0
    assert summary.request_edit_count == 0
    assert summary.abstain_count == 0
    assert summary.quorum_k == 2


async def test_vr_outcome_list_empty_investigation_returns_no_outcomes(test_db) -> None:
    team_id, target_id = await _seed_team()
    inv_id, _br = await _seed_investigation(team_id, target_id, active=2)

    items = await _list(inv_id, team_id)

    assert items == {}


async def test_vr_outcome_list_reflects_review_inserted_after_first_read(test_db) -> None:
    team_id, target_id = await _seed_team()
    inv_id, br = await _seed_investigation(team_id, target_id, active=3)
    oc = await _seed_outcome(inv_id, br[0])

    first = await _list(inv_id, team_id)
    assert first[oc].approve_count == 0
    assert first[oc].quorum_k == 2

    await _seed_review(oc, br[1], "approve")

    second = await _list(inv_id, team_id)
    assert second[oc].approve_count == 1
    assert second[oc].quorum_k == 2


async def test_vr_outcome_list_issues_one_grouped_review_query(test_db) -> None:
    team_id, target_id = await _seed_team()
    inv_id, br = await _seed_investigation(team_id, target_id, active=6)
    outcome_ids = [await _seed_outcome(inv_id, br[i]) for i in range(3)]
    for oid in outcome_ids:
        await _seed_review(oid, br[5], "approve")

    captured: list[str] = []

    def _capture(_conn, _cursor, statement, _params, _context, _executemany):
        captured.append(statement)

    # Listen on the Engine class, not one instance: the cached session
    # factory may be bound to a different engine than ``get_async_engine()``
    # returns once another test file has run in the same process.
    event.listen(Engine, "before_cursor_execute", _capture)
    try:
        items = await _list(inv_id, team_id)
    finally:
        event.remove(Engine, "before_cursor_execute", _capture)

    assert set(items) == set(outcome_ids)
    review_selects = [
        s for s in captured
        if "vr_outcome_reviews" in s and s.lstrip().upper().startswith("SELECT")
    ]
    assert len(review_selects) == 1

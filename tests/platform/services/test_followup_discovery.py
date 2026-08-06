"""Unit tests for ``aila.platform.services.followup_discovery`` -- the
autonomous take-over primitive that spawns follow-up-discovery children
at final verdict when the panel's polarity is negative and the panel
recommended further work.

The tests exercise the primitive with FAKE record models + a FAKE
UnitOfWork so no live DB, no live ARQ queue, and no VR / malware code
is required. Every guard the operator locked in gets one green + one
red path:

* Spawns on ``no_finding`` + non-empty recommendations.
* Spawns on ``inconclusive`` + non-empty recommendations.
* Skips ``finding`` (confirmed) polarity -- takes the module's
  confirmed-finding path instead.
* Skips empty / missing recommendations.
* Skips at the depth cap (parent stamped ``[followup-depth=5]``
  cannot produce a depth-6 child under ``max_depth=5``).
* Skips when the halved child budget falls below the floor.
* Idempotent: a second call after a spawn returns ``already_spawned``
  and never spawns a duplicate.
* Child row shape: parent_investigation_id link, ``kind=discovery``,
  halved budget, ``[followup-depth=1]`` marker in initial_question,
  status CREATED, strategy_family carried, mandate + recommendations
  in the body.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import pytest
from sqlmodel import Field, SQLModel

from aila.platform.contracts.enums import BranchStatus, InvestigationStatus
from aila.platform.services.followup_discovery import (
    DEFAULT_MAX_DEPTH,
    maybe_spawn_followup_discovery,
)


# --------------------------------------------------------------------------- #
#  FAKE ORM record models (SQLModel tables so ``sqlmodel.select(...)`` picks   #
#  them up as ORM entities -- no real DB is ever bound; the fake session       #
#  ignores the built statement and returns queued rows).                       #
# --------------------------------------------------------------------------- #


class _FakeInvestigation(SQLModel, table=True):
    """Stand-in for a module's investigation record.

    Carries the exact attribute surface the primitive touches. Uses a
    unique tablename so the SQLModel metadata registry doesn't collide
    with the real vr / malware tables. ``id`` uses a UUID default_factory
    so the primitive's ``investigation_model(**kwargs)`` construction
    (no explicit id passed for the child) yields a populated id
    without touching a DB -- matching the RFC-01 base contract.
    """

    __tablename__ = "_test_followup_investigations"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    target_id: str = Field(default="target-1")
    team_id: str | None = Field(default="team-1")
    parent_investigation_id: str | None = Field(default=None)
    kind: str = Field(default="discovery")
    title: str = Field(default="Parent investigation")
    initial_question: str = Field(default="")
    status: str = Field(default=InvestigationStatus.CREATED.value)
    auto_pilot: bool = Field(default=True)
    strategy_family: str = Field(
        default="vulnerability_research.discovery_research",
    )
    cost_budget_usd: float = Field(default=50.0)
    primary_outcome_id: str | None = Field(default=None)


class _FakeBranch(SQLModel, table=True):
    """Stand-in for a module's branch record."""

    __tablename__ = "_test_followup_branches"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(default="")
    status: str = Field(default=BranchStatus.ACTIVE.value)
    fork_reason: str = Field(default="")


class _FakeOutcome(SQLModel, table=True):
    """Stand-in for a module's outcome record."""

    __tablename__ = "_test_followup_outcomes"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(default="")
    outcome_kind: str = Field(default="audit_memo")
    payload_json: str = Field(default="{}")


# --------------------------------------------------------------------------- #
#  FAKE session + UoW (queue-driven; no SQL).                                  #
# --------------------------------------------------------------------------- #


@dataclass
class _FakeSession:
    """SQLAlchemy session stand-in.

    ``exec`` returns an object with ``.first()`` popping from
    ``exec_returns``. The primitive issues at most 3 selects per
    invocation, in this order: investigation -> outcome ->
    idempotency-probe. Tests seed ``exec_returns`` accordingly.
    ``add`` / ``flush`` / ``commit`` are recorded so tests can assert
    the child row + branch row got persisted.
    """

    exec_returns: list[Any] = field(default_factory=list)
    added: list[Any] = field(default_factory=list)
    flushed: int = 0
    exec_calls: int = 0

    async def exec(self, _stmt: Any) -> Any:
        self.exec_calls += 1
        row = self.exec_returns.pop(0) if self.exec_returns else None

        class _Scalar:
            def __init__(self, r: Any) -> None:
                self._r = r

            def first(self) -> Any:
                return self._r

        return _Scalar(row)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushed += 1


class _FakeUoW:
    """Async-context stand-in for ``UnitOfWork``.

    One test scenario == one UoW == one shared ``_FakeSession`` so the
    single ``async with`` block inside the primitive sees consistent
    state, and the test can inspect what was added after the block
    exits.
    """

    def __init__(self, session: _FakeSession) -> None:
        self.session = session
        self.committed = False

    async def __aenter__(self) -> _FakeUoW:
        return self

    async def __aexit__(self, *_args: Any) -> bool:
        return False

    async def commit(self) -> None:
        self.committed = True


# --------------------------------------------------------------------------- #
#  Fake enqueue + polarity + extractor closures.                               #
# --------------------------------------------------------------------------- #


class _EnqueueRecorder:
    """Record every enqueue call so the tests can assert the child got
    submitted with the expected (child_id, team_id) pair.
    """

    def __init__(self, raises: BaseException | None = None) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self._raises = raises

    async def __call__(self, child_id: str, team_id: str | None) -> str:
        self.calls.append((child_id, team_id))
        if self._raises is not None:
            raise self._raises
        return "task-handle"


def _polarity_no_finding(kind: str, _payload: dict[str, Any]) -> str | None:
    """Test polarity fn: everything is ``no_finding`` except the empty kind."""
    return None if not kind else "no_finding"


def _polarity_inconclusive(_kind: str, _payload: dict[str, Any]) -> str | None:
    return "inconclusive"


def _polarity_finding(_kind: str, _payload: dict[str, Any]) -> str | None:
    return "finding"


def _extract_from_payload(payload: dict[str, Any]) -> list[str]:
    """Test extractor reading the same shape the VR binding reads."""
    ps = payload.get("panel_summary") or {}
    return list(ps.get("recommended_next_actions") or [])


# --------------------------------------------------------------------------- #
#  Test scaffolding.                                                           #
# --------------------------------------------------------------------------- #


def _prime(
    *,
    inv: _FakeInvestigation | None,
    outcome: _FakeOutcome | None,
    existing_child: _FakeInvestigation | None = None,
) -> tuple[_FakeSession, _FakeUoW]:
    """Seed a fake session with the 3-select answer sequence the primitive expects."""
    session = _FakeSession(
        exec_returns=[inv, outcome, existing_child],
    )
    return session, _FakeUoW(session)


def _default_kwargs(
    session_uow: _FakeUoW,
    *,
    derive_polarity: Any = _polarity_no_finding,
    enqueue: _EnqueueRecorder | None = None,
    extract: Any = _extract_from_payload,
    **overrides: Any,
) -> dict[str, Any]:
    """Build the full kwargs dict for the primitive under test."""
    kwargs: dict[str, Any] = {
        "investigation_model": _FakeInvestigation,
        "branch_model": _FakeBranch,
        "outcome_model": _FakeOutcome,
        "discovery_kind": "discovery",
        "strategy_family": "vulnerability_research.discovery_research",
        "derive_polarity": derive_polarity,
        "extract_recommendations": extract,
        "enqueue_investigate": enqueue or _EnqueueRecorder(),
        "uow_factory": lambda: session_uow,
    }
    kwargs.update(overrides)
    return kwargs


# --------------------------------------------------------------------------- #
#  Green paths.                                                                #
# --------------------------------------------------------------------------- #


class TestSpawnsOnNegativePolarity:
    """Both ``no_finding`` and ``inconclusive`` polarities trigger a child."""

    @pytest.mark.asyncio
    async def test_spawns_on_no_finding_with_recommendations(self) -> None:
        payload = (
            '{"panel_summary": {'
            '  "recommended_next_actions": ["Audit parser.c:120 bounds check",'
            '                               "Re-run fuzzer with larger corpus"]'
            "}}"
        )
        outcome = _FakeOutcome(payload_json=payload)
        inv = _FakeInvestigation(
            id="inv-parent",
            primary_outcome_id=outcome.id,
            cost_budget_usd=40.0,
        )
        session, uow = _prime(inv=inv, outcome=outcome)
        enq = _EnqueueRecorder()

        result = await maybe_spawn_followup_discovery(
            inv.id, **_default_kwargs(uow, enqueue=enq),
        )

        assert result["status"] == "spawned"
        assert result["depth"] == 1
        assert result["budget"] == pytest.approx(20.0)
        assert result["recommendations"] == 2
        assert result["polarity"] == "no_finding"
        # Child row + branch row were added AND commit fired.
        assert len(session.added) == 2
        assert uow.committed is True
        # Enqueue was called exactly once with the child id + team id.
        assert enq.calls == [(session.added[0].id, "team-1")]

    @pytest.mark.asyncio
    async def test_spawns_on_inconclusive_with_recommendations(self) -> None:
        payload = (
            '{"panel_summary": {'
            '  "recommended_next_actions": ["Manually review renderer/*.c"]'
            "}}"
        )
        outcome = _FakeOutcome(payload_json=payload, outcome_kind="assessment_report")
        inv = _FakeInvestigation(
            id="inv-inc",
            primary_outcome_id=outcome.id,
            cost_budget_usd=30.0,
        )
        session, uow = _prime(inv=inv, outcome=outcome)

        result = await maybe_spawn_followup_discovery(
            inv.id,
            **_default_kwargs(uow, derive_polarity=_polarity_inconclusive),
        )

        assert result["status"] == "spawned"
        assert result["polarity"] == "inconclusive"
        assert result["depth"] == 1
        assert result["budget"] == pytest.approx(15.0)


class TestChildRowShape:
    """The persisted child row carries every field the operator locked in."""

    @pytest.mark.asyncio
    async def test_child_row_carries_parent_link_kind_budget_and_marker(
        self,
    ) -> None:
        payload = (
            '{"panel_summary": {'
            '  "recommended_next_actions": ["Audit shader.c reflection path"]'
            "}}"
        )
        outcome = _FakeOutcome(payload_json=payload)
        inv = _FakeInvestigation(
            id="parent-xyz",
            target_id="tgt-9",
            team_id="team-42",
            title="WebAssembly boundary audit",
            primary_outcome_id=outcome.id,
            cost_budget_usd=80.0,
            auto_pilot=True,
        )
        session, uow = _prime(inv=inv, outcome=outcome)

        result = await maybe_spawn_followup_discovery(
            inv.id, **_default_kwargs(uow),
        )

        assert result["status"] == "spawned"
        # First add is the child investigation, second is its primary branch.
        child = session.added[0]
        branch = session.added[1]
        assert isinstance(child, _FakeInvestigation)
        assert isinstance(branch, _FakeBranch)
        # Parent link
        assert child.parent_investigation_id == "parent-xyz"
        # kind + strategy_family from the discovery-mode inputs
        assert child.kind == "discovery"
        assert child.strategy_family == "vulnerability_research.discovery_research"
        # Halved budget
        assert child.cost_budget_usd == pytest.approx(40.0)
        # Team + target inherited from parent
        assert child.team_id == "team-42"
        assert child.target_id == "tgt-9"
        # Auto-pilot inherited
        assert child.auto_pilot is True
        # Status = CREATED
        assert child.status == InvestigationStatus.CREATED.value
        # Depth marker + mandate + recommendations in the body
        assert child.initial_question.startswith("[followup-depth=1]")
        assert "parent-xyz" in child.initial_question
        assert "no_finding" in child.initial_question
        assert "- Audit shader.c reflection path" in child.initial_question
        # Title carries the parent title
        assert child.title.startswith("Follow-up discovery: ")
        # Primary branch bound to child + active + fork_reason primary
        assert branch.investigation_id == child.id
        assert branch.status == BranchStatus.ACTIVE.value
        assert branch.fork_reason == "primary"


# --------------------------------------------------------------------------- #
#  Skip paths.                                                                 #
# --------------------------------------------------------------------------- #


class TestSkipsWhenNotEligible:
    """Every guard the operator wired in has one skip path."""

    @pytest.mark.asyncio
    async def test_skips_when_investigation_is_missing(self) -> None:
        session, uow = _prime(inv=None, outcome=None)
        result = await maybe_spawn_followup_discovery(
            "missing", **_default_kwargs(uow),
        )
        assert result == {"status": "skipped", "reason": "investigation_not_found"}
        assert session.added == []

    @pytest.mark.asyncio
    async def test_skips_when_no_primary_outcome(self) -> None:
        inv = _FakeInvestigation(primary_outcome_id=None)
        session, uow = _prime(inv=inv, outcome=None)
        result = await maybe_spawn_followup_discovery(
            inv.id, **_default_kwargs(uow),
        )
        assert result == {"status": "skipped", "reason": "no_primary_outcome"}
        assert session.added == []

    @pytest.mark.asyncio
    async def test_skips_on_finding_polarity(self) -> None:
        outcome = _FakeOutcome(
            outcome_kind="direct_finding",
            payload_json='{"panel_summary": {"recommended_next_actions": ["x"]}}',
        )
        inv = _FakeInvestigation(primary_outcome_id=outcome.id)
        session, uow = _prime(inv=inv, outcome=outcome)
        result = await maybe_spawn_followup_discovery(
            inv.id,
            **_default_kwargs(uow, derive_polarity=_polarity_finding),
        )
        assert result["status"] == "skipped"
        assert result["reason"] == "polarity_not_terminal_negative"
        assert result["polarity"] == "finding"
        assert session.added == []

    @pytest.mark.asyncio
    async def test_skips_when_recommendations_are_empty(self) -> None:
        outcome = _FakeOutcome(payload_json='{"panel_summary": {}}')
        inv = _FakeInvestigation(primary_outcome_id=outcome.id)
        session, uow = _prime(inv=inv, outcome=outcome)
        result = await maybe_spawn_followup_discovery(
            inv.id, **_default_kwargs(uow),
        )
        assert result == {"status": "skipped", "reason": "no_recommendations"}
        assert session.added == []

    @pytest.mark.asyncio
    async def test_skips_at_depth_cap(self) -> None:
        payload = (
            '{"panel_summary": {'
            '  "recommended_next_actions": ["deeper still"]'
            "}}"
        )
        outcome = _FakeOutcome(payload_json=payload)
        # Parent already at MAX_DEPTH -- child would be MAX_DEPTH+1 = 6.
        parent_q = f"[followup-depth={DEFAULT_MAX_DEPTH}] some prior mandate"
        inv = _FakeInvestigation(
            primary_outcome_id=outcome.id,
            initial_question=parent_q,
        )
        session, uow = _prime(inv=inv, outcome=outcome)
        result = await maybe_spawn_followup_discovery(
            inv.id, **_default_kwargs(uow),
        )
        assert result["status"] == "skipped"
        assert result["reason"] == "followup_depth_exceeded"
        assert result["depth"] == DEFAULT_MAX_DEPTH
        assert result["max_depth"] == DEFAULT_MAX_DEPTH
        assert session.added == []

    @pytest.mark.asyncio
    async def test_skips_when_halved_budget_falls_below_floor(self) -> None:
        payload = (
            '{"panel_summary": {'
            '  "recommended_next_actions": ["do something"]'
            "}}"
        )
        outcome = _FakeOutcome(payload_json=payload)
        # Parent budget $8 -> halved = $4, below the $5 floor.
        inv = _FakeInvestigation(
            primary_outcome_id=outcome.id,
            cost_budget_usd=8.0,
        )
        session, uow = _prime(inv=inv, outcome=outcome)
        result = await maybe_spawn_followup_discovery(
            inv.id, **_default_kwargs(uow),
        )
        assert result["status"] == "skipped"
        assert result["reason"] == "followup_budget_below_floor"
        assert result["budget"] == pytest.approx(4.0)
        assert session.added == []


# --------------------------------------------------------------------------- #
#  Idempotency.                                                                #
# --------------------------------------------------------------------------- #


class TestIdempotency:
    """A second invocation for the same parent MUST NOT spawn a duplicate."""

    @pytest.mark.asyncio
    async def test_second_call_returns_already_spawned(self) -> None:
        payload = (
            '{"panel_summary": {'
            '  "recommended_next_actions": ["once"]'
            "}}"
        )
        outcome = _FakeOutcome(payload_json=payload)
        inv = _FakeInvestigation(primary_outcome_id=outcome.id)
        existing_child = _FakeInvestigation(
            id="child-already",
            parent_investigation_id=inv.id,
            initial_question="[followup-depth=1] prior mandate",
        )
        # First two selects: inv + outcome; third select: idempotency probe
        # returns an already-persisted child.
        session = _FakeSession(exec_returns=[inv, outcome, existing_child])
        uow = _FakeUoW(session)
        enq = _EnqueueRecorder()

        result = await maybe_spawn_followup_discovery(
            inv.id, **_default_kwargs(uow, enqueue=enq),
        )

        assert result == {
            "status": "skipped",
            "reason": "already_spawned",
            "child_id": "child-already",
        }
        # No new row was added, nothing was enqueued.
        assert session.added == []
        assert enq.calls == []


# --------------------------------------------------------------------------- #
#  Enqueue failure isolation.                                                  #
# --------------------------------------------------------------------------- #


class TestEnqueueFailureIsolated:
    """A queue transport blip MUST NOT roll back the committed child row."""

    @pytest.mark.asyncio
    async def test_enqueue_failure_returns_spawned_with_error_note(self) -> None:
        payload = (
            '{"panel_summary": {'
            '  "recommended_next_actions": ["queue this later"]'
            "}}"
        )
        outcome = _FakeOutcome(payload_json=payload)
        inv = _FakeInvestigation(primary_outcome_id=outcome.id)
        session, uow = _prime(inv=inv, outcome=outcome)
        enq = _EnqueueRecorder(raises=OSError("redis down"))

        result = await maybe_spawn_followup_discovery(
            inv.id, **_default_kwargs(uow, enqueue=enq),
        )

        # Spawn is still recorded as success -- an operator re-enqueue
        # can drive the row from CREATED.
        assert result["status"] == "spawned"
        assert result["enqueue_error"] is not None
        assert "OSError" in result["enqueue_error"]
        # Child + branch were still committed.
        assert len(session.added) == 2
        assert uow.committed is True

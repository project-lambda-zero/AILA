"""Regression tests for issues #177 + #202.

Covers the lock-order + FOR UPDATE additions in the reaper /
finalizer / eval-promotion layer. The four target files after the
fix:

* ``platform/services/investigation_reaper.py``
  :func:`_flip_branches_and_inv_to_completed` -- locks the
  investigation row BEFORE any branch write (issue #177 lock-order
  standardization: platform-wide invariant is investigation-first).
* ``platform/services/investigation_finalizers.py``
  :func:`close_rejected_outcomes` -- SELECT FOR UPDATE on the
  target investigation with a ``status == RUNNING`` guard;
  :func:`_synthesize_one_no_finding` -- same lock + guard, plus
  ``ON CONFLICT (id) DO NOTHING`` on the outcome INSERT and
  per-inv savepoint isolation via ``session.begin_nested()``.
* ``platform/eval/calibrator.py`` :func:`promote_calibrator` --
  FOR UPDATE on both the candidate row and the currently active
  row for the same task_type.
* ``platform/eval/calibration.py`` :meth:`CalibrationProposer.persist`
  -- FOR UPDATE on the active-proposal rows for the outcome_kind
  before superseding.

Approach: two-track. Structural tests inspect the compiled SQL a
mocked session receives and assert ``FOR UPDATE`` is present in
the right statement AND that (for the reaper) the lock is issued
BEFORE the branch UPDATE. Where the target uses
``async_session_scope`` (calibrator + calibration proposer) we
patch the scope with a fake async-session that captures the
compiled statement text. These tests prove the query now carries
FOR UPDATE and (for the reaper + close_rejected) that the lock
statement precedes the write -- they do NOT reproduce the race
under contention because a deterministic multi-connection race
needs a live Postgres, which the unit-test tier does not have.
Contention is exercised by the live-worker path after restart.
"""
from __future__ import annotations

import contextlib
import inspect
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import Select, Update

from aila.modules.vr.db_models.branch import VRInvestigationBranchRecord
from aila.modules.vr.db_models.investigation import VRInvestigationRecord
from aila.modules.vr.db_models.outcome import VRInvestigationOutcomeRecord
from aila.modules.vr.db_models.outcome_review import (
    VRInvestigationOutcomeReviewRecord,
)
from aila.platform.contracts import utc_now
from aila.platform.eval import calibration as calibration_mod
from aila.platform.eval import calibrator as calibrator_mod
from aila.platform.services import investigation_finalizers
from aila.platform.services.investigation_finalizers import (
    _synthesize_one_no_finding,
    close_rejected_outcomes,
)
from aila.platform.services.investigation_reaper import (
    _flip_branches_and_inv_to_completed,
)


def _compile(stmt: Any) -> str:
    """Compile a SQLAlchemy statement for the Postgres dialect."""
    if hasattr(stmt, "compile"):
        return str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": False},
            ),
        )
    return str(stmt)


class _RecordingSession:
    """Async-session shim that records every ``.exec()`` argument.

    Returns a fake result object whose ``.first()``/``.all()`` yield
    ``None`` and ``[]`` respectively, so the callers exit their
    per-inv loops immediately after the first read. That is enough
    to observe the SELECT ... FOR UPDATE was issued.
    """

    def __init__(self, first_returns: list[Any] | None = None) -> None:
        self.executed: list[Any] = []
        self._firsts = list(first_returns or [])

    async def exec(self, stmt: Any, **_kw: Any) -> Any:  # noqa: A003
        self.executed.append(stmt)
        return _RecordingResult(
            first=self._firsts.pop(0) if self._firsts else None,
        )

    async def execute(self, stmt: Any, **_kw: Any) -> Any:
        return await self.exec(stmt, **_kw)

    def add(self, _row: Any) -> None:
        return None

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None

    async def refresh(self, _row: Any) -> None:
        return None

    def begin_nested(self) -> Any:
        # Return an async CM that is a no-op so
        # ``async with session.begin_nested():`` succeeds without a
        # real transaction.
        @contextlib.asynccontextmanager
        async def _noop() -> Any:
            yield None
        return _noop()


class _RecordingResult:
    def __init__(self, first: Any = None, all_: list[Any] | None = None) -> None:
        self._first = first
        self._all = list(all_ or [])

    def first(self) -> Any:
        return self._first

    def all(self) -> list[Any]:
        return list(self._all)

    def mappings(self) -> Any:
        return self


class _FakeUoW:
    def __init__(self, session: _RecordingSession) -> None:
        self.session = session

    async def commit(self) -> None:
        return None


# ─────────────────────────────────────────────────────────────────
# Issue #177: reaper cascade locks investigation before branches
# ─────────────────────────────────────────────────────────────────


class TestReaperLockOrder:
    """Investigation-first lock order in
    ``_flip_branches_and_inv_to_completed``."""

    @pytest.mark.asyncio
    async def test_investigation_locked_before_branch_update(self) -> None:

        session = _RecordingSession()
        uow = _FakeUoW(session)
        await _flip_branches_and_inv_to_completed(
            uow,  # type: ignore[arg-type]
            "inv-xyz",
            "test_reason",
            utc_now(),
            branch_model=VRInvestigationBranchRecord,
            investigation_model=VRInvestigationRecord,
        )

        assert len(session.executed) == 3, (
            "expected exactly 3 statements: SELECT FOR UPDATE (inv), "
            "UPDATE branches, UPDATE inv"
        )
        first_sql = _compile(session.executed[0])
        assert "FOR UPDATE" in first_sql.upper(), (
            f"first statement must be SELECT ... FOR UPDATE; got: {first_sql!r}"
        )
        assert "vr_investigations" in first_sql, (
            "first lock must target the investigation table"
        )
        # The order matters: branch UPDATE MUST come after the inv
        # lock, otherwise the deadlock #177 flags is back.
        second = session.executed[1]
        assert isinstance(second, Update), (
            "second statement should be the branch UPDATE"
        )
        assert "vr_investigation_branches" in _compile(second)
        third = session.executed[2]
        assert isinstance(third, Update), (
            "third statement should be the guarded inv UPDATE"
        )
        third_sql = _compile(third)
        assert "vr_investigations" in third_sql
        # Guard still present (RUNNING check on the inv UPDATE).
        assert "status" in third_sql.lower()

    def test_docstring_names_the_invariant(self) -> None:
        # A drive-by revert that drops the SELECT FOR UPDATE but
        # keeps the docstring would still pass the compile test
        # above (because the docstring shows the invariant only,
        # not the enforcement). Pin the invariant text so a
        # careless doc change surfaces here too.

        doc = _flip_branches_and_inv_to_completed.__doc__ or ""
        assert "#177" in doc, "docstring must cite issue #177"
        assert "investigation" in doc.lower() and "first" in doc.lower(), (
            "docstring must state the investigation-first invariant"
        )


# ─────────────────────────────────────────────────────────────────
# Issue #202: close_rejected_outcomes locks + guards the inv row
# ─────────────────────────────────────────────────────────────────


class TestCloseRejectedOutcomes:
    """close_rejected_outcomes issues SELECT FOR UPDATE with
    ``status == RUNNING`` guard on the target investigation."""

    @pytest.mark.asyncio
    async def test_target_inv_select_carries_for_update(self) -> None:

        # Present one candidate row: (inv_id, outcome_id, proposer)
        candidate = ("inv-A", "out-1", "br-proposer")
        # After the candidate scan the code reads voters, then
        # active branches, then acquires the FOR UPDATE lock on the
        # target inv row. Return empty lists / None for those so
        # the loop reaches the lock statement.
        session = _RecordingSession()
        # Custom exec that returns the shape each call expects.
        call_seq = iter([
            _RecordingResult(all_=[candidate]),   # candidate scan
            _RecordingResult(all_=[]),            # voter_rows
            _RecordingResult(all_=[]),            # active_rows
            # target_inv SELECT (this is the lock we care about).
            _RecordingResult(first=None),
        ])

        async def _exec(stmt: Any, **_kw: Any) -> Any:
            session.executed.append(stmt)
            try:
                return next(call_seq)
            except StopIteration:
                return _RecordingResult()

        session.exec = _exec  # type: ignore[assignment]
        uow = _FakeUoW(session)

        result = await close_rejected_outcomes(
            uow,  # type: ignore[arg-type]
            investigation_model=VRInvestigationRecord,
            branch_model=VRInvestigationBranchRecord,
            outcome_model=VRInvestigationOutcomeRecord,
            outcome_review_model=VRInvestigationOutcomeReviewRecord,
            only_id="inv-A",
        )
        assert result == 0, (
            "concurrent-terminal-flip guard: when the FOR UPDATE "
            "read returns no row (already terminal), close count = 0"
        )
        # The 4th statement is the target_inv lock.
        assert len(session.executed) >= 4
        lock_sql = _compile(session.executed[3])
        assert "FOR UPDATE" in lock_sql.upper(), (
            f"target inv select must carry FOR UPDATE; got: {lock_sql!r}"
        )
        assert "vr_investigations" in lock_sql
        assert "status" in lock_sql.lower(), (
            "target inv select must guard on status (RUNNING)"
        )


# ─────────────────────────────────────────────────────────────────
# Issue #202: synthesize_no_finding -- per-inv savepoint + inv lock
# ─────────────────────────────────────────────────────────────────


class TestSynthesizeNoFinding:
    """Per-inv work is savepoint-isolated and locks the inv row
    before the outcome INSERT + UPDATE cascade."""

    @pytest.mark.asyncio
    async def test_per_inv_savepoint_wraps_synthesis(self) -> None:
        # Assert the outer loop opens a savepoint per inv id. We
        # observe this by having ``begin_nested`` record its calls.
        session = _RecordingSession()
        savepoint_calls: list[int] = []
        real_begin = session.begin_nested

        def _tracked_begin_nested() -> Any:
            savepoint_calls.append(1)
            return real_begin()

        session.begin_nested = _tracked_begin_nested  # type: ignore[assignment]
        uow = _FakeUoW(session)

        # Two orphan inv ids in the batch. Rig the exec sequence:
        #   [0] candidate_stmt -> two rows, each terminal.
        # The two rows have (id, branch_count=1, terminal_count=1).
        call_seq = iter([
            _RecordingResult(all_=[
                ("inv-A", 1, 1),
                ("inv-B", 1, 1),
            ]),
        ])

        async def _exec(stmt: Any, **_kw: Any) -> Any:
            session.executed.append(stmt)
            try:
                return next(call_seq)
            except StopIteration:
                # Every subsequent read (per-inv lock select, etc.)
                # returns None so ``_synthesize_one_no_finding``
                # exits without doing writes. We only care that the
                # savepoint was opened per iteration.
                return _RecordingResult(first=None, all_=[])

        session.exec = _exec  # type: ignore[assignment]

        # ``is_llm_recently_unhealthy`` -> False so the outer guard
        # does not short-circuit the tick.
        monkey = MagicMock(return_value=False)
        original = investigation_finalizers.is_llm_recently_unhealthy
        investigation_finalizers.is_llm_recently_unhealthy = monkey
        try:
            await investigation_finalizers.synthesize_no_finding_outcomes(
                uow,  # type: ignore[arg-type]
                investigation_model=VRInvestigationRecord,
                branch_model=VRInvestigationBranchRecord,
                branch_table="vr_investigation_branches",
                outcome_table="vr_investigation_outcomes",
                no_finding_outcome_kind="audit_memo",
                build_no_finding_payload=lambda **_kw: {"stub": True},
            )
        finally:
            investigation_finalizers.is_llm_recently_unhealthy = original

        assert len(savepoint_calls) == 2, (
            "each per-inv iteration must open its own savepoint via "
            "session.begin_nested() so a single failing row cannot "
            f"roll back the batch; observed: {len(savepoint_calls)}"
        )

    @pytest.mark.asyncio
    async def test_inv_lock_precedes_writes(self) -> None:

        session = _RecordingSession()
        # Return None for the FOR UPDATE lock select so the function
        # exits at "concurrent writer beat us to it".
        call_seq = iter([_RecordingResult(first=None)])

        async def _exec(stmt: Any, **_kw: Any) -> Any:
            session.executed.append(stmt)
            try:
                return next(call_seq)
            except StopIteration:
                return _RecordingResult()

        session.exec = _exec  # type: ignore[assignment]
        uow = _FakeUoW(session)

        now = utc_now()
        ok = await _synthesize_one_no_finding(
            uow,  # type: ignore[arg-type]
            inv_id="inv-A",
            investigation_model=VRInvestigationRecord,
            branch_model=VRInvestigationBranchRecord,
            branch_table="vr_investigation_branches",
            outcome_table="vr_investigation_outcomes",
            no_finding_outcome_kind="audit_memo",
            build_no_finding_payload=lambda **_kw: {"stub": True},
            now=now,
            now_iso=now.isoformat(),
        )
        assert ok is False, (
            "when the FOR UPDATE read returns no row (already terminal), "
            "the per-inv path must be a no-op"
        )
        assert len(session.executed) == 1, (
            "the very first statement must be the SELECT ... FOR UPDATE; "
            "no writes are permitted before the lock"
        )
        lock_sql = _compile(session.executed[0])
        assert "FOR UPDATE" in lock_sql.upper(), (
            f"first statement in _synthesize_one_no_finding must be "
            f"SELECT ... FOR UPDATE on the investigation row; got: {lock_sql!r}"
        )
        assert "vr_investigations" in lock_sql
        assert "status" in lock_sql.lower(), (
            "the lock statement must carry the status = RUNNING guard"
        )

    def test_outcome_insert_uses_on_conflict_do_nothing(self) -> None:
        # The outcome INSERT is a raw SQL literal. Structural check
        # on the source text guarantees the ON CONFLICT clause is
        # present -- a revert would fail this assertion.


        src = inspect.getsource(_synthesize_one_no_finding)
        assert "ON CONFLICT (id) DO NOTHING" in src, (
            "outcome INSERT must be idempotent via ON CONFLICT DO NOTHING "
            "so a duplicate id from a concurrent per-id finalize cannot "
            "raise IntegrityError inside the batch's savepoint"
        )


# ─────────────────────────────────────────────────────────────────
# Issue #202: promote_calibrator locks candidate + active rows
# ─────────────────────────────────────────────────────────────────


class TestPromoteCalibratorLocks:
    """Both selects in ``promote_calibrator`` must carry FOR UPDATE."""

    @pytest.mark.asyncio
    async def test_candidate_and_active_selects_are_locked(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Fake candidate row so the function progresses past the
        # first FOR UPDATE and issues the second one on the active
        # row for the same task_type.
        candidate_row = types.SimpleNamespace(
            id="cand-1",
            task_type="vr.hypothesis",
            status=calibrator_mod.CALIBRATOR_STATUS_CANDIDATE,
            ece_after=0.05,
            actor="tester",
        )
        active_row = types.SimpleNamespace(
            id="active-1",
            task_type="vr.hypothesis",
            status=calibrator_mod.CALIBRATOR_STATUS_ACTIVE,
            ece_after=0.10,
            actor="prev",
            superseded_by=None,
        )
        # Two rows to return in order: first exec -> candidate,
        # second exec -> active.
        session = _RecordingSession(first_returns=[candidate_row, active_row])

        @contextlib.asynccontextmanager
        async def _fake_scope() -> Any:
            yield session

        monkeypatch.setattr(
            calibrator_mod, "async_session_scope", _fake_scope,
        )
        # Quorum resolver -> 0 so the quorum gate always clears.
        monkeypatch.setattr(
            calibrator_mod, "_resolve_promotion_quorum",
            AsyncMock(return_value=0),
        )

        result = await calibrator_mod.promote_calibrator(
            "cand-1", actor="tester", quorum_approver_ids=[],
        )
        assert result is candidate_row

        assert len(session.executed) >= 2
        cand_sql = _compile(session.executed[0])
        active_sql = _compile(session.executed[1])
        assert "FOR UPDATE" in cand_sql.upper(), (
            "candidate SELECT must carry FOR UPDATE; got: "
            f"{cand_sql!r}"
        )
        assert "FOR UPDATE" in active_sql.upper(), (
            "active SELECT (same task_type) must carry FOR UPDATE; got: "
            f"{active_sql!r}"
        )


# ─────────────────────────────────────────────────────────────────
# Issue #202: CalibrationProposer.persist locks active rows
# ─────────────────────────────────────────────────────────────────


class TestCalibrationProposerPersistLock:
    """persist() locks the active-proposal row set for the
    outcome_kind before writing the SUPERSEDED + new ACTIVE rows."""

    @pytest.mark.asyncio
    async def test_active_stmt_carries_for_update(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        session = _RecordingSession()

        @contextlib.asynccontextmanager
        async def _fake_scope() -> Any:
            yield session

        monkeypatch.setattr(
            calibration_mod, "async_session_scope", _fake_scope,
        )

        async def _current(_kind: str) -> float:
            return 0.5

        proposer = calibration_mod.CalibrationProposer(
            _current,
            min_evidence=5,
            margin=0.05,
        )
        proposal = calibration_mod.CalibrationProposal(
            outcome_kind="vr.hypothesis",
            before_threshold=0.5,
            after_threshold=0.55,
            approve_count=1,
            reject_count=0,
            mean_confidence_reject=None,
            mean_confidence_approve=0.9,
            reasoning="test",
            evidence=[],
        )
        new_id = await proposer.persist(proposal, actor="tester")
        assert isinstance(new_id, str) and new_id

        assert session.executed, "persist must issue at least the active SELECT"
        first = session.executed[0]
        assert isinstance(first, Select), (
            "first statement must be the active-proposal SELECT"
        )
        first_sql = _compile(first)
        assert "FOR UPDATE" in first_sql.upper(), (
            "active-proposal SELECT for the outcome_kind must carry "
            f"FOR UPDATE before superseding; got: {first_sql!r}"
        )
        assert "eval_calibration_proposals" in first_sql

"""Forensics panel emit -- RFC-08 experience recording hook (RFC-12 Phase 4).

Proves the standalone :func:`state_forensics_panel_emit` calls the
:class:`ExperienceWriter` closure on a terminal quorum transition and
that a writer failure never breaks the finalize path. Every DB/service
touch inside the emit body is monkeypatched away so the tests run with
no live Postgres, no embedding, no LLM.

Two acceptance clauses:

* ``test_emit_records_experience_on_approved_quorum`` -- a terminal
  APPROVED quorum triggers ``ExperienceWriter.record`` with
  ``workspace_id`` == the investigation's ``project_id`` (forensics
  binds project as workspace),
  ``pattern_create_cls=ForensicsPatternCreate``, and
  ``pattern_kind=ForensicsPatternKind.TRIAGE_RULE`` -- matching the
  contract every module's RFC-08 module-closure must satisfy.

* ``test_emit_swallows_experience_writer_failure`` -- a raising
  :meth:`ExperienceWriter.record` is logged + swallowed; the emit
  state returns cleanly and the finalized investigation status the
  primary-branch path derived still propagates on the output payload.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.modules.forensics.contracts.pattern import (
    ForensicsPatternCreate,
    ForensicsPatternKind,
)
from aila.modules.forensics.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    QuorumOutcome,
)
from aila.modules.forensics.workflow.panel import emit as panel_emit
from aila.platform.workflows.types import RESERVED_SUCCEEDED

# ---------------------------------------------------------------------------
# Fakes for the ExperienceWriter dependency graph.
#
# Mocking at the emit-module level (``panel_emit.ExperienceWriter`` etc.)
# rather than at the platform level keeps the substitution narrow: only
# the symbols the emit body dereferences are replaced. The record kwargs
# are captured on the instance so the test can assert every field the
# forensics binding contract requires (workspace_id, pattern_create_cls,
# pattern_kind).
# ---------------------------------------------------------------------------


class _FakeExperienceResult:
    """Duck-typed :class:`ExperienceWriteResult` for the logger call.

    The emit closure only reads three attributes off the returned
    result (``pattern_id``, ``polarity``, ``skipped_reason``) so a bag
    of literals is enough here -- no need to construct the real
    dataclass and drag its imports into the test surface.
    """

    pattern_id = "fake-pattern-id"
    polarity = "positive"
    skipped_reason = ""


class _FakeExperienceWriter:
    """Capture constructor + ``record`` kwargs; optional raise on record."""

    instances: list[_FakeExperienceWriter] = []

    def __init__(
        self,
        *,
        pattern_store: Any,
        pattern_create_cls: Any,
        pattern_kind: Any,
    ) -> None:
        self.pattern_store = pattern_store
        self.pattern_create_cls = pattern_create_cls
        self.pattern_kind = pattern_kind
        self.record_calls: list[dict[str, Any]] = []
        # Test can set this to have record() raise -- proves the emit
        # try/except swallows it without breaking finalize.
        self.raise_on_record: Exception | None = None
        type(self).instances.append(self)

    async def record(self, **kwargs: Any) -> _FakeExperienceResult:
        self.record_calls.append(kwargs)
        if self.raise_on_record is not None:
            raise self.raise_on_record
        return _FakeExperienceResult()


class _FakePatternStore:
    """PatternStore stub -- emit never dereferences beyond construction."""

    def __init__(self, *, knowledge: Any) -> None:
        self.knowledge = knowledge


class _FakeServiceFactory:
    """ServiceFactory stub -- only ``.knowledge`` is read by emit."""

    class _Knowledge:
        """Sentinel identity check via ``is`` in assertions."""

    def __init__(self) -> None:
        self.knowledge = self._Knowledge()


class _FakeInvestigation:
    """InvestigationRunRecord stub -- only project_id + team_id are read."""

    def __init__(self, *, project_id: str, team_id: str | None) -> None:
        self.project_id = project_id
        self.team_id = team_id


class _FakeSession:
    """Session stub -- ``exec(stmt).first()`` returns the seeded row."""

    def __init__(self, row: Any) -> None:
        self._row = row

    async def exec(self, _stmt: Any) -> Any:
        row = self._row

        class _Result:
            def first(self) -> Any:
                return row

            def all(self) -> list[Any]:
                return [] if row is None else [row]

        return _Result()


class _FakeUow:
    """UnitOfWork stub -- yields a session over ``exec(...).first() -> row``.

    The record_experience closure only opens one UnitOfWork (loads the
    investigation row). All other DB helpers in emit are patched out
    individually, so this fake never has to satisfy a heterogeneous
    query stream -- one row shape is enough.
    """

    def __init__(self, row: Any) -> None:
        self._row = row

    async def __aenter__(self) -> _FakeUow:
        self.session = _FakeSession(self._row)
        return self

    async def __aexit__(self, *_exc_info: Any) -> bool:
        return False


def _make_uow_factory(row: Any):
    def _factory() -> _FakeUow:
        return _FakeUow(row)

    return _factory


def _approved_verdict(outcome_id: str) -> QuorumOutcome:
    """Build a QuorumOutcome that models an approve-quorum terminal flip."""
    return QuorumOutcome(
        outcome_id=outcome_id,
        new_state=OUTCOME_STATE_APPROVED,
        approve_count=2,
        reject_count=0,
        request_edit_count=0,
        abstain_count=0,
        quorum_k=2,
        siblings_active=2,
        transition_occurred=True,
        transition_reason="approved_2_of_2_required",
    )


def _install_panel_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    outcome_id: str,
    inv: _FakeInvestigation,
    finalized_status: str = "completed",
    payload_json: str = '{"answer": "Suspicious lateral movement at 03:14 UTC"}',
) -> None:
    """Patch every DB helper + ExperienceWriter dep on ``panel_emit``.

    The test drives ``state_forensics_panel_emit`` end to end with no
    live DB; every ``async with UnitOfWork()`` inside the emit body
    routes through :class:`_FakeUow`, and the four DB-lookup helpers
    (``_load_draft_outcome_ids``, ``_is_primary_branch``,
    ``_finalize_investigation_if_ready``, ``_load_outcome_payload``)
    return canned values.
    """
    _FakeExperienceWriter.instances = []

    async def _fake_load_draft_ids(_inv_id: str) -> list[str]:
        return [outcome_id]

    async def _fake_evaluate_quorum(oid: str) -> QuorumOutcome:
        return _approved_verdict(oid)

    async def _fake_is_primary(_bid: str) -> bool:
        return True

    async def _fake_finalize(_inv_id: str) -> str | None:
        return finalized_status

    async def _fake_load_payload(_oid: str) -> str | None:
        return payload_json

    monkeypatch.setattr(panel_emit, "_load_draft_outcome_ids", _fake_load_draft_ids)
    monkeypatch.setattr(panel_emit, "evaluate_quorum", _fake_evaluate_quorum)
    monkeypatch.setattr(panel_emit, "_is_primary_branch", _fake_is_primary)
    monkeypatch.setattr(
        panel_emit, "_finalize_investigation_if_ready", _fake_finalize,
    )
    monkeypatch.setattr(panel_emit, "_load_outcome_payload", _fake_load_payload)
    monkeypatch.setattr(panel_emit, "UnitOfWork", _make_uow_factory(inv))
    monkeypatch.setattr(panel_emit, "PatternStore", _FakePatternStore)
    monkeypatch.setattr(panel_emit, "ServiceFactory", _FakeServiceFactory)
    monkeypatch.setattr(panel_emit, "ExperienceWriter", _FakeExperienceWriter)


async def test_emit_records_experience_on_approved_quorum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Approved terminal quorum wires ``record`` with the forensics contract.

    The forensics module binds ``workspace_id`` to the investigation's
    ``project_id`` (forensics has no target row -- the project IS the
    workspace). The pattern-create shape + pattern-kind identify this
    call as forensics-owned; any other module's writer would carry a
    different pair, and the platform's ExperienceWriter is generic
    over both. Locking these three fields is the acceptance clause for
    the RFC-08 forensics binding.
    """
    outcome_id = "outcome-approved-1"
    inv = _FakeInvestigation(project_id="project-abc", team_id="team-xyz")
    _install_panel_stubs(monkeypatch, outcome_id=outcome_id, inv=inv)

    result = await panel_emit.state_forensics_panel_emit(
        {"investigation_id": "inv-1", "branch_id": "branch-primary"},
        services=None,
    )

    # One writer built, one record() call.
    assert len(_FakeExperienceWriter.instances) == 1
    writer = _FakeExperienceWriter.instances[0]
    assert len(writer.record_calls) == 1

    # Contract: forensics binds the pattern shape + kind on construction.
    assert writer.pattern_create_cls is ForensicsPatternCreate
    assert writer.pattern_kind is ForensicsPatternKind.TRIAGE_RULE
    assert isinstance(writer.pattern_store, _FakePatternStore)
    assert isinstance(writer.pattern_store.knowledge, _FakeServiceFactory._Knowledge)

    # Contract: record() carries the investigation's project_id as
    # workspace_id, the verdict, the outcome id in evidence_refs, and the
    # investigation's team_id for team-scope stamping.
    call = writer.record_calls[0]
    assert call["workspace_id"] == "project-abc"
    assert call["investigation_id"] == "inv-1"
    assert call["team_id"] == "team-xyz"
    assert call["evidence_refs"] == [outcome_id]
    assert call["verdict"].new_state == OUTCOME_STATE_APPROVED
    assert call["verdict"].outcome_id == outcome_id
    assert call["verdict"].transition_occurred is True
    # Summary + body derived from the payload's ``answer`` field via
    # ``summarize_outcome_for_review``; both non-empty so the writer
    # would proceed to a real create() in production.
    assert "Suspicious lateral movement" in call["summary"]
    assert "Suspicious lateral movement" in call["body"]
    assert call["summary"] == call["summary"].strip()

    # State finalization still returned SUCCEEDED with the primary branch's
    # derived status echoed on the output payload.
    assert result.next_state == RESERVED_SUCCEEDED
    assert result.output["quorum_evaluated_outcome_ids"] == [outcome_id]
    assert result.output["investigation_status"] == "completed"


async def test_emit_swallows_experience_writer_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raising ``record`` is logged + swallowed; emit still finalizes.

    The panel emit is standalone (not built on ``investigation_emit_base``)
    so the RFC-08 hook has no built-in safety net -- the module closure
    itself must wrap every store call best-effort. A ``RuntimeError``
    inside :meth:`ExperienceWriter.record` MUST NOT propagate and MUST
    NOT prevent the primary-branch finalize path from returning.
    """
    outcome_id = "outcome-approved-2"
    inv = _FakeInvestigation(project_id="project-abc", team_id="team-xyz")
    _install_panel_stubs(
        monkeypatch,
        outcome_id=outcome_id,
        inv=inv,
        finalized_status="completed",
    )
    # Every writer instance built by the emit body should raise on record.
    original_init = _FakeExperienceWriter.__init__

    def _init_raising(self: _FakeExperienceWriter, **kwargs: Any) -> None:
        original_init(self, **kwargs)
        self.raise_on_record = RuntimeError("simulated pattern-store crash")

    monkeypatch.setattr(_FakeExperienceWriter, "__init__", _init_raising)

    result = await panel_emit.state_forensics_panel_emit(
        {"investigation_id": "inv-2", "branch_id": "branch-primary"},
        services=None,
    )

    # Writer was constructed and record was called -- the failure came
    # from record itself, not from a short-circuit that skipped the call.
    assert len(_FakeExperienceWriter.instances) == 1
    writer = _FakeExperienceWriter.instances[0]
    assert len(writer.record_calls) == 1

    # Emit returned normally; the exception did not propagate.
    assert result.next_state == RESERVED_SUCCEEDED
    assert result.output["quorum_evaluated_outcome_ids"] == [outcome_id]
    # And the primary-branch finalize path still ran (status flipped to
    # completed) even though the record_experience hook raised.
    assert result.output["investigation_status"] == "completed"

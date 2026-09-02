"""Stream B (VR-truth) targeted tests for ClaimVerifierAgentBase.

Covers the two behavioural changes shipped in release 0.5.51:

* B1 -- ``_maybe_auto_promote`` no longer requires the original row's
  ``dispatch_status`` to equal SKIPPED. A verifier-confirmed finding
  above the module's floor promotes regardless of dispatch_status; the
  retained confidence-floor, negative-claim, and already-promoted
  guards still bound the widening.
* Negative-claim guard still fires and blocks promotion for a
  "no bug found" answer even when the confirmed-verdict + floor gates
  pass.

The tests mock the UnitOfWork, outcome model, and outcome dispatcher
so no DB is required. They exercise ``_maybe_auto_promote`` directly.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from aila.modules.vr.agents.claim_verifier import ClaimVerifierAgent
from aila.modules.vr.contracts import OutcomeDispatchStatus, OutcomeKind

# --------------------------------------------------------------------- #
#  Fakes                                                                #
# --------------------------------------------------------------------- #


@dataclass
class _FakeOutcomeRow:
    id: str
    investigation_id: str = "inv-1"
    branch_id: str = "br-1"
    outcome_kind: str = OutcomeKind.ASSESSMENT_REPORT.value
    dispatch_status: str = OutcomeDispatchStatus.PENDING.value
    payload_json: str = "{}"
    confidence: str = "strong"
    evidence_refs_json: str = "[]"
    state: str | None = None
    dispatch_target: str | None = None


def _make_outcome_model():
    """Return a stand-in outcome model class that yields _FakeOutcomeRow.

    Must be a CLASS (not a bare function) because the platform
    ``_maybe_auto_promote`` path builds a SQLModel-style select over
    it (``_select(self._outcome_model).where(self._outcome_model.id ==
    canonical_id)``). The ``.id`` class attribute needs to be a plain
    sentinel that ``==`` returns something the stubbed ``.where``
    accepts (any value works -- the stub ignores it).
    """

    class _FakeOutcomeModel:
        # Class attribute so ``cls.id == canonical_id`` yields a plain
        # bool the stubbed ``.where`` swallows; the SQL machinery is
        # bypassed entirely by the ``_select`` stub installed alongside
        # this class.
        id = None

        def __new__(cls, **kwargs: Any) -> _FakeOutcomeRow:  # type: ignore[misc]
            return _FakeOutcomeRow(**kwargs)

    return _FakeOutcomeModel


@dataclass
class _FakeSession:
    rows: list[_FakeOutcomeRow] = field(default_factory=list)
    added: list[Any] = field(default_factory=list)
    deleted: list[Any] = field(default_factory=list)

    async def exec(self, _stmt):
        row = self.rows.pop(0) if self.rows else None

        class _Scalar:
            def __init__(self, r):
                self._r = r

            def first(self):
                return self._r

        return _Scalar(row)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def delete(self, obj: Any) -> None:
        self.deleted.append(obj)


class _FakeUoW:
    _session: _FakeSession | None = None

    def __init__(self) -> None:
        if _FakeUoW._session is None:
            _FakeUoW._session = _FakeSession()
        self.session = _FakeUoW._session

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def commit(self) -> None:
        pass

    @classmethod
    def reset(cls, rows: list[_FakeOutcomeRow] | None = None) -> None:
        cls._session = _FakeSession(rows=list(rows or []))


@dataclass
class _FakeDispatchResult:
    dispatch_status: Any
    dispatch_target: str
    reason: str


class _FakeDispatcher:
    def __init__(self, *_a: Any, **_kw: Any) -> None:
        pass

    async def dispatch(self, _outcome_id: str) -> _FakeDispatchResult:
        class _Enum:
            value = "delivered"

        return _FakeDispatchResult(
            dispatch_status=_Enum(),
            dispatch_target="review_queue",
            reason="ok",
        )


@pytest.fixture(autouse=True)
def _reset_fake_uow() -> Iterator[None]:
    _FakeUoW.reset()
    yield
    _FakeUoW.reset()


def _install_promote_seams(
    agent: ClaimVerifierAgent,
    monkeypatch: pytest.MonkeyPatch,
    *,
    original_row: _FakeOutcomeRow,
    floor: float = 0.5,
) -> _FakeSession:
    """Wire the seams _maybe_auto_promote reaches."""
    _FakeUoW.reset([original_row])
    monkeypatch.setattr(
        "aila.platform.agents.claim_verifier.UnitOfWork", _FakeUoW,
    )

    # Replace _select with a chainable stub so the promote path's
    # ``_select(self._outcome_model).where(...)`` chain does not run
    # through SQLAlchemy at all -- the _FakeSession.exec ignores the
    # statement and pops from ``rows`` regardless.
    class _FakeStmt:
        def where(self, *_a: Any, **_kw: Any) -> _FakeStmt:
            return self

    monkeypatch.setattr(
        "aila.platform.agents.claim_verifier._select",
        lambda *_a, **_kw: _FakeStmt(),
    )

    async def _floor() -> float:
        return floor

    monkeypatch.setattr(agent, "_read_auto_promote_floor", _floor)

    # Replace the outcome model with a plain dataclass factory so the
    # promote path can construct new rows without hitting SQLModel /
    # DB metadata.
    monkeypatch.setattr(
        type(agent), "_outcome_model", _make_outcome_model(), raising=False,
    )
    monkeypatch.setattr(
        type(agent), "_outcome_dispatcher_cls", _FakeDispatcher, raising=False,
    )

    # ServiceFactory is only touched to build the dispatcher; return an
    # object exposing the .knowledge attribute the dispatcher would
    # normally consume.
    class _FakeSvc:
        knowledge = object()

    monkeypatch.setattr(
        "aila.platform.agents.claim_verifier.ServiceFactory",
        lambda: _FakeSvc(),
    )
    assert _FakeUoW._session is not None
    return _FakeUoW._session


# --------------------------------------------------------------------- #
#  Tests                                                                #
# --------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_auto_promote_fires_when_dispatch_status_is_not_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B1: promotion no longer requires dispatch_status == SKIPPED."""
    agent = ClaimVerifierAgent(investigation_id="inv-b1")
    original = _FakeOutcomeRow(
        id="oc-b1",
        outcome_kind=OutcomeKind.ASSESSMENT_REPORT.value,
        # Explicitly NOT SKIPPED -- the pre-B1 code short-circuited here.
        dispatch_status=OutcomeDispatchStatus.PENDING.value,
        payload_json='{"answer": "CVE-2024-XXXX is exploitable via foo()"}',
    )
    session = _install_promote_seams(
        agent, monkeypatch, original_row=original, floor=0.5,
    )

    result = await agent._maybe_auto_promote(
        canonical_id="oc-b1", confidence=0.9, summary="confirmed by probes",
    )

    assert result["status"] == "promoted", result
    assert result["promoted_outcome_id"]
    # A new row (target kind) was added AND the original row was
    # re-added with the ``promoted_to`` payload link.
    added_kinds = [getattr(r, "outcome_kind", None) for r in session.added]
    assert OutcomeKind.DIRECT_FINDING.value in added_kinds
    assert original in session.added


@pytest.mark.asyncio
async def test_auto_promote_skips_negative_claim_even_with_confirmed_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative-claim guard still short-circuits promotion."""
    agent = ClaimVerifierAgent(investigation_id="inv-neg")
    original = _FakeOutcomeRow(
        id="oc-neg",
        outcome_kind=OutcomeKind.ASSESSMENT_REPORT.value,
        dispatch_status=OutcomeDispatchStatus.PENDING.value,
        payload_json='{"answer": "No exploitable vulnerabilities were found."}',
    )
    session = _install_promote_seams(
        agent, monkeypatch, original_row=original, floor=0.5,
    )

    result = await agent._maybe_auto_promote(
        canonical_id="oc-neg", confidence=0.95, summary="probes negative",
    )

    assert result["status"] == "skipped"
    assert result["reason"] == "answer_starts_negative_no_bug_to_promote"
    # Nothing added: no new row, no promoted_to link on the original.
    assert session.added == []

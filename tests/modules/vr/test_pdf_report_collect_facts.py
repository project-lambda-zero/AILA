"""#314 -- ``_collect_facts`` reads the total message count as a scalar.

``select(func.count()).first()`` returns the bare integer, not a row. The
collector must convert that scalar directly: positive counts must not be
indexed as rows, and a zero count must still produce ``0``.

These tests run the REAL ``_collect_facts``. The only substitutes are the
UnitOfWork boundary (a scripted session that answers each query in the
collector's fixed order, no database) and the git-backed audit metadata
helper, which is not under test here.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from aila.modules.vr.reporting import pdf_report


class _Result:
    """Answers ``.first()`` and ``.all()`` the way a SQLModel result does."""

    def __init__(self, *, first: Any = None, rows: list[Any] | None = None) -> None:
        self._first = first
        self._rows = rows or []

    def first(self) -> Any:
        return self._first

    def all(self) -> list[Any]:
        return list(self._rows)


class _ScriptedSession:
    """Returns queued results in the order ``_collect_facts`` issues queries."""

    def __init__(self, results: list[_Result]) -> None:
        self._results = list(results)

    async def exec(self, _stmt: Any) -> _Result:
        if not self._results:
            raise AssertionError("_collect_facts issued more queries than scripted")
        return self._results.pop(0)


class _UoW:
    def __init__(self, session: _ScriptedSession) -> None:
        self.session = session

    async def __aenter__(self) -> _UoW:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False


def _script_session(message_count_scalar: Any) -> _ScriptedSession:
    """Build the query responses for an investigation with no branches,
    outcomes, children, or findings, so only the message count varies.

    Query order inside ``_collect_facts``:
      1 investigation, 2 target, 3 primary branch, 4 outcomes,
      5 panel branches, 6 tool-call messages, 7 total message count,
      8 variant children, 9 own findings.
    """
    investigation = SimpleNamespace(
        id="inv-1",
        target_id="target-1",
        primary_outcome_id=None,
        title="Audit",
        kind="vulnerability",
        initial_question="Audit the parser",
        status="completed",
        created_at=None,
        stopped_at=None,
        updated_at=None,
    )
    target = SimpleNamespace(
        id="target-1",
        kind="repository",
        display_name="parser",
        descriptor_json="{}",
    )
    return _ScriptedSession([
        _Result(first=investigation),
        _Result(first=target),
        _Result(first=None),
        _Result(rows=[]),
        _Result(rows=[]),
        _Result(rows=[]),
        _Result(first=message_count_scalar),
        _Result(rows=[]),
        _Result(rows=[]),
    ])


async def _collect(monkeypatch: pytest.MonkeyPatch, session: _ScriptedSession) -> dict[str, Any]:
    monkeypatch.setattr(pdf_report, "UnitOfWork", lambda: _UoW(session))

    def _no_git_metadata(_inv: object, _descriptor: dict[str, Any]) -> dict[str, Any]:
        return {}

    monkeypatch.setattr(pdf_report, "_resolve_audit_metadata", _no_git_metadata)

    facts = await pdf_report._collect_facts("inv-1")
    assert facts is not None
    return facts


@pytest.mark.asyncio
async def test_collect_facts_reports_positive_scalar_message_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = await _collect(monkeypatch, _script_session(7))

    assert facts["message_count"] == 7


@pytest.mark.asyncio
async def test_collect_facts_preserves_zero_message_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = await _collect(monkeypatch, _script_session(0))

    assert facts["message_count"] == 0

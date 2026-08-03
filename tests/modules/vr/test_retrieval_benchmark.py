"""RFC-12 Phase 6: benchmark builder from stored VR findings.

Locks: a finding entry with a resolvable originating question yields a case
(query = the question, relevant = the entry id); an entry with no finding_id
or no resolvable question is skipped so the benchmark stays honest.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import aila.modules.vr.services.retrieval_benchmark as rb


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _Session:
    def __init__(self, kb_rows, inv_sequence):
        self._kb_rows = kb_rows
        self._inv_sequence = list(inv_sequence)
        self._calls = 0

    async def exec(self, _stmt):
        self._calls += 1
        if self._calls == 1:
            return _Result(self._kb_rows)
        return _Result(self._inv_sequence.pop(0) if self._inv_sequence else [])


class _UoW:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


def _kb_row(entry_id, finding_id):
    meta = {"finding_id": finding_id} if finding_id else {}
    return SimpleNamespace(id=entry_id, entry_metadata=json.dumps(meta))


async def test_builder_pairs_question_with_entry(monkeypatch) -> None:
    kb_rows = [
        _kb_row(3761, "f-1"),        # -> resolvable question -> one case
        _kb_row(3762, "f-2"),        # -> no investigation -> skipped
        _kb_row(3763, None),         # -> no finding_id -> skipped
    ]
    inv_sequence = [
        [SimpleNamespace(initial_question="Audit MSTG-ARCH-4 on the APK", title="t")],
        [],  # f-2 has no linking investigation
    ]
    session = _Session(kb_rows, inv_sequence)
    monkeypatch.setattr(rb, "UnitOfWork", lambda *a, **k: _UoW(session))

    cases = await rb.build_vr_finding_benchmark_cases()

    assert len(cases) == 1
    case = cases[0]
    assert case["query_id"] == "f-1"
    assert case["query"] == "Audit MSTG-ARCH-4 on the APK"
    assert case["relevant_ids"] == ["3761"]


async def test_builder_skips_blank_question(monkeypatch) -> None:
    kb_rows = [_kb_row(9001, "f-blank")]
    inv_sequence = [[SimpleNamespace(initial_question="   ", title="")]]
    session = _Session(kb_rows, inv_sequence)
    monkeypatch.setattr(rb, "UnitOfWork", lambda *a, **k: _UoW(session))

    cases = await rb.build_vr_finding_benchmark_cases()
    assert cases == []

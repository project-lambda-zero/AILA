"""#209 dead-column liveness: journal dead-letter replay stamps
``replayed_at`` and ``replay_seq``.

Pure unit-level: mocks the async session and monkey-patches
:func:`aila.platform.services.journal.append` so the test locks the wiring
between :func:`replay_deadletters` and the dead-letter row without needing
a live Postgres. Would FAIL on the pre-wire code because neither the
service function nor the two column writes existed.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

import aila.platform.services.journal as journal_mod
from aila.platform.services.journal import (
    JournalAppendResult,
    JournalWriteError,
    replay_deadletters,
)


class _FakeExecResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)


class _FakeNested:
    def __init__(self, on_exit: Any = None) -> None:
        self._on_exit = on_exit

    async def __aenter__(self) -> _FakeNested:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        # False -> propagate any exception out to replay_deadletters, mirroring
        # a real savepoint rollback + re-raise.
        return False


class _FakeSession:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows
        self.info: dict[str, Any] = {}
        self.added: list[Any] = []
        self.flushes = 0

    async def exec(self, _stmt: Any) -> _FakeExecResult:
        return _FakeExecResult(self._rows)

    def begin_nested(self) -> _FakeNested:
        return _FakeNested()

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushes += 1


class _FakeDeadletterRow:
    """Duck-typed stand-in for PlatformJournalDeadletterRecord.

    Assignment to ``replayed_at`` / ``replay_seq`` mirrors what SQLModel does
    on attribute set; the test asserts on those two attributes directly.
    """

    def __init__(
        self,
        *,
        row_id: str,
        chain_id: str,
        team_id: str | None,
        entry_json: dict[str, Any],
    ) -> None:
        self.id = row_id
        self.chain_id = chain_id
        self.team_id = team_id
        self.entry_json = entry_json
        self.replayed_at: datetime | None = None
        self.replay_seq: int | None = None


def _entry_json(action: str) -> dict[str, Any]:
    return {
        "kind": "audit",
        "source": "tests.replay",
        "action": action,
        "payload": {"note": action},
    }


async def test_replay_deadletters_stamps_replayed_at_and_replay_seq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row_a = _FakeDeadletterRow(
        row_id="dl-a",
        chain_id="team:t1",
        team_id="t1",
        entry_json=_entry_json("first"),
    )
    row_b = _FakeDeadletterRow(
        row_id="dl-b",
        chain_id="global",
        team_id=None,
        entry_json=_entry_json("second"),
    )
    session = _FakeSession([row_a, row_b])

    # append() call order drives the fake seqs: row_a -> 7, row_b -> 42.
    call_log: list[tuple[str, str | None]] = []
    seq_by_chain = {"team:t1": 7, "global": 42}

    async def _fake_append(
        _session: Any, *, entry: Any, team_id: str | None = None
    ) -> JournalAppendResult:
        chain_id = f"team:{team_id}" if team_id else "global"
        call_log.append((chain_id, team_id))
        return JournalAppendResult(
            journal_id=f"j-{chain_id}",
            seq=seq_by_chain[chain_id],
            chain_id=chain_id,
            row_hash="0" * 64,
        )

    monkeypatch.setattr(journal_mod, "append", _fake_append)

    result = await replay_deadletters(session)

    # Both rows re-appended and stamped.
    assert result.scanned == 2
    assert result.replayed == 2
    assert result.failed == 0
    assert [e.deadletter_id for e in result.entries] == ["dl-a", "dl-b"]
    assert [e.seq for e in result.entries] == [7, 42]
    assert all(e.replayed for e in result.entries)

    # The two dead columns (replayed_at, replay_seq) are now populated on
    # every row. This is the acceptance criterion that would FAIL against
    # the pre-wire code (which never wrote either column).
    assert row_a.replayed_at is not None
    assert row_a.replayed_at.tzinfo is not None
    assert row_a.replay_seq == 7
    assert row_b.replayed_at is not None
    assert row_b.replay_seq == 42

    # append() was called once per deadletter row with the stored team_id
    # preserved (so the original chain is honored, not the ambient scope).
    assert call_log == [("team:t1", "t1"), ("global", None)]


async def test_replay_deadletters_leaves_still_failing_rows_unstamped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A row whose re-append still raises JournalWriteError stays un-replayed
    and does not break the batch -- other rows in the same batch still land."""
    ok_row = _FakeDeadletterRow(
        row_id="dl-ok",
        chain_id="team:t1",
        team_id="t1",
        entry_json=_entry_json("ok"),
    )
    bad_row = _FakeDeadletterRow(
        row_id="dl-bad",
        chain_id="team:t2",
        team_id="t2",
        entry_json=_entry_json("bad"),
    )
    session = _FakeSession([bad_row, ok_row])

    async def _fake_append(
        _session: Any, *, entry: Any, team_id: str | None = None
    ) -> JournalAppendResult:
        if team_id == "t2":
            raise JournalWriteError("chain still broken")
        chain_id = f"team:{team_id}"
        return JournalAppendResult(
            journal_id="j",
            seq=99,
            chain_id=chain_id,
            row_hash="0" * 64,
        )

    monkeypatch.setattr(journal_mod, "append", _fake_append)

    result = await replay_deadletters(session)

    assert result.scanned == 2
    assert result.replayed == 1
    assert result.failed == 1

    # Failed row keeps both columns NULL (leave for next replay).
    assert bad_row.replayed_at is None
    assert bad_row.replay_seq is None

    # Succeeding row was stamped on the same batch.
    assert ok_row.replayed_at is not None
    assert ok_row.replay_seq == 99

    bad_entry = next(e for e in result.entries if e.deadletter_id == "dl-bad")
    assert bad_entry.replayed is False
    assert bad_entry.error == "JournalWriteError"

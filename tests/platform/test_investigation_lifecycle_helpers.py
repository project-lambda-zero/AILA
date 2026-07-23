"""Platform terminal-transition helper (RFC-02).

``mark_investigation_completed`` is the one place every terminal writer
(synthesis agents, emit finalizer, future terminal paths) flips an
investigation row to COMPLETED. The contract: all three fields
(status / stopped_at / updated_at) move together to one timestamp.
"""
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.services.investigation_lifecycle import (
    mark_investigation_completed,
)


def test_marks_status_and_stamps_both_timestamps() -> None:
    row = SimpleNamespace(status="running", stopped_at=None, updated_at=None)

    mark_investigation_completed(row)

    assert row.status == InvestigationStatus.COMPLETED.value
    assert row.stopped_at is not None
    # stopped_at and updated_at share ONE timestamp, not two utc_now() calls.
    assert row.stopped_at == row.updated_at


def test_shared_now_is_honored() -> None:
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    row = SimpleNamespace(status="running", stopped_at=None, updated_at=None)

    mark_investigation_completed(row, now=stamp)

    assert row.stopped_at == stamp
    assert row.updated_at == stamp

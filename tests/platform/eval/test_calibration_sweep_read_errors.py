"""#451 -- calibration sweep reports failed and refused reads.

A read that fails, or a table pair the sweep refuses, must appear in the
report's ``errors`` list; a readable pair with no reviews in the window is
an empty result with no error. The database session is the replaced
boundary: one variant raises on execute, the other returns no rows.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
import sqlalchemy.exc

from aila.platform.eval import calibration_sweep
from aila.platform.eval.calibration_sweep import DEFAULT_CALIBRATION_TABLES, run_calibration_sweep


class _NoRows:
    def all(self) -> list[tuple[object, ...]]:
        return []


class _EmptySession:
    async def execute(self, *_args: object, **_kwargs: object) -> _NoRows:
        return _NoRows()


class _BrokenSession:
    async def execute(self, *_args: object, **_kwargs: object) -> _NoRows:
        raise sqlalchemy.exc.OperationalError("SELECT", {}, OSError("connection reset"))


def _scope(session: object):
    @asynccontextmanager
    async def _session_scope(*_args: object, **_kwargs: object):
        yield session

    return _session_scope


async def test_failed_reads_are_reported_per_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(calibration_sweep, "async_session_scope", _scope(_BrokenSession()))

    report = await run_calibration_sweep()

    assert report["samples_read"] == 0
    assert report["errors"] == [f"read:{o}/{r}:OperationalError" for o, r in DEFAULT_CALIBRATION_TABLES]


async def test_unsafe_override_pair_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(calibration_sweep, "async_session_scope", _scope(_EmptySession()))

    report = await run_calibration_sweep(
        table_pairs=[["vr_investigation_outcomes", "vr_outcome_reviews"], ["outcomes; drop", "reviews"], "not-a-pair"],
    )

    assert report["errors"] == ["read:outcomes; drop/reviews:unsafe_table_name", "table_pairs:malformed_entry"]
    assert report["samples_read"] == 0


async def test_readable_empty_pairs_report_no_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(calibration_sweep, "async_session_scope", _scope(_EmptySession()))

    report = await run_calibration_sweep()

    assert report == {
        "kinds_seen": 0,
        "samples_read": 0,
        "proposals_persisted": 0,
        "kinds_below_min_evidence": 0,
        "errors": [],
    }

"""#48-8 -- is_cache_fresh treats a NULL outcome_updated_at as never fresh."""
from __future__ import annotations

from datetime import UTC, datetime

from aila.modules.vr.reporting.section_writer import is_cache_fresh


def _cached(generated_at: str) -> dict:
    return {"generated_at": generated_at, "section": "x"}


def test_none_outcome_updated_at_is_not_fresh():
    # A NULL updated_at signals an under-populated row -> regenerate, not serve.
    assert is_cache_fresh(_cached("2026-01-01T00:00:00+00:00"), None) is False


def test_cache_newer_than_outcome_is_fresh():
    outcome = datetime(2026, 1, 1, tzinfo=UTC)
    assert is_cache_fresh(_cached("2026-01-02T00:00:00+00:00"), outcome) is True


def test_cache_older_than_outcome_is_stale():
    outcome = datetime(2026, 1, 2, tzinfo=UTC)
    assert is_cache_fresh(_cached("2026-01-01T00:00:00+00:00"), outcome) is False


def test_missing_or_empty_cache_is_not_fresh():
    outcome = datetime(2026, 1, 1, tzinfo=UTC)
    assert is_cache_fresh(None, outcome) is False
    assert is_cache_fresh({}, outcome) is False


def test_unparseable_generated_at_is_not_fresh():
    outcome = datetime(2026, 1, 1, tzinfo=UTC)
    assert is_cache_fresh(_cached("not-a-date"), outcome) is False

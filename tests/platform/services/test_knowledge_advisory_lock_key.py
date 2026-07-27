"""_advisory_lock_key gives a stable, distinct, signed-64-bit key per dedup
identity so concurrent upserts of the same (namespace, dedup_key) serialize
instead of racing check-then-insert into duplicate rows (issue #37)."""
from __future__ import annotations

from aila.platform.services.knowledge import _advisory_lock_key


def test_deterministic() -> None:
    assert _advisory_lock_key("ns", "k") == _advisory_lock_key("ns", "k")


def test_distinct_per_identity() -> None:
    assert _advisory_lock_key("ns", "k1") != _advisory_lock_key("ns", "k2")
    assert _advisory_lock_key("ns1", "k") != _advisory_lock_key("ns2", "k")


def test_signed_64_bit_range() -> None:
    v = _advisory_lock_key("ns", "k")
    assert -(2**63) <= v < 2**63

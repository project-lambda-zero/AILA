"""RFC-12 Phase 5: config-gated trust weight + temporal decay re-rank.

Covers the two pure helpers behind ``retrieve_routed``'s post-gate re-rank:
``_age_hours`` (timestamp parsing) and ``_apply_trust_decay`` (down-weight
untrusted namespaces, exponential temporal decay, floor drop, re-sort). The
retrieve_routed -> config integration is exercised live; here we lock the
scoring math and the floor/sort contract without a DB.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aila.platform.services.knowledge import _age_hours, _apply_trust_decay

_NOW = datetime(2026, 8, 2, 12, 0, 0, tzinfo=UTC)


def _hit(entry_id: int, namespace: str, score: float, *, updated_at=None) -> dict:
    return {
        "id": entry_id,
        "namespace": namespace,
        "score": score,
        "provenance": {"namespace": namespace, "updated_at": updated_at},
    }


def test_age_hours_parses_datetime_string_none_and_future() -> None:
    assert _age_hours(_NOW - timedelta(hours=6), _NOW) == 6.0
    assert _age_hours((_NOW - timedelta(hours=3)).isoformat(), _NOW) == 3.0
    # tz-naive is read as UTC to match utc_now
    assert _age_hours(datetime(2026, 8, 2, 6, 0, 0), _NOW) == 6.0
    # future timestamp (clock skew) clamps to 0 so decay never boosts a score
    assert _age_hours(_NOW + timedelta(hours=5), _NOW) == 0.0
    assert _age_hours(None, _NOW) is None
    assert _age_hours("not-a-date", _NOW) is None


def test_trust_weight_downweights_only_target_derived_and_resorts() -> None:
    gated = [
        _hit(1, "vr.observation.workspace.x", 0.90),  # untrusted, higher raw
        _hit(2, "vr.finding.workspace.x", 0.80),  # verified, lower raw
    ]
    out = _apply_trust_decay(
        gated,
        target_derived_weight=0.5,
        decay_half_life_hours=0.0,
        floor=0.0,
        now=_NOW,
    )
    by_id = {h["id"]: h for h in out}
    # untrusted hit scaled 0.90 * 0.5 = 0.45; verified untouched at 0.80
    assert by_id[1]["score"] == 0.45
    assert by_id[1]["base_score"] == 0.90
    assert by_id[2]["score"] == 0.80
    # re-sorted: verified now outranks the down-weighted untrusted hit
    assert [h["id"] for h in out] == [2, 1]


def test_temporal_decay_scales_by_age_half_life() -> None:
    gated = [
        _hit(1, "vr.finding.workspace.x", 0.80, updated_at=_NOW),  # fresh
        _hit(2, "vr.finding.workspace.x", 0.80, updated_at=_NOW - timedelta(hours=24)),
    ]
    out = _apply_trust_decay(
        gated,
        target_derived_weight=1.0,
        decay_half_life_hours=24.0,
        floor=0.0,
        now=_NOW,
    )
    by_id = {h["id"]: h for h in out}
    assert by_id[1]["score"] == 0.80  # age 0 -> factor 1
    assert by_id[2]["score"] == 0.40  # age == one half-life -> factor 0.5
    assert [h["id"] for h in out] == [1, 2]


def test_floor_drops_hit_pushed_below_min_score() -> None:
    gated = [
        _hit(1, "vr.observation.workspace.x", 0.50),
        _hit(2, "vr.finding.workspace.x", 0.50),
    ]
    out = _apply_trust_decay(
        gated,
        target_derived_weight=0.4,  # 0.50 * 0.4 = 0.20 < floor
        decay_half_life_hours=0.0,
        floor=0.30,
        now=_NOW,
    )
    assert [h["id"] for h in out] == [2]  # untrusted hit dropped below floor

"""#37 -- _merge_and_rank ranks hybrid results and applies the relevance floor.

Pure function: synthetic vector/FTS maps, no database or embedding model.
combined = 0.6*(1 - distance/2) + 0.4*min(rank, 1).
"""
from __future__ import annotations

from aila.platform.services.knowledge import _merge_and_rank


def _vec(distance: float) -> dict:
    return {
        "distance": distance,
        "content": "c",
        "entry_metadata": "{}",
        "namespace": "agent:x",
    }


def _maps() -> tuple[dict, dict, dict]:
    # entry 1: hybrid  -> 0.6*0.9 + 0.4*0.5 = 0.74
    # entry 2: vec_only-> 0.6*0.2           = 0.12
    # entry 3: fts_only-> 0.4*0.8           = 0.32
    vec_map = {1: _vec(0.2), 2: _vec(1.6)}
    fts_map = {1: 0.5, 3: 0.8}
    fts_content_map = {
        3: {"content": "f", "entry_metadata": "{}", "namespace": "agent:x"},
    }
    return vec_map, fts_map, fts_content_map


def test_ranks_by_combined_score_desc() -> None:
    rows = _merge_and_rank(*_maps(), limit=10, min_score=0.0)
    assert [r["id"] for r in rows] == [1, 3, 2]
    by_id = {r["id"]: r["source"] for r in rows}
    assert by_id == {1: "hybrid", 3: "fts_only", 2: "vec_only"}


def test_min_score_drops_below_floor() -> None:
    rows = _merge_and_rank(*_maps(), limit=10, min_score=0.3)
    ids = {r["id"] for r in rows}
    assert ids == {1, 3}  # entry 2 (0.12) is below the floor


def test_min_score_zero_keeps_all() -> None:
    rows = _merge_and_rank(*_maps(), limit=10, min_score=0.0)
    assert len(rows) == 3


def test_limit_caps_results() -> None:
    rows = _merge_and_rank(*_maps(), limit=1, min_score=0.0)
    assert len(rows) == 1
    assert rows[0]["id"] == 1

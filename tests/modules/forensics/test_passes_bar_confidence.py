"""Confidence gate tests for ``_passes_bar`` (#320).

Investigation-summary rows use their own rank map (exact=3, strong=2,
medium=1, caveated/unknown=0). Collector rows and typed investigation
rows keep their prior behavior.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from aila.modules.forensics.api_router import _passes_bar


def _summary_row() -> Any:
    return SimpleNamespace(
        artifact_type="investigation_summary",
        source_investigation_id="inv-1",
        lead_score=None,
    )


def _collector_row() -> Any:
    return SimpleNamespace(
        artifact_type="prefetch_run",
        source_investigation_id=None,
        lead_score=None,
    )


def _typed_row(artifact_type: str) -> Any:
    return SimpleNamespace(
        artifact_type=artifact_type,
        source_investigation_id="inv-1",
        lead_score=None,
    )


@pytest.mark.parametrize(
    ("confidence", "bar", "expected"),
    [
        # exact (3) passes every bar
        ("exact", 0, True), ("exact", 1, True), ("exact", 2, True),
        # strong (2) passes every bar
        ("strong", 0, True), ("strong", 1, True), ("strong", 2, True),
        # medium (1) fails only the high bar
        ("medium", 0, True), ("medium", 1, True), ("medium", 2, False),
        # caveated (0) passes only the low bar
        ("caveated", 0, True), ("caveated", 1, False), ("caveated", 2, False),
        # unknown (0) passes only the low bar
        ("unknown", 0, True), ("unknown", 1, False), ("unknown", 2, False),
    ],
)
def test_summary_confidence_ranks_at_each_bar(
    confidence: str, bar: int, expected: bool
) -> None:
    payload = {"confidence": confidence}
    assert _passes_bar(_summary_row(), payload, bar) is expected


@pytest.mark.parametrize("bar", [0, 1, 2])
def test_summary_missing_confidence_is_rank_zero(bar: int) -> None:
    # Missing confidence maps to 0: admitted only at the low bar.
    assert _passes_bar(_summary_row(), {}, bar) is (bar == 0)


@pytest.mark.parametrize(("confidence", "bar"), [("exact", 1), ("exact", 2), ("strong", 1), ("strong", 2)])
def test_collector_exact_and_strong_confidence_unchanged(confidence: str, bar: int) -> None:
    # Collector rows still use the shared _CONFIDENCE_RANK, which has no
    # exact/strong keys, so they rank 0 and fail the medium/high bars.
    payload = {"confidence": confidence}
    assert _passes_bar(_collector_row(), payload, bar) is False


@pytest.mark.parametrize("bar", [0, 1, 2])
def test_collector_confirmed_and_high_confidence_unchanged(bar: int) -> None:
    assert _passes_bar(_collector_row(), {"confidence": "confirmed"}, bar) is True
    assert _passes_bar(_collector_row(), {"confidence": "high"}, bar) is True


@pytest.mark.parametrize("artifact_type", ["trigger_artifact", "ioc_observation"])
@pytest.mark.parametrize("confidence", ["exact", "strong", "caveated", "unknown", None])
@pytest.mark.parametrize("bar", [0, 1, 2])
def test_typed_non_summary_rows_admitted_regardless_of_confidence(
    artifact_type: str, confidence: Any, bar: int
) -> None:
    assert _passes_bar(_typed_row(artifact_type), {"confidence": confidence}, bar) is True


@pytest.mark.parametrize("bar", [0, 1, 2])
def test_untyped_investigation_rows_still_excluded(bar: int) -> None:
    row = _typed_row("some_untyped_row")
    assert _passes_bar(row, {"confidence": "exact"}, bar) is False

"""VR v0.1 benchmark -- parametrized over 20 retired CVEs.

These tests validate the benchmark data file itself (schema, coverage,
consistency) without requiring live infrastructure. The actual end-to-end
benchmark that exercises the full VR pipeline (upload → research → PoC →
advisory) is gated behind the ``--run-e2e`` marker and requires IDA MCP,
SSH workstations, and a running AILA backend.

Run data validation only::

    pytest tests/vr_benchmark/test_benchmark.py -v

Run full benchmark (requires infra)::

    pytest tests/vr_benchmark/test_benchmark.py -v --run-e2e
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

_BENCHMARK_PATH = Path(__file__).parent / "benchmark_cves.json"

with _BENCHMARK_PATH.open("r", encoding="utf-8") as _fh:
    _DATA = json.load(_fh)

_CVES: list[dict] = _DATA["cves"]
_CVE_IDS = [c["cve_id"] for c in _CVES]


# ---------------------------------------------------------------------------
# Data integrity tests (always run)
# ---------------------------------------------------------------------------


def test_benchmark_file_loads() -> None:
    assert isinstance(_DATA, dict)
    assert "cves" in _DATA
    assert "_meta" in _DATA


def test_benchmark_has_20_cves() -> None:
    assert len(_CVES) == 20, f"Expected 20 benchmark CVEs, got {len(_CVES)}"


def test_cve_ids_are_unique() -> None:
    assert len(set(_CVE_IDS)) == len(_CVE_IDS), "Duplicate CVE IDs in benchmark"


@pytest.mark.parametrize("cve", _CVES, ids=_CVE_IDS)
def test_cve_has_required_fields(cve: dict) -> None:
    required = {
        "cve_id", "name", "crash_type", "target", "target_class",
        "target_format", "tier", "patch_ref", "vulnerable_version",
        "patched_version", "poc_language", "expected_cvss_min", "notes",
    }
    missing = required - set(cve.keys())
    assert not missing, f"{cve['cve_id']} missing fields: {missing}"


@pytest.mark.parametrize("cve", _CVES, ids=_CVE_IDS)
def test_crash_type_in_vocabulary(cve: dict) -> None:
    from aila.modules.vr.contracts.finding import CrashType

    valid = {ct.value for ct in CrashType}
    assert cve["crash_type"] in valid, (
        f"{cve['cve_id']}: crash_type {cve['crash_type']!r} not in CrashType enum"
    )


@pytest.mark.parametrize("cve", _CVES, ids=_CVE_IDS)
def test_target_class_in_vocabulary(cve: dict) -> None:
    from aila.modules.vr.contracts.project import TargetClass

    valid = {tc.value for tc in TargetClass}
    assert cve["target_class"] in valid, (
        f"{cve['cve_id']}: target_class {cve['target_class']!r} not in TargetClass enum"
    )


@pytest.mark.parametrize("cve", _CVES, ids=_CVE_IDS)
def test_target_format_in_vocabulary(cve: dict) -> None:
    from aila.modules.vr.contracts.project import TargetFormat

    valid = {tf.value for tf in TargetFormat}
    assert cve["target_format"] in valid, (
        f"{cve['cve_id']}: target_format {cve['target_format']!r} not in TargetFormat enum"
    )


@pytest.mark.parametrize("cve", _CVES, ids=_CVE_IDS)
def test_tier_is_valid(cve: dict) -> None:
    assert cve["tier"] in (1, 2, 3), f"{cve['cve_id']}: tier must be 1, 2, or 3"


@pytest.mark.parametrize("cve", _CVES, ids=_CVE_IDS)
def test_cvss_min_is_positive(cve: dict) -> None:
    score = cve["expected_cvss_min"]
    assert isinstance(score, (int, float)) and 0.0 < score <= 10.0, (
        f"{cve['cve_id']}: expected_cvss_min must be in (0, 10], got {score}"
    )


def test_tier_distribution() -> None:
    """Verify the benchmark has the planned tier mix: 10/7/3."""
    tiers = [c["tier"] for c in _CVES]
    counts = {t: tiers.count(t) for t in (1, 2, 3)}
    assert counts[1] >= 7, f"Need at least 7 Tier-1 CVEs, got {counts[1]}"
    assert counts[2] >= 5, f"Need at least 5 Tier-2 CVEs, got {counts[2]}"
    assert counts[3] >= 2, f"Need at least 2 Tier-3 CVEs, got {counts[3]}"


def test_crash_type_diversity() -> None:
    """At least 5 distinct crash types across the 20 CVEs."""
    types = {c["crash_type"] for c in _CVES}
    assert len(types) >= 5, f"Need at least 5 crash types, got {len(types)}: {types}"


def test_target_class_diversity() -> None:
    """At least 3 distinct target classes."""
    classes = {c["target_class"] for c in _CVES}
    assert len(classes) >= 3, f"Need at least 3 target classes, got {len(classes)}: {classes}"


def test_has_non_native_targets() -> None:
    """At least 2 non-native targets (JVM, PHP, etc.)."""
    non_native = [c for c in _CVES if c["target_class"] != "native" and c["target_class"] != "kernel"]
    assert len(non_native) >= 2, f"Need at least 2 non-native/non-kernel targets, got {len(non_native)}"

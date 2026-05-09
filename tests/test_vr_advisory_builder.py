"""Phase 7: VR AdvisoryBuilderTool unit tests.

Verifies CVSS 3.1 base-score arithmetic against the FIRST specification,
crash-type → CWE mapping from the bundled JSON data, and the advisory
formatter contract. The tool loads its data files via paths derived from
``Path(__file__)`` so the default constructor works without overrides.
"""
from __future__ import annotations

import pytest

from aila.modules.vr.tools.advisory_builder import (
    AdvisoryBuilderTool,
    _roundup,
    _severity,
)

__all__ = [
    "TestComputeCVSS",
    "TestMapCWE",
    "TestFormatAdvisory",
    "TestSeverity",
    "TestRoundup",
]


@pytest.fixture
def tool() -> AdvisoryBuilderTool:
    return AdvisoryBuilderTool()


class TestComputeCVSS:
    def test_overflow_heap_base_score(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.compute_cvss("overflow_heap")
        assert r["status"] == "ready"
        assert r["base_score"] > 0.0
        assert r["vector_string"].startswith("CVSS:3.1/")
        assert r["severity"] in {"HIGH", "CRITICAL"}

    def test_critical_vector_evaluates_to_9_8(self, tool: AdvisoryBuilderTool) -> None:
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is the canonical 9.8 vector."""
        r = tool.compute_cvss("overflow_heap")
        assert r["base_score"] == 9.8
        assert r["severity"] == "CRITICAL"
        assert r["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_av_local_lowers_score(self, tool: AdvisoryBuilderTool) -> None:
        baseline = tool.compute_cvss("overflow_heap")
        local = tool.compute_cvss("overflow_heap", overrides={"AV": "L"})
        assert local["status"] == "ready"
        assert local["base_score"] < baseline["base_score"]
        assert local["vector_string"].startswith("CVSS:3.1/AV:L/")

    def test_invalid_crash_type_errors(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.compute_cvss("not_a_real_crash_type")
        assert r["status"] == "error"

    def test_empty_crash_type_errors(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.compute_cvss("")
        assert r["status"] == "error"

    def test_invalid_metric_value_errors(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.compute_cvss("overflow_heap", overrides={"AV": "ZZ"})
        assert r["status"] == "error"
        assert "metric" in r["error"].lower()


class TestMapCWE:
    def test_overflow_heap_maps_to_cwe_122(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.map_cwe("overflow_heap")
        assert r["status"] == "ready"
        assert r["cwe_id"] == "CWE-122"
        assert "Heap" in r["name"]

    def test_uaf_maps_to_cwe_416(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.map_cwe("uaf")
        assert r["status"] == "ready"
        assert "CWE-416" in r["cwe_id"]

    def test_unknown_crash_type_errors(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.map_cwe("nonexistent")
        assert r["status"] == "error"


class TestFormatAdvisory:
    def test_minimal_finding(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.format_advisory({"crash_type": "overflow_heap"})
        assert r["status"] == "ready"
        adv = r["advisory"]
        assert adv["title"]
        assert adv["summary"]
        assert adv["remediation"]
        assert adv["cvss"]["base_score"] == 9.8
        assert adv["cvss"]["severity"] == "CRITICAL"
        assert adv["cwe"] is not None
        assert adv["cwe"]["cwe_id"] == "CWE-122"

    def test_full_finding_populates_all_fields(self, tool: AdvisoryBuilderTool) -> None:
        finding = {
            "id": "f-7",
            "crash_type": "overflow_heap",
            "root_cause": "Unchecked memcpy in ParseHeader.",
            "vulnerable_function": "ParseHeader",
            "cve_id": "CVE-2026-9999",
            "affected_versions": ["1.0", "1.1"],
            "remediation": "Upgrade to 1.2.",
            "references": ["https://example.test/advisory"],
            "poc_reliability": "5/5",
            "crash_signature": {"signature_hash": "0123456789abcdef" * 4},
        }
        r = tool.format_advisory(finding)
        adv = r["advisory"]
        assert adv["finding_id"] == "f-7"
        assert adv["cve_id"] == "CVE-2026-9999"
        assert adv["title"] == "Overflow Heap in ParseHeader"
        assert "ParseHeader" in adv["technical_details"]
        assert "Unchecked memcpy" in adv["technical_details"]
        assert "Crash signature" in adv["technical_details"]
        assert "5/5" in adv["impact"]
        assert "CVSS 3.1" in adv["impact"]
        assert adv["affected_versions"] == ["1.0", "1.1"]
        assert adv["remediation"] == "Upgrade to 1.2."
        assert adv["references"] == ["https://example.test/advisory"]

    def test_empty_finding_falls_back_to_generic(self, tool: AdvisoryBuilderTool) -> None:
        r = tool.format_advisory({})
        adv = r["advisory"]
        assert adv["title"] == "Vulnerability"
        assert adv["cwe"] is None
        # Default remediation kicks in when nothing is supplied
        assert "patched version" in adv["remediation"].lower()


class TestSeverity:
    @pytest.mark.parametrize(
        ("score", "label"),
        [
            (0.0, "NONE"),
            (3.9, "LOW"),
            (4.0, "MEDIUM"),
            (6.9, "MEDIUM"),
            (7.0, "HIGH"),
            (8.9, "HIGH"),
            (9.0, "CRITICAL"),
            (9.8, "CRITICAL"),
            (10.0, "CRITICAL"),
        ],
    )
    def test_band_thresholds(self, score: float, label: str) -> None:
        assert _severity(score) == label


class TestRoundup:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (4.0, 4.0),       # already on 0.1 grid → unchanged
            (4.02, 4.1),      # rounds up to next 0.1
            (4.001, 4.1),     # any non-zero residue rounds up
            (0.0, 0.0),
            (10.0, 10.0),
        ],
    )
    def test_known_values(self, raw: float, expected: float) -> None:
        assert _roundup(raw) == expected

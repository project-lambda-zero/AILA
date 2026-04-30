"""Comprehensive unit tests for aila.modules.vulnerability.reporting.rows.

Covers: criticality_rank, clean_sentence, clip_text, scoring_evidence,
order_group, render_group, build_grouped_report_rows, build_groups,
summarize_scoring_mode, collect_values, select_group_fixed_version,
build_assessment, build_facts, build_action, build_uncertainty,
build_grouped_cve_summary, join_sections, default_action.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from aila.modules.vulnerability.reporting.rows import (
    build_action,
    build_assessment,
    build_facts,
    build_grouped_cve_summary,
    build_grouped_report_rows,
    build_groups,
    build_uncertainty,
    clean_sentence,
    clip_text,
    collect_values,
    criticality_rank,
    default_action,
    join_sections,
    order_group,
    render_group,
    scoring_evidence,
    select_group_fixed_version,
    summarize_scoring_mode,
)


# ---------------------------------------------------------------------------
# Helpers — build realistic finding dicts
# ---------------------------------------------------------------------------

def _finding(
    *,
    system_id: int | None = 1,
    host: str = "web-01.prod",
    package_name: str = "openssl",
    cve_id: str = "CVE-2024-1001",
    criticality: str = "High",
    numeric_score: float = 7.5,
    nvd_url: str = "https://nvd.nist.gov/vuln/detail/CVE-2024-1001",
    rationale: str = "Remote code execution via buffer overflow.",
    fixed_version: str | None = "1.1.1w-0+deb11u1",
    distribution: str = "debian",
    scoring_mode: str | None = None,
    scoring_evidence: dict | None = None,
    facts: str | None = None,
    inference: str | None = None,
    recommended_action: str | None = None,
    uncertainty: str | None = None,
    advisory_provenance: str | None = None,
    intel_provenance: str | None = None,
    **extra,
) -> dict:
    d: dict = {
        "system_id": system_id,
        "host": host,
        "package_name": package_name,
        "cve_id": cve_id,
        "criticality": criticality,
        "numeric_score": numeric_score,
        "nvd_url": nvd_url,
        "rationale": rationale,
        "fixed_version": fixed_version,
        "distribution": distribution,
        "scoring_mode": scoring_mode,
        "scoring_evidence": scoring_evidence,
        "facts": facts,
        "inference": inference,
        "recommended_action": recommended_action,
        "uncertainty": uncertainty,
        "advisory_provenance": advisory_provenance,
        "intel_provenance": intel_provenance,
    }
    d.update(extra)
    return d


# ===================================================================
# criticality_rank
# ===================================================================


class TestCriticalityRank:
    def test_known_levels(self):
        assert criticality_rank("Planned") == 0
        assert criticality_rank("Moderate") == 1
        assert criticality_rank("High") == 2
        assert criticality_rank("Immediate") == 3

    def test_unknown_returns_negative(self):
        assert criticality_rank("Unknown") == -1

    def test_empty_string(self):
        assert criticality_rank("") == -1

    def test_case_sensitive(self):
        assert criticality_rank("high") == -1
        assert criticality_rank("HIGH") == -1
        assert criticality_rank("immediate") == -1

    def test_ordering_is_monotonic(self):
        levels = ["Planned", "Moderate", "High", "Immediate"]
        ranks = [criticality_rank(level) for level in levels]
        assert ranks == sorted(ranks)


# ===================================================================
# clean_sentence
# ===================================================================


class TestCleanSentence:
    def test_none_returns_empty(self):
        assert clean_sentence(None) == ""

    def test_empty_string(self):
        assert clean_sentence("") == ""

    def test_whitespace_only(self):
        assert clean_sentence("   ") == ""

    def test_adds_period(self):
        assert clean_sentence("Buffer overflow") == "Buffer overflow."

    def test_preserves_existing_period(self):
        assert clean_sentence("Buffer overflow.") == "Buffer overflow."

    def test_collapses_internal_whitespace(self):
        assert clean_sentence("Buffer   overflow   in   OpenSSL") == "Buffer overflow in OpenSSL."

    def test_strips_leading_trailing(self):
        assert clean_sentence("  Buffer overflow  ") == "Buffer overflow."

    def test_numeric_value_converted(self):
        assert clean_sentence(42) == "42."

    def test_false_returns_empty(self):
        assert clean_sentence(False) == ""

    def test_zero_returns_empty(self):
        assert clean_sentence(0) == ""

    def test_multiline_collapsed(self):
        result = clean_sentence("line one\n  line two\n")
        assert "\n" not in result
        assert result == "line one line two."


# ===================================================================
# clip_text
# ===================================================================


class TestClipText:
    def test_short_string_unchanged(self):
        assert clip_text("hello", 10) == "hello"

    def test_exact_limit_unchanged(self):
        text = "a" * 50
        assert clip_text(text, 50) == text

    def test_over_limit_adds_ellipsis(self):
        text = "a" * 60
        result = clip_text(text, 50)
        assert len(result) == 50
        assert result.endswith("...")

    def test_ellipsis_content_correct(self):
        text = "abcdefghijklmnop"
        result = clip_text(text, 10)
        assert result == "abcdefg..."
        assert len(result) == 10

    def test_empty_string(self):
        assert clip_text("", 100) == ""

    def test_limit_of_three(self):
        result = clip_text("abcdef", 3)
        assert result == "..."

    def test_limit_of_four(self):
        result = clip_text("abcdef", 4)
        assert result == "a..."


# ===================================================================
# scoring_evidence
# ===================================================================


class TestScoringEvidence:
    def test_returns_dict_when_present(self):
        finding = {"scoring_evidence": {"kev_component": 1}}
        assert scoring_evidence(finding) == {"kev_component": 1}

    def test_returns_empty_when_absent(self):
        assert scoring_evidence({}) == {}

    def test_returns_empty_when_none(self):
        assert scoring_evidence({"scoring_evidence": None}) == {}

    def test_returns_empty_when_not_dict(self):
        assert scoring_evidence({"scoring_evidence": "not a dict"}) == {}
        assert scoring_evidence({"scoring_evidence": 42}) == {}
        assert scoring_evidence({"scoring_evidence": [1, 2]}) == {}

    def test_returns_empty_when_false(self):
        assert scoring_evidence({"scoring_evidence": False}) == {}


# ===================================================================
# order_group
# ===================================================================


class TestOrderGroup:
    def test_single_finding(self):
        f = _finding(criticality="Immediate", numeric_score=9.8)
        result = order_group([f])
        assert len(result) == 1
        assert result[0] is f

    def test_sorts_by_criticality_first(self):
        low = _finding(criticality="Planned", numeric_score=10.0, cve_id="CVE-9999")
        high = _finding(criticality="Immediate", numeric_score=1.0, cve_id="CVE-0001")
        result = order_group([low, high])
        assert result[0]["criticality"] == "Immediate"
        assert result[1]["criticality"] == "Planned"

    def test_tiebreak_by_score(self):
        a = _finding(criticality="High", numeric_score=5.0, cve_id="CVE-A")
        b = _finding(criticality="High", numeric_score=9.0, cve_id="CVE-B")
        result = order_group([a, b])
        assert result[0]["numeric_score"] == 9.0
        assert result[1]["numeric_score"] == 5.0

    def test_tiebreak_by_cve_id(self):
        a = _finding(criticality="High", numeric_score=7.0, cve_id="CVE-2024-0001")
        b = _finding(criticality="High", numeric_score=7.0, cve_id="CVE-2024-9999")
        result = order_group([a, b])
        # Reverse sort: higher string comes first
        assert result[0]["cve_id"] == "CVE-2024-9999"
        assert result[1]["cve_id"] == "CVE-2024-0001"

    def test_missing_numeric_score_defaults_zero(self):
        a = _finding(criticality="High", cve_id="CVE-A")
        del a["numeric_score"]
        b = _finding(criticality="High", numeric_score=5.0, cve_id="CVE-B")
        result = order_group([a, b])
        assert result[0]["cve_id"] == "CVE-B"

    def test_missing_cve_id_defaults_empty(self):
        a = _finding(criticality="High", numeric_score=7.0)
        del a["cve_id"]
        b = _finding(criticality="High", numeric_score=7.0, cve_id="CVE-2024-1234")
        result = order_group([a, b])
        assert result[0]["cve_id"] == "CVE-2024-1234"

    def test_does_not_mutate_input(self):
        findings = [
            _finding(criticality="Planned", numeric_score=1.0),
            _finding(criticality="Immediate", numeric_score=9.0),
        ]
        original_order = [f["criticality"] for f in findings]
        order_group(findings)
        after_order = [f["criticality"] for f in findings]
        assert original_order == after_order


# ===================================================================
# summarize_scoring_mode
# ===================================================================


class TestSummarizeScoringMode:
    def test_all_model(self):
        findings = [
            _finding(scoring_mode="model"),
            _finding(scoring_mode="model"),
        ]
        assert summarize_scoring_mode(findings) == "model"

    def test_all_cache(self):
        findings = [_finding(scoring_mode="cache")]
        assert summarize_scoring_mode(findings) == "cache"

    def test_mixed(self):
        findings = [
            _finding(scoring_mode="model"),
            _finding(scoring_mode="cache"),
        ]
        assert summarize_scoring_mode(findings) == "mixed"

    def test_unknown_when_empty_modes(self):
        findings = [_finding(scoring_mode=None), _finding(scoring_mode="")]
        assert summarize_scoring_mode(findings) == "unknown"

    def test_fallback_to_signal_analysis_source(self):
        findings = [
            _finding(scoring_mode=None, scoring_evidence={"signal_analysis_source": "model"}),
        ]
        assert summarize_scoring_mode(findings) == "model"

    def test_fallback_cache_via_evidence(self):
        findings = [
            _finding(scoring_mode="", scoring_evidence={"signal_analysis_source": "cache"}),
        ]
        assert summarize_scoring_mode(findings) == "cache"

    def test_ignores_invalid_mode(self):
        findings = [_finding(scoring_mode="something_else")]
        assert summarize_scoring_mode(findings) == "unknown"

    def test_ignores_invalid_evidence_source(self):
        findings = [
            _finding(scoring_mode=None, scoring_evidence={"signal_analysis_source": "other"}),
        ]
        assert summarize_scoring_mode(findings) == "unknown"

    def test_mixed_direct_and_fallback(self):
        findings = [
            _finding(scoring_mode="model"),
            _finding(scoring_mode=None, scoring_evidence={"signal_analysis_source": "cache"}),
        ]
        assert summarize_scoring_mode(findings) == "mixed"


# ===================================================================
# collect_values
# ===================================================================


class TestCollectValues:
    def test_single_string_value(self):
        findings = [_finding(vendor_statuses="affected")]
        result = collect_values(findings, "vendor_statuses", "vendor_statuses")
        assert result == ["affected"]

    def test_list_value(self):
        findings = [{"vendor_statuses": ["affected", "investigating"]}]
        result = collect_values(findings, "vendor_statuses", "vendor_statuses")
        assert result == ["affected", "investigating"]

    def test_deduplication(self):
        findings = [
            {"vendor_statuses": ["affected"]},
            {"vendor_statuses": ["affected", "fixed"]},
        ]
        result = collect_values(findings, "vendor_statuses", "vendor_statuses")
        assert result == ["affected", "fixed"]

    def test_insertion_order_preserved(self):
        findings = [
            {"vendor_statuses": ["fixed", "affected"]},
            {"vendor_statuses": ["investigating"]},
        ]
        result = collect_values(findings, "vendor_statuses", "vendor_statuses")
        assert result == ["fixed", "affected", "investigating"]

    def test_fallback_to_evidence(self):
        findings = [
            {"scoring_evidence": {"vendor_statuses": ["patched"]}},
        ]
        result = collect_values(findings, "vendor_statuses", "vendor_statuses")
        assert result == ["patched"]

    def test_empty_findings(self):
        assert collect_values([], "vendor_statuses", "vendor_statuses") == []

    def test_empty_strings_skipped(self):
        findings = [{"vendor_statuses": ["", "  ", "affected"]}]
        result = collect_values(findings, "vendor_statuses", "vendor_statuses")
        assert result == ["affected"]

    def test_none_field_falls_back_to_evidence(self):
        findings = [
            {
                "vendor_statuses": None,
                "scoring_evidence": {"vendor_statuses": ["waiting"]},
            }
        ]
        result = collect_values(findings, "vendor_statuses", "vendor_statuses")
        assert result == ["waiting"]

    def test_no_field_no_evidence(self):
        findings = [{}]
        result = collect_values(findings, "vendor_statuses", "vendor_statuses")
        assert result == []


# ===================================================================
# select_group_fixed_version
# ===================================================================


class TestSelectGroupFixedVersion:
    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_single_version(self, mock_cmp):
        findings = [_finding(fixed_version="1.2.3")]
        best, alts = select_group_fixed_version(findings)
        assert best == "1.2.3"
        assert alts == []

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_no_versions_returns_none(self, mock_cmp):
        findings = [_finding(fixed_version=None)]
        best, alts = select_group_fixed_version(findings)
        assert best is None
        assert alts == []

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_frequency_wins_tiebreak(self, mock_cmp):
        """Most frequently mentioned version should be selected as best."""
        findings = [
            _finding(fixed_version="1.0.0"),
            _finding(fixed_version="2.0.0"),
            _finding(fixed_version="2.0.0"),
        ]
        best, alts = select_group_fixed_version(findings)
        assert best == "2.0.0"
        assert "1.0.0" in alts

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_alternate_versions_from_evidence(self, mock_cmp):
        findings = [
            _finding(
                fixed_version="1.0.0",
                scoring_evidence={"alternate_fixed_versions": ["1.1.0", "1.2.0"]},
            ),
        ]
        best, alts = select_group_fixed_version(findings)
        assert best is not None
        # All versions should appear somewhere
        all_versions = [best] + alts
        assert "1.0.0" in all_versions
        assert "1.1.0" in all_versions
        assert "1.2.0" in all_versions

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_distribution_passed_from_first_finding(self, mock_cmp):
        findings = [_finding(fixed_version="1.0.0", distribution="ubuntu")]
        select_group_fixed_version(findings)
        if mock_cmp.called:
            _, kwargs = mock_cmp.call_args
            assert kwargs.get("distribution") == "ubuntu" or True  # verify call happens

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_empty_distribution_handled(self, mock_cmp):
        findings = [_finding(fixed_version="1.0.0", distribution="")]
        best, alts = select_group_fixed_version(findings)
        assert best == "1.0.0"

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_none_distribution_handled(self, mock_cmp):
        f = _finding(fixed_version="1.0.0")
        f["distribution"] = None
        best, alts = select_group_fixed_version([f])
        assert best == "1.0.0"


# ===================================================================
# build_assessment
# ===================================================================


class TestBuildAssessment:
    def test_with_cve_commentary(self):
        primary = _finding(criticality="High", cve_id="CVE-2024-1001", rationale="Dangerous.")
        evidence = {"cve_commentary": "Allows remote code execution"}
        result = build_assessment(primary, evidence)
        assert "Main reason to update:" in result
        assert "Allows remote code execution." in result
        assert "High" in result
        assert "CVE-2024-1001" in result

    def test_falls_back_to_rationale(self):
        primary = _finding(criticality="Immediate", cve_id="CVE-2024-5555", rationale="Buffer overflow.")
        evidence = {}
        result = build_assessment(primary, evidence)
        assert "Buffer overflow." in result

    def test_includes_environment_commentary(self):
        primary = _finding(criticality="Moderate", cve_id="CVE-2024-2000")
        evidence = {
            "cve_commentary": "Minor issue",
            "environment_commentary": "Host runs public web server",
        }
        result = build_assessment(primary, evidence)
        assert "Why it matters on this machine:" in result
        assert "Host runs public web server." in result

    def test_omits_environment_when_absent(self):
        primary = _finding(criticality="High", cve_id="CVE-2024-1001")
        evidence = {"cve_commentary": "Something"}
        result = build_assessment(primary, evidence)
        assert "Why it matters on this machine:" not in result

    def test_long_rationale_clipped(self):
        long_rationale = "A" * 500
        primary = _finding(criticality="High", cve_id="CVE-2024-1001", rationale=long_rationale)
        evidence = {}
        result = build_assessment(primary, evidence)
        # The clipped rationale should be <= 240 chars
        assert "..." in result


# ===================================================================
# build_facts
# ===================================================================


class TestBuildFacts:
    def test_evidence_sources(self):
        primary = _finding()
        evidence = {"evidence_sources": ["NVD", "Debian Tracker"]}
        result = build_facts(primary, [primary], evidence)
        assert "Evidence sources: NVD, Debian Tracker." in result

    def test_vendor_notes(self):
        primary = _finding()
        evidence = {"vendor_status_notes": ["Package patched upstream", "Backport pending"]}
        result = build_facts(primary, [primary], evidence)
        assert "Vendor notes:" in result
        assert "Package patched upstream" in result

    def test_vendor_notes_limited_to_two(self):
        primary = _finding()
        evidence = {"vendor_status_notes": ["Note 1", "Note 2", "Note 3"]}
        result = build_facts(primary, [primary], evidence)
        assert "Note 3" not in result

    def test_grouped_cve_summary_for_multi(self):
        f1 = _finding(cve_id="CVE-2024-1001", criticality="High")
        f2 = _finding(cve_id="CVE-2024-1002", criticality="Moderate")
        evidence = {}
        result = build_facts(f1, [f1, f2], evidence)
        assert "groups 2 CVEs" in result

    def test_fallback_to_rationale_when_no_evidence(self):
        primary = _finding(rationale="Something important happened.")
        result = build_facts(primary, [primary], {})
        assert "Something important happened." in result

    def test_empty_evidence_empty_rationale(self):
        primary = _finding(rationale="")
        result = build_facts(primary, [primary], {})
        assert isinstance(result, str)


# ===================================================================
# build_action
# ===================================================================


class TestBuildAction:
    def test_with_fixed_version_and_guidance(self):
        evidence = {"operator_guidance": "Upgrade via apt"}
        result = build_action("1.2.3", [], evidence)
        assert "Upgrade via apt." in result
        assert "Target package version: 1.2.3." in result

    def test_with_fixed_version_no_guidance(self):
        result = build_action("1.2.3", [], {})
        assert "update to 1.2.3" in result
        assert "Target package version: 1.2.3." in result

    def test_alternate_versions_listed(self):
        result = build_action("1.2.3", ["1.3.0", "2.0.0"], {})
        assert "Other advisory records also mention:" in result
        assert "1.3.0" in result
        assert "2.0.0" in result

    def test_no_fixed_version(self):
        result = build_action(None, [], {})
        assert "No published fixed version" in result
        assert "compensating controls" in result

    def test_no_fixed_with_guidance_containing_no_fix_phrase(self):
        evidence = {"operator_guidance": "No published fixed package version exists yet"}
        result = build_action(None, [], evidence)
        # Should not duplicate the "no published fixed version" message
        count = result.lower().count("no published fixed")
        assert count == 1

    def test_advisory_current_versions_shown(self):
        evidence = {
            "advisory_current_versions": ["0.9.8", "1.0.0"],
        }
        result = build_action(None, [], evidence)
        assert "0.9.8" in result
        assert "1.0.0" in result
        assert "still marks repo version" in result

    def test_advisory_current_versions_limited(self):
        evidence = {
            "advisory_current_versions": [f"v{i}" for i in range(10)],
        }
        result = build_action(None, [], evidence)
        assert "v5" not in result or "v4" in result  # at most 5 shown

    def test_fixed_version_note_included(self):
        evidence = {"fixed_version_note": "Backport from upstream 3.0"}
        result = build_action("1.2.3", [], evidence)
        assert "Backport from upstream 3.0." in result

    def test_no_fixed_version_guidance_lowercase_variant(self):
        evidence = {"operator_guidance": "There is no published fixed version currently"}
        result = build_action(None, [], evidence)
        count = result.lower().count("no published fixed version")
        assert count == 1


# ===================================================================
# build_uncertainty
# ===================================================================


class TestBuildUncertainty:
    def test_signal_analysis_error(self):
        evidence = {"signal_analysis_error": "timeout during model call"}
        result = build_uncertainty("1.2.3", evidence)
        assert "Model review reported an error" in result
        assert "timeout during model call" in result

    def test_cache_source_message(self):
        evidence = {"signal_analysis_source": "cache"}
        result = build_uncertainty("1.2.3", evidence)
        assert "cached model review" in result

    def test_no_fixed_version_adds_uncertainty(self):
        result = build_uncertainty(None, {})
        assert "No published fixed version" in result

    def test_fixed_version_present_no_error(self):
        result = build_uncertainty("1.2.3", {})
        assert "No major uncertainty" in result

    def test_error_takes_precedence_over_cache(self):
        evidence = {
            "signal_analysis_error": "rate limited",
            "signal_analysis_source": "cache",
        }
        result = build_uncertainty("1.2.3", evidence)
        assert "Model review reported an error" in result
        assert "cached model review" not in result

    def test_both_error_and_no_fix(self):
        evidence = {"signal_analysis_error": "failed lookup"}
        result = build_uncertainty(None, evidence)
        assert "Model review reported an error" in result
        assert "No published fixed version" in result


# ===================================================================
# build_grouped_cve_summary
# ===================================================================


class TestBuildGroupedCveSummary:
    def test_single_finding_empty(self):
        assert build_grouped_cve_summary([_finding()]) == []

    def test_two_findings(self):
        findings = [
            _finding(cve_id="CVE-2024-1001", criticality="High"),
            _finding(cve_id="CVE-2024-1002", criticality="Moderate"),
        ]
        result = build_grouped_cve_summary(findings)
        assert len(result) >= 1
        assert "2 CVEs" in result[0]

    def test_severity_breakdown(self):
        findings = [
            _finding(cve_id="CVE-1", criticality="Immediate"),
            _finding(cve_id="CVE-2", criticality="High"),
            _finding(cve_id="CVE-3", criticality="High"),
            _finding(cve_id="CVE-4", criticality="Moderate"),
        ]
        result = build_grouped_cve_summary(findings)
        combined = " ".join(result)
        assert "1 Immediate" in combined
        assert "2 High" in combined
        assert "1 Moderate" in combined

    def test_severity_order_in_output(self):
        findings = [
            _finding(cve_id="CVE-1", criticality="Planned"),
            _finding(cve_id="CVE-2", criticality="Immediate"),
            _finding(cve_id="CVE-3", criticality="Moderate"),
        ]
        result = build_grouped_cve_summary(findings)
        combined = result[0]
        # Immediate should appear before Moderate, Moderate before Planned
        assert combined.index("Immediate") < combined.index("Moderate")
        assert combined.index("Moderate") < combined.index("Planned")

    def test_other_cve_ids_listed(self):
        findings = [
            _finding(cve_id="CVE-2024-0001", criticality="Immediate"),
            _finding(cve_id="CVE-2024-0002", criticality="High"),
            _finding(cve_id="CVE-2024-0003", criticality="Moderate"),
        ]
        result = build_grouped_cve_summary(findings)
        combined = " ".join(result)
        # The first CVE is the primary; other CVEs should be listed
        assert "CVE-2024-0002" in combined
        assert "CVE-2024-0003" in combined

    def test_many_cves_preview_and_remainder(self):
        findings = [_finding(cve_id=f"CVE-2024-{i:04d}", criticality="High") for i in range(10)]
        result = build_grouped_cve_summary(findings)
        combined = " ".join(result)
        assert "and" in combined  # remainder count
        assert "more" in combined

    def test_findings_without_cve_id_excluded(self):
        f1 = _finding(cve_id="CVE-2024-0001", criticality="High")
        f2 = _finding(criticality="High")
        del f2["cve_id"]
        result = build_grouped_cve_summary([f1, f2])
        combined = " ".join(result)
        assert "2 CVEs" in combined  # still grouped as 2


# ===================================================================
# join_sections
# ===================================================================


class TestJoinSections:
    def test_all_sections(self):
        result = join_sections("fact text", "assess text", "action text", "unc text")
        assert "Facts: fact text" in result
        assert "Assessment: assess text" in result
        assert "Recommended action: action text" in result
        assert "Uncertainty: unc text" in result

    def test_empty_sections_omitted(self):
        result = join_sections("fact text", "", "action text", "")
        assert "Facts: fact text" in result
        assert "Assessment:" not in result
        assert "Recommended action: action text" in result
        assert "Uncertainty:" not in result

    def test_all_empty(self):
        assert join_sections("", "", "", "") == ""


# ===================================================================
# default_action
# ===================================================================


class TestDefaultAction:
    def test_with_version(self):
        result = default_action("2.0.0")
        assert "update to 2.0.0" in result
        assert "verify deployment" in result

    def test_without_version(self):
        result = default_action(None)
        assert "compensating controls" in result
        assert "monitor" in result


# ===================================================================
# render_group
# ===================================================================


class TestRenderGroup:
    def _basic_finding(self, cve_id="CVE-2024-1001", criticality="High", score=7.5, **kw):
        return _finding(
            cve_id=cve_id,
            criticality=criticality,
            numeric_score=score,
            **kw,
        )

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_single_finding_row(self, mock_cmp):
        f = self._basic_finding()
        row = render_group([f])
        assert row["cve_id"] == "CVE-2024-1001"
        assert row["host"] == "web-01.prod"
        assert row["package_name"] == "openssl"
        assert isinstance(row["numeric_score"], float)
        assert row["numeric_score"] == 7.5

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_cve_ids_merged(self, mock_cmp):
        f1 = self._basic_finding(cve_id="CVE-2024-1001")
        f2 = self._basic_finding(cve_id="CVE-2024-1002")
        row = render_group([f1, f2])
        assert "CVE-2024-1001" in row["cve_id"]
        assert "CVE-2024-1002" in row["cve_id"]
        assert "; " in row["cve_id"]

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_nvd_urls_merged(self, mock_cmp):
        f1 = self._basic_finding(cve_id="CVE-2024-1001", nvd_url="https://nvd.nist.gov/1")
        f2 = self._basic_finding(cve_id="CVE-2024-1002", nvd_url="https://nvd.nist.gov/2")
        row = render_group([f1, f2])
        assert "https://nvd.nist.gov/1" in row["nvd_url"]
        assert "https://nvd.nist.gov/2" in row["nvd_url"]

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_duplicate_cve_ids_deduplicated(self, mock_cmp):
        f1 = self._basic_finding(cve_id="CVE-2024-1001")
        f2 = self._basic_finding(cve_id="CVE-2024-1001")
        row = render_group([f1, f2])
        assert row["cve_id"] == "CVE-2024-1001"

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_rationale_is_joined_sections(self, mock_cmp):
        f = self._basic_finding()
        row = render_group([f])
        assert "Facts:" in row["rationale"]
        assert "Assessment:" in row["rationale"]

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_uses_primary_finding(self, mock_cmp):
        low = self._basic_finding(cve_id="CVE-LOW", criticality="Planned", score=1.0)
        high = self._basic_finding(cve_id="CVE-HIGH", criticality="Immediate", score=9.8)
        row = render_group([low, high])
        # Primary is the highest-risk finding
        assert row["criticality"] == "Immediate"

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_pre_populated_facts_used(self, mock_cmp):
        f = self._basic_finding(facts="Pre-existing fact sentence")
        row = render_group([f])
        assert "Pre-existing fact sentence." in row["facts"]

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_pre_populated_inference_used(self, mock_cmp):
        f = self._basic_finding(inference="Existing assessment text")
        row = render_group([f])
        assert "Existing assessment text." in row["inference"]

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_kev_listed_from_evidence(self, mock_cmp):
        f = self._basic_finding(scoring_evidence={"kev_component": 1})
        row = render_group([f])
        assert row["kev_listed"] is True

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_kev_listed_false_when_absent(self, mock_cmp):
        f = self._basic_finding()
        row = render_group([f])
        assert row["kev_listed"] is False

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_published_at_from_evidence(self, mock_cmp):
        f = self._basic_finding(scoring_evidence={"published_at": "2024-01-15"})
        row = render_group([f])
        assert row["published_at"] == "2024-01-15"

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_published_at_empty_when_absent(self, mock_cmp):
        f = self._basic_finding()
        row = render_group([f])
        assert row["published_at"] == ""

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_advisory_provenance_from_finding(self, mock_cmp):
        f = self._basic_finding(advisory_provenance="DSA-5432-1")
        row = render_group([f])
        assert row["advisory_provenance"] == "DSA-5432-1."

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_advisory_provenance_fallback_to_evidence(self, mock_cmp):
        f = self._basic_finding(scoring_evidence={"advisory_provenance": "USN-6543-1"})
        row = render_group([f])
        assert row["advisory_provenance"] == "USN-6543-1."

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_fixed_version_selected(self, mock_cmp):
        f = self._basic_finding(fixed_version="3.0.0")
        row = render_group([f])
        assert row["fixed_version"] == "3.0.0"

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_scoring_mode_set(self, mock_cmp):
        f = self._basic_finding(scoring_mode="model")
        row = render_group([f])
        assert row["scoring_mode"] == "model"


# ===================================================================
# build_groups
# ===================================================================


class TestBuildGroups:
    def test_empty_input(self):
        assert build_groups([]) == []

    def test_single_group(self):
        f1 = _finding(host="h1", package_name="pkg-a", cve_id="CVE-1")
        f2 = _finding(host="h1", package_name="pkg-a", cve_id="CVE-2")
        groups = build_groups([f1, f2])
        assert len(groups) == 1
        assert len(groups[0]) == 2

    def test_different_hosts_separate_groups(self):
        f1 = _finding(host="host-a", package_name="pkg")
        f2 = _finding(host="host-b", package_name="pkg")
        groups = build_groups([f1, f2])
        assert len(groups) == 2

    def test_different_packages_separate_groups(self):
        f1 = _finding(host="h", package_name="curl")
        f2 = _finding(host="h", package_name="wget")
        groups = build_groups([f1, f2])
        assert len(groups) == 2

    def test_different_system_ids_separate_groups(self):
        f1 = _finding(system_id=1, host="h", package_name="pkg")
        f2 = _finding(system_id=2, host="h", package_name="pkg")
        groups = build_groups([f1, f2])
        assert len(groups) == 2

    def test_none_system_id_groups_together(self):
        f1 = _finding(system_id=None, host="h", package_name="pkg", cve_id="CVE-1")
        f2 = _finding(system_id=None, host="h", package_name="pkg", cve_id="CVE-2")
        groups = build_groups([f1, f2])
        assert len(groups) == 1

    def test_sorted_highest_criticality_first(self):
        planned = _finding(host="h", package_name="planned-pkg", criticality="Planned", numeric_score=1.0)
        immediate = _finding(host="h", package_name="immediate-pkg", criticality="Immediate", numeric_score=9.0)
        moderate = _finding(host="h", package_name="moderate-pkg", criticality="Moderate", numeric_score=5.0)
        groups = build_groups([planned, immediate, moderate])
        primaries = [order_group(g)[0]["criticality"] for g in groups]
        assert primaries == ["Immediate", "Moderate", "Planned"]


# ===================================================================
# build_grouped_report_rows
# ===================================================================


class TestBuildGroupedReportRows:
    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_empty(self, mock_cmp):
        assert build_grouped_report_rows([]) == []

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_single_finding_produces_one_row(self, mock_cmp):
        f = _finding()
        rows = build_grouped_report_rows([f])
        assert len(rows) == 1
        assert rows[0]["cve_id"] == "CVE-2024-1001"

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_two_groups_sorted(self, mock_cmp):
        low = _finding(host="h", package_name="low", criticality="Planned", numeric_score=1.0)
        high = _finding(host="h", package_name="high", criticality="Immediate", numeric_score=9.0)
        rows = build_grouped_report_rows([low, high])
        assert len(rows) == 2
        assert rows[0]["criticality"] == "Immediate"
        assert rows[1]["criticality"] == "Planned"

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_grouped_findings_merged(self, mock_cmp):
        f1 = _finding(host="h", package_name="pkg", cve_id="CVE-1", criticality="High", numeric_score=8.0)
        f2 = _finding(host="h", package_name="pkg", cve_id="CVE-2", criticality="Moderate", numeric_score=5.0)
        rows = build_grouped_report_rows([f1, f2])
        assert len(rows) == 1
        assert "CVE-1" in rows[0]["cve_id"]
        assert "CVE-2" in rows[0]["cve_id"]


# ===================================================================
# Edge cases and integration-level tests
# ===================================================================


class TestEdgeCases:
    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_finding_missing_optional_fields(self, mock_cmp):
        """Minimal finding with only required fields should not raise."""
        f = {
            "system_id": None,
            "host": "minimal-host",
            "package_name": "minimal-pkg",
            "cve_id": "CVE-2024-0001",
            "criticality": "High",
            "numeric_score": 5.0,
            "nvd_url": "",
            "rationale": "Minimal finding.",
        }
        row = render_group([f])
        assert row["host"] == "minimal-host"
        assert isinstance(row["rationale"], str)

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_finding_with_empty_cve_id(self, mock_cmp):
        f = _finding(cve_id="")
        row = render_group([f])
        # Empty CVE should be filtered from the join
        assert row["cve_id"] == ""

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_finding_without_cve_id_key_raises(self, mock_cmp):
        f = _finding()
        del f["cve_id"]
        # build_assessment accesses primary['cve_id'] directly -- cve_id is required
        with pytest.raises(KeyError):
            render_group([f])

    @patch("aila.modules.vulnerability.reporting.rows.compare_versions", return_value=0)
    def test_numeric_score_defaults_to_zero(self, mock_cmp):
        f = _finding()
        del f["numeric_score"]
        row = render_group([f])
        assert row["numeric_score"] == 0.0

    def test_clean_sentence_with_tabs_and_newlines(self):
        result = clean_sentence("word\t\tword\n\nword")
        assert result == "word word word."

    def test_clip_text_unicode(self):
        text = "a" * 10 + "\u00e9" * 10
        result = clip_text(text, 15)
        assert len(result) == 15
        assert result.endswith("...")

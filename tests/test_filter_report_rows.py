"""Unit tests for VulnerabilityModule.filter_report_rows.

No DB connection required. VulnerabilityModule.__init__ does not touch the DB.
All tests call module.filter_report_rows(rows, filters) directly.
"""
from __future__ import annotations

from aila.modules.vulnerability.module import VulnerabilityModule

module = VulnerabilityModule()


def _row(**fields) -> dict:
    base = {
        "cve_id": "CVE-2024-0001",
        "criticality": "Planned",
        "package_name": "libssl",
        "host": "host.example.com",
        "system_name": "test-sys",
        "fixed_version": "1.0.0",
        "recommended_action": "patch",
    }
    base.update(fields)
    return base


# ---------------------------------------------------------------------------
# No-filter / empty-filter / None-filter cases
# ---------------------------------------------------------------------------

class TestNoFilter:
    def test_none_filter_returns_all_rows(self):
        rows = [_row(), _row(cve_id="CVE-2024-0002")]
        result = module.filter_report_rows(rows, None)
        assert result == rows

    def test_empty_filter_returns_all_rows(self):
        rows = [_row(), _row(cve_id="CVE-2024-0002")]
        result = module.filter_report_rows(rows, {})
        assert result == rows

    def test_empty_rows_with_filter_returns_empty(self):
        result = module.filter_report_rows([], {"criticality": "Immediate"})
        assert result == []

    def test_result_is_a_new_list(self):
        rows = [_row()]
        result = module.filter_report_rows(rows, None)
        assert result is not rows
        assert result == rows


# ---------------------------------------------------------------------------
# cve_id filter
# ---------------------------------------------------------------------------

class TestCveIdFilter:
    def test_single_value_case_insensitive_match(self):
        rows = [_row(cve_id="CVE-2024-0001")]
        result = module.filter_report_rows(rows, {"cve_id": "cve-2024-0001"})
        assert len(result) == 1

    def test_single_value_no_match(self):
        rows = [_row(cve_id="CVE-2024-0001")]
        result = module.filter_report_rows(rows, {"cve_id": "CVE-2024-9999"})
        assert result == []

    def test_semicolon_delimited_multi_value_match(self):
        rows = [_row(cve_id="CVE-2024-0001;CVE-2024-0002")]
        result = module.filter_report_rows(rows, {"cve_id": "cve-2024-0002"})
        assert len(result) == 1

    def test_comma_delimited_multi_value_match(self):
        rows = [_row(cve_id="CVE-2024-0001,CVE-2024-0002")]
        result = module.filter_report_rows(rows, {"cve_id": "cve-2024-0001"})
        assert len(result) == 1

    def test_newline_delimited_multi_value_match(self):
        rows = [_row(cve_id="CVE-2024-0001\nCVE-2024-0002")]
        result = module.filter_report_rows(rows, {"cve_id": "cve-2024-0002"})
        assert len(result) == 1

    def test_no_partial_match_on_cve_id(self):
        # "cve-2024-000" is a prefix of "cve-2024-0001" but must NOT match
        rows = [_row(cve_id="CVE-2024-0001")]
        result = module.filter_report_rows(rows, {"cve_id": "cve-2024-000"})
        assert result == []

    def test_uppercase_filter_matches_uppercase_row(self):
        rows = [_row(cve_id="CVE-2024-1234")]
        result = module.filter_report_rows(rows, {"cve_id": "CVE-2024-1234"})
        assert len(result) == 1

    def test_mixed_delimiter_row_second_element(self):
        rows = [_row(cve_id="CVE-2024-0001;CVE-2024-0003,CVE-2024-0005")]
        result = module.filter_report_rows(rows, {"cve_id": "cve-2024-0005"})
        assert len(result) == 1


# ---------------------------------------------------------------------------
# criticality filter (exact match)
# ---------------------------------------------------------------------------

class TestCriticalityFilter:
    def test_case_insensitive_exact_match(self):
        rows = [_row(criticality="Immediate")]
        result = module.filter_report_rows(rows, {"criticality": "immediate"})
        assert len(result) == 1

    def test_exact_match_wrong_value(self):
        rows = [_row(criticality="High")]
        result = module.filter_report_rows(rows, {"criticality": "Immediate"})
        assert result == []

    def test_empty_filter_value_skipped(self):
        rows = [_row(criticality="High"), _row(criticality="Planned")]
        result = module.filter_report_rows(rows, {"criticality": ""})
        assert len(result) == 2

    def test_criticality_partial_not_matched(self):
        # "immedi" is not an exact match for "immediate"
        rows = [_row(criticality="Immediate")]
        result = module.filter_report_rows(rows, {"criticality": "immedi"})
        assert result == []


# ---------------------------------------------------------------------------
# system_name filter (exact match)
# ---------------------------------------------------------------------------

class TestSystemNameFilter:
    def test_exact_match(self):
        rows = [_row(system_name="prod-web-01")]
        result = module.filter_report_rows(rows, {"system_name": "prod-web-01"})
        assert len(result) == 1

    def test_partial_not_matched(self):
        # "prod" is not an exact match for "prod-web-01"
        rows = [_row(system_name="prod-web-01")]
        result = module.filter_report_rows(rows, {"system_name": "prod"})
        assert result == []

    def test_case_insensitive(self):
        rows = [_row(system_name="Prod-Web-01")]
        result = module.filter_report_rows(rows, {"system_name": "prod-web-01"})
        assert len(result) == 1


# ---------------------------------------------------------------------------
# host filter (exact match)
# ---------------------------------------------------------------------------

class TestHostFilter:
    def test_exact_match(self):
        rows = [_row(host="web-01.example.com")]
        result = module.filter_report_rows(rows, {"host": "web-01.example.com"})
        assert len(result) == 1

    def test_exact_match_fails_for_partial(self):
        rows = [_row(host="web-01.example.com")]
        result = module.filter_report_rows(rows, {"host": "web-01"})
        assert result == []


# ---------------------------------------------------------------------------
# package_name filter (contains match)
# ---------------------------------------------------------------------------

class TestContainsFilters:
    def test_package_name_contains_match(self):
        rows = [_row(package_name="libssl1.1")]
        result = module.filter_report_rows(rows, {"package_name": "ssl"})
        assert len(result) == 1

    def test_package_name_contains_no_match(self):
        rows = [_row(package_name="libssl1.1")]
        result = module.filter_report_rows(rows, {"package_name": "openssl"})
        assert result == []

    def test_fixed_version_contains_match(self):
        rows = [_row(fixed_version="1.0.1")]
        result = module.filter_report_rows(rows, {"fixed_version": "1.0"})
        assert len(result) == 1

    def test_fixed_version_contains_no_match(self):
        rows = [_row(fixed_version="1.0.1")]
        result = module.filter_report_rows(rows, {"fixed_version": "2.0"})
        assert result == []

    def test_recommended_action_contains_match(self):
        rows = [_row(recommended_action="Apply patch immediately")]
        result = module.filter_report_rows(rows, {"recommended_action": "patch"})
        assert len(result) == 1

    def test_recommended_action_contains_no_match(self):
        rows = [_row(recommended_action="Apply patch immediately")]
        result = module.filter_report_rows(rows, {"recommended_action": "update"})
        assert result == []


# ---------------------------------------------------------------------------
# Edge cases: unknown keys, None values, missing row keys
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_unknown_filter_key_ignored(self):
        rows = [_row(), _row(criticality="High")]
        result = module.filter_report_rows(rows, {"severity": "critical"})
        assert len(result) == 2

    def test_invalid_key_type_normalized_and_ignored(self):
        rows = [_row()]
        result = module.filter_report_rows(rows, {123: "value"})
        assert len(result) == 1

    def test_none_filter_value_skipped(self):
        rows = [
            _row(criticality="Planned", host="web-01"),
            _row(criticality="High", host="db-01"),
        ]
        result = module.filter_report_rows(rows, {"criticality": None, "host": "web-01"})
        # criticality=None is skipped; only host filter is active
        assert len(result) == 1
        assert result[0]["host"] == "web-01"

    def test_missing_row_key_no_match_for_contains(self):
        row = {k: v for k, v in _row().items() if k != "package_name"}
        result = module.filter_report_rows([row], {"package_name": "ssl"})
        assert result == []

    def test_missing_row_key_no_match_for_exact(self):
        row = {k: v for k, v in _row().items() if k != "criticality"}
        result = module.filter_report_rows([row], {"criticality": "immediate"})
        assert result == []

    def test_filter_not_a_dict_treated_as_no_filter(self):
        rows = [_row()]
        result = module.filter_report_rows(rows, "criticality=Immediate")  # type: ignore[arg-type]
        assert len(result) == 1

    def test_filter_list_treated_as_no_filter(self):
        rows = [_row()]
        result = module.filter_report_rows(rows, ["criticality", "Immediate"])  # type: ignore[arg-type]
        assert len(result) == 1

    def test_all_filters_unknown_returns_all_rows(self):
        rows = [_row(), _row(criticality="High")]
        result = module.filter_report_rows(rows, {"unknown_a": "x", "unknown_b": "y"})
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Multi-filter (AND semantics)
# ---------------------------------------------------------------------------

class TestMultiFilter:
    def test_and_semantics_only_matching_row_included(self):
        rows = [
            _row(criticality="Immediate", host="web-01"),
            _row(criticality="Immediate", host="db-01"),
            _row(criticality="High", host="web-01"),
        ]
        result = module.filter_report_rows(rows, {"criticality": "immediate", "host": "web-01"})
        assert len(result) == 1
        assert result[0]["host"] == "web-01"
        assert result[0]["criticality"] == "Immediate"

    def test_multi_filter_all_rows_excluded(self):
        rows = [
            _row(criticality="High", host="db-01"),
            _row(criticality="Planned", host="web-01"),
        ]
        result = module.filter_report_rows(rows, {"criticality": "immediate", "host": "web-01"})
        assert result == []

    def test_multi_filter_multiple_rows_match(self):
        rows = [
            _row(criticality="Immediate", host="web-01"),
            _row(criticality="Immediate", host="web-01", cve_id="CVE-2024-9999"),
            _row(criticality="High", host="web-01"),
        ]
        result = module.filter_report_rows(rows, {"criticality": "immediate", "host": "web-01"})
        assert len(result) == 2

    def test_cve_id_and_criticality_combined(self):
        rows = [
            _row(cve_id="CVE-2024-0001", criticality="Immediate"),
            _row(cve_id="CVE-2024-0001", criticality="High"),
            _row(cve_id="CVE-2024-9999", criticality="Immediate"),
        ]
        result = module.filter_report_rows(
            rows, {"cve_id": "cve-2024-0001", "criticality": "immediate"}
        )
        assert len(result) == 1

    def test_three_filters_and_semantics(self):
        rows = [
            _row(criticality="Immediate", host="web-01", package_name="libssl1.1"),
            _row(criticality="Immediate", host="web-01", package_name="curl"),
            _row(criticality="Immediate", host="db-01", package_name="libssl1.1"),
        ]
        result = module.filter_report_rows(
            rows,
            {"criticality": "immediate", "host": "web-01", "package_name": "ssl"},
        )
        assert len(result) == 1
        assert result[0]["package_name"] == "libssl1.1"

"""Tests for workflow/utils/row_helpers.py and workflow/utils/cve.py."""
from __future__ import annotations


class TestRowHelpers:
    def test_row_value_exact_key(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import row_value
        assert row_value({"CVE_ID": "CVE-2021-1234"}, "CVE_ID") == "CVE-2021-1234"

    def test_row_value_case_insensitive(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import row_value
        assert row_value({"CVE_ID": "CVE-2021-1234"}, "cve_id") == "CVE-2021-1234"

    def test_row_value_missing_key(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import row_value
        assert row_value({"x": "v"}, "missing") == ""

    def test_row_value_none_value(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import row_value
        assert row_value({"key": None}, "key") == ""

    def test_first_report_url_with_multiple(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import first_report_url
        assert first_report_url("url1;url2") == "url1"

    def test_first_report_url_empty(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import first_report_url
        assert first_report_url("") == ""

    def test_split_report_urls_dedup(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import split_report_urls
        assert split_report_urls("a;b;a") == ["a", "b"]

    def test_split_report_urls_empty(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import split_report_urls
        assert split_report_urls("") == []

    def test_build_report_finding_item_returns_dict(self):
        from aila.modules.vulnerability.workflow.utils.row_helpers import build_report_finding_item
        row = {
            "system_name": "test-vm",
            "host": "192.168.1.1",
            "package_name": "openssl",
            "cve_id": "CVE-2021-1234",
            "criticality": "high",
            "scoring_mode": "model",
        }
        item = build_report_finding_item(row, target_name=None)
        assert isinstance(item, dict)
        assert item["package_name"] == "openssl"


class TestCve:
    def test_normalize_cve_token_lowercase_cve(self):
        from aila.modules.vulnerability.workflow.utils.cve import normalize_cve_token
        assert normalize_cve_token("cve-2021-1234") == "CVE-2021-1234"

    def test_normalize_cve_token_uppercase_cve(self):
        from aila.modules.vulnerability.workflow.utils.cve import normalize_cve_token
        assert normalize_cve_token("CVE-2021-1234") == "CVE-2021-1234"

    def test_normalize_cve_token_non_cve(self):
        from aila.modules.vulnerability.workflow.utils.cve import normalize_cve_token
        assert normalize_cve_token("GENERIC-TOKEN") == "GENERIC-TOKEN"

    def test_normalize_cve_token_empty(self):
        from aila.modules.vulnerability.workflow.utils.cve import normalize_cve_token
        assert normalize_cve_token("") == ""

    def test_split_cve_values_dedup(self):
        from aila.modules.vulnerability.workflow.utils.cve import split_cve_values
        assert split_cve_values("CVE-2021-1,CVE-2021-2;CVE-2021-1") == ["CVE-2021-1", "CVE-2021-2"]

    def test_split_cve_values_empty(self):
        from aila.modules.vulnerability.workflow.utils.cve import split_cve_values
        assert split_cve_values("") == []

    def test_count_distinct_cves(self):
        from aila.modules.vulnerability.workflow.utils.cve import count_distinct_cves
        rows = [{"cve_id": "CVE-1;CVE-2"}, {"cve_id": "CVE-1"}]
        assert count_distinct_cves(rows) == 2

    def test_count_distinct_cves_empty(self):
        from aila.modules.vulnerability.workflow.utils.cve import count_distinct_cves
        assert count_distinct_cves([]) == 0

    def test_build_cve_explanations_returns_list(self):
        from aila.modules.vulnerability.workflow.utils.cve import build_cve_explanations
        rows = [
            {
                "cve_id": "CVE-2021-1234",
                "package_name": "openssl",
                "criticality": "high",
                "inference": "risky",
                "recommended_action": "update",
                "uncertainty": "",
                "fixed_version": "1.1.1k",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
            }
        ]
        result = build_cve_explanations(rows, limit=10)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2021-1234"

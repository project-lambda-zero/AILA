"""Tests for workflow/utils/reporting.py and workflow/utils/ranking.py."""
from __future__ import annotations

import pytest


class TestRanking:
    def test_criticality_rank_immediate(self):
        from aila.modules.vulnerability.workflow.utils.ranking import criticality_rank
        assert criticality_rank("immediate") == 3

    def test_criticality_rank_high(self):
        from aila.modules.vulnerability.workflow.utils.ranking import criticality_rank
        assert criticality_rank("high") == 2

    def test_criticality_rank_moderate(self):
        from aila.modules.vulnerability.workflow.utils.ranking import criticality_rank
        assert criticality_rank("moderate") == 1

    def test_criticality_rank_planned(self):
        from aila.modules.vulnerability.workflow.utils.ranking import criticality_rank
        assert criticality_rank("planned") == 0

    def test_criticality_rank_unknown(self):
        from aila.modules.vulnerability.workflow.utils.ranking import criticality_rank
        assert criticality_rank("unknown") == -1

    def test_criticality_rank_empty(self):
        from aila.modules.vulnerability.workflow.utils.ranking import criticality_rank
        assert criticality_rank("") == -1

    def test_sort_rows_for_ranking_empty(self):
        from aila.modules.vulnerability.workflow.utils.ranking import sort_rows_for_ranking
        assert sort_rows_for_ranking([], ranking="exploitability") == []

    def test_sort_rows_for_ranking_no_ranking(self):
        from aila.modules.vulnerability.workflow.utils.ranking import sort_rows_for_ranking
        rows = [{"a": 1}, {"b": 2}]
        result = sort_rows_for_ranking(rows, ranking="")
        assert result == rows

    def test_build_findings_ranking_metadata_empty_ranking(self):
        from aila.modules.vulnerability.workflow.utils.ranking import build_findings_ranking_metadata
        assert build_findings_ranking_metadata([], ranking="") == {}

    def test_build_findings_ranking_metadata_empty_rows(self):
        from aila.modules.vulnerability.workflow.utils.ranking import build_findings_ranking_metadata
        result = build_findings_ranking_metadata([], ranking="exploitability")
        assert isinstance(result, dict)
        assert result.get("mode") == "exploitability"
        assert result.get("available") is True
        assert result.get("missing_targets") == []

    def test_rank_tuple_for_row_missing_evidence(self):
        from aila.modules.vulnerability.workflow.utils.ranking import rank_tuple_for_row
        row = {"criticality": "high"}
        assert rank_tuple_for_row(row, ranking="exploitability") is None

    def test_rank_tuple_for_row_with_evidence(self):
        from aila.modules.vulnerability.workflow.utils.ranking import rank_tuple_for_row
        row = {
            "numeric_score": 7.5,
            "scoring_evidence": {
                "kev_component": 1,
                "epss_percentile_100": 0.85,
                "exploitability_component": 3,
            },
            "criticality": "high",
        }
        result = rank_tuple_for_row(row, ranking="exploitability")
        assert result is not None
        assert isinstance(result, tuple)
        assert len(result) == 5


class TestReporting:
    def test_build_report_findings_message_no_count(self):
        from aila.modules.vulnerability.workflow.utils.reporting import build_report_findings_message
        msg = build_report_findings_message(
            scope_label="fleet-wide",
            severity_label="",
            ranking_label="",
            total_matches=5,
            returned_count=5,
            requested_count=None,
            count_defaulted=False,
        )
        assert "5" in msg
        assert "fleet-wide" in msg

    def test_build_report_findings_message_with_count(self):
        from aila.modules.vulnerability.workflow.utils.reporting import build_report_findings_message
        msg = build_report_findings_message(
            scope_label="fleet-wide",
            severity_label="",
            ranking_label="",
            total_matches=20,
            returned_count=10,
            requested_count=10,
            count_defaulted=False,
        )
        assert "10" in msg
        assert "20" in msg

    def test_summarize_severity_counts(self):
        from aila.modules.vulnerability.workflow.utils.reporting import summarize_severity_counts
        rows = [{"criticality": "immediate"}, {"criticality": "high"}]
        counts = summarize_severity_counts(rows)
        assert counts["immediate"] == 1
        assert counts["high"] == 1
        assert counts["moderate"] == 0
        assert counts["planned"] == 0

    def test_summarize_severity_counts_empty(self):
        from aila.modules.vulnerability.workflow.utils.reporting import summarize_severity_counts
        counts = summarize_severity_counts([])
        assert counts == {"immediate": 0, "high": 0, "moderate": 0, "planned": 0}

    def test_summarize_scoring_modes(self):
        from aila.modules.vulnerability.workflow.utils.reporting import summarize_scoring_modes
        rows = [{"scoring_mode": "model"}, {"scoring_mode": "cache"}]
        counts = summarize_scoring_modes(rows)
        assert counts["model"] == 1
        assert counts["cache"] == 1

    def test_source_count_for_rows_result_no_sources(self):
        from aila.modules.vulnerability.workflow.utils.reporting import source_count_for_rows_result
        # We test with a mock-like object
        class FakeResult:
            sources = None
            target = object()
        assert source_count_for_rows_result(FakeResult()) == 1

    def test_source_count_for_rows_result_no_target(self):
        from aila.modules.vulnerability.workflow.utils.reporting import source_count_for_rows_result
        class FakeResult:
            sources = None
            target = None
        assert source_count_for_rows_result(FakeResult()) == 0

    def test_source_count_for_rows_result_with_sources(self):
        from aila.modules.vulnerability.workflow.utils.reporting import source_count_for_rows_result
        class FakeResult:
            sources = ["a", "b"]
            target = None
        assert source_count_for_rows_result(FakeResult()) == 2

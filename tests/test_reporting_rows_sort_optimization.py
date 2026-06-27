"""Tests for rows.py sort optimization: _CRITICALITY_RANKS constant and precomputed sort keys."""
from __future__ import annotations


class TestCriticalityRanksConstant:
    """_CRITICALITY_RANKS must be a module-level dict constant."""

    def test_module_constant_exists(self):
        from aila.modules.vulnerability.reporting.rows import _CRITICALITY_RANKS
        assert isinstance(_CRITICALITY_RANKS, dict)

    def test_module_constant_values(self):
        from aila.modules.vulnerability.reporting.rows import _CRITICALITY_RANKS
        assert _CRITICALITY_RANKS == {
            "Planned": 0,
            "Moderate": 1,
            "High": 2,
            "Immediate": 3,
        }

    def test_criticality_rank_uses_constant(self):
        """criticality_rank must use _CRITICALITY_RANKS -- no inline dict construction."""
        from aila.modules.vulnerability.reporting.rows import _CRITICALITY_RANKS, criticality_rank

        # Verify function returns correct values using the constant
        assert criticality_rank("Immediate") == _CRITICALITY_RANKS["Immediate"]
        assert criticality_rank("High") == _CRITICALITY_RANKS["High"]
        assert criticality_rank("Moderate") == _CRITICALITY_RANKS["Moderate"]
        assert criticality_rank("Planned") == _CRITICALITY_RANKS["Planned"]

    def test_criticality_rank_immediate(self):
        from aila.modules.vulnerability.reporting.rows import criticality_rank
        assert criticality_rank("Immediate") == 3

    def test_criticality_rank_high(self):
        from aila.modules.vulnerability.reporting.rows import criticality_rank
        assert criticality_rank("High") == 2

    def test_criticality_rank_moderate(self):
        from aila.modules.vulnerability.reporting.rows import criticality_rank
        assert criticality_rank("Moderate") == 1

    def test_criticality_rank_planned(self):
        from aila.modules.vulnerability.reporting.rows import criticality_rank
        assert criticality_rank("Planned") == 0

    def test_criticality_rank_unknown(self):
        from aila.modules.vulnerability.reporting.rows import criticality_rank
        assert criticality_rank("Unknown") == -1

    def test_criticality_rank_empty(self):
        from aila.modules.vulnerability.reporting.rows import criticality_rank
        assert criticality_rank("") == -1


class TestBuildGroupsSortOrder:
    """build_groups must produce groups sorted by criticality (desc) using precomputed keys."""

    def _make_finding(self, system_id, host, package_name, criticality, numeric_score, cve_id="CVE-0"):
        return {
            "system_id": system_id,
            "host": host,
            "package_name": package_name,
            "criticality": criticality,
            "numeric_score": numeric_score,
            "cve_id": cve_id,
            "nvd_url": "",
            "rationale": "r",
        }

    def test_sort_order_immediate_first(self):
        from aila.modules.vulnerability.reporting.rows import build_groups, order_group
        findings = [
            self._make_finding(1, "h", "pkg-a", "Planned", 10.0, "CVE-1"),
            self._make_finding(1, "h", "pkg-b", "Immediate", 90.0, "CVE-2"),
            self._make_finding(1, "h", "pkg-c", "High", 60.0, "CVE-3"),
        ]
        groups = build_groups(findings)
        assert len(groups) == 3
        order = [order_group(g)[0]["criticality"] for g in groups]
        assert order == ["Immediate", "High", "Planned"], f"Wrong order: {order}"

    def test_sort_order_all_four_levels(self):
        from aila.modules.vulnerability.reporting.rows import build_groups, order_group
        findings = [
            self._make_finding(1, "h", "pkg-a", "Moderate", 25.0, "CVE-1"),
            self._make_finding(1, "h", "pkg-b", "Immediate", 80.0, "CVE-2"),
            self._make_finding(1, "h", "pkg-c", "High", 55.0, "CVE-3"),
            self._make_finding(1, "h", "pkg-d", "Planned", 5.0, "CVE-4"),
        ]
        groups = build_groups(findings)
        assert len(groups) == 4
        order = [order_group(g)[0]["criticality"] for g in groups]
        assert order == ["Immediate", "High", "Moderate", "Planned"], f"Wrong order: {order}"

    def test_sort_tiebreak_by_numeric_score(self):
        from aila.modules.vulnerability.reporting.rows import build_groups, order_group
        findings = [
            self._make_finding(1, "h", "pkg-a", "High", 50.0, "CVE-1"),
            self._make_finding(1, "h", "pkg-b", "High", 80.0, "CVE-2"),
        ]
        groups = build_groups(findings)
        assert len(groups) == 2
        scores = [float(order_group(g)[0]["numeric_score"]) for g in groups]
        assert scores[0] >= scores[1], f"Higher score should come first, got {scores}"

    def test_grouping_same_host_package(self):
        from aila.modules.vulnerability.reporting.rows import build_groups
        findings = [
            self._make_finding(1, "host-a", "pkg-x", "Planned", 10.0, "CVE-1"),
            self._make_finding(1, "host-a", "pkg-x", "Immediate", 90.0, "CVE-2"),
        ]
        groups = build_groups(findings)
        # Both findings share the same (system_id, host, package_name) -- one group
        assert len(groups) == 1
        assert len(groups[0]) == 2

    def test_empty_findings(self):
        from aila.modules.vulnerability.reporting.rows import build_groups
        assert build_groups([]) == []


class TestBuildGroupsOrderGroupCallCount:
    """order_group must be called exactly once per group during sort key extraction, not O(N log N) times."""

    def test_order_group_called_once_per_group(self, monkeypatch):
        from aila.modules.vulnerability.reporting import rows as rows_module

        call_count = {"n": 0}
        original_order_group = rows_module.order_group

        def counted_order_group(findings):
            call_count["n"] += 1
            return original_order_group(findings)

        monkeypatch.setattr(rows_module, "order_group", counted_order_group)

        findings = [
            {"system_id": 1, "host": "h", "package_name": f"pkg-{i}",
             "criticality": "High", "numeric_score": float(i),
             "cve_id": f"CVE-{i}", "nvd_url": "", "rationale": "r"}
            for i in range(10)
        ]
        rows_module.build_groups(findings)

        # 10 unique groups -- order_group should be called exactly 10 times
        # (once per group for key extraction), not O(10 log 10 * C) times
        assert call_count["n"] == 10, (
            f"order_group called {call_count['n']} times for 10 groups; "
            f"expected exactly 10 (once per group)"
        )

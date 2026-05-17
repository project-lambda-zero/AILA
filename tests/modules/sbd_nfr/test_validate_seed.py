"""Tests for SbD NFR seed data validator."""

from __future__ import annotations

from pathlib import Path

import pytest

from aila.modules.sbd_nfr.scripts.validate_seed import (
    check_circular_depends_on,
    check_dead_references,
    check_display_order_uniqueness,
    check_duplicate_ids,
    check_option_references,
    check_subtask_coverage,
    validate,
)

# --- Fixtures ---

def _q(qid: str, subgroup: str = "sg1", dep: str | None = None, expected: str | None = None, order: int = 1) -> dict:
    return {
        "id": qid,
        "subgroup_key": subgroup,
        "depends_on_question_id": dep,
        "expected_when": expected,
        "display_order": order,
    }


def _sec(key: str, dep: str | None = None, subgroups: list[dict] | None = None) -> dict:
    return {
        "section_key": key,
        "depends_on_question_id": dep,
        "expected_when": "YES" if dep else None,
        "subgroups": subgroups or [{"subgroup_key": f"{key}_sg", "display_order": 0}],
    }


def _st(key: str) -> dict:
    return {"key": key, "label": key, "category": "test", "description": "test"}


def _map(qid: str, stk: str) -> dict:
    return {"question_id": qid, "subtask_key": stk}


def _opt(qid: str, val: str = "YES") -> dict:
    return {"question_id": qid, "value": val, "label": val}


# --- check_duplicate_ids ---

class TestDuplicateIds:
    def test_duplicate_question_id(self) -> None:
        qs = [_q("Q1"), _q("Q1")]
        errs = check_duplicate_ids(qs, [], [])
        assert len(errs) == 1
        assert "Q1" in errs[0]
        assert "2 times" in errs[0]

    def test_duplicate_section_key(self) -> None:
        secs = [
            _sec("sec1", subgroups=[{"subgroup_key": "sg_a", "display_order": 0}]),
            _sec("sec1", subgroups=[{"subgroup_key": "sg_b", "display_order": 0}]),
        ]
        errs = check_duplicate_ids([], secs, [])
        assert any("sec1" in e for e in errs)

    def test_duplicate_subgroup_key(self) -> None:
        secs = [
            _sec("s1", subgroups=[{"subgroup_key": "dup", "display_order": 0}]),
            _sec("s2", subgroups=[{"subgroup_key": "dup", "display_order": 0}]),
        ]
        errs = check_duplicate_ids([], secs, [])
        assert len(errs) == 1
        assert "dup" in errs[0]

    def test_duplicate_subtask_key(self) -> None:
        sts = [_st("net"), _st("net")]
        errs = check_duplicate_ids([], [], sts)
        assert len(errs) == 1
        assert "net" in errs[0]

    def test_no_duplicates(self) -> None:
        errs = check_duplicate_ids([_q("Q1"), _q("Q2")], [_sec("s1")], [_st("st1")])
        assert errs == []


# --- check_circular_depends_on ---

class TestCircularDependsOn:
    def test_simple_cycle(self) -> None:
        qs = [_q("A", dep="B"), _q("B", dep="A")]
        errs = check_circular_depends_on(qs, [])
        assert len(errs) >= 1
        assert "A" in errs[0] and "B" in errs[0]

    def test_three_node_cycle(self) -> None:
        qs = [_q("A", dep="B"), _q("B", dep="C"), _q("C", dep="A")]
        errs = check_circular_depends_on(qs, [])
        assert len(errs) >= 1

    def test_no_cycle(self) -> None:
        qs = [_q("A", dep="B"), _q("B")]
        errs = check_circular_depends_on(qs, [])
        assert errs == []

    def test_section_cycle(self) -> None:
        secs = [_sec("s1", dep="s2"), _sec("s2", dep="s1")]
        # sections depend on question IDs not section keys, so this won't cycle
        # unless the dep matches a question ID that chains back
        qs = [_q("s1", dep="s2"), _q("s2", dep="s1")]
        errs = check_circular_depends_on(qs, secs)
        assert len(errs) >= 1


# --- check_dead_references ---

class TestDeadReferences:
    def test_dead_question_depends_on(self) -> None:
        qs = [_q("Q1", dep="NONEXISTENT")]
        secs = [_sec("s1")]  # provides sg1 via default subgroup
        errs = check_dead_references(qs, secs, [], [], [])
        assert any("NONEXISTENT" in e for e in errs)

    def test_dead_section_depends_on(self) -> None:
        secs = [_sec("s1", dep="NONEXISTENT")]
        errs = check_dead_references([], secs, [], [], [])
        assert any("NONEXISTENT" in e for e in errs)

    def test_dead_subgroup_ref(self) -> None:
        qs = [_q("Q1", subgroup="MISSING_SG")]
        secs = [_sec("s1")]
        errs = check_dead_references(qs, secs, [], [], [])
        assert any("MISSING_SG" in e for e in errs)

    def test_dead_mapping_question(self) -> None:
        maps = [_map("MISSING", "st1")]
        sts = [_st("st1")]
        errs = check_dead_references([], [], [], maps, sts)
        assert any("MISSING" in e for e in errs)

    def test_dead_mapping_subtask(self) -> None:
        qs = [_q("Q1")]
        maps = [_map("Q1", "MISSING")]
        errs = check_dead_references(qs, [], [], maps, [])
        assert any("MISSING" in e for e in errs)

    def test_valid_refs(self) -> None:
        qs = [_q("Q1", dep="Q2", subgroup="s1_sg"), _q("Q2", subgroup="s1_sg")]
        secs = [_sec("s1")]
        sts = [_st("st1")]
        maps = [_map("Q1", "st1")]
        errs = check_dead_references(qs, secs, [], maps, sts)
        assert errs == []


# --- check_subtask_coverage ---

class TestSubtaskCoverage:
    def test_unmapped_subtask(self) -> None:
        sts = [_st("mapped"), _st("orphan")]
        maps = [_map("Q1", "mapped"), _map("Q2", "mapped")]
        errs = check_subtask_coverage(sts, maps)
        assert len(errs) == 1
        assert "orphan" in errs[0]

    def test_insufficient_mapping(self) -> None:
        sts = [_st("st1")]
        maps = [_map("Q1", "st1")]
        errs = check_subtask_coverage(sts, maps)
        assert len(errs) == 1
        assert "insufficient" in errs[0]

    def test_all_mapped(self) -> None:
        sts = [_st("st1")]
        maps = [_map("Q1", "st1"), _map("Q2", "st1")]
        errs = check_subtask_coverage(sts, maps)
        assert errs == []


# --- check_display_order_uniqueness ---

class TestDisplayOrderUniqueness:
    def test_collision_in_subgroup(self) -> None:
        qs = [_q("Q1", subgroup="sg1", order=1), _q("Q2", subgroup="sg1", order=1)]
        errs = check_display_order_uniqueness(qs, [])
        assert len(errs) == 1
        assert "Q1" in errs[0] and "Q2" in errs[0]

    def test_no_collision_different_subgroups(self) -> None:
        qs = [_q("Q1", subgroup="sg1", order=1), _q("Q2", subgroup="sg2", order=1)]
        errs = check_display_order_uniqueness(qs, [])
        assert errs == []

    def test_subgroup_order_collision(self) -> None:
        secs = [_sec("s1", subgroups=[
            {"subgroup_key": "a", "display_order": 0},
            {"subgroup_key": "b", "display_order": 0},
        ])]
        errs = check_display_order_uniqueness([], secs)
        assert len(errs) == 1


# --- check_option_references ---

class TestOptionReferences:
    def test_dead_option_ref(self) -> None:
        opts = [_opt("NONEXISTENT")]
        errs = check_option_references(opts, [])
        assert len(errs) == 1
        assert "NONEXISTENT" in errs[0]

    def test_compliance_template_ignored(self) -> None:
        opts = [_opt("__COMPLIANCE__")]
        errs = check_option_references(opts, [])
        assert errs == []

    def test_binary_template_ignored(self) -> None:
        opts = [_opt("__BINARY__", "Yes"), _opt("__BINARY__", "No"), _opt("__BINARY__", "NA")]
        errs = check_option_references(opts, [])
        assert errs == []

    def test_maturity_tier_template_ignored(self) -> None:
        opts = [_opt("__MATURITY_TIER__", "0"), _opt("__MATURITY_TIER__", "1")]
        errs = check_option_references(opts, [])
        assert errs == []

    def test_valid_option(self) -> None:
        opts = [_opt("Q1")]
        qs = [_q("Q1")]
        errs = check_option_references(opts, qs)
        assert errs == []


# --- Regression guard ---

_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "src" / "aila" / "modules" / "sbd_nfr" / "data"


def _load_json(path: Path) -> list[dict]:
    import json
    return json.loads(path.read_text(encoding="utf-8"))


class TestRegression:
    def test_current_seed_data_valid(self) -> None:
        if not _DATA_DIR.exists():
            pytest.skip(f"Seed data directory not found: {_DATA_DIR}")
        errors = validate(_DATA_DIR)
        assert errors == [], "Current seed data has errors:\n" + "\n".join(errors)

    def test_question_count_is_80(self) -> None:
        if not _DATA_DIR.exists():
            pytest.skip(f"Seed data directory not found: {_DATA_DIR}")
        questions = _load_json(_DATA_DIR / "seed_questions.json")
        assert len(questions) == 80, f"Expected 80 questions, got {len(questions)}"

    def test_section_count_is_11(self) -> None:
        if not _DATA_DIR.exists():
            pytest.skip(f"Seed data directory not found: {_DATA_DIR}")
        sections = _load_json(_DATA_DIR / "seed_sections.json")
        assert len(sections) == 11, f"Expected 11 sections, got {len(sections)}"

    def test_new_section_questions_all_mapped(self) -> None:
        """All new question IDs from Sections 7-10 must have at least one mapping entry."""
        if not _DATA_DIR.exists():
            pytest.skip(f"Seed data directory not found: {_DATA_DIR}")
        mappings = _load_json(_DATA_DIR / "seed_mappings.json")
        mapped_q_ids = {m["question_id"] for m in mappings}
        new_ids = (
            [f"API-0{i}" for i in range(1, 9)]
            + [f"WEB-0{i}" for i in range(1, 9)]
            + [f"SUPPLY-0{i}" for i in range(1, 7)]
            + [f"GOV-0{i}" for i in range(1, 7)]
        )
        missing = [qid for qid in new_ids if qid not in mapped_q_ids]
        assert not missing, f"New question IDs with no mapping: {missing}"

    def test_conditional_sections_have_condition_expr(self) -> None:
        """Sections api_security/web_mobile/supply_chain must carry condition_expr_json; governance must not."""
        if not _DATA_DIR.exists():
            pytest.skip(f"Seed data directory not found: {_DATA_DIR}")
        sections = _load_json(_DATA_DIR / "seed_sections.json")
        sec_by_key = {s["section_key"]: s for s in sections}
        for key in ("api_security", "web_mobile", "supply_chain"):
            assert sec_by_key[key].get("condition_expr_json") is not None, \
                f"{key} must have condition_expr_json"
        assert sec_by_key["governance"].get("condition_expr_json") is None, \
            "governance must have no condition_expr_json"

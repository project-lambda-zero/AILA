"""Tests for sbd_nfr seed JSON data structure and integrity.

Validates QSCHEMA-01 and QSCHEMA-02: canonical seed data exists, has correct
structure, and contains no duplicate question IDs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_DATA_DIR = (
    Path(__file__).resolve().parents[3]
    / "src" / "aila" / "modules" / "sbd_nfr" / "data"
)

_REQUIRED_FILES = [
    "seed_subtasks.json",
    "seed_sections.json",
    "seed_questions.json",
    "seed_options.json",
    "seed_mappings.json",
]


def _load(filename: str) -> object:
    path = _DATA_DIR / filename
    assert path.exists(), f"Seed file missing: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Existence
# ---------------------------------------------------------------------------


def test_all_seed_files_exist() -> None:
    """All five seed JSON files must exist in the data directory."""
    for filename in _REQUIRED_FILES:
        path = _DATA_DIR / filename
        assert path.exists(), f"Missing seed file: {path}"


# ---------------------------------------------------------------------------
# seed_subtasks.json
# ---------------------------------------------------------------------------


class TestSeedSubtasks:
    def setup_method(self) -> None:
        self.data = _load("seed_subtasks.json")

    def test_is_list(self) -> None:
        assert isinstance(self.data, list)

    def test_exactly_25_entries(self) -> None:
        assert len(self.data) == 25, f"Expected 25 subtasks, got {len(self.data)}"

    def test_required_keys(self) -> None:
        required = {"key", "label", "category", "description", "icon_hint", "display_order", "is_active"}
        for idx, entry in enumerate(self.data):
            missing = required - set(entry.keys())
            assert not missing, f"Entry {idx} missing keys: {missing}"

    def test_display_order_sequential(self) -> None:
        orders = [e["display_order"] for e in self.data]
        assert sorted(orders) == list(range(1, 26)), "display_order must be 1..25"

    def test_all_active(self) -> None:
        assert all(e["is_active"] is True for e in self.data)

    def test_no_duplicate_keys(self) -> None:
        keys = [e["key"] for e in self.data]
        assert len(keys) == len(set(keys)), "Duplicate subtask keys found"

    def test_category_not_empty(self) -> None:
        for entry in self.data:
            assert entry["category"], f"Empty category for key={entry['key']}"


# ---------------------------------------------------------------------------
# seed_sections.json
# ---------------------------------------------------------------------------


class TestSeedSections:
    def setup_method(self) -> None:
        self.data = _load("seed_sections.json")

    def test_is_list(self) -> None:
        assert isinstance(self.data, list)

    def test_at_least_10_entries(self) -> None:
        assert len(self.data) >= 10, f"Expected >= 10 sections, got {len(self.data)}"

    def test_required_keys(self) -> None:
        required = {
            "section_key", "label", "display_order",
            "depends_on_question_id", "expected_when", "is_active",
        }
        for idx, entry in enumerate(self.data):
            missing = required - set(entry.keys())
            assert not missing, f"Section {idx} missing keys: {missing}"

    def test_scope_section_present(self) -> None:
        keys = [s["section_key"] for s in self.data]
        assert "scope" in keys, "scope section must be present"

    def test_scope_section_no_dependency(self) -> None:
        scope = next(s for s in self.data if s["section_key"] == "scope")
        assert scope["depends_on_question_id"] is None

    def test_conditional_sections_have_dependencies(self) -> None:
        # v3.0: conditional sections use condition_expr_json, not depends_on_question_id
        conditional = [s for s in self.data if s.get("condition_expr_json") is not None]
        assert len(conditional) >= 3, "At least 3 conditional sections expected (using condition_expr_json)"

    def test_subgroups_present(self) -> None:
        for section in self.data:
            assert "subgroups" in section, f"Section {section['section_key']} missing subgroups"
            assert isinstance(section["subgroups"], list)

    def test_display_order_unique(self) -> None:
        orders = [s["display_order"] for s in self.data]
        assert len(orders) == len(set(orders)), "Duplicate display_order values in sections"

    def test_no_duplicate_section_keys(self) -> None:
        keys = [s["section_key"] for s in self.data]
        assert len(keys) == len(set(keys)), "Duplicate section keys found"


# ---------------------------------------------------------------------------
# seed_questions.json
# ---------------------------------------------------------------------------


class TestSeedQuestions:
    def setup_method(self) -> None:
        self.data = _load("seed_questions.json")

    def test_is_list(self) -> None:
        assert isinstance(self.data, list)

    def test_has_entries(self) -> None:
        assert len(self.data) > 0

    def test_required_keys(self) -> None:
        required = {
            "id", "subgroup_key", "question_type", "depth_level",
            "answer_type", "label", "instruction", "guideline", "help_text",
            "is_required", "depends_on_question_id", "expected_when", "display_order",
        }
        for idx, entry in enumerate(self.data):
            missing = required - set(entry.keys())
            assert not missing, f"Question {idx} missing keys: {missing}"

    def test_no_duplicate_question_ids(self) -> None:
        """QSCHEMA-02: question IDs must be unique across the entire seed."""
        ids = [q["id"] for q in self.data]
        duplicates = {i for i in ids if ids.count(i) > 1}
        assert not duplicates, f"Duplicate question IDs found: {duplicates}"

    def test_scope_questions_use_scope_prefix(self) -> None:
        scope_qs = [q for q in self.data if q["question_type"] == "scope"]
        for q in scope_qs:
            assert re.match(r"^SCOPE-\d{2,3}$", q["id"]), (
                f"Scope question ID {q['id']!r} must match SCOPE-NN pattern"
            )

    def test_requirement_questions_use_semantic_prefix(self) -> None:
        r"""IDs for requirement questions must match [A-Z]{2,5}-\d{2,3}."""
        pattern = re.compile(r"^[A-Z]{2,5}-\d{2,3}$")
        requirement_qs = [q for q in self.data if q["question_type"] == "requirement"]
        for q in requirement_qs:
            assert pattern.match(q["id"]), (
                f"Requirement question ID {q['id']!r} must match [A-Z]{{2,5}}-NNN"
            )

    def test_scope_questions_have_single_choice_answer_type(self) -> None:
        for q in self.data:
            if q["question_type"] == "scope":
                assert q["answer_type"] == "single_choice", (
                    f"Scope question {q['id']} must have answer_type=single_choice"
                )

    def test_control_and_practice_questions_have_binary_or_maturity_answer_type(self) -> None:
        # v3.0: question types are "control" and "practice", answer types are "binary" or "maturity_tier"
        valid_answer_types = {"binary", "maturity_tier"}
        for q in self.data:
            if q["question_type"] in ("control", "practice"):
                assert q["answer_type"] in valid_answer_types, (
                    f"Question {q['id']} (type={q['question_type']!r}) must have "
                    f"answer_type in {valid_answer_types}, got {q['answer_type']!r}"
                )

    def test_label_not_empty(self) -> None:
        for q in self.data:
            assert q["label"], f"Question {q['id']} has empty label"

    def test_scope_questions_count(self) -> None:
        # v3.0: exactly 6 scope questions (SCOPE-01 through SCOPE-06)
        scope_qs = [q for q in self.data if q["question_type"] == "scope"]
        assert len(scope_qs) == 6, f"Expected 6 scope questions, got {len(scope_qs)}"

    def test_questions_exist_for_each_nfr_section(self) -> None:
        # v3.0 STRIDE-grounded prefixes: AUTH, AUTHZ, DPROT, IVAL, AUDIT, AVAIL,
        # API, WEB, SUPPLY, GOV
        prefixes_expected = {"AUTH", "AUTHZ", "DPROT", "IVAL", "AUDIT", "AVAIL", "API", "WEB", "SUPPLY", "GOV"}
        ids = [q["id"] for q in self.data]
        found_prefixes = {i.split("-")[0] for i in ids}
        missing = prefixes_expected - found_prefixes
        assert not missing, f"Missing questions for sections: {missing}"


# ---------------------------------------------------------------------------
# seed_options.json
# ---------------------------------------------------------------------------


class TestSeedOptions:
    def setup_method(self) -> None:
        self.data = _load("seed_options.json")

    def test_is_list(self) -> None:
        assert isinstance(self.data, list)

    def test_required_keys(self) -> None:
        required = {"question_id", "value", "label", "description", "display_order"}
        for idx, entry in enumerate(self.data):
            missing = required - set(entry.keys())
            assert not missing, f"Option {idx} missing keys: {missing}"

    def test_binary_template_marker_present(self) -> None:
        # v3.0: __BINARY__ template replaces __COMPLIANCE__
        binary = [o for o in self.data if o["question_id"] == "__BINARY__"]
        assert len(binary) == 3, (
            f"Expected 3 __BINARY__ template entries (Yes/No/NA), got {len(binary)}"
        )

    def test_binary_values(self) -> None:
        binary = [o for o in self.data if o["question_id"] == "__BINARY__"]
        values = {o["value"] for o in binary}
        assert values == {"Yes", "No", "NA"}

    def test_maturity_tier_template_marker_present(self) -> None:
        # v3.0: __MATURITY_TIER__ template for maturity-graded questions
        maturity = [o for o in self.data if o["question_id"] == "__MATURITY_TIER__"]
        assert len(maturity) == 4, (
            f"Expected 4 __MATURITY_TIER__ entries (0/1/2/3), got {len(maturity)}"
        )

    def test_maturity_tier_values(self) -> None:
        maturity = [o for o in self.data if o["question_id"] == "__MATURITY_TIER__"]
        values = {o["value"] for o in maturity}
        assert values == {"0", "1", "2", "3"}

    def test_scope_options_present(self) -> None:
        # Per-question options exist for scope questions
        template_ids = {"__BINARY__", "__MATURITY_TIER__"}
        scope_q_ids = {o["question_id"] for o in self.data if o["question_id"] not in template_ids}
        assert scope_q_ids, "No per-question options found"

    def test_display_order_positive(self) -> None:
        for opt in self.data:
            assert opt["display_order"] >= 1, f"display_order must be >= 1 for {opt}"

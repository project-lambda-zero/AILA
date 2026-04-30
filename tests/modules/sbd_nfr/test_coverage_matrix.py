"""Tests for the sbd_nfr question-to-subtask coverage matrix.

Validates QSCHEMA-04: all 25 SbD sub-task keys must appear at least once in
seed_mappings.json.  Also validates referential integrity between mappings,
questions, and subtasks.
"""

from __future__ import annotations

import json
from pathlib import Path

_DATA_DIR = (
    Path(__file__).resolve().parents[3]
    / "src" / "aila" / "modules" / "sbd_nfr" / "data"
)


def _load(filename: str) -> list[dict]:
    path = _DATA_DIR / filename
    assert path.exists(), f"Seed file missing: {path}"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list), f"{filename} must be a JSON array"
    return data


class TestCoverageMatrix:
    def setup_method(self) -> None:
        self.subtasks = _load("seed_subtasks.json")
        self.mappings = _load("seed_mappings.json")
        self.questions = _load("seed_questions.json")

    def test_all_25_subtask_keys_appear_in_mappings(self) -> None:
        """QSCHEMA-04: every one of the 25 SbD subtask keys must be mapped."""
        all_subtask_keys = {s["key"] for s in self.subtasks}
        assert len(all_subtask_keys) == 25, "Expected exactly 25 subtask keys"

        covered_keys = {m["subtask_key"] for m in self.mappings}
        missing = all_subtask_keys - covered_keys
        assert not missing, (
            f"The following subtask keys have no question mapping: {sorted(missing)}"
        )

    def test_mapping_question_ids_exist_in_questions(self) -> None:
        """Every question_id referenced in mappings must exist in seed_questions.json."""
        valid_ids = {q["id"] for q in self.questions}
        for mapping in self.mappings:
            assert mapping["question_id"] in valid_ids, (
                f"Mapping references unknown question_id: {mapping['question_id']!r}"
            )

    def test_mapping_subtask_keys_exist_in_subtasks(self) -> None:
        """Every subtask_key referenced in mappings must exist in seed_subtasks.json."""
        valid_keys = {s["key"] for s in self.subtasks}
        for mapping in self.mappings:
            assert mapping["subtask_key"] in valid_keys, (
                f"Mapping references unknown subtask_key: {mapping['subtask_key']!r}"
            )

    def test_mapping_entries_have_required_keys(self) -> None:
        required = {"question_id", "subtask_key"}
        for idx, entry in enumerate(self.mappings):
            missing = required - set(entry.keys())
            assert not missing, f"Mapping {idx} missing keys: {missing}"

    def test_mappings_are_not_empty(self) -> None:
        assert len(self.mappings) > 0, "seed_mappings.json must not be empty"

    def test_all_nfr_sections_contribute_at_least_one_mapping(self) -> None:
        """Each NFR section (non-scope) must contribute at least one mapping."""
        # Get all question IDs that appear in mappings
        mapped_question_ids = {m["question_id"] for m in self.mappings}

        # Gather which question prefixes are mapped
        mapped_prefixes = {qid.split("-")[0] for qid in mapped_question_ids}

        # v3.0 STRIDE-grounded prefixes
        expected_prefixes = {"AUTH", "AUTHZ", "DPROT", "IVAL", "AUDIT", "AVAIL", "API", "WEB", "SUPPLY", "GOV"}
        missing = expected_prefixes - mapped_prefixes
        assert not missing, (
            f"These NFR sections contribute no mappings: {missing}"
        )

    def test_coverage_per_subtask_category(self) -> None:
        """Each subtask category must be represented in the coverage matrix."""
        # Build category -> subtask_key map
        category_keys: dict[str, set[str]] = {}
        for s in self.subtasks:
            category_keys.setdefault(s["category"], set()).add(s["key"])

        covered_keys = {m["subtask_key"] for m in self.mappings}

        for category, keys in category_keys.items():
            covered_in_category = keys & covered_keys
            assert covered_in_category, (
                f"Category {category!r} has no subtask keys in coverage matrix"
            )

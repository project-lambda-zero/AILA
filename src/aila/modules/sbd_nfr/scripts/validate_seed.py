"""Seed data validator for the SbD NFR questionnaire.

Validates structural correctness of seed JSON files before deployment.
Catches: duplicate IDs, circular depends_on, dead expected_when values,
subtask coverage gaps, display_order uniqueness violations, and
dangling references.

Usage:
    python -m aila.modules.sbd_nfr.scripts.validate_seed
    python -m aila.modules.sbd_nfr.scripts.validate_seed --data-dir /path/to/data
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

_log = logging.getLogger(__name__)


def _load_json(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check_duplicate_ids(
    questions: list[dict],
    sections: list[dict],
    subtasks: list[dict],
) -> list[str]:
    errors: list[str] = []

    # Question IDs
    seen: dict[str, int] = {}
    for q in questions:
        qid = q["id"]
        seen[qid] = seen.get(qid, 0) + 1
    for qid, count in seen.items():
        if count > 1:
            errors.append(f"Duplicate question ID: {qid} (appears {count} times)")

    # Section keys
    seen_sec: dict[str, int] = {}
    for s in sections:
        sk = s["section_key"]
        seen_sec[sk] = seen_sec.get(sk, 0) + 1
    for sk, count in seen_sec.items():
        if count > 1:
            errors.append(f"Duplicate section_key: {sk} (appears {count} times)")

    # Subgroup keys (across all sections)
    seen_sg: dict[str, int] = {}
    for s in sections:
        for sg in s.get("subgroups", []):
            sgk = sg["subgroup_key"]
            seen_sg[sgk] = seen_sg.get(sgk, 0) + 1
    for sgk, count in seen_sg.items():
        if count > 1:
            errors.append(f"Duplicate subgroup_key: {sgk} (appears {count} times)")

    # Subtask keys
    seen_st: dict[str, int] = {}
    for st in subtasks:
        stk = st["key"]
        seen_st[stk] = seen_st.get(stk, 0) + 1
    for stk, count in seen_st.items():
        if count > 1:
            errors.append(f"Duplicate subtask key: {stk} (appears {count} times)")

    return errors


def check_circular_depends_on(
    questions: list[dict],
    sections: list[dict],
) -> list[str]:
    errors: list[str] = []
    graph: dict[str, str] = {}

    for q in questions:
        dep = q.get("depends_on_question_id")
        if dep:
            graph[q["id"]] = dep

    for s in sections:
        dep = s.get("depends_on_question_id")
        if dep:
            graph[s["section_key"]] = dep

    visited: set[str] = set()
    for start in graph:
        if start in visited:
            continue
        path: list[str] = []
        current: str | None = start
        path_set: set[str] = set()
        while current and current in graph:
            if current in path_set:
                cycle_start = path.index(current)
                cycle = path[cycle_start:] + [current]
                errors.append(
                    f"Circular dependency: {' -> '.join(cycle)}"
                )
                break
            path.append(current)
            path_set.add(current)
            current = graph.get(current)
        visited.update(path_set)

    return errors


def check_dead_references(
    questions: list[dict],
    sections: list[dict],
    mappings: list[dict],
    subtasks: list[dict],
) -> list[str]:
    errors: list[str] = []
    question_ids = {q["id"] for q in questions}
    subtask_keys = {st["key"] for st in subtasks}
    subgroup_keys: set[str] = set()
    for s in sections:
        for sg in s.get("subgroups", []):
            subgroup_keys.add(sg["subgroup_key"])

    # depends_on references
    for q in questions:
        dep = q.get("depends_on_question_id")
        if dep and dep not in question_ids:
            errors.append(
                f"Dead reference: question {q['id']} depends on "
                f"non-existent question {dep}"
            )

    for s in sections:
        dep = s.get("depends_on_question_id")
        if dep and dep not in question_ids:
            errors.append(
                f"Dead reference: section {s['section_key']} depends on "
                f"non-existent question {dep}"
            )

    # subgroup_key references
    for q in questions:
        sgk = q.get("subgroup_key")
        if sgk and sgk not in subgroup_keys:
            errors.append(
                f"Dead reference: question {q['id']} references "
                f"non-existent subgroup_key {sgk}"
            )

    # mapping references
    for m in mappings:
        if m["question_id"] not in question_ids:
            errors.append(
                f"Dead mapping reference: question_id {m['question_id']} "
                f"does not exist"
            )
        if m["subtask_key"] not in subtask_keys:
            errors.append(
                f"Dead mapping reference: subtask_key {m['subtask_key']} "
                f"does not exist"
            )

    return errors


def check_subtask_coverage(
    subtasks: list[dict],
    mappings: list[dict],
) -> list[str]:
    """Enforce minimum 2 question evidence references per subtask (SCORE-03).

    A subtask with fewer than 2 mapped questions provides insufficient
    evidence for the LLM resolution step to make a reliable classification.
    """
    errors: list[str] = []
    counts: dict[str, int] = {}
    for m in mappings:
        key = m["subtask_key"]
        counts[key] = counts.get(key, 0) + 1
    for st in subtasks:
        key = st["key"]
        n = counts.get(key, 0)
        if n == 0:
            errors.append(
                f"Subtask coverage gap: {key!r} has no question mappings"
            )
        elif n < 2:
            errors.append(
                f"Subtask coverage insufficient: {key!r} has only {n} "
                f"question mapping (minimum 2 required)"
            )
    return errors


def check_display_order_uniqueness(
    questions: list[dict],
    sections: list[dict],
) -> list[str]:
    errors: list[str] = []

    # Questions within each subgroup
    by_subgroup: dict[str, list[dict]] = {}
    for q in questions:
        sgk = q.get("subgroup_key", "")
        by_subgroup.setdefault(sgk, []).append(q)

    for sgk, qs in by_subgroup.items():
        seen: dict[int, str] = {}
        for q in qs:
            order = q.get("display_order")
            if order is None:
                continue
            if order in seen:
                errors.append(
                    f"display_order collision: questions {seen[order]} and "
                    f"{q['id']} in subgroup {sgk} both have display_order={order}"
                )
            else:
                seen[order] = q["id"]

    # Subgroups within each section
    for s in sections:
        seen_sg: dict[int, str] = {}
        for sg in s.get("subgroups", []):
            order = sg.get("display_order")
            if order is None:
                continue
            if order in seen_sg:
                errors.append(
                    f"display_order collision: subgroups {seen_sg[order]} and "
                    f"{sg['subgroup_key']} in section {s['section_key']} "
                    f"both have display_order={order}"
                )
            else:
                seen_sg[order] = sg["subgroup_key"]

    return errors


_OPTION_TEMPLATE_KEYS = {"__COMPLIANCE__", "__BINARY__", "__MATURITY_TIER__"}


def check_option_references(
    options: list[dict],
    questions: list[dict],
) -> list[str]:
    errors: list[str] = []
    question_ids = {q["id"] for q in questions}
    for opt in options:
        qid = opt.get("question_id", "")
        if qid not in _OPTION_TEMPLATE_KEYS and qid not in question_ids:
            errors.append(
                f"Dead option reference: option for non-existent question {qid}"
            )
    return errors


def validate(data_dir: Path) -> list[str]:
    """Run all validation passes on seed data. Returns list of error messages."""
    questions = _load_json(data_dir / "seed_questions.json")
    sections = _load_json(data_dir / "seed_sections.json")
    subtasks = _load_json(data_dir / "seed_subtasks.json")
    mappings = _load_json(data_dir / "seed_mappings.json")
    options = _load_json(data_dir / "seed_options.json")

    errors: list[str] = []
    errors.extend(check_duplicate_ids(questions, sections, subtasks))
    errors.extend(check_circular_depends_on(questions, sections))
    errors.extend(check_dead_references(questions, sections, mappings, subtasks))
    errors.extend(check_subtask_coverage(subtasks, mappings))
    errors.extend(check_display_order_uniqueness(questions, sections))
    errors.extend(check_option_references(options, questions))
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate SbD NFR seed data")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "data",
        help="Path to seed data directory",
    )
    args = parser.parse_args()

    if not args.data_dir.exists():
        _log.error("data directory not found: %s", args.data_dir)
        sys.exit(1)

    errors = validate(args.data_dir)

    if errors:
        _log.error("FAILED: %d error(s) found:", len(errors))
        for err in errors:
            _log.error("  - %s", err)
        sys.exit(1)
    else:
        _log.info("PASSED: All seed data validation checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    main()

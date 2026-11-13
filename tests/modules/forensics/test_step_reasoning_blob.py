"""A persisted investigator step keeps its structure at any turn size.

The investigator stores the per-turn case model as a JSON blob in the step's
``reasoning`` column; the step endpoint parses it back into structured
fields. A long turn must still produce valid JSON and read back with its
contract, hypotheses, and submitted flag.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from aila.modules.forensics.agents.investigator import _compose_step_reasoning
from aila.modules.forensics.api_router import _agent_step_from_record


def _long_turn() -> dict[str, Any]:
    return {
        "reasoning": "Correlating prefetch and run key timestamps. " * 400,
        "expected_observation": "a run key written within a minute of first execution",
        "contract": {"question": "How did the implant persist?", "answer_format": "mechanism and path"},
        "hypotheses": [
            {"id": f"h{i}", "statement": f"Persistence via mechanism {i}. " * 40, "status": "live"}
            for i in range(12)
        ],
        "rejected": [{"id": "h99", "reason": "no scheduled task artifacts on disk"}],
        "observables": {f"reading_{i}": "x" * 5000 for i in range(8)},
        "provenance": {"primary_artifact": "C:/Users/a/NTUSER.DAT"},
        "submitted": True,
    }


def test_long_turn_serializes_to_valid_json_with_structure() -> None:
    turn = _long_turn()
    assert len(json.dumps(turn)) > 6000

    blob = json.loads(_compose_step_reasoning(turn))

    assert blob["contract"] == turn["contract"]
    assert [h["id"] for h in blob["hypotheses"]] == [h["id"] for h in turn["hypotheses"]]
    assert blob["submitted"] is True
    assert blob["reasoning"].startswith("Correlating prefetch")


def test_long_step_reads_back_with_structured_fields() -> None:
    turn = _long_turn()
    record = SimpleNamespace(
        id="step-1", step_number=3, action="script", script_content=None, command=None,
        stdout="", stderr="", exit_code=0, created_at=datetime.now(UTC),
        reasoning=_compose_step_reasoning(turn),
    )

    step = _agent_step_from_record(record)

    assert step.contract == turn["contract"]
    assert [h["id"] for h in step.hypotheses] == [h["id"] for h in turn["hypotheses"]]
    assert step.rejected == turn["rejected"]
    assert step.provenance == turn["provenance"]
    assert step.submitted is True
    assert step.reasoning.startswith("Correlating prefetch")

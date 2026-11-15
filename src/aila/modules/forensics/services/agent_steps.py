"""Persisted step records for forensics investigations.

Each executed step is one ``AgentStepRecord``. Its ``reasoning`` column holds a
JSON blob that the UI and the write-up read, so the free-flow investigator and
the panel action dispatcher both build the row here.
"""

from __future__ import annotations

import json
from typing import Any

from aila.modules.forensics.db_models import AgentStepRecord
from aila.modules.forensics.services.analyzer_actions import sanitize_for_postgres_text

__all__ = [
    "STEP_REASONING_MAX_CHARS",
    "bound_text",
    "build_step_record",
    "compose_step_reasoning",
]

# Persisted step reasoning stays valid JSON at any turn size: free text is
# bounded per field before serialization instead of slicing the serialized
# string, which would cut the JSON mid-token.
STEP_REASONING_MAX_CHARS = 6000
_STEP_FIELD_MAX_CHARS = 2000


def bound_text(value: str, limit: int) -> str:
    """Return ``value`` unchanged when within ``limit``, otherwise cut it with a marker."""
    if len(value) <= limit:
        return value
    return f"{value[:limit]}... [{len(value) - limit} chars truncated]"


def _bound_strings(value: Any, limit: int) -> Any:
    """Return ``value`` with every string leaf bounded to ``limit`` characters."""
    if isinstance(value, str):
        return bound_text(value, limit)
    if isinstance(value, dict):
        return {key: _bound_strings(item, limit) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_bound_strings(item, limit) for item in value]
    return value


def compose_step_reasoning(turn: dict[str, Any], *, panel: dict[str, Any] | None = None) -> str:
    """Build the persisted reasoning blob used by the UI and write-up.

    ``panel`` (``persona_voice``, ``branch_id``, ``at_turn``) marks a step taken
    by a panel branch. It is written only when given, so free-flow blobs keep
    their existing shape.
    """
    blob: dict[str, Any] = {
        "reasoning": bound_text(str(turn.get("reasoning") or ""), STEP_REASONING_MAX_CHARS),
        "expected_observation": turn.get("expected_observation", ""),
        "strategy_family": turn.get("strategy_family", "generic"),
        "contract": turn.get("contract", {}),
        "hypotheses": turn.get("hypotheses", []),
        "rejected": turn.get("rejected", []),
        # Auto-bucketed hypotheses at terminal submit (issue #175).
        # Empty on non-terminal turns; consumers must not treat
        # ``resolved`` as an alternative to ``rejected``.
        "resolved": turn.get("resolved", []),
        "observables": turn.get("observables", {}),
        "evidence_graph": turn.get("evidence_graph", {}),
        "provenance": turn.get("provenance", {}),
        "submitted": bool(turn.get("submitted")),
    }
    if panel is not None:
        blob["panel"] = panel
    bounded = {
        key: value if key == "reasoning" else _bound_strings(value, _STEP_FIELD_MAX_CHARS)
        for key, value in blob.items()
    }
    # ``default=str`` renders any non-JSON value (enum, datetime) as text, so
    # serialization cannot fail and there is no non-JSON fallback.
    return json.dumps(bounded, ensure_ascii=False, default=str)


def build_step_record(
    *,
    investigation_id: str,
    team_id: str | None,
    step_number: int,
    turn_result: dict[str, Any],
    panel: dict[str, Any] | None = None,
) -> AgentStepRecord:
    """Return the ``AgentStepRecord`` for one executed step with text sanitised for Postgres."""
    return AgentStepRecord(
        investigation_id=investigation_id,
        team_id=team_id,
        step_number=step_number,
        action=turn_result.get("action", "reasoning"),
        script_content=sanitize_for_postgres_text(turn_result.get("script_content")),
        command=sanitize_for_postgres_text(turn_result.get("command")),
        stdout=sanitize_for_postgres_text(turn_result.get("stdout")),
        stderr=sanitize_for_postgres_text(turn_result.get("stderr")),
        exit_code=turn_result.get("exit_code"),
        reasoning=sanitize_for_postgres_text(compose_step_reasoning(turn_result, panel=panel)),
    )

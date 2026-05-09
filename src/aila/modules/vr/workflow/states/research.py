"""Research state — thin wrapper around :class:`NdayResearcher`.

The closed-loop reasoning, action dispatch, evidence pack, and
obligation adjudication live on the agent. This state hydrates the
agent from the workflow input dict, runs ``research()``, and forwards
the structured result to the next state.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.agents.nday_researcher import NdayResearcher
from aila.platform.contracts.budget import BudgetConfig, BudgetState
from aila.platform.workflows.types import StateResult

__all__ = ["state_research"]

_BUDGET_EXHAUSTED_MARKER = "(budget exhausted; agent could not converge)"
_FORWARDED_KEYS: tuple[str, ...] = (
    "project_id", "target_path", "patched_path", "binary_id",
    "patched_binary_id", "mitigations", "cve_id", "integration",
    "context_notes",
)


async def state_research(input: dict[str, Any], services: Any) -> StateResult:
    """Run the N-day research agent and emit a structured result."""
    raw_budget = input.get("budget_json")
    budget = (
        BudgetState.from_json(raw_budget) if raw_budget
        else BudgetState(config=BudgetConfig(
            max_turns=services.config.nday_max_turns,
            max_tool_time_seconds=services.config.nday_tool_time_seconds,
        ))
    )
    researcher = NdayResearcher(
        run_id=services.run_id,
        project_id=str(input.get("project_id") or ""),
        cve_id=str(input.get("cve_id") or ""),
        binary_id=str(input["binary_id"]),
        patched_binary_id=input.get("patched_binary_id"),
        mitigations=input.get("mitigations") or {},
        ida_bridge=services.ida_bridge,
        config=services.config,
        budget=budget,
    )
    result = await researcher.research()
    root_cause = result.get("root_cause") or ""
    status = "completed" if root_cause and root_cause != _BUDGET_EXHAUSTED_MARKER else "stalled"

    return StateResult(
        next_state="poc_development",
        output={
            **{k: input.get(k) for k in _FORWARDED_KEYS},
            "research": result,
            "research_status": status,
            "budget_json": result.get("budget") or budget.to_json(),
        },
    )

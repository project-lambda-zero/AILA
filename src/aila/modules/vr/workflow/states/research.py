"""Research state — bounded N-day root-cause investigation loop.

Drives a small LLM-backed investigation that triangulates the vulnerable
function using the IDA bridge, the patch differ (when a patched binary is
available), and decompilation. The loop is intentionally narrow: it does
not run PoCs (poc_development handles that) and it does not score
exploitability (advisory handles that). Its sole product is a structured
research record describing the root cause and the function under test.

Budget enforcement:
- Turn budget caps reasoning depth (config.nday_max_turns).
- Tool-time budget caps cumulative wall-clock spent in expensive tool
  calls (config.nday_tool_time_seconds).
On exhaustion the loop returns whatever partial findings it has and
flags ``status="stalled"`` so the workflow continues into PoC dev with
best-effort inputs rather than aborting.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from aila.modules.vr.contracts.finding import CrashType
from aila.platform.contracts.budget import BudgetState
from aila.platform.workflows.types import StateResult

__all__ = ["state_research"]

_log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a vulnerability research analyst in a closed-loop \
investigation harness. Your goal is to identify the vulnerable function and \
root cause for a known or suspected N-day in a binary.

Each turn you receive:
- the binary_id (already uploaded to IDA headless MCP)
- the patched_binary_id (optional; when present prefer the patch diff signal)
- mitigations (NX/PIE/RELRO/Canary)
- prior turns' tool outputs

Return ONE JSON object exactly matching this shape (no prose outside it):
{
  "thought": "brief reasoning",
  "action": "find_patched_functions | decompile | xrefs_to | assess_exploitability | submit",
  "args": {... action-specific args ...},
  "submit": {
    "vulnerable_function": "name or 0x address",
    "root_cause": "one-paragraph technical explanation",
    "crash_type": "one of: overflow_stack, overflow_heap, uaf, double_free, \
type_confusion, format_string, integer_overflow, null_deref, oob_read, \
oob_write, info_disclosure, cmd_injection",
    "evidence": ["short citation 1", "short citation 2"]
  }
}

Rules:
- Only set "submit" when you have decompiled the candidate function AT LEAST \
once and can name a concrete primitive.
- When a patched_binary_id is present, START with action=find_patched_functions \
to short-list candidates.
- Without a patch, START with action=decompile on a heuristic name (main, \
parse, handle_*, *_request, *_packet) drawn from the context notes.
- Never repeat an action with identical args twice; pivot instead.
"""


_TOOL_BUDGET_PER_CALL_S = 180.0
_MAX_DECOMPILE_LINES = 600


def _build_user_prompt(turn: int, context: dict[str, Any], history: list[dict[str, Any]]) -> str:
    parts = [
        f"Turn {turn}/{context['max_turns']}. {context['budget_summary']}",
        "",
        f"binary_id: {context['binary_id']}",
        f"patched_binary_id: {context.get('patched_binary_id') or '(none)'}",
        f"mitigations: {json.dumps(context.get('mitigations') or {})}",
        f"cve_id: {context.get('cve_id') or '(none)'}",
        f"context_notes: {context.get('context_notes') or '(none)'}",
        "",
        "Previous turns (last 6):",
    ]
    for entry in history[-6:]:
        parts.append(f"  T{entry['turn']} action={entry['action']} -> {entry['summary'][:240]}")
    parts.append("")
    parts.append("Return a single JSON object matching the response contract.")
    return "\n".join(parts)


def _summarize(payload: Any) -> str:
    if isinstance(payload, dict):
        return json.dumps({k: payload[k] for k in list(payload)[:6]}, default=str)[:280]
    return str(payload)[:280]


async def _llm_decision(services: Any, system: str, user: str) -> dict[str, Any]:
    response = await services.llm_client.chat(
        task_type="vulnerability_research",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        run_id=services.run_id,
    )
    if response.disabled:
        raise RuntimeError("LLM disabled by operator")
    raw = response.content or "{}"
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end < 0:
        raise ValueError(f"LLM returned no JSON object: {raw[:200]}")
    return json.loads(raw[start : end + 1])


def _execute_action(action: str, args: dict[str, Any], services: Any) -> dict[str, Any]:
    """Dispatch a single tool action. Returns the raw tool result dict."""
    if action == "find_patched_functions":
        return services.patch_differ.forward(action="find_patched_functions", **args)
    if action == "decompile":
        # Cap pseudocode size to keep prompts bounded.
        return services.ida_bridge.forward(
            action="decompile", max_lines=_MAX_DECOMPILE_LINES, **args,
        )
    if action == "xrefs_to":
        return services.ida_bridge.forward(action="xrefs_to", **args)
    if action == "assess_exploitability":
        return services.ida_bridge.forward(action="assess_exploitability", **args)
    return {"status": "error", "error": f"unknown action: {action!r}"}


def _normalize_crash_type(value: str) -> str:
    candidate = (value or "").strip().lower()
    valid = {item.value for item in CrashType}
    if candidate in valid:
        return candidate
    return CrashType.INFO_DISCLOSURE.value


async def state_research(input: dict[str, Any], services: Any) -> StateResult:
    """Drive the bounded N-day research loop and emit a structured result."""
    budget = BudgetState.from_json(input["budget_json"])
    context = {
        "binary_id": input["binary_id"],
        "patched_binary_id": input.get("patched_binary_id"),
        "mitigations": input.get("mitigations") or {},
        "cve_id": input.get("cve_id"),
        "context_notes": input.get("context_notes") or "",
        "max_turns": budget.config.max_turns,
        "budget_summary": budget.summary_for_prompt(),
    }
    history: list[dict[str, Any]] = []
    research: dict[str, Any] | None = None
    status = "completed"
    last_error: str | None = None

    while not budget.exhausted:
        budget.record_turn()
        context["budget_summary"] = budget.summary_for_prompt()
        try:
            decision = await _llm_decision(
                services,
                _SYSTEM_PROMPT,
                _build_user_prompt(budget.turns_used, context, history),
            )
        except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
            last_error = f"llm error: {type(exc).__name__}: {exc}"
            _log.warning("research turn %d LLM error: %s", budget.turns_used, exc)
            history.append({"turn": budget.turns_used, "action": "llm_error", "summary": last_error})
            continue

        action = str(decision.get("action") or "").strip()
        if action == "submit":
            payload = decision.get("submit") or {}
            research = {
                "vulnerable_function": str(payload.get("vulnerable_function") or ""),
                "root_cause": str(payload.get("root_cause") or ""),
                "crash_type": _normalize_crash_type(str(payload.get("crash_type") or "")),
                "evidence": list(payload.get("evidence") or []),
            }
            break

        args = decision.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        # Always inject the binary_id for IDA-bridge tools when missing.
        if "binary_id" not in args and action in {"decompile", "xrefs_to", "assess_exploitability"}:
            args["binary_id"] = context["binary_id"]
        if action == "find_patched_functions":
            args.setdefault("binary_id_old", context["binary_id"])
            args.setdefault("binary_id_new", context.get("patched_binary_id"))
            if not args.get("binary_id_new"):
                history.append({"turn": budget.turns_used, "action": action, "summary": "skipped: no patched_binary_id"})
                continue

        t0 = time.monotonic()
        result = _execute_action(action, args, services)
        elapsed = time.monotonic() - t0
        budget.record_tool_time(min(elapsed, _TOOL_BUDGET_PER_CALL_S))
        history.append({
            "turn": budget.turns_used,
            "action": action,
            "summary": _summarize(result),
        })

    if research is None:
        status = "stalled"
        research = {
            "vulnerable_function": "",
            "root_cause": last_error or "research budget exhausted before submission",
            "crash_type": CrashType.INFO_DISCLOSURE.value,
            "evidence": [],
        }

    return StateResult(
        next_state="poc_development",
        output={
            **{k: input.get(k) for k in (
                "project_id", "target_path", "patched_path", "binary_id",
                "patched_binary_id", "mitigations", "cve_id", "integration",
                "context_notes",
            )},
            "research": research,
            "research_status": status,
            "research_history": history,
            "budget_json": budget.to_json(),
        },
    )

"""N-day researcher agent for the VR module.

Drives the research phase of ``VR_NDAY_V1``: identify the patch, decompile
the vulnerable function, classify the bug primitive, produce a root-cause
statement. Uses ``AilaLLMClient`` for multi-turn LLM reasoning, the IDA
bridge for analysis actions, and platform ``ObligationSet`` /
``BudgetState`` / ``BoundedEvidencePack`` to bound + adjudicate output.
``research()`` is the only entry point.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

from aila.platform.contracts.budget import BudgetConfig, BudgetState
from aila.platform.contracts.obligations import (
    AdjudicationResult,
    EvidenceObligation,
    ObligationSet,
    ObligationSeverity,
    adjudicate,
)
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
from aila.platform.services.evidence_pack import BoundedEvidencePack, EvidenceSection
from aila.platform.services.factory import ServiceFactory

from ..config_schema import VRConfigSchema
from ..contracts.finding import CrashType

__all__ = ["NdayResearcher"]

_log = logging.getLogger(__name__)
_VALID_CRASH_TYPES: frozenset[str] = frozenset(ct.value for ct in CrashType)
_VALID_ACTIONS: frozenset[str] = frozenset({
    "decompile", "diff_versions", "call_chain", "trace_dataflow",
    "xrefs_to", "search_pattern", "binary_survey", "reasoning", "submit",
})
_PRIO_PATCH = 10
_PRIO_VULN = 20
_PRIO_FLOW = 30
_PRIO_MITIGATIONS = 50
_PRIO_OTHER = 80
_HISTORY_WINDOW = 6

_CRITICAL = ObligationSeverity.CRITICAL
_REQUIRED = ObligationSeverity.REQUIRED
_RECOMMENDED = ObligationSeverity.RECOMMENDED
_OBLIGATION_DEFS: tuple[tuple[str, str, str, ObligationSeverity], ...] = (
    ("patch_identified", "The CVE patch has been identified by binary diff.", "diff_versions result naming the patched function(s)", _CRITICAL),
    ("root_cause_documented", "A concrete root cause has been written.", "submission.root_cause non-empty paragraph", _REQUIRED),
    ("vulnerable_function_decompiled", "The vulnerable function has been decompiled.", "decompile result for the named function", _REQUIRED),
    ("crash_type_classified", "The bug primitive is one of the CrashType values.", "submission.crash_type \u2208 CrashType vocabulary", _REQUIRED),
    ("mitigation_analysis", "Target mitigations are accounted for.", "machine_readiness mitigations report", _REQUIRED),
    ("cvss_vector", "A CVSS vector has been derived.", "downstream advisory builder run", _RECOMMENDED),
    ("cwe_mapped", "A CWE has been mapped from the bug primitive.", "downstream advisory builder run", _RECOMMENDED),
    ("affected_versions", "Affected versions are recorded.", "downstream advisory builder run or operator input", _RECOMMENDED),
)


def _shape_decompile(p: dict[str, Any]) -> dict[str, Any]:
    return {"address_or_name": str(p.get("address_or_name") or "")}


def _shape_call_chain(p: dict[str, Any]) -> dict[str, Any]:
    direction = str(p.get("direction") or "callers")
    return {
        "target_function": str(p.get("target_function") or ""),
        "direction": direction if direction in ("callers", "callees") else "callers",
    }


def _shape_trace_dataflow(p: dict[str, Any]) -> dict[str, Any]:
    try:
        idx = int(p.get("sink_argument_index", 0))
    except (TypeError, ValueError):
        idx = 0
    return {
        "address_or_name": str(p.get("address_or_name") or ""),
        "sink_function": str(p.get("sink_function") or ""),
        "sink_argument_index": idx,
    }


def _shape_xrefs_to(p: dict[str, Any]) -> dict[str, Any]:
    return {"address_or_name": str(p.get("address_or_name") or "")}


def _shape_search_pattern(p: dict[str, Any]) -> dict[str, Any]:
    return {"pattern_type": str(p.get("pattern_type") or "")}


def _shape_binary_survey(_p: dict[str, Any]) -> dict[str, Any]:
    return {}


# Action → (param shaper). Each shaper returns the kwargs forwarded to the
# IDA bridge in addition to the implicit ``binary_id`` field. ``diff_versions``
# is handled separately because it requires both the vulnerable and patched ids.
_ACTION_SHAPERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "decompile": _shape_decompile,
    "call_chain": _shape_call_chain,
    "trace_dataflow": _shape_trace_dataflow,
    "xrefs_to": _shape_xrefs_to,
    "search_pattern": _shape_search_pattern,
    "binary_survey": _shape_binary_survey,
}


def _title_decompile(p: dict[str, Any]) -> str:
    return f"Decompile: {p.get('address_or_name') or '?'}"


def _title_diff_versions(_p: dict[str, Any]) -> str:
    return "Patch diff (vulnerable vs patched)"


def _title_call_chain(p: dict[str, Any]) -> str:
    return (
        f"Call chain ({p.get('direction') or 'callers'}) → "
        f"{p.get('target_function') or '?'}"
    )


def _title_trace_dataflow(p: dict[str, Any]) -> str:
    return (
        f"Dataflow → {p.get('sink_function') or '?'}"
        f"[{p.get('sink_argument_index')}] in "
        f"{p.get('address_or_name') or '?'}"
    )


def _title_xrefs_to(p: dict[str, Any]) -> str:
    return f"Xrefs to {p.get('address_or_name') or '?'}"


def _title_search_pattern(p: dict[str, Any]) -> str:
    return f"Pattern: {p.get('pattern_type') or '?'}"


def _title_binary_survey(_p: dict[str, Any]) -> str:
    return "Binary survey"


_TITLE_BUILDERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "decompile": _title_decompile,
    "diff_versions": _title_diff_versions,
    "call_chain": _title_call_chain,
    "trace_dataflow": _title_trace_dataflow,
    "xrefs_to": _title_xrefs_to,
    "search_pattern": _title_search_pattern,
    "binary_survey": _title_binary_survey,
}


_SYSTEM_PROMPT = """You are an autonomous N-day vulnerability researcher.

Goal: explain the named CVE on the named binary by identifying the patch,
understanding the root cause, and classifying the bug primitive. You are
NOT exploiting it -- you are explaining it with primary evidence.

Each turn you receive: CVE id, vulnerable + patched binary ids, target
mitigations report, the obligation ledger, the budget status, the
evidence pack accumulated from prior turns, and a transcript of recent
turns.

You MUST return ONE JSON object with this shape (no prose outside it):
{
  "reasoning": "1-3 sentences explaining what you decided and why.",
  "action":   "decompile|diff_versions|call_chain|trace_dataflow|xrefs_to|search_pattern|binary_survey|reasoning|submit",
  "params":   { ... action-specific parameters ... },
  "submission": {  // ONLY when action="submit"
    "root_cause":          "one paragraph explaining the bug mechanism",
    "crash_type":          "one of the CrashType vocabulary values",
    "vulnerable_function": "function name or 0x-address",
    "exploitation_notes":  "how this could be exploited, or why it can't"
  }
}

Action parameter keys (anything else is ignored):
- decompile      : address_or_name
- diff_versions  : <none -- uses the binary ids from context>
- call_chain     : target_function, direction ("callers" or "callees")
- trace_dataflow : address_or_name, sink_function, sink_argument_index
- xrefs_to       : address_or_name
- search_pattern : pattern_type
- binary_survey  : <none>
- reasoning      : <none -- internal step, no tool call>
- submit         : provide "submission"; obligations must be met

Hard rules:
- Do NOT guess. If you have not proven a claim, do not make it.
- Do NOT submit while CRITICAL obligations are outstanding.
- Avoid hedge phrases ("might be", "could potentially") in reasoning;
  the adjudicator downgrades hedged claims.
- Pick the cheapest action with the highest information gain.
- diff_versions is unavailable if no patched binary id is in context;
  pick a different action in that case.
"""


class NdayResearcher:
    """Closed-loop N-day research agent. One instance per run."""
    def __init__(
        self,
        run_id: str,
        project_id: str,
        cve_id: str,
        binary_id: str,
        patched_binary_id: str | None,
        mitigations: dict[str, Any],
        ida_bridge: IDABridgeTool,
        config: VRConfigSchema,
        budget: BudgetState | None = None,
        context_notes: str = "",
    ) -> None:
        self.run_id = run_id
        self.project_id = project_id
        self.cve_id = cve_id
        self.binary_id = binary_id
        self.patched_binary_id = patched_binary_id
        self.mitigations = mitigations or {}
        self.context_notes = context_notes or ""
        self.ida = ida_bridge
        self.config = config
        self.obligations = self._build_obligations()
        if budget is not None:
            self.budget = budget
        else:
            self.budget = BudgetState(config=BudgetConfig(
                max_turns=self.config.nday_max_turns,
                max_tool_time_seconds=self.config.nday_tool_time_seconds,
            ))
        self._sections: list[EvidenceSection] = []
        if self.mitigations:
            self._sections.append(EvidenceSection(
                title="Target mitigations",
                content=json.dumps(self.mitigations, indent=2, default=str),
                source="machine_readiness",
                priority=_PRIO_MITIGATIONS,
            ))
            self.obligations.satisfy(
                "mitigation_analysis", "machine_readiness mitigations report",
            )
    async def research(self, emitter: Any = None) -> dict[str, Any]:
        steps: list[dict[str, Any]] = []
        submission: dict[str, Any] | None = None
        adjudication: AdjudicationResult | None = None
        while not self.budget.exhausted:
            turn = self.budget.turns_used + 1
            self.budget.record_turn()
            if self.budget.should_waive_recommended:
                self._auto_waive_recommended()
            await self._emit(
                emitter, f"Turn {turn}/{self.budget.config.max_turns} -- planning",
                stage="turn_start", turn=turn,
            )
            try:
                turn_result = await self._run_turn(turn, steps)
            except (RuntimeError, ValueError, KeyError, TypeError) as exc:
                _log.exception("nday turn %d raised -- recording as failure", turn)
                turn_result = {
                    "turn": turn, "action": "reasoning",
                    "reasoning": f"[turn_exception] {type(exc).__name__}: {exc}",
                    "result": None, "error": str(exc),
                }
            steps.append(turn_result)
            await self._emit(
                emitter, f"Turn {turn} → action={turn_result.get('action')}",
                stage="turn_done", turn=turn, action=turn_result.get("action"),
            )
            if turn_result.get("submitted"):
                submission = turn_result.get("submission")
                adjudication = turn_result.get("adjudication")
                break
        if submission is None:
            submission = self._partial_submission(steps)
            await self._emit(
                emitter, "Budget exhausted -- auto-submitting partial result.",
                stage="auto_submit",
            )
        evidence_refs = sorted({s.source for s in self._sections if s.source})
        return {
            "root_cause": submission.get("root_cause"),
            "crash_type": submission.get("crash_type"),
            "vulnerable_function": submission.get("vulnerable_function"),
            "exploitation_notes": submission.get("exploitation_notes"),
            "evidence_refs": evidence_refs,
            "obligations": self.obligations.model_dump(mode="json"),
            "budget": self.budget.to_json(),
            "adjudication": (
                adjudication.model_dump(mode="json") if adjudication else None
            ),
            "steps": steps,
        }
    async def _run_turn(
        self, turn: int, prior_steps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        pack = self._build_pack()
        prompt = self._build_user_prompt(turn, pack, prior_steps)
        client = ServiceFactory().llm_client
        t0 = time.monotonic()
        response = await client.chat(
            task_type="vulnerability_research",
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            run_id=self.run_id,
        )
        # LLM wall-clock counts against the tool-time budget.
        self.budget.record_tool_time(time.monotonic() - t0)
        if response.disabled:
            return {
                "turn": turn, "action": "reasoning",
                "reasoning": "LLM kill-switch active.",
                "result": None, "error": "llm_disabled",
            }
        parsed = self._parse_llm_json(response.content)
        if parsed is None:
            return {
                "turn": turn, "action": "reasoning",
                "reasoning": "[invalid_json] could not extract a JSON object",
                "raw_response": response.content[:400], "result": None,
            }
        action = str(parsed.get("action") or "reasoning").strip()
        reasoning = str(parsed.get("reasoning") or "").strip()
        params = parsed.get("params") if isinstance(parsed.get("params"), dict) else {}
        if action not in _VALID_ACTIONS:
            _log.warning("nday turn %d invalid action %r -- coerced to reasoning", turn, action)
            action = "reasoning"
        record: dict[str, Any] = {
            "turn": turn, "action": action, "reasoning": reasoning,
            "params": params, "submitted": False, "result": None,
        }
        if action == "submit":
            sub = self._validate_submission(parsed.get("submission") or {})
            adj = adjudicate(
                claim=sub.get("root_cause") or "",
                reasoning_text=reasoning, obligations=self.obligations,
            )
            record["submission"] = sub
            record["adjudication"] = adj
            if adj.verdict == "blocked":
                # Convert to reasoning -- agent will see unmet obligations next turn.
                record["action"] = "reasoning"
                hedge = (
                    f" hedge={adj.contradiction_signals}"
                    if adj.contradiction_signals else ""
                )
                record["reasoning"] = f"[submission_blocked] {adj.reason}{hedge}"
                return record
            if sub.get("crash_type"):
                self.obligations.satisfy("crash_type_classified", "submission.crash_type")
            if sub.get("root_cause"):
                self.obligations.satisfy("root_cause_documented", "submission.root_cause")
            record["submitted"] = True
            return record
        if action == "reasoning":
            return record
        # Tool action through the IDA bridge.
        tool_t0 = time.monotonic()
        outcome = await self._dispatch_action(action, params)
        record["tool_seconds"] = round(time.monotonic() - tool_t0, 2)
        self.budget.record_tool_time(record["tool_seconds"])
        record["result"] = outcome
        self._absorb_outcome(action, params, outcome)
        return record
    @staticmethod
    def _parse_llm_json(content: str) -> dict[str, Any] | None:
        if not content:
            return None
        text = content.strip()
        if text.startswith("```"):
            nl = text.find("\n")
            if nl >= 0:
                text = text[nl + 1:]
            if text.rstrip().endswith("```"):
                text = text.rstrip()[:-3].rstrip()
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            obj = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
        return obj if isinstance(obj, dict) else None
    @staticmethod
    def _validate_submission(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {
                "root_cause": None, "crash_type": None,
                "vulnerable_function": None, "exploitation_notes": None,
            }
        crash = raw.get("crash_type")
        if not (isinstance(crash, str) and crash in _VALID_CRASH_TYPES):
            crash = None
        return {
            "root_cause": (raw.get("root_cause") or None),
            "crash_type": crash,
            "vulnerable_function": (raw.get("vulnerable_function") or None),
            "exploitation_notes": (raw.get("exploitation_notes") or None),
        }
    async def _dispatch_action(
        self, action: str, params: dict[str, Any],
    ) -> dict[str, Any]:
        """Translate one LLM action into one IDA bridge HTTP call."""
        if action == "diff_versions":
            if not self.patched_binary_id:
                return {"status": "error", "error": "no patched_binary_id available"}
            return await self.ida.forward(
                action="diff_binary",
                binary_id_old=self.binary_id,
                binary_id_new=self.patched_binary_id,
            )
        shaper = _ACTION_SHAPERS.get(action)
        if shaper is None:  # pragma: no cover -- guarded by _VALID_ACTIONS
            return {"status": "error", "error": f"unhandled action: {action}"}
        return await self.ida.forward(
            action=action, binary_id=self.binary_id, **shaper(params),
        )
    def _absorb_outcome(
        self, action: str, params: dict[str, Any], outcome: dict[str, Any],
    ) -> None:
        """Translate a tool result into evidence + obligation updates."""
        if not isinstance(outcome, dict):
            return
        status = str(outcome.get("status") or "").lower()
        if status in ("error", "pending"):
            # error: don't pollute the pack. pending: agent will re-issue.
            return
        self._sections.append(EvidenceSection(
            title=self._title_for(action, params),
            content=json.dumps(outcome, indent=2, default=str),
            source=f"ida.{action}",
            priority=self._priority_for(action),
        ))
        if action == "diff_versions":
            self.obligations.satisfy(
                "patch_identified",
                f"diff_binary({self.binary_id} vs {self.patched_binary_id})",
            )
        elif action == "decompile":
            self.obligations.satisfy(
                "vulnerable_function_decompiled",
                f"decompile({params.get('address_or_name') or '?'})",
            )
    @staticmethod
    def _title_for(action: str, params: dict[str, Any]) -> str:
        builder = _TITLE_BUILDERS.get(action)
        return builder(params) if builder else f"Result: {action}"
    @staticmethod
    def _priority_for(action: str) -> int:
        if action == "diff_versions":
            return _PRIO_PATCH
        if action == "decompile":
            return _PRIO_VULN
        if action in ("call_chain", "trace_dataflow"):
            return _PRIO_FLOW
        return _PRIO_OTHER
    def _build_pack(self) -> BoundedEvidencePack:
        pack = BoundedEvidencePack(
            hypothesis=f"Reproduce {self.cve_id} on {self.binary_id}",
        )
        for s in self._sections:
            pack.add(EvidenceSection(
                title=s.title, content=s.content,
                source=s.source, priority=s.priority,
            ))
        return pack
    def _build_user_prompt(
        self, turn: int, pack: BoundedEvidencePack,
        prior_steps: list[dict[str, Any]],
    ) -> str:
        header = (
            f"CVE: {self.cve_id}\n"
            f"Vulnerable binary id: {self.binary_id}\n"
            f"Patched binary id:    {self.patched_binary_id or '(not provided)'}\n"
            f"Project: {self.project_id}\n"
            f"Run id:  {self.run_id}\n"
            f"Turn:    {turn}\n"
            f"Context notes: {self.context_notes or '(none)'}\n"
        )
        evidence = pack.render() or "(no evidence collected yet)"
        history = self._render_history(prior_steps[-_HISTORY_WINDOW:])
        return (
            f"{header}\nBudget: {self.budget.summary_for_prompt()}\n\n"
            f"Obligations:\n{self.obligations.summary_for_prompt()}\n\n"
            f"=== EVIDENCE PACK ===\n{evidence}\n\n"
            f"=== RECENT TURNS ===\n{history}\n\n"
            "Reply with the JSON object specified in the system prompt."
        )
    @staticmethod
    def _render_history(steps: list[dict[str, Any]]) -> str:
        if not steps:
            return "(none -- this is your first turn)"
        lines: list[str] = []
        for step in steps:
            status = "submitted" if step.get("submitted") else step.get("action")
            line = f"- t{step.get('turn')}: {status}"
            params = step.get("params")
            if isinstance(params, dict) and params:
                line += f" params={json.dumps(params, default=str)[:120]}"
            err = step.get("error")
            result = step.get("result")
            if err:
                line += f" ERROR={str(err)[:120]}"
            elif isinstance(result, dict):
                line += f" → {result.get('status') or '?'}"
            lines.append(line)
        return "\n".join(lines)
    @staticmethod
    def _build_obligations() -> ObligationSet:
        obs = ObligationSet()
        for ob_id, claim, evidence, severity in _OBLIGATION_DEFS:
            obs.add(EvidenceObligation(
                id=ob_id, claim=claim,
                required_evidence=evidence, severity=severity,
            ))
        return obs
    def _auto_waive_recommended(self) -> None:
        for ob in self.obligations.obligations:
            if ob.severity is ObligationSeverity.RECOMMENDED and ob.outstanding:
                self.obligations.waive(
                    ob.id,
                    reason=f"auto-waived at {self.budget.turn_fraction:.0%} of turn budget",
                    source="budget",
                )
    def _partial_submission(self, steps: list[dict[str, Any]]) -> dict[str, Any]:
        """Best-effort dict when the agent ran out of budget."""
        for step in reversed(steps):
            sub = step.get("submission")
            if isinstance(sub, dict):
                return sub
        vuln_func: str | None = None
        for step in steps:
            if step.get("action") == "decompile":
                params = step.get("params") or {}
                vuln_func = str(params.get("address_or_name") or "") or None
                if vuln_func:
                    break
        return {
            "root_cause": "(budget exhausted; agent could not converge)",
            "crash_type": None,
            "vulnerable_function": vuln_func,
            "exploitation_notes": None,
        }
    @staticmethod
    async def _emit(emitter: Any, msg: str, **payload: Any) -> None:
        if emitter is None:
            return
        try:
            await emitter.emit("nday_research", msg, payload)
        except (RuntimeError, AttributeError, TypeError) as exc:
            _log.debug("nday emitter failed: %s", exc)

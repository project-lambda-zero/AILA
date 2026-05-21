"""ClaimVerifierAgent — adversarial verification of canonical-outcome claims.

Runs AFTER the synthesis agent has consolidated the deliberation panel
into a single narrative. The verifier's job is the opposite of the
deliberation panel: instead of producing a finding, it tries to REFUTE
the finding the panel produced.

The flow:

    1. EXTRACTOR LLM call — parses ``canonical_outcome.payload.answer``
       (and ``panel_summary.narrative`` if present) into a structured list
       of falsifiable preconditions. Each precondition carries a single
       ``audit_mcp.<tool>(...)`` probe call whose result will either
       confirm or refute it.

    2. PROBE EXECUTOR — runs every proposed probe directly against the
       audit-mcp HTTP surface via ``AuditMcpBridgeTool``. Pure mechanical
       execution; no reasoning step here, so the verifier cannot drift.

    3. VERDICT LLM call — given each precondition + the raw probe output,
       classifies the precondition as ``true | false | unknown`` and then
       emits an overall verdict ``confirmed | refuted | inconclusive``
       with a counter-evidence narrative when refuted.

    4. PERSIST — writes ``verifier_report`` into the canonical outcome's
       payload alongside ``panel_summary``. The frontend surfaces the
       refuted/inconclusive verdict as a visible warning so the operator
       doesn't trust a false-positive finding by default.

This catches the two false-positive classes we hit on the nginx variant
hunts (investigations e4e4d474 and 65505622):

    - "shape predicate matches the parent CVE" without verifying the
      preconditions are actually reachable in the audited bytecode array
    - "no per-iteration reset of state X carries across iterations"
      without verifying that any opcode actually mutates X in that array

Both finalised with strong-confidence false-positives that a single
counter-evidence probe (``compile_args = 1`` callsite search; opcode
emission grep) would have killed.

Idempotency: skips when ``verifier_report`` is already present in the
canonical outcome's payload. Triggered post-synthesis from
``investigation_emit._maybe_trigger_synthesis``.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.platform.contracts._common import utc_now
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

_NEGATIVE_ANSWER_PREFIXES = (
    "NEGATIVE",
    "NOT VULNERABLE",
    "NO BUG",
    "NO VULNERABILITY",
    "NO FINDING",
    "PATCH PRESENT",
    "VARIANT DEAD",
    "VARIANT IS DEAD",
    "NO VARIANTS",
)

_AUTO_PROMOTE_MIN_CONFIDENCE = 0.70


def is_negative_finding_claim(answer: str) -> bool:
    """A 'confirmed' verifier verdict only means the agent's CLAIM was
    correct — not that a bug exists. When the agent's claim is 'this
    is NOT vulnerable / patch present / no variants', the verdict
    'confirmed' actually means 'confirmed there is no bug'. Those
    must NOT be auto-promoted to direct_finding.
    """
    head = (answer or "").strip().upper()[:80]
    return any(head.startswith(p) for p in _NEGATIVE_ANSWER_PREFIXES)



__all__ = ["ClaimVerifierAgent", "is_negative_finding_claim"]

_log = logging.getLogger(__name__)


_PROBE_TOOL_ALLOWLIST = frozenset({
    "search_source",
    "search_macros",
    "search_constants",
    "search_types",
    "search_functions",
    "read_function",
    "callers_of",
    "callees_of",
    "paths_between",
    "taint_paths_to",
    "nodes_with_annotation",
})


async def _fetch_audit_mcp_signatures() -> str:
    """Pull live tool schemas from audit-mcp so the extractor LLM
    proposes probes with the right argument names. Returns a compact
    markdown list of ``tool: required_args; optional_args`` for the
    tools the verifier is allowed to call. Failure-tolerant — returns
    an empty string so the verifier falls back on the LLM's prior
    knowledge of audit-mcp instead of crashing.
    """
    import urllib.request  # noqa: PLC0415

    bridge = AuditMcpBridgeTool()
    try:
        base_url = await bridge._resolve_base_url()
    except (OSError, RuntimeError):
        return ""
    try:
        with urllib.request.urlopen(f"{base_url}/tools", timeout=5) as r:
            raw = json.loads(r.read().decode())
    except (OSError, ValueError, TimeoutError):
        return ""
    tools = raw.get("tools", raw) if isinstance(raw, dict) else raw
    if not isinstance(tools, list):
        return ""
    lines: list[str] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = t.get("name")
        if name not in _PROBE_TOOL_ALLOWLIST:
            continue
        params = t.get("parameters") or {}
        props = params.get("properties") or {}
        required = list(params.get("required") or [])
        optional = [k for k in props if k not in required]
        sig = f"  - audit_mcp.{name}({', '.join(required)})"
        if optional:
            sig += f"   [optional: {', '.join(optional)}]"
        lines.append(sig)
    return "\n".join(lines)

def _render_probe_payload(tool: str, raw: Any) -> str:
    """Format an audit-mcp probe response for the verifier verdict prompt.

    Tool-aware so each probe shape produces the densest readable
    output. ``read_function`` joins the ``body`` line list back into
    real source (vs JSON-encoding which 2x's the byte cost from
    quote-escapes). ``search_*`` emits one match per line in
    ``file:line: text`` form. Everything else falls back to
    JSON.dumps. Callers should still clamp the result — this helper
    only chooses the encoding; bounding is the caller's job.
    """
    if not isinstance(raw, dict):
        try:
            return json.dumps(raw)
        except (TypeError, ValueError):
            return repr(raw)

    tool_name = tool.split(".", 1)[1] if "." in tool else tool

    if tool_name == "read_function":
        body = raw.get("body") or raw.get("source") or raw.get("text") or ""
        if isinstance(body, list):
            body_text = "\n".join(str(line) for line in body)
        else:
            body_text = str(body)
        fp = raw.get("file_path") or raw.get("file") or ""
        ln = raw.get("start_line") or raw.get("line") or ""
        header = f"// {fp}:{ln}  ({raw.get('line_count','?')} lines)" if fp else ""
        return f"{header}\n{body_text}" if header else body_text

    if tool_name in ("search_source", "search_macros", "search_constants",
                     "search_types", "search_functions"):
        matches = (raw.get("matches") or raw.get("results")
                   or raw.get("hits") or [])
        if not isinstance(matches, list):
            return json.dumps(raw)
        lines = [f"({len(matches)} matches)"]
        for m in matches:
            if not isinstance(m, dict):
                lines.append(str(m))
                continue
            fp = m.get("file_path") or m.get("file") or m.get("path") or "?"
            ln = m.get("line") or m.get("start_line") or "?"
            txt = (m.get("text") or m.get("snippet")
                   or m.get("match") or m.get("body") or "").strip()
            if isinstance(txt, list):
                txt = " ".join(str(x) for x in txt).strip()
            lines.append(f"{fp}:{ln}: {txt}")
        return "\n".join(lines)

    if tool_name in ("callers_of", "callees_of"):
        entries = (raw.get("callers") or raw.get("callees")
                   or raw.get("results") or [])
        if isinstance(entries, list):
            lines = [f"({len(entries)} entries)"]
            for e in entries:
                if isinstance(e, dict):
                    name = e.get("name") or e.get("function_name") or "?"
                    fp = e.get("file_path") or e.get("file") or ""
                    ln = e.get("line") or e.get("start_line") or ""
                    lines.append(f"{name}  {fp}:{ln}")
                else:
                    lines.append(str(e))
            return "\n".join(lines)

    try:
        return json.dumps(raw)
    except (TypeError, ValueError):
        return repr(raw)


_EXTRACTOR_SYSTEM_PROMPT = """You are an adversarial vulnerability-finding verifier.

You are given a finding produced by a panel of reasoning agents about a
specific vulnerability claim in source code. Your job is NOT to confirm
the finding. Your job is to enumerate the falsifiable preconditions the
finding depends on, then for each one propose ONE audit_mcp tool call
that would refute it if the precondition is wrong.

OUTPUT FORMAT (strict JSON, no prose, no markdown fences):

{
  "preconditions": [
    {
      "id": "P1",
      "claim": "<one-sentence claim the finding depends on>",
      "if_refuted_then": "<what the finding gets if this is false>",
      "probe": {
        "tool": "audit_mcp.<tool_name>",
        "args": { "index_id": "$INDEX_ID", ... }
      },
      "refutation_signature": "<what we would see in the probe result if the claim is FALSE>"
    },
    ...
  ]
}

Rules:
  - 3 to 6 preconditions. Be selective; pick the load-bearing ones.
  - Each ``probe`` must be a real audit-mcp tool (search_source,
    search_macros, read_function, search_constants, callers_of,
    callees_of, etc.). Use ``$INDEX_ID`` as a literal placeholder for
    the index — the executor substitutes the real id.
  - Prefer probes that, if they return ZERO matches, would refute the
    precondition. The whole point is asymmetric refutation.
  - **CRITICAL — probe sizing rule**: when verifying whether a SPECIFIC
    PATTERN (e.g. `sc.complete_lengths = 1`, `mark_args_code`, an
    `if (x->is_args)` gate) is present or absent inside a function,
    ALWAYS use `search_source` with the exact pattern — NEVER use
    `read_function`. `read_function` returns the whole function body
    and a 500-line function's body will not fit in the verifier's
    per-probe budget; the load-bearing region almost always lives in
    the middle or end of large functions, gets truncated, and the
    verifier returns inconclusive when it should return refuted.
    `search_source` returns one line per match — bounded, cheap,
    diagnostic. Only fall back to `read_function` when the
    precondition is about overall function structure (e.g. "function
    is short enough that no missing-counterpart can hide") rather
    than about a specific pattern.
  - Examples of high-value precondition shapes:
      * "Opcode X is reachable from bytecode Y because callsite Z sets
        sc.compile_args = 1" → probe: search_source for
        'compile_args = 1' across the file containing the relevant
        init_params function.
      * "Function F is missing the per-iteration reset of e->is_args" →
        probe: search_source for `e->is_args = 0` scoped to F's file.
      * "Block X does NOT set sc.complete_lengths" → probe:
        search_source for `complete_lengths` scoped to F's file (NOT
        read_function on the wrapper — too long to fit).
      * "Macro M expands to a length-prefix write" → probe:
        search_macros for M.
"""


_VERDICT_SYSTEM_PROMPT = """You are an adversarial verifier producing a
final verdict on whether a vulnerability finding is correct given probe
results from the source.

OUTPUT FORMAT (strict JSON, no prose, no markdown fences):

{
  "verdict": "confirmed" | "refuted" | "inconclusive",
  "confidence": 0.0 to 1.0,
  "preconditions": [
    {
      "id": "P1",
      "claim": "<verbatim claim>",
      "result": "true" | "false" | "unknown",
      "evidence": "<one-sentence summary of what the probe showed>"
    },
    ...
  ],
  "counter_evidence": "<empty string when confirmed, otherwise a 1-3
    paragraph explanation of WHY the finding is wrong, citing the
    specific probe results>",
  "summary": "<one paragraph for the operator>"
}

Rules:
  - "refuted" requires AT LEAST ONE precondition with result=false that
    is load-bearing (the finding cannot survive its falsification).
  - "inconclusive" when probes don't cleanly resolve (e.g. all returned
    unknown / partial data).
  - "confirmed" when all probes either returned true OR returned
    unknown but the load-bearing ones returned true.
  - Be honest about disagreement with the panel. The panel can be
    wrong; that's why you exist.
"""


class ClaimVerifierAgent:
    """Three-stage adversarial verifier: extract → probe → verdict."""

    _EXTRACTOR_TASK_TYPE = "vulnerability_research.synthesizer"
    _VERDICT_TASK_TYPE = "vulnerability_research.synthesizer"
    _MAX_PROBES = 8
    _PROBE_TIMEOUT_S = 30.0

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id

    async def run(self) -> dict[str, Any]:
        """Run the full extract → probe → verdict pipeline once."""
        # Stage 0: load canonical outcome + target index_id
        loaded = await self._load_context()
        if loaded.get("status") != "ok":
            return loaded
        canonical = loaded["canonical"]
        canonical_payload = loaded["canonical_payload"]
        index_id = loaded["index_id"]

        if "verifier_report" in canonical_payload:
            return {
                "status": "skipped",
                "reason": "already_verified",
                "canonical_outcome_id": canonical.id,
            }

        # Build the source text the extractor will reason about.
        narrative = ""
        ps = canonical_payload.get("panel_summary")
        if isinstance(ps, dict):
            narrative = str(ps.get("narrative") or "")
        finding_text = str(canonical_payload.get("answer") or "") + (
            ("\n\n# Panel synthesis narrative\n" + narrative) if narrative else ""
        )
        if not finding_text.strip():
            return {"status": "skipped", "reason": "no_finding_text"}

        # Stage 1: extractor — parse the claim into structured preconditions
        services = ServiceFactory()
        signatures_block = await _fetch_audit_mcp_signatures()
        sig_section = (
            f"## Available audit-mcp probes (live signatures)\n\n{signatures_block}\n\n"
            if signatures_block else ""
        )
        extractor_input = (
            f"# Finding to verify\n\n"
            f"Investigation kind: {loaded['kind']}\n"
            f"Target index_id: {index_id}\n\n"
            f"{sig_section}"
            f"## Finding text\n\n{finding_text[:8000]}\n"
        )
        try:
            extractor_response = await services.llm_client.chat(
                task_type=self._EXTRACTOR_TASK_TYPE,
                messages=[
                    {"role": "system", "content": _EXTRACTOR_SYSTEM_PROMPT},
                    {"role": "user", "content": extractor_input},
                ],
            )
        except (RuntimeError, OSError, TimeoutError) as exc:
            _log.warning("claim_verifier extractor failed inv=%s err=%s",
                         self.investigation_id, exc)
            return {"status": "failed", "reason": f"extractor_error:{exc}"}
        if extractor_response.disabled:
            return {"status": "skipped", "reason": "llm_kill_switch_active"}
        preconditions = self._parse_preconditions(extractor_response.content)
        if not preconditions:
            return {"status": "failed", "reason": "extractor_returned_no_preconditions"}

        # Stage 2: probe executor — substitute $INDEX_ID + run each probe
        bridge = AuditMcpBridgeTool()
        probe_results: list[dict[str, Any]] = []
        for p in preconditions[: self._MAX_PROBES]:
            probe_spec = p.get("probe") or {}
            tool = str(probe_spec.get("tool") or "")
            tool_name = tool.split(".", 1)[1] if tool.startswith("audit_mcp.") else ""
            args = dict(probe_spec.get("args") or {})
            # enforce allowlist — extractor can hallucinate tool names;
            # only run the curated set used for source-level verification
            if tool_name not in _PROBE_TOOL_ALLOWLIST:
                probe_results.append({
                    "id": p.get("id"),
                    "ok": False,
                    "error": f"refused: probe tool {tool!r} not on verifier allowlist",
                    "raw": None,
                })
                continue
            # substitute the index_id placeholder
            for k, v in list(args.items()):
                if v == "$INDEX_ID":
                    args[k] = index_id
            action = tool_name
            try:
                raw = await bridge.forward(action=action, **args)
                ok = raw.get("status") != "error"
                probe_results.append({
                    "id": p.get("id"),
                    "ok": ok,
                    "error": raw.get("error") if not ok else None,
                    "raw": raw,
                })
            except (OSError, RuntimeError, TimeoutError) as exc:
                probe_results.append({
                    "id": p.get("id"),
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "raw": None,
                })

        # Stage 3: verdict — feed precondition + probe result pairs back
        verdict_input = self._render_verdict_input(preconditions, probe_results)
        try:
            verdict_response = await services.llm_client.chat(
                task_type=self._VERDICT_TASK_TYPE,
                messages=[
                    {"role": "system", "content": _VERDICT_SYSTEM_PROMPT},
                    {"role": "user", "content": verdict_input},
                ],
            )
        except (RuntimeError, OSError, TimeoutError) as exc:
            _log.warning("claim_verifier verdict LLM failed inv=%s err=%s",
                         self.investigation_id, exc)
            return {"status": "failed", "reason": f"verdict_error:{exc}"}
        if verdict_response.disabled:
            return {"status": "skipped", "reason": "llm_kill_switch_active"}
        verdict = self._parse_verdict(verdict_response.content)
        if verdict is None:
            return {"status": "failed", "reason": "verdict_unparseable"}

        # Stage 4: persist verifier_report on canonical outcome
        verifier_report = {
            "verdict": verdict.get("verdict") or "inconclusive",
            "confidence": verdict.get("confidence"),
            "preconditions": verdict.get("preconditions") or [],
            "counter_evidence": verdict.get("counter_evidence") or "",
            "summary": verdict.get("summary") or "",
            "probes_run": len(probe_results),
            "probes_succeeded": sum(1 for p in probe_results if p["ok"]),
            "verified_at": utc_now().isoformat(),
        }

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == canonical.id,
                )
            )).first()
            if row is None:
                return {"status": "failed", "reason": "canonical_disappeared"}
            try:
                payload = json.loads(row.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            if "verifier_report" in payload:
                return {
                    "status": "skipped",
                    "reason": "already_verified_under_lock",
                    "canonical_outcome_id": canonical.id,
                }
            payload["verifier_report"] = verifier_report
            row.payload_json = json.dumps(payload)
            uow.session.add(row)
            await uow.commit()

        # Auto-promote on verifier-confirmed positive findings.
        # Only fires when:
        #   - verdict == confirmed AND confidence >= 0.70
        #   - outcome currently sits in the assessment_report /
        #     dispatch=skipped trap (the routing dead-end fixed by the
        #     operator-promote endpoint; this path closes the loop so
        #     the operator doesn't have to click the button by hand
        #     for every confirmed finding)
        #   - agent's answer doesn't open with NEGATIVE / PATCH
        #     PRESENT / NO VULNERABILITY / etc. (a confirmed-negative
        #     means "confirmed no bug", which must not be promoted)
        #   - payload doesn't already carry promoted_from (idempotent)
        promote_result: dict[str, Any] | None = None
        if verifier_report["verdict"] == "confirmed":
            promote_result = await self._maybe_auto_promote(
                canonical_id=canonical.id,
                confidence=verifier_report.get("confidence"),
                summary=verifier_report.get("summary") or "",
            )

        _log.info(
            "claim_verifier DONE inv=%s verdict=%s probes=%d auto_promote=%s",
            self.investigation_id, verifier_report["verdict"],
            len(probe_results),
            (promote_result or {}).get("status", "not_attempted"),
        )
        return {
            "status": "ok",
            "verdict": verifier_report["verdict"],
            "preconditions_count": len(preconditions),
            "probes_run": len(probe_results),
            "canonical_outcome_id": canonical.id,
            "auto_promote": promote_result,
        }

    async def _maybe_auto_promote(
        self,
        *,
        canonical_id: str,
        confidence: Any,
        summary: str,
    ) -> dict[str, Any]:
        """Promote a confirmed assessment_report -> direct_finding +
        re-dispatch through OutcomeDispatcher, so the verifier-confirmed
        finding lands in vr_findings with a PoC writer task enqueued
        (on variant children). Returns a small dict describing what
        happened for the run() return payload.
        """
        from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher  # noqa: PLC0415
        from aila.modules.vr.contracts import (  # noqa: PLC0415
            OutcomeDispatchStatus,
            OutcomeKind,
        )

        if not isinstance(confidence, (int, float)):
            return {"status": "skipped", "reason": "no_numeric_confidence"}
        conf = float(confidence)
        if conf < _AUTO_PROMOTE_MIN_CONFIDENCE:
            return {"status": "skipped", "reason": f"confidence_below_floor:{conf:.2f}<{_AUTO_PROMOTE_MIN_CONFIDENCE}"}

        # Re-load the canonical outcome row to mutate it transactionally
        # (the verifier_report write happened in a previous UoW; another
        # writer could have raced in between, so we re-read + re-check).
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == canonical_id,
                )
            )).first()
            if row is None:
                return {"status": "skipped", "reason": "outcome_disappeared"}
            if row.outcome_kind != OutcomeKind.ASSESSMENT_REPORT.value:
                return {
                    "status": "skipped",
                    "reason": f"outcome_kind_not_assessment:{row.outcome_kind}",
                }
            if row.dispatch_status != OutcomeDispatchStatus.SKIPPED.value:
                return {
                    "status": "skipped",
                    "reason": f"dispatch_status_not_skipped:{row.dispatch_status}",
                }
            try:
                payload = json.loads(row.payload_json or "{}")
            except (ValueError, TypeError):
                return {"status": "skipped", "reason": "payload_unparseable"}
            if payload.get("promoted_from"):
                return {"status": "skipped", "reason": "already_promoted"}
            if is_negative_finding_claim(payload.get("answer") or ""):
                return {
                    "status": "skipped",
                    "reason": "answer_starts_negative_no_bug_to_promote",
                }

            payload["promoted_from"] = {
                "kind": OutcomeKind.ASSESSMENT_REPORT.value,
                "at": utc_now().isoformat(),
                "by_user_id": "verifier_auto_promote",
                "reason": f"verifier confirmed conf={conf:.2f} | {summary[:300]}",
                "prior_dispatch_status": row.dispatch_status,
            }
            row.outcome_kind = OutcomeKind.DIRECT_FINDING.value
            row.payload_json = json.dumps(payload)
            row.dispatch_status = OutcomeDispatchStatus.PENDING.value
            row.dispatch_target = None
            uow.session.add(row)
            await uow.commit()

        try:
            dispatcher = OutcomeDispatcher(knowledge=ServiceFactory().knowledge)
            result = await dispatcher.dispatch(canonical_id)
        except (OSError, RuntimeError, ValueError) as exc:
            _log.warning(
                "auto_promote dispatch FAILED inv=%s outcome=%s err=%s",
                self.investigation_id, canonical_id, exc,
            )
            return {
                "status": "promoted_dispatch_failed",
                "reason": f"{type(exc).__name__}:{exc}",
            }
        _log.info(
            "auto_promote OK inv=%s outcome=%s -> %s (%s)",
            self.investigation_id, canonical_id,
            result.dispatch_target, result.dispatch_status.value,
        )
        return {
            "status": "promoted",
            "dispatch_status": result.dispatch_status.value,
            "dispatch_target": result.dispatch_target,
            "dispatch_reason": result.reason[:200],
        }

    async def _load_context(self) -> dict[str, Any]:
        from aila.modules.vr.db_models import VRTargetRecord  # noqa: PLC0415

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                )
            )).first()
            if inv is None:
                return {"status": "skipped", "reason": "investigation_not_found"}
            if inv.status not in (
                InvestigationStatus.COMPLETED.value,
                InvestigationStatus.PAUSED.value,
                InvestigationStatus.FAILED.value,
            ):
                # Run only on terminal-state investigations so we never
                # verify a moving target.
                return {"status": "skipped", "reason": f"status_not_terminal:{inv.status}"}
            canonical = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.investigation_id == self.investigation_id)
                .order_by(VRInvestigationOutcomeRecord.created_at.asc())
                .limit(1)
            )).first()
            if canonical is None:
                return {"status": "skipped", "reason": "no_canonical_outcome"}
            try:
                canonical_payload = json.loads(canonical.payload_json or "{}")
            except (ValueError, TypeError):
                canonical_payload = {}
            # Pull index_id from the target so probes hit the right index
            index_id = ""
            if inv.target_id:
                tgt = (await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == inv.target_id),
                )).first()
                if tgt is not None:
                    try:
                        handles = json.loads(tgt.mcp_handles_json or "{}")
                        index_id = str(handles.get("audit_mcp_index_id") or "")
                    except (ValueError, TypeError):
                        pass
            if not index_id:
                return {"status": "skipped", "reason": "target_has_no_audit_mcp_index"}
            return {
                "status": "ok",
                "canonical": canonical,
                "canonical_payload": canonical_payload,
                "index_id": index_id,
                "kind": inv.kind,
            }

    def _parse_preconditions(self, raw_content: str) -> list[dict[str, Any]]:
        """Extract the preconditions array from the extractor LLM output.

        Tolerates fenced JSON, leading prose, trailing prose. Returns an
        empty list when parsing fails so the caller emits a clean
        ``failed`` status instead of a half-loaded report.
        """
        text = (raw_content or "").strip()
        # Strip fenced markdown if present
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(
                line for line in lines if not line.startswith("```")
            ).strip()
        # Try direct parse, then bracket-scan fallback
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end <= start:
                return []
            try:
                obj = json.loads(text[start : end + 1])
            except (ValueError, TypeError):
                return []
        pre = obj.get("preconditions") if isinstance(obj, dict) else None
        return pre if isinstance(pre, list) else []

    def _render_verdict_input(
        self,
        preconditions: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> str:
        """Compose the user message for the verdict LLM call."""
        out: list[str] = ["# Preconditions and probe results\n"]
        # Index results by precondition id for joining
        results_by_id = {r.get("id"): r for r in results}
        for p in preconditions:
            pid = p.get("id") or "(no id)"
            out.append(f"## {pid}: {p.get('claim')}")
            out.append(f"refutation_signature: {p.get('refutation_signature')}")
            out.append(f"if_refuted_then: {p.get('if_refuted_then')}")
            probe = p.get("probe") or {}
            out.append(f"probe: {probe.get('tool')} args={probe.get('args')}")
            r = results_by_id.get(pid)
            if r is None:
                out.append("probe_result: <skipped — over max probe count>")
            elif not r["ok"]:
                out.append(f"probe_result: ERROR {r.get('error')}")
            else:
                # Format the probe result smartly by shape:
                #   read_function → join the `body` list as raw source
                #     (avoids the 2x cost of JSON-escaping every line)
                #   search_source / search_macros / search_constants →
                #     emit matches one per line as `file:line: text`
                #   everything else → JSON-stringified
                # Then truncate to 40000 chars (was 1800 — way too small;
                # at 1800 a single read_function on a 500-line function
                # comes back as ~40 lines, so the verifier never sees
                # the load-bearing region of the function).
                raw = r["raw"]
                tool = (p.get("probe") or {}).get("tool") or ""
                rendered = _render_probe_payload(tool, raw)
                if len(rendered) > 40000:
                    rendered = rendered[:40000] + (
                        f"\n... [truncated — {len(rendered)} chars total; "
                        f"if load-bearing region of the function is past this, "
                        f"re-issue with a narrower search_source probe targeting "
                        f"the exact pattern]"
                    )
                out.append(f"probe_result:\n{rendered}")
            out.append("")
        out.append(
            "Now produce the JSON verdict per the system prompt. Be willing"
            " to say 'refuted' when the load-bearing precondition fails."
        )
        return "\n".join(out)

    def _parse_verdict(self, raw_content: str) -> dict[str, Any] | None:
        """Parse the verdict LLM output."""
        text = (raw_content or "").strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(
                line for line in lines if not line.startswith("```")
            ).strip()
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end <= start:
                return None
            try:
                return json.loads(text[start : end + 1])
            except (ValueError, TypeError):
                return None

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

import asyncio
import json
import logging
import os
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

# fix §345 — env override for the auto-promote confidence floor.
# 0.70 is the tuned default (matches the synthesis pipeline's
# medium/high threshold). Operators can bump it (e.g. 0.85) during
# noisy investigation campaigns where verifier confirmation is
# cheap but a false promote ships a wrong DIRECT_FINDING downstream.
# Read at module load — acceptable for a tuning knob; changing it
# requires a worker restart, same as every other tunable in this file.
_AUTO_PROMOTE_MIN_CONFIDENCE_DEFAULT = 0.70


def _read_auto_promote_floor() -> float:
    raw = os.environ.get("VR_CLAIM_VERIFIER_AUTO_PROMOTE_FLOOR")
    if not raw:
        return _AUTO_PROMOTE_MIN_CONFIDENCE_DEFAULT
    try:
        return float(raw)
    except (TypeError, ValueError):
        return _AUTO_PROMOTE_MIN_CONFIDENCE_DEFAULT


_AUTO_PROMOTE_MIN_CONFIDENCE = _read_auto_promote_floor()


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
    import httpx  # noqa: PLC0415

    bridge = AuditMcpBridgeTool()
    try:
        base_url = await bridge._resolve_base_url()
    except (OSError, RuntimeError):
        return ""
    # Async HTTP — was urllib.request.urlopen() which is fully sync and
    # blocks the asyncio loop for the call duration. With audit-mcp's
    # /tools serializing 60+ tool schemas the call takes 1-5s; that
    # blocked the WHOLE backend (every other request in flight)
    # whenever a claim verification fired. Switching to httpx.AsyncClient
    # keeps the loop responsive — other requests interleave during the
    # round-trip.
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base_url}/tools")
        raw = resp.json()
    except (httpx.HTTPError, ValueError):
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
      "rank": 1,
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
  - ``rank`` is a 1-based importance ordinal: 1 = most load-bearing,
    2 = next most load-bearing, etc. Output as many preconditions as
    are warranted by the finding — the executor runs at most the top
    8 by rank, so put the load-bearing ones first by ``rank``. Rank
    ties are broken by output order.
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

    # fix §340 — task-type diversity. Both stages used to share
    # ``vulnerability_research.synthesizer``, which routes to the
    # same model the synthesis agent uses. An adversarial verifier
    # that shares a model with the agent it audits has no diversity —
    # the same prompt biases lead to the same blind spots. Each stage
    # gets its own task_type so operators can route them to a
    # different model via ConfigRegistry keys
    # ``llm_model_vulnerability_research.verifier_extractor`` and
    # ``llm_model_vulnerability_research.verifier_verdict``. Until
    # those keys are populated they fall back to ``llm_default_model``
    # (same as any unknown task_type); routing the verdict stage to
    # a different model is the meaningful follow-up.
    _EXTRACTOR_TASK_TYPE = "vulnerability_research.verifier_extractor"
    _VERDICT_TASK_TYPE = "vulnerability_research.verifier_verdict"
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
        # fix §342 — answer and panel narrative cap INDEPENDENTLY.
        # Originally both were concatenated into one ``finding_text``
        # then clamped to 8000 chars total; a long panel narrative
        # crowded the agent's actual answer out of the prompt. The
        # two carry different information: ``answer`` is the agent's
        # verbatim claim (we need most of it intact — bump to 16000);
        # ``panel_narrative`` is the synthesis prose around it (8000
        # remains plenty for grounding). Capped fields are rendered
        # as separate, labelled sections so the extractor sees both
        # truncations explicitly and can decide which to lean on.
        answer_full = str(canonical_payload.get("answer") or "")
        narrative_full = ""
        ps = canonical_payload.get("panel_summary")
        if isinstance(ps, dict):
            narrative_full = str(ps.get("narrative") or "")
        if not (answer_full.strip() or narrative_full.strip()):
            return {"status": "skipped", "reason": "no_finding_text"}

        _ANSWER_CAP = 16000
        _PANEL_CAP = 8000
        answer_capped = answer_full[:_ANSWER_CAP]
        panel_capped = narrative_full[:_PANEL_CAP]
        answer_section = (
            f"## Agent answer\n\n{answer_capped}"
            + ("\n\n[answer truncated to {n} chars]".format(n=_ANSWER_CAP)
               if len(answer_full) > _ANSWER_CAP else "")
        )
        panel_section = ""
        if panel_capped:
            panel_section = (
                f"\n\n## Panel synthesis narrative\n\n{panel_capped}"
                + ("\n\n[panel narrative truncated to {n} chars]".format(n=_PANEL_CAP)
                   if len(narrative_full) > _PANEL_CAP else "")
            )

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
            f"{answer_section}"
            f"{panel_section}\n"
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
        # fix §341 — pick top-N probes by extractor-supplied rank, not
        # by sequence order. Output order is the LLM's writing order,
        # not a load-bearing-ness signal; without this sort an extractor
        # that lists low-rank preconditions first burned the probe
        # budget on irrelevant ones. ``rank`` is 1-based; missing/non-
        # numeric rank sorts to the end via a large sentinel so old
        # extractor outputs degrade to sequence order rather than
        # crashing on the comparison.
        preconditions = sorted(
            enumerate(preconditions),
            key=lambda iv: (
                iv[1].get("rank") if isinstance(iv[1].get("rank"), (int, float)) else 10_000,
                iv[0],
            ),
        )
        preconditions = [p for _, p in preconditions]

        # Stage 2: probe executor — substitute $INDEX_ID + run each probe.
        # fix §343 — probes run in parallel via asyncio.gather. The
        # previous sequential loop paid serial latency for 8 audit-mcp
        # round-trips (each tool call hits the bridge → HTTP → graph
        # engine; 200-500ms typical, multi-second on cold semble).
        # The AuditMcpBridgeTool is concurrency-safe (per-instance
        # warm-lock + httpx client created per-call), and audit-mcp's
        # async runtime (per CLAUDE.md notes) deduplicates identical
        # tool calls — concurrent probes benefit from server-side
        # dedup as well as wall-clock overlap.
        bridge = AuditMcpBridgeTool()
        top_preconditions = preconditions[: self._MAX_PROBES]

        async def _run_one_probe(p: dict[str, Any]) -> dict[str, Any]:
            probe_spec = p.get("probe") or {}
            tool = str(probe_spec.get("tool") or "")
            tool_name = tool.split(".", 1)[1] if tool.startswith("audit_mcp.") else ""
            args = dict(probe_spec.get("args") or {})
            # enforce allowlist — extractor can hallucinate tool names;
            # only run the curated set used for source-level verification
            if tool_name not in _PROBE_TOOL_ALLOWLIST:
                return {
                    "id": p.get("id"),
                    "ok": False,
                    "error": f"refused: probe tool {tool!r} not on verifier allowlist",
                    "raw": None,
                }
            # substitute the index_id placeholder.
            # fix §344 — substring substitution. The previous ``v == "$INDEX_ID"``
            # equality check only worked when the extractor passed
            # ``$INDEX_ID`` as a bare value. Composed strings like
            # ``$INDEX_ID/src/foo.c`` (perfectly natural for ``file_path``
            # args) silently kept the literal placeholder and the probe
            # hit the bridge with an unresolvable path. ``str.replace``
            # handles both shapes; non-string values pass through.
            for k, v in list(args.items()):
                if isinstance(v, str) and "$INDEX_ID" in v:
                    args[k] = v.replace("$INDEX_ID", index_id)
            try:
                raw = await bridge.forward(action=tool_name, **args)
                ok = raw.get("status") != "error"
                return {
                    "id": p.get("id"),
                    "ok": ok,
                    "error": raw.get("error") if not ok else None,
                    "raw": raw,
                }
            except (OSError, RuntimeError, TimeoutError) as exc:
                return {
                    "id": p.get("id"),
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "raw": None,
                }

        probe_results: list[dict[str, Any]] = list(
            await asyncio.gather(*[_run_one_probe(p) for p in top_preconditions])
        )

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

        fix §347 — audit-trail preservation. The previous implementation
        mutated the original ASSESSMENT_REPORT row's ``outcome_kind`` in
        place, losing the prior kind from the row itself (only the
        payload's ``promoted_from`` block preserved it). That broke any
        query that scanned ``outcome_kind`` to count assessment reports
        vs direct findings and made the kind flip invisible to consumers
        that only read the column.

        New shape: KEEP BOTH ROWS. The original assessment_report row
        stays untouched in terms of ``outcome_kind`` / ``dispatch_status``;
        a NEW direct_finding row is inserted with ``state='approved'``
        carrying the same payload plus a ``derived_from`` block linking
        back to the original. The original row's payload gets a
        ``promoted_to`` block so the audit trail is bi-directional. The
        dispatcher then operates on the NEW row.

        Choice: approach (a) keep-both-rows rather than (b) alembic
        migration adding a ``promoted_kind`` column. Alembic on a hot
        outcomes table during a release wave is heavier than a logical
        row insert; bi-directional payload links give us the same
        observability without DDL.
        """
        from uuid import uuid4  # noqa: PLC0415

        from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher  # noqa: PLC0415
        from aila.modules.vr.contracts import (  # noqa: PLC0415
            OutcomeDispatchStatus,
            OutcomeKind,
        )
        from aila.modules.vr.services.outcome_review import (  # noqa: PLC0415
            OUTCOME_STATE_APPROVED,
        )

        if not isinstance(confidence, (int, float)):
            return {"status": "skipped", "reason": "no_numeric_confidence"}
        conf = float(confidence)
        if conf < _AUTO_PROMOTE_MIN_CONFIDENCE:
            return {"status": "skipped", "reason": f"confidence_below_floor:{conf:.2f}<{_AUTO_PROMOTE_MIN_CONFIDENCE}"}

        new_outcome_id = str(uuid4())
        async with UnitOfWork() as uow:
            original = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == canonical_id,
                )
            )).first()
            if original is None:
                return {"status": "skipped", "reason": "outcome_disappeared"}
            if original.outcome_kind != OutcomeKind.ASSESSMENT_REPORT.value:
                return {
                    "status": "skipped",
                    "reason": f"outcome_kind_not_assessment:{original.outcome_kind}",
                }
            if original.dispatch_status != OutcomeDispatchStatus.SKIPPED.value:
                return {
                    "status": "skipped",
                    "reason": f"dispatch_status_not_skipped:{original.dispatch_status}",
                }
            try:
                orig_payload = json.loads(original.payload_json or "{}")
            except (ValueError, TypeError):
                return {"status": "skipped", "reason": "payload_unparseable"}
            if orig_payload.get("promoted_to"):
                return {"status": "skipped", "reason": "already_promoted"}
            if is_negative_finding_claim(orig_payload.get("answer") or ""):
                return {
                    "status": "skipped",
                    "reason": "answer_starts_negative_no_bug_to_promote",
                }

            promotion_ts = utc_now().isoformat()
            promotion_reason = f"verifier confirmed conf={conf:.2f} | {summary[:300]}"

            # Build new DIRECT_FINDING payload — copy original + link back.
            new_payload = dict(orig_payload)
            new_payload["derived_from"] = {
                "outcome_id": canonical_id,
                "kind": OutcomeKind.ASSESSMENT_REPORT.value,
                "at": promotion_ts,
                "by_user_id": "verifier_auto_promote",
                "reason": promotion_reason,
                "verifier_confidence": conf,
            }
            # Verifier report lives on the ORIGINAL row only; the new
            # row points at it via derived_from rather than duplicating.
            new_payload.pop("verifier_report", None)

            new_row = VRInvestigationOutcomeRecord(
                id=new_outcome_id,
                investigation_id=original.investigation_id,
                branch_id=original.branch_id,
                outcome_kind=OutcomeKind.DIRECT_FINDING.value,
                payload_json=json.dumps(new_payload),
                confidence=original.confidence,
                evidence_refs_json=original.evidence_refs_json,
                state=OUTCOME_STATE_APPROVED,
                dispatch_status=OutcomeDispatchStatus.PENDING.value,
                dispatch_target=None,
            )
            uow.session.add(new_row)

            # Bi-directional link on the original row's payload so a
            # query against the original surfaces the promotion.
            orig_payload["promoted_to"] = {
                "outcome_id": new_outcome_id,
                "kind": OutcomeKind.DIRECT_FINDING.value,
                "at": promotion_ts,
                "by_user_id": "verifier_auto_promote",
                "reason": promotion_reason,
            }
            original.payload_json = json.dumps(orig_payload)
            uow.session.add(original)
            await uow.commit()

        # fix §348 — atomicity for the kind flip + dispatch pair. The
        # previous shape committed the new DIRECT_FINDING row, then
        # dispatched outside any transaction; if dispatch raised an
        # exception not caught by the dispatcher (or the broad-but-
        # finite tuple here missed the actual class), the new row was
        # left dispatch_status=PENDING with no reaper, indistinguishable
        # from a row legitimately mid-flight.
        #
        # New shape: catch ALL exceptions around dispatch, and on any
        # uncaught failure REVERT the promotion atomically — delete the
        # new DIRECT_FINDING row, strip ``promoted_to`` from the original
        # row's payload. The dispatcher's own catch handles the
        # in-protocol failure path (returns FAILED, dispatcher already
        # set the row to FAILED — observable, no further action needed).
        # The revert here covers the out-of-protocol failure path that
        # leaves nothing observable downstream.
        #
        # Cross-ref §109: vuln_researcher applies the same in-UoW
        # pattern on the engine-crash side; this is the same idea on
        # the verifier-promote side.
        try:
            dispatcher = OutcomeDispatcher(knowledge=ServiceFactory().knowledge)
            result = await dispatcher.dispatch(new_outcome_id)
        except Exception as exc:  # noqa: BLE001 — see comment above
            _log.warning(
                "auto_promote dispatch FAILED — reverting inv=%s original=%s new=%s err=%s",
                self.investigation_id, canonical_id, new_outcome_id, exc,
            )
            await self._revert_auto_promote(
                original_id=canonical_id,
                new_outcome_id=new_outcome_id,
            )
            return {
                "status": "promoted_dispatch_failed_reverted",
                "reason": f"{type(exc).__name__}:{exc}",
            }
        _log.info(
            "auto_promote OK inv=%s original=%s new=%s -> %s (%s)",
            self.investigation_id, canonical_id, new_outcome_id,
            result.dispatch_target, result.dispatch_status.value,
        )
        return {
            "status": "promoted",
            "promoted_outcome_id": new_outcome_id,
            "dispatch_status": result.dispatch_status.value,
            "dispatch_target": result.dispatch_target,
            "dispatch_reason": result.reason[:200],
        }

    async def _revert_auto_promote(
        self,
        *,
        original_id: str,
        new_outcome_id: str,
    ) -> None:
        """fix §348 — reverse a partially-applied auto-promote.

        Called when ``dispatcher.dispatch`` raises an uncaught exception
        AFTER the promotion UoW already committed. Deletes the new
        DIRECT_FINDING row and strips the ``promoted_to`` block from
        the original ASSESSMENT_REPORT row so the next verifier run
        can retry, and so no orphan PENDING row sits on the table
        with no reaper.

        Best-effort: this method swallows its own DB errors and logs
        them. The caller already returns a ``promoted_dispatch_failed_
        reverted`` status so the operator sees the failure regardless.
        """
        try:
            async with UnitOfWork() as uow:
                new_row = (await uow.session.exec(
                    _select(VRInvestigationOutcomeRecord).where(
                        VRInvestigationOutcomeRecord.id == new_outcome_id,
                    )
                )).first()
                if new_row is not None:
                    await uow.session.delete(new_row)
                original = (await uow.session.exec(
                    _select(VRInvestigationOutcomeRecord).where(
                        VRInvestigationOutcomeRecord.id == original_id,
                    )
                )).first()
                if original is not None:
                    try:
                        payload = json.loads(original.payload_json or "{}")
                    except (ValueError, TypeError):
                        payload = {}
                    if payload.pop("promoted_to", None) is not None:
                        original.payload_json = json.dumps(payload)
                        uow.session.add(original)
                await uow.commit()
        except (OSError, RuntimeError, ValueError) as exc:
            _log.exception(
                "auto_promote REVERT FAILED inv=%s original=%s new=%s err=%s",
                self.investigation_id, original_id, new_outcome_id, exc,
            )

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

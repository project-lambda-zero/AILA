"""Shared ClaimVerifierAgent (RFC-03 Phase 5).

``ClaimVerifierAgentBase.run`` is the three-stage adversarial verifier:
extractor LLM parses the canonical outcome into falsifiable
preconditions, the probe executor runs each precondition's audit-mcp
probe in parallel, and the verdict LLM classifies the finding as
``confirmed`` / ``refuted`` / ``inconclusive`` against the raw probe
output. Both LLM stages route through :func:`idempotent_llm_call` so a
worker retry replays the cached decision instead of double-paying the
model.

The vr and malware modules ship byte-identical helper bodies (prompt
texts, probe allowlist, signature fetcher, probe payload renderer,
precondition/verdict parsers, verdict prompt renderer, verifier report
shape, revert-auto-promote body). They diverge on:

* task-type routing keys (per-module cost / rate-limit routing),
* the negative-finding phrase tables (VR carries the vr vocabulary,
  malware adds a superset of malware-domain terms),
* the record models used in the UoW SELECTs,
* how the extractor claim text is derived from the canonical payload
  (VR reads ``payload["answer"]``; malware routes through
  ``render_outcome_claim_text`` because its payload is per-kind typed),
* the auto-promote gate (VR promotes ASSESSMENT_REPORT ->
  DIRECT_FINDING; malware promotes ANALYSIS_REPORT -> ANALYSIS_REPORT),
* which text feeds ``is_negative_finding_claim`` on the promote path
  (VR: ``payload["answer"]``; malware: ``payload["summary"]`` +
  ``payload["report_body"]``),
* malware short-circuits on ``NON_VERIFIABLE_OUTCOME_KINDS`` and adds
  the outcome-kind line to the extractor prompt.

Everything else is shared and lifted verbatim; per-module divergences
are expressed as class attributes and small hook methods that each
thin subclass overrides. Both module wrappers keep the
``ClaimVerifierAgent`` class name so aggregator re-exports and
``from aila.modules.<mod>.agents.claim_verifier import ClaimVerifierAgent``
sites keep working.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any, ClassVar
from uuid import uuid4

import httpx
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.contracts import utc_now
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

__all__ = [
    "ClaimVerifierAgentBase",
    "is_negative_finding_claim",
]

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


_EXTRACTOR_SYSTEM_PROMPT = """You are an adversarial vulnerability-finding verifier.

You are given a finding produced by a panel of reasoning agents about a
specific vulnerability claim in source code. Default stance: the panel
is wrong until you have proven otherwise from the source. Your job is
to enumerate the falsifiable preconditions the finding depends on,
then for each one propose ONE audit_mcp tool call whose result would
REFUTE that precondition if the panel is wrong.

Walk these four questions BEFORE you write a precondition:
  A. **Open the cited code.** What does it actually do? The panel's
     description is a claim, not evidence -- re-read the cited function
     body or line and state what you actually see.
  B. **Walk the call chain outward.** Who calls the cited code, and
     does the data really arrive there from an external entry point?
     A precondition that asserts the entry point exists is one of the
     load-bearing ones; pick a probe that returns ZERO matches if no
     caller reaches it.
  C. **Try to kill the finding.** Look for input validation,
     allow-lists, framework escapes, type guards, platform defaults
     (Android manifest, network_security_config), and authn/authz
     gates that sit between source and sink. Each defense you can
     name becomes a candidate precondition: "no defense X exists
     between source and sink".
  D. **Probe the defense once you find one.** If a defense exists,
     does it cover every route into the sink, or just the one the
     panel read? Edge cases (encoding tricks, nulls, oversized
     values, alternative call chains) bypass partial defenses; the
     "no edge-case bypass" assertion is a precondition with its own
     probe.

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
    are warranted by the finding -- the executor runs at most the top
    8 by rank, so put the load-bearing ones first by ``rank``. Rank
    ties are broken by output order.
  - Each ``probe`` must be a real audit-mcp tool (search_source,
    search_macros, read_function, search_constants, callers_of,
    callees_of, etc.). Use ``$INDEX_ID`` as a literal placeholder for
    the index -- the executor substitutes the real id.
  - Prefer probes that, if they return ZERO matches, would refute the
    precondition. The whole point is asymmetric refutation.
  - **CRITICAL -- probe sizing rule**: when verifying whether a SPECIFIC
    PATTERN (e.g. `sc.complete_lengths = 1`, `mark_args_code`, an
    `if (x->is_args)` gate) is present or absent inside a function,
    ALWAYS use `search_source` with the exact pattern -- NEVER use
    `read_function`. `read_function` returns the whole function body
    and a 500-line function's body will not fit in the verifier's
    per-probe budget; the load-bearing region almost always lives in
    the middle or end of large functions, gets truncated, and the
    verifier returns inconclusive when it should return refuted.
    `search_source` returns one line per match -- bounded, cheap,
    diagnostic. Only fall back to `read_function` when the
    precondition is about overall function structure (e.g. "function
    is short enough that no missing-counterpart can hide") rather
    than about a specific pattern.
  - Examples of high-value precondition shapes:
      * "Opcode X is reachable from bytecode Y because callsite Z sets
        sc.compile_args = 1" \u2192 probe: search_source for
        'compile_args = 1' across the file containing the relevant
        init_params function.
      * "Function F is missing the per-iteration reset of e->is_args" \u2192
        probe: search_source for `e->is_args = 0` scoped to F's file.
      * "Block X does NOT set sc.complete_lengths" \u2192 probe:
        search_source for `complete_lengths` scoped to F's file (NOT
        read_function on the wrapper -- too long to fit).
      * "Macro M expands to a length-prefix write" \u2192 probe:
        search_macros for M.
      * "Decompiled JS slice at `react/slices/slice_NNNNN_*.js`
        contains the literal string `<token-shaped value>` near
        an `Original name: <fn>` marker" \u2192 probe: read_lines on
        the slice range cited by the panel and confirm the
        literal + the marker are both present.
"""


_VERDICT_SYSTEM_PROMPT = """You are an adversarial verifier producing a
final verdict on whether a vulnerability finding is correct given probe
results from the source.

Default stance: the panel that proposed this finding was wrong until
the probe results force you to conclude otherwise. Your job is NOT to
ratify the panel; it is to actively search for the verdict that
disagrees with them and only fall back to "confirmed" when no
disagreement survives the probes.

Decision rule:
  - **confirmed** -- every load-bearing precondition returned `true`,
    AND every load-bearing precondition reached an external entry
    point, AND no probe revealed an upstream defense that fully
    neutralizes the source-to-sink flow.
  - **refuted** -- at least one load-bearing precondition returned
    `false`, OR a probe revealed an upstream defense that closes
    every route into the sink. The finding cannot survive the
    falsification.
  - **inconclusive** -- probes returned `unknown` on the load-bearing
    preconditions and the source you read does not let you decide
    either way. Say so plainly; do not default to "confirmed" out of
    caution toward the panel.

Confidence anchor (gates the operator's review queue priority):
  - **0.9 to 1.0** -- you actively searched for the opposite verdict
    via the probe set, found no surviving counter-claim, and the
    probes covered every load-bearing precondition with at least one
    `true`/`false` result (no `unknown` left on a load-bearing one).
  - **0.7 to 0.89** -- verdict is well-supported but one load-bearing
    probe returned `unknown` or the source had a region the probe
    couldn't fully reach. State which one in `counter_evidence` or
    `summary`.
  - **0.5 to 0.69** -- multiple load-bearing probes returned
    `unknown`, OR the source surface is too large for the probe set
    to cover. The verdict is your best read but you are guessing on
    at least one axis; say so explicitly in `summary`.
  - **below 0.5** -- do NOT emit a final verdict. Return
    `verdict: "inconclusive"` and name in `counter_evidence` exactly
    what probe or source read would resolve it.

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
    wrong; that's why you exist. A verdict that ratifies the panel
    when the probe set did not actively search for refutation is
    less useful than an `inconclusive` that names what's missing.
  - Decompiler pseudo-code IS valid probe evidence. Register-
    machine output from Hermes-dec (`r1 = r2.setItem;
    r4 = r5.bind(r0)(r3)`) has opaque control flow, but the
    literal string constants, the `// Original name: <fn>,
    environment: ...` comments above closure bodies, and the
    `NativeModules.<Module>` access pattern survive the
    decompile intact. When a probe reads a `react/slices/*.js`
    file and the literal/marker the panel cited is present at
    the cited range, that is `result: "true"` -- do not downgrade
    to "unknown" just because the surrounding pseudo-code looks
    generated. The asymmetric inverse also holds: when the cited
    literal is NOT present at the cited range, that is
    `result: "false"`.
"""


def is_negative_finding_claim(
    answer: str,
    *,
    prefixes: tuple[str, ...],
    substrings: tuple[str, ...],
) -> bool:
    """Return True when ``answer`` reads as a "no bug found" claim.

    A 'confirmed' verifier verdict only means the agent's CLAIM was
    correct -- not that a bug exists. When the agent's claim is 'this
    is NOT vulnerable / patch present / no variants', the verdict
    'confirmed' actually means 'confirmed there is no bug'. Those
    must NOT be auto-promoted to a positive finding.

    ``prefixes`` are matched at the start of the head window (uppercased,
    first 200 chars). ``substrings`` are matched anywhere in the same
    window. Modules pass their own phrase tables through their thin
    subclasses so vr and malware negatives stay isolated where they
    matter but callers can widen either set.
    """
    # Widen the head window to 200 chars so the substring matchers can
    # see past a brief lead-in like ``"Verdict: ..."``; startswith
    # comparisons remain anchored at position 0 by construction.
    head = (answer or "").strip().upper()[:200]
    if any(head.startswith(p) for p in prefixes):
        return True
    return any(phrase in head for phrase in substrings)


async def _fetch_audit_mcp_signatures(
    recorder: Callable[..., Any],
) -> tuple[str, bool]:
    """Pull live tool schemas from audit-mcp so the extractor LLM
    proposes probes with the right argument names. Returns a tuple of
    ``(markdown_text, ok_flag)``. ``ok_flag`` is True when the fetch
    succeeded (text may still be empty if no allowlisted tools are
    exposed); False when the bridge URL could not be resolved or the
    HTTP / JSON parse failed. Callers use ``ok_flag`` to stamp a
    ``signatures_fetch_failed`` field in the verifier report so an
    operator can correlate verifier inconclusiveness with audit-mcp
    unavailability -- previously this swallowed silently and the
    verifier was inconclusive for unexplained reasons.
    """
    bridge = AuditMcpBridgeTool(recorder=recorder)
    try:
        base_url = await bridge._resolve_base_url()
    except (OSError, RuntimeError) as exc:
        _log.warning(
            "claim_verifier signatures fetch failed (resolve_base_url): %s",
            exc.__class__.__name__,
        )
        return "", False
    # Async HTTP -- was urllib.request.urlopen() which is fully sync and
    # blocks the asyncio loop for the call duration. With audit-mcp's
    # /tools serializing 60+ tool schemas the call takes 1-5s; that
    # blocked the WHOLE backend (every other request in flight)
    # whenever a claim verification fired. Switching to httpx.AsyncClient
    # keeps the loop responsive -- other requests interleave during the
    # round-trip.
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base_url}/tools")
        raw = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        _log.warning(
            "claim_verifier signatures fetch failed (%s): %s",
            exc.__class__.__name__, exc,
        )
        return "", False
    tools = raw.get("tools", raw) if isinstance(raw, dict) else raw
    if not isinstance(tools, list):
        _log.warning(
            "claim_verifier signatures fetch returned unexpected shape: %s",
            type(raw).__name__,
        )
        return "", False
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
    return "\n".join(lines), True


def _render_probe_payload(tool: str, raw: Any) -> str:
    """Format an audit-mcp probe response for the verifier verdict prompt.

    Tool-aware so each probe shape produces the densest readable
    output. ``read_function`` joins the ``body`` line list back into
    real source (vs JSON-encoding which 2x's the byte cost from
    quote-escapes). ``search_*`` emits one match per line in
    ``file:line: text`` form. Everything else falls back to
    JSON.dumps. Callers should still clamp the result -- this helper
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


class ClaimVerifierAgentBase:
    """Three-stage adversarial verifier: extract -> probe -> verdict.

    Construction takes only an ``investigation_id``. Subclasses set the
    class attributes documented below plus a small hook set; the base
    owns the full pipeline (context load, extractor LLM, probe fan-out,
    verdict LLM, verifier-report persist, auto-promote + revert).

    Class attribute contract (subclasses MUST set every unassigned name):

    * ``_EXTRACTOR_TASK_TYPE`` / ``_VERDICT_TASK_TYPE`` -- module-scoped
      ``idempotent_llm_call`` task-type keys so operators can route each
      stage to a different model via ``ConfigRegistry`` overrides.
    * ``_NEGATIVE_ANSWER_PREFIXES`` / ``_NEGATIVE_ANSWER_SUBSTRINGS`` --
      the module's negative-finding phrase tables passed straight into
      :func:`is_negative_finding_claim`.
    * ``_investigation_model`` / ``_outcome_model`` / ``_target_model``
      -- the module's SQLModel record classes used in the read-only
      SELECTs and the persist / auto-promote UoWs.
    * ``_outcome_dispatcher_cls`` -- the module's ``OutcomeDispatcher``
      class, constructed as ``cls(knowledge=ServiceFactory().knowledge)``
      on the auto-promote path so the verifier-confirmed row lands in
      the module's findings table.
    * Auto-promote gate constants: ``_promote_source_kind`` (expected
      original outcome kind), ``_promote_target_kind`` (kind assigned
      to the new row + written into the ``derived_from`` / ``promoted_to``
      audit blocks), ``_promote_wrong_kind_reason`` (reason label used
      when the original is the wrong kind),
      ``_promote_negative_skip_reason`` (reason label when the negative
      guard fires).
    * ``_dispatch_status_pending`` / ``_dispatch_status_skipped`` --
      the module's ``OutcomeDispatchStatus`` enum values for the new
      row insert + the skipped-eligibility check.
    * ``_outcome_state_approved`` -- ``OUTCOME_STATE_APPROVED`` string
      constant the new row's ``state`` column is set to.
    """

    # ---- Required subclass attributes ----
    _EXTRACTOR_TASK_TYPE: ClassVar[str]
    _VERDICT_TASK_TYPE: ClassVar[str]
    _NEGATIVE_ANSWER_PREFIXES: ClassVar[tuple[str, ...]]
    _NEGATIVE_ANSWER_SUBSTRINGS: ClassVar[tuple[str, ...]]
    _investigation_model: ClassVar[type]
    _outcome_model: ClassVar[type]
    _target_model: ClassVar[type]
    _outcome_dispatcher_cls: ClassVar[type]
    _promote_source_kind: ClassVar[str]
    _promote_target_kind: ClassVar[str]
    _promote_wrong_kind_reason: ClassVar[str]
    _promote_negative_skip_reason: ClassVar[str]
    _dispatch_status_pending: ClassVar[str]
    _dispatch_status_skipped: ClassVar[str]
    _outcome_state_approved: ClassVar[str]

    # ---- Optional attributes with defaults ----
    _MAX_PROBES: ClassVar[int] = 8
    _PROBE_TIMEOUT_S: ClassVar[float] = 30.0
    _LOG_LABEL: ClassVar[str] = "claim_verifier"
    # Terminal investigation states valid for verification. All modules
    # currently share this set (COMPLETED / PAUSED / FAILED); a module
    # may override if its InvestigationStatus differs.
    _TERMINAL_INVESTIGATION_STATES: ClassVar[tuple[str, ...]] = (
        "completed", "paused", "failed",
    )

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id

    # ---- Hooks subclasses MUST implement ----

    async def _read_auto_promote_floor(self) -> float:
        """Read ``claim_verifier_auto_promote_floor`` from module config.

        Modules bind the platform ``ConfigRegistry`` reader at their own
        namespace (vr / malware) so ``ConfigRegistry.get`` resolves the
        key against ``<module>.claim_verifier_auto_promote_floor``.
        """
        raise NotImplementedError

    def _bridge_recorder(self) -> Callable[..., Any]:
        """Return the module's mcp call recorder passed to ``AuditMcpBridgeTool``.

        Each module has its own ``mcp_call_logger.record_call`` so probe
        traffic is attributed to the correct module dashboard.
        """
        raise NotImplementedError

    def _extract_claim_text(
        self, canonical_kind: str, canonical_payload: dict[str, Any],
    ) -> str:
        """Return the extractor-input claim text for the canonical outcome.

        VR reads ``payload["answer"]``; malware routes through
        ``render_outcome_claim_text(kind, payload)`` because its payload
        is per-kind typed.
        """
        del canonical_kind, canonical_payload
        raise NotImplementedError

    def _promote_negative_claim_text(
        self, orig_payload: dict[str, Any],
    ) -> str:
        """Return the text to check with :meth:`is_negative_finding_claim` on the promote path.

        VR reads ``orig_payload["answer"]``; malware joins
        ``orig_payload["summary"]`` and ``orig_payload["report_body"]``.
        """
        del orig_payload
        raise NotImplementedError

    # ---- Hooks with defaults (VR-shaped) that subclasses may override ----

    def _check_verifiable_outcome_kind(
        self, canonical_kind: str,
    ) -> str | None:
        """Return a skip reason if the outcome kind is not verifiable.

        Default: every kind is verifiable (VR). Malware overrides to
        short-circuit on ``NON_VERIFIABLE_OUTCOME_KINDS`` (achievement-
        gated artifacts, runner traces, stalled-failure markers,
        lineage markers).
        """
        del canonical_kind
        return None

    def _claim_section_header(self, canonical_kind: str) -> str:
        """Header for the claim section in the extractor input.

        Default: ``"Agent answer"`` (VR). Malware overrides to
        ``"Outcome claim ({kind})"`` because the extractor prompt
        surfaces the outcome kind so the LLM adjusts its precondition
        set per-kind.
        """
        del canonical_kind
        return "Agent answer"

    def _extractor_prelude(
        self, loaded_kind: str, canonical_kind: str, index_id: str,
    ) -> str:
        """First lines of the extractor user message.

        Default: VR's shape (investigation kind + target index_id only).
        Malware overrides to insert an explicit ``Outcome kind:`` line
        so the LLM sees both the panel-level investigation kind and
        the per-outcome kind the payload was structured for.
        """
        del canonical_kind
        return (
            f"# Finding to verify\n\n"
            f"Investigation kind: {loaded_kind}\n"
            f"Target index_id: {index_id}\n\n"
        )

    # ---- Convenience wrappers over module-scoped helpers ----

    def is_negative_finding_claim(self, answer: str) -> bool:
        """Instance wrapper -- passes the subclass's phrase tables through."""
        return is_negative_finding_claim(
            answer,
            prefixes=self._NEGATIVE_ANSWER_PREFIXES,
            substrings=self._NEGATIVE_ANSWER_SUBSTRINGS,
        )

    # ---- Pipeline entry point ----

    async def run(self) -> dict[str, Any]:
        """Run the full extract -> probe -> verdict pipeline once."""
        # Stage 0: load canonical outcome + target index_id
        loaded = await self._load_context()
        if loaded.get("status") != "ok":
            return loaded
        canonical = loaded["canonical"]
        canonical_payload = loaded["canonical_payload"]
        canonical_kind = loaded["canonical_kind"]
        index_id = loaded["index_id"]

        if "verifier_report" in canonical_payload:
            return {
                "status": "skipped",
                "reason": "already_verified",
                "canonical_outcome_id": canonical.id,
            }

        # Short-circuit on outcome kinds whose payload is not a
        # source-grounded claim.
        skip_reason = self._check_verifiable_outcome_kind(canonical_kind)
        if skip_reason is not None:
            return {
                "status": "skipped",
                "reason": skip_reason,
                "canonical_outcome_id": canonical.id,
            }

        # Build the source text the extractor will reason about.
        # Claim and panel narrative cap INDEPENDENTLY so a long panel
        # narrative doesn't crowd the agent's actual claim out of the
        # prompt. Capped fields are rendered as separate, labelled
        # sections so the extractor sees both truncations explicitly
        # and can decide which to lean on.
        claim_full = self._extract_claim_text(canonical_kind, canonical_payload)
        narrative_full = ""
        ps = canonical_payload.get("panel_summary")
        if isinstance(ps, dict):
            narrative_full = str(ps.get("narrative") or "")
        if not (claim_full.strip() or narrative_full.strip()):
            return {"status": "skipped", "reason": "no_finding_text"}

        claim_cap = 16000
        panel_cap = 8000
        claim_capped = claim_full[:claim_cap]
        panel_capped = narrative_full[:panel_cap]
        claim_section = (
            f"## {self._claim_section_header(canonical_kind)}\n\n{claim_capped}"
            + (f"\n\n[claim truncated to {claim_cap} chars]"
               if len(claim_full) > claim_cap else "")
        )
        panel_section = ""
        if panel_capped:
            panel_section = (
                f"\n\n## Panel synthesis narrative\n\n{panel_capped}"
                + (f"\n\n[panel narrative truncated to {panel_cap} chars]"
                   if len(narrative_full) > panel_cap else "")
            )

        # Stage 1: extractor -- parse the claim into structured preconditions
        services = ServiceFactory()
        signatures_block, signatures_ok = await _fetch_audit_mcp_signatures(
            self._bridge_recorder(),
        )
        sig_section = (
            f"## Available audit-mcp probes (live signatures)\n\n{signatures_block}\n\n"
            if signatures_block else ""
        )
        extractor_input = (
            self._extractor_prelude(loaded["kind"], canonical_kind, index_id)
            + f"{sig_section}"
            + f"{claim_section}"
            + f"{panel_section}\n"
        )
        try:
            extractor_response, _ = await idempotent_llm_call(
                services.llm_client,
                method="chat",
                task_type=self._EXTRACTOR_TASK_TYPE,
                messages=[
                    {"role": "system", "content": _EXTRACTOR_SYSTEM_PROMPT},
                    {"role": "user", "content": extractor_input},
                ],
                investigation_id=self.investigation_id,
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
        # Pick top-N probes by extractor-supplied rank, not by sequence
        # order. Output order is the LLM's writing order, not a
        # load-bearing-ness signal; missing/non-numeric rank sorts to
        # the end via a large sentinel so old extractor outputs degrade
        # to sequence order rather than crashing on the comparison.
        preconditions = sorted(
            enumerate(preconditions),
            key=lambda iv: (
                iv[1].get("rank") if isinstance(iv[1].get("rank"), (int, float)) else 10_000,
                iv[0],
            ),
        )
        preconditions = [p for _, p in preconditions]

        # Stage 2: probe executor -- substitute $INDEX_ID + run each probe.
        # Probes run in parallel via asyncio.gather. AuditMcpBridgeTool
        # is concurrency-safe (per-instance warm-lock + httpx client
        # created per-call), and audit-mcp deduplicates identical tool
        # calls -- concurrent probes benefit from server-side dedup as
        # well as wall-clock overlap.
        bridge = AuditMcpBridgeTool(recorder=self._bridge_recorder())
        top_preconditions = preconditions[: self._MAX_PROBES]

        async def _run_one_probe(p: dict[str, Any]) -> dict[str, Any]:
            probe_spec = p.get("probe") or {}
            tool = str(probe_spec.get("tool") or "")
            tool_name = tool.split(".", 1)[1] if tool.startswith("audit_mcp.") else ""
            args = dict(probe_spec.get("args") or {})
            # enforce allowlist -- extractor can hallucinate tool names;
            # only run the curated set used for source-level verification
            if tool_name not in _PROBE_TOOL_ALLOWLIST:
                return {
                    "id": p.get("id"),
                    "ok": False,
                    "error": f"refused: probe tool {tool!r} not on verifier allowlist",
                    "raw": None,
                }
            # substitute the index_id placeholder. Substring substitution
            # so composed values like ``$INDEX_ID/src/foo.c`` also work
            # (bare-equality fails on those).
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

        # Stage 3: verdict -- feed precondition + probe result pairs back
        verdict_input = self._render_verdict_input(preconditions, probe_results)
        try:
            verdict_response, _ = await idempotent_llm_call(
                services.llm_client,
                method="chat",
                task_type=self._VERDICT_TASK_TYPE,
                messages=[
                    {"role": "system", "content": _VERDICT_SYSTEM_PROMPT},
                    {"role": "user", "content": verdict_input},
                ],
                investigation_id=self.investigation_id,
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
            # Surface signatures-fetch failure so the operator can
            # correlate an inconclusive verdict with audit-mcp being
            # briefly unavailable rather than with a genuinely ambiguous
            # source pattern.
            "signatures_fetch_failed": not signatures_ok,
        }

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(self._outcome_model).where(
                    self._outcome_model.id == canonical.id,
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
        """Promote a verifier-confirmed outcome by inserting a fresh row
        tagged with the verifier endorsement and re-dispatching it via
        the module's ``OutcomeDispatcher``.

        Guards (any one of these short-circuits with ``status='skipped'``):
          - confidence is not numeric.
          - confidence below the module's ``claim_verifier_auto_promote_floor``.
          - original ``outcome_kind`` is not the module's promote source
            kind, or ``dispatch_status`` is not SKIPPED (only the
            operator-promote dead-end auto-closes; anything else is
            left alone).
          - the original payload already carries ``promoted_to``
            (idempotent re-run protection).
          - :meth:`is_negative_finding_claim` matches the module's
            "negative claim" text extracted via
            :meth:`_promote_negative_claim_text`.

        Audit trail: the original row stays untouched in terms of
        ``outcome_kind`` / ``dispatch_status``; a NEW row of the
        module's ``_promote_target_kind`` is inserted with
        ``state=OUTCOME_STATE_APPROVED`` and
        ``dispatch_status=PENDING``, carrying the same payload plus a
        ``derived_from`` block pointing back at the original. The
        original row's payload picks up a ``promoted_to`` block so the
        audit trail is bi-directional. The dispatcher then operates on
        the NEW row.

        Atomicity for the kind flip + dispatch pair: catch ALL
        dispatch exceptions and on any uncaught failure REVERT the
        promotion atomically -- delete the new row, strip
        ``promoted_to`` from the original row's payload.
        """
        if not isinstance(confidence, (int, float)):
            return {"status": "skipped", "reason": "no_numeric_confidence"}
        conf = float(confidence)
        floor = await self._read_auto_promote_floor()
        if conf < floor:
            return {
                "status": "skipped",
                "reason": f"confidence_below_floor:{conf:.2f}<{floor}",
            }

        new_outcome_id = str(uuid4())
        async with UnitOfWork() as uow:
            original = (await uow.session.exec(
                _select(self._outcome_model).where(
                    self._outcome_model.id == canonical_id,
                )
            )).first()
            if original is None:
                return {"status": "skipped", "reason": "outcome_disappeared"}
            if original.outcome_kind != self._promote_source_kind:
                return {
                    "status": "skipped",
                    "reason": (
                        f"{self._promote_wrong_kind_reason}:{original.outcome_kind}"
                    ),
                }
            if original.dispatch_status != self._dispatch_status_skipped:
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
            if self.is_negative_finding_claim(
                self._promote_negative_claim_text(orig_payload),
            ):
                return {
                    "status": "skipped",
                    "reason": self._promote_negative_skip_reason,
                }

            promotion_ts = utc_now().isoformat()
            promotion_reason = f"verifier confirmed conf={conf:.2f} | {summary[:300]}"

            # Build the promoted payload -- copy original + link back.
            new_payload = dict(orig_payload)
            new_payload["derived_from"] = {
                "outcome_id": canonical_id,
                "kind": self._promote_target_kind,
                "at": promotion_ts,
                "by_user_id": "verifier_auto_promote",
                "reason": promotion_reason,
                "verifier_confidence": conf,
            }
            # Verifier report lives on the ORIGINAL row only; the new
            # row points at it via derived_from rather than duplicating.
            new_payload.pop("verifier_report", None)

            new_row = self._outcome_model(
                id=new_outcome_id,
                investigation_id=original.investigation_id,
                branch_id=original.branch_id,
                outcome_kind=self._promote_target_kind,
                payload_json=json.dumps(new_payload),
                confidence=original.confidence,
                evidence_refs_json=original.evidence_refs_json,
                state=self._outcome_state_approved,
                dispatch_status=self._dispatch_status_pending,
                dispatch_target=None,
            )
            uow.session.add(new_row)

            # Bi-directional link on the original row's payload so a
            # query against the original surfaces the promotion.
            orig_payload["promoted_to"] = {
                "outcome_id": new_outcome_id,
                "kind": self._promote_target_kind,
                "at": promotion_ts,
                "by_user_id": "verifier_auto_promote",
                "reason": promotion_reason,
            }
            original.payload_json = json.dumps(orig_payload)
            uow.session.add(original)
            await uow.commit()

        try:
            dispatcher = self._outcome_dispatcher_cls(
                knowledge=ServiceFactory().knowledge,
            )
            result = await dispatcher.dispatch(new_outcome_id)
        except (
            SQLAlchemyError, OSError, RuntimeError,
            ValueError, TypeError, AttributeError, KeyError,
        ) as exc:
            # The revert path is the last line of defense; if the
            # dispatcher crashed out-of-protocol the operator needs
            # the full stack to diagnose, not just the class:msg pair
            # already in payload.
            _log.warning(
                "auto_promote dispatch FAILED -- reverting inv=%s original=%s new=%s err=%s",
                self.investigation_id, canonical_id, new_outcome_id, exc,
                exc_info=True,
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
        """Reverse a partially-applied auto-promote.

        Called when ``dispatcher.dispatch`` raises an uncaught exception
        AFTER the promotion UoW already committed. Deletes the new
        promoted-kind row and strips the ``promoted_to`` block from
        the original row so the next verifier run can retry, and so no
        orphan PENDING row sits on the table with no reaper.

        Best-effort: this method swallows its own DB errors and logs
        them. The caller already returns a ``promoted_dispatch_failed_
        reverted`` status so the operator sees the failure regardless.
        """
        try:
            async with UnitOfWork() as uow:
                new_row = (await uow.session.exec(
                    _select(self._outcome_model).where(
                        self._outcome_model.id == new_outcome_id,
                    )
                )).first()
                if new_row is not None:
                    await uow.session.delete(new_row)
                original = (await uow.session.exec(
                    _select(self._outcome_model).where(
                        self._outcome_model.id == original_id,
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
        """Load the investigation, canonical outcome, and index_id.

        Every module returns the same dict shape; ``canonical_kind`` is
        surfaced for both modules because the platform run() reads it
        even though VR previously ignored the field.
        """
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(self._investigation_model).where(
                    self._investigation_model.id == self.investigation_id,
                )
            )).first()
            if inv is None:
                return {"status": "skipped", "reason": "investigation_not_found"}
            if inv.status not in self._TERMINAL_INVESTIGATION_STATES:
                # Run only on terminal-state investigations so we never
                # verify a moving target.
                return {"status": "skipped", "reason": f"status_not_terminal:{inv.status}"}
            canonical = (await uow.session.exec(
                _select(self._outcome_model)
                .where(self._outcome_model.investigation_id == self.investigation_id)
                .order_by(self._outcome_model.created_at.asc())
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
                    _select(self._target_model).where(
                        self._target_model.id == inv.target_id,
                    ),
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
                "canonical_kind": canonical.outcome_kind,
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
            except (ValueError, TypeError) as exc:
                _log.warning(
                    "claim_verifier preconditions parse FAILED reason=%s", exc,
                )
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
                out.append("probe_result: <skipped -- over max probe count>")
            elif not r["ok"]:
                out.append(f"probe_result: ERROR {r.get('error')}")
            else:
                # Format the probe result smartly by shape:
                #   read_function -> join the `body` list as raw source
                #     (avoids the 2x cost of JSON-escaping every line)
                #   search_source / search_macros / search_constants ->
                #     emit matches one per line as `file:line: text`
                #   everything else -> JSON-stringified
                # Then truncate to 40000 chars; at smaller caps a single
                # read_function on a 500-line function comes back too
                # short, so the verifier never sees the load-bearing
                # region of the function.
                raw = r["raw"]
                tool = (p.get("probe") or {}).get("tool") or ""
                rendered = _render_probe_payload(tool, raw)
                if len(rendered) > 40000:
                    rendered = rendered[:40000] + (
                        f"\n... [truncated -- {len(rendered)} chars total; "
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
            except (ValueError, TypeError) as exc:
                _log.warning(
                    "claim_verifier verdict parse FAILED reason=%s", exc,
                )
                return None

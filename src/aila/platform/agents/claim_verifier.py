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
import re
from collections.abc import Callable
from typing import Any, ClassVar
from uuid import uuid4

import httpx
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.contracts import utc_now
from aila.platform.mcp.factory import make_bridge
from aila.platform.prompts import PromptNotFoundError, PromptRegistry
from aila.platform.prompts.seeds import (
    CLAIM_VERIFIER_EXTRACTOR_TEXT,
    CLAIM_VERIFIER_VERDICT_TEXT,
)
from aila.platform.prompts.version_store import PromptVersionStore
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

__all__ = [
    "ClaimVerifierAgentBase",
    "is_negative_finding_claim",
    "platform_claim_verifier_seed_entries",
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


def _normalize_probe_tool_name(tool: str) -> str:
    """Strip an optional ``<server>.`` namespace prefix from a probe tool
    name so a bare name (``search_source``) and a server-qualified name
    (``audit_mcp.search_source``) both resolve to the same allowlist key.

    The extractor LLM names probes either way. Without this normalization
    a bare name collapsed to ``""`` at the allowlist gate and every probe
    was refused as "not on verifier allowlist", blinding the verifier so
    every verdict came back ``inconclusive``. Mirrors the server-prefix
    split utilities that MCP clients ship for the same reason.
    """
    return tool.split(".", 1)[1] if "." in tool else tool


_EXTRACTOR_REGISTRY = PromptRegistry(
    module="platform",
    version_store=PromptVersionStore(),
)
_VERDICT_REGISTRY = PromptRegistry(
    module="platform",
    version_store=PromptVersionStore(),
)


def _load_extractor_prompt() -> str:
    """Return the extractor system prompt from the platform prompt registry.

    RFC-09 / req 20: prompt body is resolved from the version store via
    :class:`PromptRegistry` so cost / seal rows carry the prompt_content_hash +
    prompt_version stamp.
    """
    try:
        return _EXTRACTOR_REGISTRY.load("claim_verifier_extractor")
    except PromptNotFoundError:
        return CLAIM_VERIFIER_EXTRACTOR_TEXT


def _load_verdict_prompt() -> str:
    """Return the verdict system prompt from the platform prompt registry.

    Sibling to :func:`_load_extractor_prompt`.
    """
    try:
        return _VERDICT_REGISTRY.load("claim_verifier_verdict")
    except PromptNotFoundError:
        return CLAIM_VERIFIER_VERDICT_TEXT


def platform_claim_verifier_seed_entries() -> tuple[tuple[str, str], ...]:
    """Return the platform-owned claim-verifier ``(key, body)`` seed pairs.

    Called from each module's ``seed_prompt_versions`` hook (VR + malware
    both use the shared claim verifier) so RFC-09 gets a version-store
    row + production alias for the extractor and verdict prompts even
    though they live in the platform layer. The alias-if-absent write
    lives in the calling module's ``seed_prompt_versions`` (already
    covered by the RFC-09 activation-bootstrap whitelist), so this
    helper stays a pure body lookup. Content-hash dedup on
    :meth:`PromptVersionStore.register` makes the double-registration
    from both modules safe: the first module to reach the seed writes
    the row, the second returns the existing version.
    """
    return (
        ("platform/claim_verifier/extractor", CLAIM_VERIFIER_EXTRACTOR_TEXT),
        ("platform/claim_verifier/verdict", CLAIM_VERIFIER_VERDICT_TEXT),
    )


# A general "no <thing> found / identified" negative-conclusion pattern the
# fixed prefix/substring tables miss. Three orderings are matched on the
# uppercased head window; each requires BOTH a security-negative noun and a
# discovery verb (or the explicit "no evidence of" lead) within a short span
# so an ordinary "no" ("no authentication is required to trigger the RCE")
# does not trip it:
#   A. noun between "no" and the verb -- "No exploitable vulnerability found"
#   B. verb before "no"              -- "found no memory-safety vulnerabilities"
#   C. explicit "no evidence of ..." -- "No evidence of out-of-bounds writes"
# B and C were added after live investigations shipped a strong-confidence
# "no bug" answer ("...found no memory-safety vulnerabilities", "No evidence
# of out-of-bounds array writes...") that only pattern A missed, so it burned
# into a false DIRECT_FINDING.
_NEG_CONCLUSION_NOUN = (
    r"(?:VULNERABILIT\w*|BUGS?|EXPLOIT\w*|FINDINGS?|WEAKNESS(?:ES)?|FLAWS?|"
    r"ISSUES?|ESCAPES?|BYPASS(?:ES)?|OVERFLOWS?|INJECTIONS?|"
    r"OUT[\s-]?OF[\s-]?BOUNDS|MEMORY[\s-]?SAFETY|MEMORY[\s-]?CORRUPTION|"
    r"USE[\s-]?AFTER[\s-]?FREE)"
)
_NEG_CONCLUSION_VERB = (
    r"(?:FOUND|IDENTIFIED|DETECTED|PRESENT|OBSERVED|EXISTS?|EXISTED|"
    r"REVEAL\w*|SURFACED?|UNCOVERED)"
)
_NEGATIVE_CONCLUSION_RE = re.compile(
    r"\bNO\b(?:\s+[\w'-]+){0,6}\s+" + _NEG_CONCLUSION_NOUN
    + r"(?:\s+[\w'-]+){0,4}?\s+" + _NEG_CONCLUSION_VERB + r"\b"
    + r"|"
    + _NEG_CONCLUSION_VERB + r"\b(?:\s+[\w'-]+){0,4}\s+NO\b"
    + r"(?:\s+[\w'-]+){0,6}\s+" + _NEG_CONCLUSION_NOUN
    + r"|"
    + r"\bNO\s+EVIDENCE\s+(?:OF|FOR|THAT|TO)\b",
)


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
    if _NEGATIVE_CONCLUSION_RE.search(head):
        return True
    return any(phrase in head for phrase in substrings)


async def _fetch_audit_mcp_signatures(
    recorder: Callable[..., Any],
    *,
    module_id: str,
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

    ``module_id`` is the owning module of the investigation being
    verified so the bridge is namespaced under that module's config /
    tool-name namespace (RFC-05 crit 4 hardening).
    """
    bridge = make_bridge("audit_mcp", module_id=module_id, recorder=recorder)
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

    tool_name = _normalize_probe_tool_name(tool)

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
    * ``_MODULE_ID`` -- the owning module id (``"vr"``, ``"malware"``,
      ...). Passed to every ``make_bridge`` construction so the
      platform bridge is namespaced under the module the investigation
      belongs to (RFC-05 crit 4 hardening).
    """

    # ---- Required subclass attributes ----
    _MODULE_ID: ClassVar[str]
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
        """Return the module's mcp call recorder passed to ``make_bridge``.

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

    async def _after_verifier_report_persisted(
        self, uow: Any, outcome_row: Any, payload: dict[str, Any],
    ) -> None:
        """Module hook: sync any denormalized investigation columns
        derived from the now-final verifier report. Base is a no-op;
        VR overrides to keep the investigations-list filter columns
        (``primary_outcome_polarity``, ``verifier_verdict``) in sync
        with the freshly-persisted verifier report. Called inside the
        same ``UnitOfWork`` block that wrote the outcome update, before
        the enclosing commit, so the investigation update commits
        atomically with the outcome.
        """
        del uow, outcome_row, payload
        return None

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
            module_id=self._MODULE_ID,
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
                    {"role": "system", "content": _load_extractor_prompt()},
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
        # Probes run in parallel via asyncio.gather. McpBridgeTool
        # is concurrency-safe (per-instance warm-lock + httpx client
        # created per-call), and audit-mcp deduplicates identical tool
        # calls -- concurrent probes benefit from server-side dedup as
        # well as wall-clock overlap.
        bridge = make_bridge("audit_mcp", module_id=self._MODULE_ID, recorder=self._bridge_recorder())
        top_preconditions = preconditions[: self._MAX_PROBES]

        async def _run_one_probe(p: dict[str, Any]) -> dict[str, Any]:
            probe_spec = p.get("probe") or {}
            tool = str(probe_spec.get("tool") or "")
            tool_name = _normalize_probe_tool_name(tool)
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
                    {"role": "system", "content": _load_verdict_prompt()},
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
            await self._after_verifier_report_persisted(uow, row, payload)
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

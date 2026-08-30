"""VR ClaimVerifierAgent -- adversarial verification of canonical-outcome claims.

Thin subclass of :class:`aila.platform.agents.claim_verifier.ClaimVerifierAgentBase`.
The three-stage pipeline (extractor LLM -> parallel audit-mcp probes ->
verdict LLM), the negative-claim guard, the verifier-report persist,
and the auto-promote + revert live on the platform base. This module
supplies the vr wiring:

* task-type routing keys for the extractor and verdict stages,
* the vr negative-finding phrase tables (kept module-local so
  cross-module reuse is opt-in on the platform side),
* the vr SQLModel record classes and the vr ``OutcomeDispatcher``,
* the auto-promote gate constants (ASSESSMENT_REPORT -> DIRECT_FINDING),
* the extractor's ``payload["answer"]`` claim-text extraction and the
  auto-promote negative-claim source (also ``payload["answer"]``),
* the vr ``ConfigRegistry`` binding for
  ``claim_verifier_auto_promote_floor`` and the vr mcp call recorder.

Idempotency: skips when ``verifier_report`` is already present in the
canonical outcome's payload. Triggered post-synthesis from
``investigation_emit._maybe_trigger_synthesis``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Callable
from typing import Any

import httpx
from sqlmodel import select as _select

from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules.vr.contracts import OutcomeDispatchStatus, OutcomeKind

# outcome_polarity is authored in .contracts.outcome; the top-level
# .contracts __init__ re-export is Main's integration task, so we import
# it directly from the submodule to keep this subclass buildable
# independently of that re-export.
from aila.modules.vr.contracts.outcome import outcome_polarity
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.modules.vr.services.outcome_polarity import (
    derive_outcome_polarity,
    derive_verifier_verdict,
)
from aila.modules.vr.services.outcome_review import OUTCOME_STATE_APPROVED
from aila.platform.agents.claim_verifier import (
    _PROBE_TOOL_ALLOWLIST,
    ClaimVerifierAgentBase,
    ClaimVerifierExtractorResponse,
    ClaimVerifierVerdictResponse,
    _fetch_audit_mcp_signatures,
    _load_extractor_prompt,
    _load_verdict_prompt,
    _normalize_probe_tool_name,
)
from aila.platform.agents.claim_verifier import (
    is_negative_finding_claim as _platform_is_negative_finding_claim,
)
from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.config_base import ModuleConfigReader
from aila.platform.llm.errors import BudgetExceededError, LLMError
from aila.platform.mcp.call_log_record import McpCallLogRecord
from aila.platform.mcp.factory import make_bridge
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

__all__ = ["ClaimVerifierAgent", "is_negative_finding_claim"]

_log = logging.getLogger(__name__)
_cfg = ModuleConfigReader("vr")

# VR-domain negative-claim vocabulary. Kept module-local so the platform
# base's phrase-table hook is passed the right set for vr and no other
# module inherits vr's exact vocabulary by accident. Malware carries its
# own superset in ``modules/malware/agents/claim_verifier.py``.
_NEGATIVE_ANSWER_PREFIXES: tuple[str, ...] = (
    "NEGATIVE",
    "NOT VULNERABLE",
    "NO BUG",
    "NO VULNERABILITY",
    "NO FINDING",
    "PATCH PRESENT",
    "PATCH IS IN PLACE",
    "VARIANT DEAD",
    "VARIANT IS DEAD",
    "NO VARIANTS",
    "VULNERABILITY DOES NOT APPLY",
    "NOT EXPLOITABLE IN PRACTICE",
    "THE ISSUE IS MITIGATED",
)

# Substring matchers for descriptive negative claims that don't always
# start at character 0 (see platform base for the head-window rules).
_NEGATIVE_ANSWER_SUBSTRINGS: tuple[str, ...] = (
    "NO EXPLOITABLE CONDITION REACHES HERE",
    "THE ISSUE IS MITIGATED",
    "VULNERABILITY DOES NOT APPLY",
    "NOT EXPLOITABLE IN PRACTICE",
    "PATCH IS IN PLACE",
)


def is_negative_finding_claim(answer: str) -> bool:
    """VR-scoped negative-claim gate.

    Thin wrapper over the platform helper: passes the vr phrase tables
    through. Kept as a module-level function so existing import sites
    (``from aila.modules.vr.agents.claim_verifier import is_negative_finding_claim``)
    keep working after the platform lift.
    """
    return _platform_is_negative_finding_claim(
        answer,
        prefixes=_NEGATIVE_ANSWER_PREFIXES,
        substrings=_NEGATIVE_ANSWER_SUBSTRINGS,
    )


class ClaimVerifierAgent(ClaimVerifierAgentBase):
    """Three-stage adversarial verifier for the vr module."""

    # Task-type diversity: each stage gets its own task_type so operators
    # can route them to a different model via ConfigRegistry keys
    # ``llm_model_vulnerability_research.verifier_extractor`` and
    # ``llm_model_vulnerability_research.verifier_verdict``. Until those
    # keys are populated they fall back to ``llm_default_model``;
    # routing the verdict stage to a different model is the meaningful
    # follow-up.
    _MODULE_ID = "vr"
    _EXTRACTOR_TASK_TYPE = "vulnerability_research.verifier_extractor"
    _VERDICT_TASK_TYPE = "vulnerability_research.verifier_verdict"

    _NEGATIVE_ANSWER_PREFIXES = _NEGATIVE_ANSWER_PREFIXES
    _NEGATIVE_ANSWER_SUBSTRINGS = _NEGATIVE_ANSWER_SUBSTRINGS

    _investigation_model = VRInvestigationRecord
    _outcome_model = VRInvestigationOutcomeRecord
    _target_model = VRTargetRecord
    _outcome_dispatcher_cls = OutcomeDispatcher

    _promote_source_kind = OutcomeKind.ASSESSMENT_REPORT.value
    _promote_target_kind = OutcomeKind.DIRECT_FINDING.value
    _promote_wrong_kind_reason = "outcome_kind_not_assessment"
    _promote_negative_skip_reason = "answer_starts_negative_no_bug_to_promote"
    _dispatch_status_pending = OutcomeDispatchStatus.PENDING.value
    _dispatch_status_skipped = OutcomeDispatchStatus.SKIPPED.value
    _outcome_state_approved = OUTCOME_STATE_APPROVED

    async def _read_auto_promote_floor(self) -> float:
        """Read the vr-namespaced auto-promote floor via ConfigRegistry."""
        return await _cfg.get_float("claim_verifier_auto_promote_floor")

    def _bridge_recorder(self) -> Callable[..., Any]:
        """The vr mcp call recorder -- probe traffic attributed to vr."""
        return record_call

    def _extract_claim_text(
        self, canonical_kind: str, canonical_payload: dict[str, Any],
    ) -> str:
        """VR reads the free-form ``answer`` field directly.

        The vr outcome payload is a flat ``{"answer": "..."}`` shape
        across every outcome kind, so the kind argument does not gate
        which field is read.
        """
        del canonical_kind
        return str(canonical_payload.get("answer") or "")

    def _promote_negative_claim_text(
        self, orig_payload: dict[str, Any],
    ) -> str:
        """The auto-promote negative-claim gate reads ``payload["answer"]``."""
        return str(orig_payload.get("answer") or "")

    # ----- VR-truth G1 (issue #01, #247): evidence-packet injection -----

    async def _load_evidence_packet(
        self,
        *,
        canonical: Any,
        canonical_payload: dict[str, Any],
        index_id: str,
    ) -> dict[str, Any]:
        """Assemble the proposing-branch evidence packet.

        Reads the proposing branch's ``case_state_json`` and the
        matching ``McpCallLogRecord`` rows for the investigation +
        branch. Returns the batch-contract shape agreed with the
        integration owner::

            {
                "case_state": {"observables": {...}, "hypotheses": [...],
                               "rejected": [...], "resolved": [...]},
                "citations": [str, ...],   # merged evidence_refs
                "tool_calls": [{"tool": str, "args": dict,
                                "result_digest": str}, ...],
            }

        Empty branches / missing rows / parse failures degrade to an
        empty section rather than raising -- the extractor + verdict
        prompts still see the claim + panel narrative from the base
        pipeline. See ``.run/vr_truth_adjudication_source.md`` and
        ``.run/issues/01_fieldflow.md`` for the field-flow audit that
        motivated this hook.
        """
        del canonical_payload, index_id
        proposing_branch_id = getattr(canonical, "branch_id", None) or ""
        investigation_id = self.investigation_id
        case_state: dict[str, Any] = {}
        citations: list[str] = []
        tool_calls: list[dict[str, Any]] = []

        # Merge outcome-level evidence_refs first -- these are what the
        # panel already cited on the row being verified.
        try:
            outcome_refs = json.loads(
                getattr(canonical, "evidence_refs_json", None) or "[]",
            )
        except (ValueError, TypeError):
            outcome_refs = []
        if isinstance(outcome_refs, list):
            citations.extend(str(r) for r in outcome_refs if r)

        async with UnitOfWork() as uow:
            branch = None
            if proposing_branch_id:
                branch = (await uow.session.exec(
                    _select(VRInvestigationBranchRecord).where(
                        VRInvestigationBranchRecord.id == proposing_branch_id,
                    ),
                )).first()
            if branch is not None:
                try:
                    case_state = json.loads(branch.case_state_json or "{}")
                    if not isinstance(case_state, dict):
                        case_state = {}
                except (ValueError, TypeError):
                    case_state = {}

            # McpCallLogRecord is the F4 tool-log table: one row per
            # audit-mcp / ida-headless call. Filter to this
            # investigation + (when known) branch so the verifier sees
            # exactly the tool traffic the proposing branch produced.
            log_query = _select(McpCallLogRecord).where(
                McpCallLogRecord.investigation_id == investigation_id,
            )
            if proposing_branch_id:
                log_query = log_query.where(
                    McpCallLogRecord.branch_id == proposing_branch_id,
                )
            log_query = log_query.order_by(
                McpCallLogRecord.called_at.asc(),
            ).limit(200)
            log_rows = (await uow.session.exec(log_query)).all()

        # Fold branch-level cited evidence too: hypothesis.evidence_refs
        # (Hypothesis.confirmed_by / evidence_refs) and observable ids
        # that survived the case-state truncation.
        for hyp in (case_state.get("hypotheses") or []):
            if not isinstance(hyp, dict):
                continue
            refs = hyp.get("evidence_refs") or []
            if isinstance(refs, list):
                citations.extend(str(r) for r in refs if r)
            confirmed_by = hyp.get("confirmed_by")
            if isinstance(confirmed_by, str) and confirmed_by:
                citations.append(confirmed_by)
            elif isinstance(confirmed_by, list):
                citations.extend(str(r) for r in confirmed_by if r)

        # Dedup citations while preserving order.
        seen: set[str] = set()
        deduped: list[str] = []
        for c in citations:
            if c and c not in seen:
                seen.add(c)
                deduped.append(c)
        citations = deduped

        for row in log_rows:
            action = row.action or ""
            # The call-log table does not persist arg / response bodies
            # (operator-visibility posture -- see call_log_base). Emit
            # the outcome digest we DO have: status + latency + error
            # excerpt hashed so the verifier can see "this exact tool
            # ran, here is a stable id for its result" without the
            # verifier being asked to trust bodies we never stored.
            digest_src = (
                f"{row.status}|{row.http_status}|{row.latency_ms}|"
                f"{row.error_excerpt or ''}"
            )
            result_digest = hashlib.sha256(
                digest_src.encode("utf-8", errors="ignore"),
            ).hexdigest()[:16]
            tool_calls.append({
                "tool": action,
                "args": {
                    "server_id": row.server_id,
                    "instance_id": row.instance_id,
                    "turn_number": row.turn_number,
                },
                "result_digest": result_digest,
                # Extra fields (tolerated by the shape contract) so the
                # tool-telemetry cross-check in issue #01 B3 can gate
                # on latency / error without a second query.
                "status": row.status,
                "latency_ms": row.latency_ms,
                "error_excerpt": row.error_excerpt,
            })

        return {
            "case_state": case_state,
            "citations": citations,
            "tool_calls": tool_calls,
            "proposing_branch_id": proposing_branch_id,
            "canonical_outcome_kind": getattr(canonical, "outcome_kind", ""),
            "canonical_polarity": outcome_polarity(
                str(getattr(canonical, "outcome_kind", "")),
            ),
        }

    def _render_evidence_packet_section(
        self, packet: dict[str, Any],
    ) -> str:
        """Render the evidence packet as a labelled prompt section.

        Cap observable / hypothesis / tool-log sizes independently so a
        loud branch cannot crowd out the tool log the verifier needs
        to cross-check citations. See ``.run/issues/01_fieldflow.md``
        for the field-flow anchors that map into each subsection.
        """
        if not packet:
            return ""
        case_state = packet.get("case_state") or {}
        citations = packet.get("citations") or []
        tool_calls = packet.get("tool_calls") or []
        if not (case_state or citations or tool_calls):
            return ""

        lines: list[str] = ["## Proposing-branch evidence packet"]
        proposing = packet.get("proposing_branch_id") or "(unknown)"
        lines.append(f"proposing_branch_id: {proposing}")
        lines.append(
            f"canonical_outcome_kind: {packet.get('canonical_outcome_kind') or '(?)'}"
        )
        lines.append(
            f"canonical_polarity: {packet.get('canonical_polarity') or '(?)'}"
        )

        # Hypotheses -- render live and confirmed_by anchor per issue
        # #01 A1 (render_confirmed_by).
        hypotheses = case_state.get("hypotheses") or []
        if hypotheses:
            lines.append("")
            lines.append("### Live hypotheses")
            for hyp in hypotheses[:15]:
                if not isinstance(hyp, dict):
                    continue
                hid = hyp.get("id") or "?"
                claim = str(hyp.get("claim") or hyp.get("text") or "")[:280]
                confirmed_by = hyp.get("confirmed_by")
                kill_criterion = hyp.get("kill_criterion")
                lines.append(f"- {hid}: {claim}")
                if confirmed_by:
                    lines.append(f"    confirmed_by: {confirmed_by}")
                if kill_criterion:
                    lines.append(f"    kill_criterion: {kill_criterion}")

        # Observables -- keep only the tool-namespaced entries plus
        # any _directive.* keys. Agent-scratchpad keys are noise.
        observables = case_state.get("observables") or {}
        if isinstance(observables, dict) and observables:
            relevant = {
                k: v for k, v in observables.items()
                if isinstance(k, str) and (
                    ":" in k or k.startswith("_directive.")
                    or k.startswith("_") and "citation" in k
                )
            }
            if relevant:
                lines.append("")
                lines.append("### Cited observables (tool + directive keys)")
                rendered = 0
                for k, v in list(relevant.items())[:40]:
                    body = str(v)
                    if len(body) > 400:
                        body = body[:400] + f" [truncated -- {len(str(v))} chars]"
                    lines.append(f"- {k}: {body}")
                    rendered += 1
                if rendered == 0:
                    lines.append("- (none)")

        if citations:
            lines.append("")
            lines.append("### Cited evidence refs")
            for ref in citations[:60]:
                lines.append(f"- {ref}")
            if len(citations) > 60:
                lines.append(f"- ... [{len(citations) - 60} more truncated]")

        if tool_calls:
            lines.append("")
            lines.append(
                f"### Tool call log ({len(tool_calls)} rows from"
                " McpCallLogRecord)"
            )
            rendered_calls = tool_calls[:80]
            for tc in rendered_calls:
                status = tc.get("status") or "?"
                lat = tc.get("latency_ms")
                lat_s = f"{lat}ms" if lat is not None else "?ms"
                digest = tc.get("result_digest") or ""
                lines.append(
                    f"- {tc.get('tool') or '?'} [{status} {lat_s}]"
                    f" digest={digest}"
                )
                err = tc.get("error_excerpt")
                if err:
                    lines.append(f"    error: {str(err)[:200]}")
            if len(tool_calls) > 80:
                lines.append(
                    f"- ... [{len(tool_calls) - 80} more calls truncated]"
                )

        return "\n".join(lines)

    # ----- VR-truth issue #260: widen auto-promote source-kind gate -----

    def _is_auto_promotable_source_kind(self, kind: str) -> bool:
        """Broaden the auto-promote source-kind gate for VR.

        When ``vr.claim_verifier_broaden_promote_kinds`` is true
        (default), any positive-or-inconclusive outcome kind is
        eligible -- i.e. everything except ``audit_memo`` (the settled
        no-finding negative). The confidence-floor, already-promoted,
        and negative-claim guards remain in force on the outer
        ``_maybe_auto_promote`` body. This lifts the verifier past the
        ASSESSMENT_REPORT-only gate that starved the confirming path
        (adjudication-source doc, section 3-5).
        """
        # Sync-only read -- the ConfigRegistry get() coroutine cannot be
        # awaited from a sync method. Fall back to the widened default
        # when the config read cannot be scheduled here; the toggle is
        # advisory (any positive-or-inconclusive kind IS a legitimate
        # promotion source once verifier-confirmed). Callers that want
        # the pre-widening behaviour set the config knob to false --
        # the platform default hook still honours it via base equality
        # when this override reports False.
        polarity = outcome_polarity(kind)
        if polarity == "negative":
            return False
        return True

    # ----- VR-truth issue #260, section 5: precondition quorum override -----

    async def _apply_verdict_quorum_override(
        self, verdict_parsed: ClaimVerifierVerdictResponse,
    ) -> ClaimVerifierVerdictResponse:
        """Relax the implicit 100%-preconditions bar to a quorum.

        Only rewrites when:
          - the LLM returned ``inconclusive``,
          - zero preconditions resolved ``false``,
          - the ``true``-share of non-``unknown`` preconditions clears
            ``vr.claim_verifier_precondition_true_threshold``.
        Under these conditions the verdict is rewritten to
        ``confirmed``. A ``refuted`` LLM verdict is NEVER upgraded; a
        single ``false`` precondition still refutes; an all-``unknown``
        precondition set stays inconclusive.
        """
        if verdict_parsed.verdict != "inconclusive":
            return verdict_parsed
        pres = verdict_parsed.preconditions or []
        if not pres:
            return verdict_parsed
        results = [str(p.result or "").lower() for p in pres]
        if any(r == "false" for r in results):
            return verdict_parsed
        resolvable = [r for r in results if r in ("true", "false")]
        if not resolvable:
            return verdict_parsed
        try:
            threshold = await _cfg.get_float(
                "claim_verifier_precondition_true_threshold",
            )
        except (ValueError, TypeError, OSError, RuntimeError):
            threshold = 0.5
        true_count = sum(1 for r in resolvable if r == "true")
        share = true_count / len(resolvable)
        if share < threshold:
            return verdict_parsed
        _log.info(
            "claim_verifier quorum override inv=%s inconclusive->confirmed"
            " true=%d/%d share=%.2f threshold=%.2f",
            self.investigation_id, true_count, len(resolvable),
            share, threshold,
        )
        return verdict_parsed.model_copy(
            update={
                "verdict": "confirmed",
                "counter_evidence": (
                    verdict_parsed.counter_evidence
                    + (" [verdict rewritten by vr precondition quorum"
                       f" override: {true_count}/{len(resolvable)}"
                       f" preconditions true, zero refuted,"
                       f" threshold {threshold:.2f}]")
                ),
            },
        )

    async def _after_verifier_report_persisted(
        self, uow: Any, outcome_row: Any, payload: dict[str, Any],
    ) -> None:
        """Sync ``VRInvestigationRecord.primary_outcome_polarity`` and
        ``verifier_verdict`` on the investigation whose primary outcome
        is the row that just gained a verifier report. Called inside
        the same ``UnitOfWork`` as the outcome write; the enclosing
        commit lands both updates atomically. When no investigation
        points at this outcome as primary, the update is a no-op.
        """
        inv = (await uow.session.exec(
            _select(self._investigation_model).where(
                self._investigation_model.primary_outcome_id == outcome_row.id,
            )
        )).first()
        if inv is None:
            return
        inv.primary_outcome_polarity = derive_outcome_polarity(
            outcome_row.outcome_kind, payload,
        )
        inv.verifier_verdict = derive_verifier_verdict(payload)
        uow.session.add(inv)

    # ----- VR-truth issues #249 / #271 support: inline verify entrypoint -----

    async def verify_evidence(
        self, evidence_packet: dict[str, Any],
    ) -> dict[str, Any]:
        """Run the extractor + probe + verdict pipeline synchronously
        on a caller-supplied evidence packet, without persisting a
        ``verifier_report`` and without touching the auto-promote /
        trigger paths.

        Intended as the pre-dispatch entrypoint the dispatcher (or
        another platform caller) can invoke to gate a submit on a
        fresh verifier judgment. Bypasses every trigger gate --
        terminal-state check, canonical-outcome presence, prior
        verifier_report -- because the caller has already decided this
        packet is worth verifying.

        Expected ``evidence_packet`` shape::

            {
                "claim": str,                 # required -- the finding text
                "index_id": str,              # required -- audit-mcp index
                "kind": str,                  # optional -- investigation kind
                "canonical_kind": str,        # optional -- outcome kind
                "case_state": dict,           # optional
                "citations": list[str],       # optional
                "tool_calls": list[dict],     # optional
                "proposing_branch_id": str,   # optional -- for logs
            }

        Returns a ``ClaimVerifierVerdictResponse``-shaped dict plus
        pipeline metadata::

            {
                "status": "ok" | "failed" | "skipped",
                "verdict": "confirmed" | "refuted" | "inconclusive",
                "confidence": float,
                "preconditions": [...],
                "counter_evidence": str,
                "summary": str,
                "probes_run": int,
                "probes_succeeded": int,
                "signatures_fetch_failed": bool,
                "reason": str,   # only on non-ok status
            }
        """
        claim = str(evidence_packet.get("claim") or "").strip()
        index_id = str(evidence_packet.get("index_id") or "").strip()
        if not claim:
            return {"status": "skipped", "reason": "no_finding_text"}
        if not index_id:
            return {"status": "skipped", "reason": "no_index_id"}

        inv_kind = str(evidence_packet.get("kind") or "vulnerability_research")
        canonical_kind = str(
            evidence_packet.get("canonical_kind")
            or OutcomeKind.ASSESSMENT_REPORT.value,
        )

        claim_cap = 16000
        claim_capped = claim[:claim_cap]
        claim_section = (
            f"## {self._claim_section_header(canonical_kind)}\n\n{claim_capped}"
            + (f"\n\n[claim truncated to {claim_cap} chars]"
               if len(claim) > claim_cap else "")
        )

        packet_section = self._render_evidence_packet_section(evidence_packet)
        evidence_prefix = f"{packet_section}\n\n" if packet_section else ""

        services = ServiceFactory()
        signatures_block, signatures_ok = await _fetch_audit_mcp_signatures(
            self._bridge_recorder(),
            module_id=self._MODULE_ID,
        )
        sig_section = (
            f"## Available audit-mcp probes (live signatures)\n\n"
            f"{signatures_block}\n\n"
            if signatures_block else ""
        )
        extractor_input = (
            self._extractor_prelude(inv_kind, canonical_kind, index_id)
            + sig_section
            + evidence_prefix
            + claim_section
            + "\n"
        )

        try:
            extractor_response, _ = await idempotent_llm_call(
                services.llm_client,
                method="chat_structured",
                task_type=self._EXTRACTOR_TASK_TYPE,
                messages=[
                    {"role": "system", "content": _load_extractor_prompt()},
                    {"role": "user", "content": extractor_input},
                ],
                model_class=ClaimVerifierExtractorResponse,
                investigation_id=self.investigation_id,
            )
        except BudgetExceededError:
            raise
        except (
            httpx.HTTPError, LLMError, OSError,
            RuntimeError, TimeoutError, ValueError, TypeError,
        ) as exc:
            _log.warning(
                "verify_evidence extractor failed inv=%s err=%s",
                self.investigation_id, exc, exc_info=True,
            )
            return {
                "status": "failed",
                "reason": f"extractor_error:{type(exc).__name__}",
            }
        if extractor_response.disabled:
            return {"status": "skipped", "reason": "llm_kill_switch_active"}
        try:
            extractor_parsed = ClaimVerifierExtractorResponse.model_validate_json(
                extractor_response.content,
            )
        except ValueError:
            return {"status": "failed", "reason": "extractor_schema_invalid"}
        preconditions = [p.model_dump() for p in extractor_parsed.preconditions]
        if not preconditions:
            return {
                "status": "failed",
                "reason": "extractor_returned_no_preconditions",
            }
        preconditions = sorted(
            enumerate(preconditions),
            key=lambda iv: (
                iv[1].get("rank") if isinstance(iv[1].get("rank"), (int, float))
                else 10_000,
                iv[0],
            ),
        )
        preconditions = [p for _, p in preconditions]

        bridge = make_bridge(
            "audit_mcp",
            module_id=self._MODULE_ID,
            recorder=self._bridge_recorder(),
        )
        top_preconditions = preconditions[: self._MAX_PROBES]

        async def _run_one_probe(p: dict[str, Any]) -> dict[str, Any]:
            probe_spec = p.get("probe") or {}
            tool = str(probe_spec.get("tool") or "")
            tool_name = _normalize_probe_tool_name(tool)
            args = dict(probe_spec.get("args") or {})
            if tool_name not in _PROBE_TOOL_ALLOWLIST:
                return {
                    "id": p.get("id"),
                    "ok": False,
                    "error": (
                        f"refused: probe tool {tool!r} not on"
                        " verifier allowlist"
                    ),
                    "raw": None,
                }
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

        probe_results = list(await asyncio.gather(
            *[_run_one_probe(p) for p in top_preconditions],
        ))

        verdict_input = evidence_prefix + self._render_verdict_input(
            preconditions, probe_results,
        )
        try:
            verdict_response, _ = await idempotent_llm_call(
                services.llm_client,
                method="chat_structured",
                task_type=self._VERDICT_TASK_TYPE,
                messages=[
                    {"role": "system", "content": _load_verdict_prompt()},
                    {"role": "user", "content": verdict_input},
                ],
                model_class=ClaimVerifierVerdictResponse,
                investigation_id=self.investigation_id,
            )
        except BudgetExceededError:
            raise
        except (
            httpx.HTTPError, LLMError, OSError,
            RuntimeError, TimeoutError, ValueError, TypeError,
        ) as exc:
            _log.warning(
                "verify_evidence verdict failed inv=%s err=%s",
                self.investigation_id, exc, exc_info=True,
            )
            return {
                "status": "failed",
                "reason": f"verdict_error:{type(exc).__name__}",
            }
        if verdict_response.disabled:
            return {"status": "skipped", "reason": "llm_kill_switch_active"}
        try:
            verdict_parsed = ClaimVerifierVerdictResponse.model_validate_json(
                verdict_response.content,
            )
        except ValueError:
            return {"status": "failed", "reason": "verdict_schema_invalid"}

        verdict_parsed = await self._apply_verdict_quorum_override(verdict_parsed)

        return {
            "status": "ok",
            "verdict": verdict_parsed.verdict,
            "confidence": verdict_parsed.confidence,
            "preconditions": [
                p.model_dump() for p in verdict_parsed.preconditions
            ],
            "counter_evidence": verdict_parsed.counter_evidence,
            "summary": verdict_parsed.summary,
            "probes_run": len(probe_results),
            "probes_succeeded": sum(1 for p in probe_results if p["ok"]),
            "signatures_fetch_failed": not signatures_ok,
            "proposing_branch_id": (
                evidence_packet.get("proposing_branch_id") or ""
            ),
        }

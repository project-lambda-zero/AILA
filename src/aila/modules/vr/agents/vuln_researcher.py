"""HonestVulnResearcher — single-turn reasoning agent (M3.R-2).

Per the M3.R-1 schema lesson and the no-overengineering rule: this
agent runs ONE turn against the platform's existing
``CyberReasoningEngine``. The workflow state machine (M3.R-7) drives
the loop; the agent itself owns no loop, no tool execution, no
branching. Each of those is a separate later milestone.

What this commit ships:
  1. ``HonestVulnResearcher.run_turn()`` — load branch state, build
     prompt context, call engine.decide_next_turn, absorb decision,
     persist message + updated branch state.
  2. ``run_turn`` returns a ``VulnResearcherTurnResult`` describing
     what happened (action chosen, terminal yes/no, message id).
  3. Tool calls are RECORDED as messages but NOT executed (M3.R-3 wires
     MCP adapters). Submit actions DO get persisted as VROutcome rows.

What this commit does NOT do:
  - Branching: only the primary branch is touched (M3.R-5).
  - Persona voicing: ignores branch.persona_voice (M3.R-5).
  - Cost tracking: turn count goes up but $ costs stay at 0 until the
    cost_tracker service ships (separate small commit).
  - Tool execution: tool_run decisions become tool_call messages but no
    real MCP call. M3.R-3 adapters convert the message into a real call.
  - Operator messaging interleave: operator messages stored in DB but
    agent does NOT incorporate them into context. M3.R-6 adds that.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.agents.mcp_adapters import (
    KNOWN_TOOLS,
    specialized_tools,
)
from aila.modules.vr.agents.persona_router import resolve_task_type
from aila.modules.vr.contracts import (
    OutcomeConfidence,
    OutcomeKind,
    PayloadKind,
    SenderKind,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.contracts._common import utc_now
from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningContract,
    ReasoningTurnDecision,
)
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.uow import UnitOfWork

__all__ = [
    "HonestVulnResearcher",
    "VulnResearcherError",
    "VulnResearcherTurnResult",
]

_log = logging.getLogger(__name__)


_PROMPT_DIR = Path(__file__).parent / "prompts"


@dataclass
class VulnResearcherTurnResult:
    """What one ``run_turn`` produced.

    ``terminal`` is True when the engine chose ``submit`` — caller
    (workflow state) should stop calling run_turn for this branch.
    """

    investigation_id: str
    branch_id: str
    turn: int
    decision: ReasoningTurnDecision
    message_id: str
    outcome_id: str | None = None
    terminal: bool = False


class VulnResearcherError(Exception):
    """Raised on fatal agent failures (branch not found, prompt missing, etc.)."""


class HonestVulnResearcher:
    """Single-branch reasoning agent.

    Construction takes the reasoning engine + identifiers. The engine
    can be swapped for a fake in tests (tests inject a stub with the
    same ``decide_next_turn`` + ``absorb`` shape).
    """

    def __init__(
        self,
        reasoning_engine: CyberReasoningEngine,
        investigation_id: str,
        branch_id: str,
        cve_intel: list[dict[str, Any]] | None = None,
    ) -> None:
        self._engine = reasoning_engine
        self.investigation_id = investigation_id
        self.branch_id = branch_id
        self._cve_intel = list(cve_intel or [])

    async def run_turn(self) -> VulnResearcherTurnResult:
        """Run one turn for this branch and write the result to the DB.

        On a ``submit`` decision, also writes a VRInvestigationOutcomeRecord
        and returns ``terminal=True`` so the workflow state knows to
        stop driving the branch.
        """
        inv, branch, target_snapshot = await self._load()

        case_state = _decode_case_state(branch.case_state_json)
        turn_number = branch.turn_count + 1

        pending_operator_messages = await self._consume_pending_operator_messages(
            turn_number,
        )

        # Re-enqueue blindness fix: on a continuation run (operator
        # re-enqueued a completed investigation), the agent has zero
        # awareness it already submitted DIRECT_FINDINGs in prior
        # passes. Without this, it re-investigates from scratch every
        # time and lands on the same root cause — 6 outcomes, 0 new
        # variants. Loading prior outcomes into the prompt forces it
        # to acknowledge prior work and EXTEND instead of REPEAT.
        prior_outcomes = await self._load_prior_outcomes()

        system_prompt = _load_prompt(inv.strategy_family)
        tool_specs = await _fetch_tool_specs(
            target_kind=(target_snapshot or {}).get("kind"),
        )
        user_prompt = self._build_user_prompt(
            inv=inv,
            branch=branch,
            case_state=case_state,
            turn=turn_number,
            pending_operator_messages=pending_operator_messages,
            cve_intel=self._cve_intel,
            target_snapshot=target_snapshot,
            tool_specs=tool_specs,
            prior_outcomes=prior_outcomes,
        )

        # v0.4 GA-52: branch persona maps to a per-role task_type
        # (researcher / implementer / critic). Falls back to the
        # investigation's strategy_family when no persona is assigned.
        task_type = resolve_task_type(branch.persona_voice) if branch.persona_voice else inv.strategy_family

        try:
            decision = await self._engine.decide_next_turn(
                task_type=task_type,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        except RuntimeError as exc:
            raise VulnResearcherError(
                f"engine.decide_next_turn failed for investigation_id="
                f"{self.investigation_id} branch_id={self.branch_id}: {exc}",
            ) from exc

        new_case_state = self._engine.absorb(case_state, decision)

        payload_kind, payload = _decision_to_message_payload(decision)
        terminal = decision.action == "submit"
        outcome_id: str | None = None

        async with UnitOfWork() as uow:
            msg = VRInvestigationMessageRecord(
                investigation_id=self.investigation_id,
                branch_id=self.branch_id,
                sender_kind=SenderKind.ENGINE.value,
                sender_id="engine",
                payload_kind=payload_kind.value,
                payload_json=json.dumps(payload),
                at_turn=turn_number,
                evidence_refs_json="[]",
            )
            uow.session.add(msg)

            branch_row = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == self.branch_id,
                )
            )).first()
            if branch_row is None:
                raise VulnResearcherError(
                    f"branch {self.branch_id} disappeared during turn",
                )
            branch_row.turn_count = turn_number
            branch_row.case_state_json = _encode_case_state(new_case_state)
            branch_row.updated_at = utc_now()
            uow.session.add(branch_row)

            if terminal:
                outcome_kind = _terminal_outcome_kind(decision)
                outcome_row = VRInvestigationOutcomeRecord(
                    investigation_id=self.investigation_id,
                    branch_id=self.branch_id,
                    outcome_kind=outcome_kind.value,
                    payload_json=json.dumps(_outcome_payload(decision)),
                    confidence=_to_outcome_confidence(decision).value,
                    evidence_refs_json="[]",
                )
                uow.session.add(outcome_row)
                await uow.session.flush()
                outcome_id = outcome_row.id

            await uow.session.commit()
            await uow.session.refresh(msg)

        _log.info(
            "vuln_researcher TURN inv=%s branch=%s turn=%d action=%s terminal=%s",
            self.investigation_id, self.branch_id, turn_number,
            decision.action, terminal,
        )

        return VulnResearcherTurnResult(
            investigation_id=self.investigation_id,
            branch_id=self.branch_id,
            turn=turn_number,
            decision=decision,
            message_id=msg.id,
            outcome_id=outcome_id,
            terminal=terminal,
        )

    async def _load(
        self,
    ) -> tuple[
        VRInvestigationRecord,
        VRInvestigationBranchRecord,
        dict[str, Any],
    ]:
        """Load investigation + branch + a snapshot of the primary target.

        Target snapshot has the fields the agent needs to pick the
        right MCP family + ground its reasoning:
          kind, display_name, primary_language, secondary_languages,
          analysis_state, descriptor (repo_url / upload_filename /
          binary_id / etc.), capability_profile.applicable_mcp_servers,
          capability_profile.applicable_fuzzing_engines,
          capability_profile.functions_of_interest (top 10),
          mcp_handles (audit_mcp_index_id / binary_id) so the agent
          knows what to pass to the bridge.
        """
        from aila.modules.vr.db_models import VRTargetRecord  # noqa: PLC0415

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                )
            )).first()
            if inv is None:
                raise VulnResearcherError(
                    f"investigation {self.investigation_id} not found",
                )
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == self.branch_id,
                )
            )).first()
            if branch is None:
                raise VulnResearcherError(
                    f"branch {self.branch_id} not found",
                )
            if branch.investigation_id != self.investigation_id:
                raise VulnResearcherError(
                    f"branch {self.branch_id} does not belong to investigation "
                    f"{self.investigation_id}",
                )
            target_snapshot: dict[str, Any] = {}
            if inv.target_id:
                target = (await uow.session.exec(
                    _select(VRTargetRecord).where(
                        VRTargetRecord.id == inv.target_id,
                    )
                )).first()
                if target is not None:
                    target_snapshot = self._snapshot_target(target)
            return inv, branch, target_snapshot

    async def _load_prior_outcomes(self) -> list[dict[str, Any]]:
        """Load every prior VRInvestigationOutcomeRecord for this investigation,
        oldest first. Used by ``_build_user_prompt`` to render a
        ``# Prior submissions`` section so the agent doesn't re-derive
        the same root cause on every re-enqueue.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.investigation_id == self.investigation_id)
                .order_by(VRInvestigationOutcomeRecord.created_at.asc()),
            )).all()
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            out.append({
                "outcome_id": row.id,
                "outcome_kind": row.outcome_kind,
                "confidence": row.confidence,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "answer": payload.get("answer") or "",
                "variant_hunt_orders": payload.get("variant_hunt_orders") or [],
                "affected_components": payload.get("affected_components") or [],
            })
        return out

    @staticmethod
    def _snapshot_target(target: Any) -> dict[str, Any]:
        """Compact dict the prompt builder renders."""
        try:
            descriptor = json.loads(target.descriptor_json or "{}")
        except (ValueError, TypeError):
            descriptor = {}
        try:
            capability = json.loads(target.capability_profile_json or "{}")
        except (ValueError, TypeError):
            capability = {}
        try:
            handles = json.loads(target.mcp_handles_json or "{}")
        except (ValueError, TypeError):
            handles = {}
        try:
            secondary = json.loads(target.secondary_languages_json or "[]")
        except (ValueError, TypeError):
            secondary = []
        return {
            "id": target.id,
            "kind": target.kind,
            "display_name": target.display_name,
            "primary_language": target.primary_language or "",
            "secondary_languages": secondary,
            "analysis_state": target.analysis_state,
            "analysis_state_message": getattr(target, "analysis_state_message", None) or "",
            "descriptor": descriptor,
            "applicable_mcp_servers": list(capability.get("applicable_mcp_servers") or []),
            "applicable_fuzzing_engines": list(capability.get("applicable_fuzzing_engines") or []),
            "applicable_strategies": list(capability.get("applicable_strategies") or []),
            "functions_of_interest": list(capability.get("functions_of_interest") or [])[:10],
            "attack_surface": list(capability.get("attack_surface") or [])[:10],
            "mitigations": capability.get("mitigations") or {},
            "mcp_handles": handles,
        }

    def _build_user_prompt(
        self,
        *,
        inv: VRInvestigationRecord,
        branch: VRInvestigationBranchRecord,
        case_state: ReasoningCaseState,
        turn: int,
        pending_operator_messages: list[dict[str, Any]] | None = None,
        cve_intel: list[dict[str, Any]] | None = None,
        target_snapshot: dict[str, Any] | None = None,
        tool_specs: dict[str, list[dict[str, Any]]] | None = None,
        prior_outcomes: list[dict[str, Any]] | None = None,
    ) -> str:
        """Render the per-turn user prompt.

        Compact + structured. Includes the investigation question,
        a target-snapshot block (kind, language, descriptor,
        applicable MCP servers, ranked candidates), the current case
        state model, turn counter, any pending operator messages
        (M3.R-6), an External-CVE-intel block, and a target-kind-
        filtered tool catalog. Render order is deliberate — target
        first so the agent grounds on what's actually being audited
        before it picks tools.
        """
        case_model = self._engine.render_case_model(case_state)
        secondary_refs = json.loads(inv.secondary_target_refs_json or "[]")
        secondary_str = (
            ", ".join(str(r) for r in secondary_refs) if secondary_refs else "(none)"
        )

        operator_section = _render_operator_messages_section(
            pending_operator_messages or [],
        )
        cve_intel_section = _render_cve_intel_section(cve_intel or [])
        target_section = _render_target_snapshot_section(target_snapshot or {})
        prior_submissions_section = _render_prior_submissions_section(
            prior_outcomes or [], inv.kind,
        )
        target_kind = (target_snapshot or {}).get("kind")

        return (
            f"# Investigation\n\n"
            f"Title: {inv.title}\n"
            f"Kind: {inv.kind}\n"
            f"Question: {inv.initial_question}\n"
            f"Primary target: {inv.target_id}\n"
            f"Secondary targets: {secondary_str}\n"
            f"Strategy: {inv.strategy_family}\n"
            f"Turn: {turn}\n"
            f"Branch: {branch.id} (persona: {branch.persona_voice or 'none'})\n"
            f"\n"
            f"{target_section}"
            f"{cve_intel_section}"
            f"# Current case state\n\n"
            f"{case_model}\n"
            f"\n"
            f"{operator_section}"
            f"{prior_submissions_section}"
            f"{_render_available_tools_section(target_kind, tool_specs)}"
            f"# Instruction\n\n"
            f"Produce the next reasoning turn as a JSON object per the "
            f"system prompt schema."
        )

    async def _consume_pending_operator_messages(
        self,
        turn_number: int,
    ) -> list[dict[str, Any]]:
        """Read + consume operator messages with at_turn IS NULL.

        Stamps at_turn=turn_number so subsequent turns don't re-read
        them. Returns the consumed messages' text + intent for prompt
        rendering. Engine messages are ignored — they're already in
        case_state via prior absorb() calls.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(
                    VRInvestigationMessageRecord.branch_id == self.branch_id,
                    VRInvestigationMessageRecord.sender_kind == SenderKind.OPERATOR.value,
                    VRInvestigationMessageRecord.at_turn.is_(None),
                )
                .order_by(VRInvestigationMessageRecord.created_at.asc())
            )).all()

            if not rows:
                return []

            consumed: list[dict[str, Any]] = []
            for row in rows:
                try:
                    payload = json.loads(row.payload_json or "{}")
                except json.JSONDecodeError:
                    payload = {}
                text = str(payload.get("text", "")).strip()
                consumed.append({
                    "id": row.id,
                    "text": text,
                    "intent": row.operator_intent or "unclassified",
                    "sender_id": row.sender_id,
                })
                row.at_turn = turn_number
                uow.session.add(row)
            await uow.commit()
            return consumed


def _render_target_snapshot_section(snapshot: dict[str, Any]) -> str:
    """Render the primary-target snapshot so the agent grounds on
    concrete artifact metadata instead of treating the target id as
    an opaque UUID.

    Without this block the agent saw only ``Primary target: <uuid>``
    and defaulted to ``ida_headless.list_binaries`` even when the
    target was a source repo already cloned + indexed by audit-mcp.
    The block surfaces:
      - kind + language
      - descriptor (repo_url / upload_filename / binary_id)
      - resolved MCP handles (audit_mcp_index_id / binary_id) so the
        agent passes the right id to the bridge
      - which MCP servers + fuzzing engines + strategies are
        APPLICABLE to this target kind
      - the top 5 ranked candidate functions, when capability_profile
        carries them
      - a hard rule that tells the agent which MCP family to use

    Returns "" when snapshot is empty so the caller concatenates
    unconditionally.
    """
    if not snapshot:
        return ""
    lines: list[str] = ["# Primary target snapshot\n"]
    kind = snapshot.get("kind") or "?"
    name = snapshot.get("display_name") or "?"
    lang = snapshot.get("primary_language") or ""
    sec_lang = snapshot.get("secondary_languages") or []
    state = snapshot.get("analysis_state") or "?"
    handles = snapshot.get("mcp_handles") or {}
    descriptor = snapshot.get("descriptor") or {}
    applicable_mcp = snapshot.get("applicable_mcp_servers") or []
    applicable_engines = snapshot.get("applicable_fuzzing_engines") or []
    applicable_strategies = snapshot.get("applicable_strategies") or []
    ranked = snapshot.get("functions_of_interest") or []
    attack_surface = snapshot.get("attack_surface") or []

    lines.append(f"kind: {kind}")
    lines.append(f"display_name: {name}")
    if lang:
        sec_str = (
            f" (secondary: {', '.join(sec_lang)})" if sec_lang else ""
        )
        lines.append(f"language: {lang}{sec_str}")
    lines.append(f"analysis_state: {state}")

    descriptor_keys = ("repo_url", "vulnerable_ref", "patched_ref",
                       "upload_filename", "binary_id", "download_url")
    descriptor_pairs = [
        f"{k}={descriptor[k]}" for k in descriptor_keys
        if descriptor.get(k)
    ]
    if descriptor_pairs:
        lines.append("descriptor: " + " · ".join(descriptor_pairs))

    if handles:
        handle_pairs = [f"{k}={v}" for k, v in handles.items() if v]
        if handle_pairs:
            lines.append("mcp_handles: " + " · ".join(handle_pairs))

    # Hard rule on which MCP family to use. This is the most
    # important line in the section — without it the LLM defaults
    # to whichever tool name catches its eye.
    rule = _mcp_family_rule_for_kind(kind, handles)
    if rule:
        lines.append("")
        lines.append(rule)

    if applicable_mcp:
        lines.append(f"applicable_mcp_servers: {', '.join(applicable_mcp)}")
    if applicable_engines:
        lines.append(f"applicable_fuzzing_engines: {', '.join(applicable_engines)}")
    if applicable_strategies:
        lines.append(f"applicable_strategies: {', '.join(applicable_strategies)}")

    if ranked:
        lines.append("")
        lines.append("ranked candidate functions (top 5 by composite score):")
        for entry in ranked[:5]:
            entry_name = (
                entry.get("name") or entry.get("function_name") or "?"
            )
            score = entry.get("score")
            score_str = f"score={score:.2f}" if isinstance(score, (int, float)) else ""
            reasons = entry.get("reasons") or []
            reason_str = "; ".join(str(r) for r in reasons[:2])
            lines.append(
                f"  - {entry_name}"
                + (f" ({score_str})" if score_str else "")
                + (f" — {reason_str}" if reason_str else "")
            )

    if attack_surface:
        lines.append("")
        lines.append("attack_surface entries (top 5):")
        for entry in attack_surface[:5]:
            ek = entry.get("kind") or "?"
            en = entry.get("name") or "?"
            loc = entry.get("location") or ""
            sev = entry.get("severity_hint") or ""
            extras = []
            if loc:
                extras.append(f"@{loc}")
            if sev:
                extras.append(f"sev={sev}")
            lines.append(
                f"  - [{ek}] {en}"
                + (" " + " ".join(extras) if extras else "")
            )

    lines.append("")
    return "\n".join(lines) + "\n"


def _mcp_family_rule_for_kind(
    kind: str | None, handles: dict[str, Any],
) -> str:
    """Emit a one-line rule telling the agent which MCP server to use.

    Picks the right family based on target kind + the handles that
    actually exist. This is what stops the agent from calling
    ``ida_headless.list_binaries`` when the target is a source repo
    that's already been indexed by audit-mcp.
    """
    k = (kind or "").lower()
    if k == "source_repo":
        idx = handles.get("audit_mcp_index_id")
        if idx:
            return (
                f"RULE: this is a source repo. Use **audit_mcp** tools "
                f"with `index_id=\"{idx}\"`. Do NOT call ida_headless — "
                f"the target was never opened in IDA."
            )
        return (
            "RULE: this is a source repo. Use **audit_mcp** tools. "
            "Do NOT call ida_headless. If you need an index_id, the "
            "target's ingestion may not be complete (analysis_state)."
        )
    if k in {
        "native_binary", "apk", "ipa", "jar", "dotnet_assembly",
        "kernel_image", "kernel_module", "hypervisor_image",
    }:
        bid = handles.get("binary_id")
        if bid:
            return (
                f"RULE: this is a binary target. Use **ida_headless** "
                f"tools with `binary_id=\"{bid}\"`. Do NOT call audit_mcp."
            )
        return (
            "RULE: this is a binary target. Use **ida_headless** "
            "tools. Do NOT call audit_mcp."
        )
    return ""



def _render_cve_intel_section(entries: list[dict[str, Any]]) -> str:
    """Render every CVE id mentioned in the operator's question with
    its resolved intel status (08_FRONTEND_UX.md §2.4).

    The reasoning agent uses this to distinguish:
      - ``status=found``     → real NVD/EPSS/KEV data — consume it
      - ``status=not_found`` → no aggregator has the CVE — do NOT
                                invent details; surface and ask
      - ``status=error``     → transport failure — treat as unknown

    Returns "" when no entries — caller concatenates unconditionally.
    """
    if not entries:
        return ""
    lines: list[str] = ["# External CVE intel\n"]
    for entry in entries:
        cve_id = entry.get("cve_id", "?")
        status = entry.get("status", "unknown")
        lines.append(f"## {cve_id} — status: {status}")
        if status == "found":
            desc = (entry.get("description") or "").strip()
            if desc:
                # Trim long descriptions; the agent needs the gist,
                # not the full advisory body.
                if len(desc) > 800:
                    desc = desc[:797] + "..."
                lines.append(f"description: {desc}")
            cwe_ids = entry.get("cwe_ids") or []
            if cwe_ids:
                lines.append(f"cwe_ids: {', '.join(cwe_ids)}")
            cvss = entry.get("cvss_score")
            sev = entry.get("base_severity")
            if cvss is not None or sev:
                lines.append(
                    f"cvss: {cvss if cvss is not None else 'n/a'} "
                    f"({sev or 'unrated'})",
                )
            if entry.get("kev_listed"):
                kev_date = entry.get("kev_date_added") or ""
                lines.append(
                    "**kev_listed: yes** — CISA flagged as actively "
                    "exploited in the wild"
                    + (f" (added {kev_date})" if kev_date else "")
                )
            epss_pct = entry.get("epss_percentile")
            epss = entry.get("epss_score")
            if epss_pct is not None or epss is not None:
                lines.append(
                    f"epss: score={epss if epss is not None else 'n/a'} "
                    f"percentile={epss_pct if epss_pct is not None else 'n/a'}",
                )
            affected = entry.get("affected_products") or []
            if affected:
                preview = affected[:6]
                more = f" (+{len(affected) - 6} more)" if len(affected) > 6 else ""
                lines.append(f"affected: {', '.join(preview)}{more}")
            notes = entry.get("notes") or []
            for note in notes[:4]:
                lines.append(f"note: {note}")
        else:
            err = (entry.get("error") or "").strip()
            if err:
                lines.append(f"reason: {err}")
            lines.append(
                "RULE: do not invent details for this CVE. Cite the "
                "missing intel in your rationale and ask the operator "
                "(via an AssessmentReport outcome) if the id is "
                "load-bearing for the investigation.",
            )
        lines.append("")
    return "\n".join(lines) + "\n"



def _render_operator_messages_section(messages: list[dict[str, Any]]) -> str:
    """Render pending operator messages as a markdown block for the prompt.

    Returns "" when no messages — caller concatenates unconditionally.
    Each message is shown with its intent classification (defaults to
    'unclassified' when the message_classifier hasn't tagged it yet).
    """
    if not messages:
        return ""
    lines: list[str] = ["# Operator messages (new — consider before acting)\n"]
    for entry in messages:
        intent = entry.get("intent") or "unclassified"
        text = entry.get("text") or ""
        lines.append(f"- [intent: {intent}] {text}")
    lines.append("")  # trailing blank for spacing before next section
    return "\n".join(lines) + "\n"


_SOURCE_REPO_KINDS = frozenset({"source_repo"})
_BINARY_KINDS = frozenset({
    "native_binary", "apk", "ipa", "jar", "dotnet_assembly",
    "kernel_image", "kernel_module", "hypervisor_image",
})


def _applicable_servers_for_kind(target_kind: str | None) -> set[str]:
    """Return the MCP server ids the agent should consider given the
    target's kind. Source repos resolve via audit-mcp; binary kinds
    via ida_headless. Unknown / mixed kinds default to BOTH so the
    agent isn't locked out of either path.
    """
    k = (target_kind or "").lower()
    if k in _SOURCE_REPO_KINDS:
        return {"audit_mcp"}
    if k in _BINARY_KINDS:
        return {"ida_headless"}
    return set(KNOWN_TOOLS.keys())


async def _fetch_tool_specs(
    target_kind: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch JSON-Schema-derived tool specs from the MCP bridges.

    Returns ``{server_id: [spec, ...]}`` only for servers applicable
    to ``target_kind`` so we don't pay the catalog fetch for a server
    the agent isn't allowed to call. This helper itself does no
    caching; the bridges back each call with a class-level cache so
    the second invocation is a dict lookup, not an HTTP round-trip.
    """
    applicable = _applicable_servers_for_kind(target_kind)
    out: dict[str, list[dict[str, Any]]] = {}
    if "audit_mcp" in applicable:
        out["audit_mcp"] = await AuditMcpBridgeTool().list_tool_specs()
    if "ida_headless" in applicable:
        out["ida_headless"] = await IDABridgeTool().list_tool_specs()
    return out


def _format_param(param: dict[str, Any]) -> str:
    """Render one parameter as ``name: type [required]`` or
    ``name: type = <default>`` so the agent sees exact call shape.
    """
    name = param.get("name", "?")
    ptype = param.get("type", "any")
    if param.get("required"):
        return f"{name}: {ptype} [required]"
    if "default" in param:
        default = param["default"]
        # json.dumps handles strings/numbers/bools/null + escapes;
        # truncate over-long defaults so a paragraph-sized default
        # doesn't wreck the signature.
        rendered = json.dumps(default)
        if len(rendered) > 60:
            rendered = rendered[:57] + "..."
        return f"{name}: {ptype} = {rendered}"
    return f"{name}: {ptype}"


def _render_available_tools_section(
    target_kind: str | None = None,
    tool_specs: dict[str, list[dict[str, Any]]] | None = None,
) -> str:
    """Render the catalog of MCP tools the engine may invoke this turn.

    When ``tool_specs`` carries per-server schemas (fetched live from
    each MCP server's ``GET /tools``), every applicable tool renders
    as ``server.name(p1: type [required], p2: type = default)`` so
    the agent sees the exact parameter names + types it must use.
    When schemas are missing (catalog fetch failed), falls back to a
    name-only listing from ``KNOWN_TOOLS`` so the prompt still works.

    Servers irrelevant to the target's kind are SUPPRESSED with a
    short note instead of listed — the agent kept choosing
    ida_headless.list_binaries for a source_repo target because the
    catalog showed every server unconditionally. Filtering at render
    time prevents the wrong tool family from ever being the obvious
    pick.
    """
    specialized = set(specialized_tools())
    applicable = _applicable_servers_for_kind(target_kind)
    specs_by_server = tool_specs or {}
    parts: list[str] = ["# Available tools\n"]
    if target_kind:
        parts.append(
            f"\nTarget kind: `{target_kind}` — only servers applicable "
            f"to this kind are listed below. Use the **exact** "
            f"parameter names shown in each signature; the bridge "
            f"rejects unknown kwargs.\n",
        )
    for server in sorted(KNOWN_TOOLS):
        if server not in applicable:
            parts.append(
                f"\n## {server} (NOT APPLICABLE for target kind "
                f"`{target_kind}`)\n\n",
            )
            parts.append(
                f"- skipped: {server} operates on a different target "
                f"family. Do not invoke its tools.\n",
            )
            continue

        live_specs = specs_by_server.get(server) or []
        if live_specs:
            parts.append(
                f"\n## {server} ({len(live_specs)} tools — live schema)\n\n",
            )
            for spec in sorted(live_specs, key=lambda s: s.get("name", "")):
                tool_name = spec.get("name", "?")
                full = f"{server}.{tool_name}"
                marker = " [structured]" if full in specialized else ""
                params = spec.get("params") or []
                signature = ", ".join(_format_param(p) for p in params)
                parts.append(f"- `{full}({signature})`{marker}\n")
            parts.append("\n")
        else:
            # Catalog fetch failed — fall back to a name-only listing
            # using the static KNOWN_TOOLS registry. Agent will still
            # know which tools exist; it just won't see signatures.
            tool_names = sorted(KNOWN_TOOLS[server])
            parts.append(
                f"\n## {server} ({len(tool_names)} tools — "
                f"schema unavailable)\n\n",
            )
            for name in tool_names:
                full = f"{server}.{name}"
                marker = " [structured]" if full in specialized else ""
                parts.append(f"- `{full}`{marker}\n")
            parts.append("\n")
    return "".join(parts)



def _decode_case_state(raw_json: str | None) -> ReasoningCaseState:
    if not raw_json:
        return ReasoningCaseState()
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return ReasoningCaseState()
    try:
        return ReasoningCaseState.model_validate(data)
    except (ValueError, TypeError):
        return ReasoningCaseState()


def _encode_case_state(state: ReasoningCaseState) -> str:
    return json.dumps(state.model_dump(mode="json"))


def _decision_to_message_payload(
    decision: ReasoningTurnDecision,
) -> tuple[PayloadKind, dict[str, Any]]:
    """Map a ReasoningTurnDecision into a typed message payload.

    The mapping is intentionally narrow for v0.3 v1:
      - tool_run    → TOOL_CALL payload with command/script_content
      - submit      → OUTCOME_PENDING payload with answer + confidence
      - everything else → TEXT payload with reasoning + expected_observation
    Richer payload kinds (graph_view, taint_flow, etc.) land in M3.R-3
    when MCP adapters produce them.
    """
    if decision.action == "tool_run":
        return PayloadKind.TOOL_CALL, {
            "command": decision.command or "",
            "script_content": decision.script_content or "",
            "reasoning": decision.reasoning,
            "expected_observation": decision.expected_observation,
        }
    if decision.action == "submit":
        return PayloadKind.OUTCOME_PENDING, {
            "answer": decision.answer or "",
            "confidence": (
                decision.confidence if decision.confidence else "unknown"
            ),
            "reasoning": decision.reasoning,
            "provenance": decision.provenance.model_dump(mode="json"),
        }
    return PayloadKind.TEXT, {
        "text": decision.reasoning,
        "expected_observation": decision.expected_observation,
    }


def _terminal_outcome_kind(decision: ReasoningTurnDecision) -> OutcomeKind:
    """Pick a terminal outcome kind from a submit decision.

    v0.3 v1 has a tiny dispatch: confidence >= strong + contract suggests
    DirectFinding -> DirectFinding; otherwise AssessmentReport. Real
    routing logic lands in M3.R-4 outcome_router.
    """
    if decision.confidence in {"strong", "exact"}:
        return OutcomeKind.DIRECT_FINDING
    return OutcomeKind.ASSESSMENT_REPORT


def _to_outcome_confidence(decision: ReasoningTurnDecision) -> OutcomeConfidence:
    if decision.confidence:
        return OutcomeConfidence(decision.confidence)
    return OutcomeConfidence.UNKNOWN


def _outcome_payload(decision: ReasoningTurnDecision) -> dict[str, Any]:
    return {
        "answer": decision.answer or "",
        "reasoning": decision.reasoning,
        "provenance": decision.provenance.model_dump(mode="json"),
        "contract": (
            decision.contract.model_dump(mode="json") if decision.contract else None
        ),
    }


def _load_prompt(strategy_family: str) -> str:
    """Load the system prompt for a strategy family.

    v0.3 v1 ships only ``system_audit.md``; other strategy families
    fall through to it for now. Per-family prompts land as needed.
    """
    candidate = _PROMPT_DIR / f"system_{strategy_family.rsplit('.', 1)[-1]}.md"
    if not candidate.exists():
        candidate = _PROMPT_DIR / "system_audit.md"
    if not candidate.exists():
        raise VulnResearcherError(f"prompt file missing: {candidate}")
    return candidate.read_text(encoding="utf-8")


# Resolves Pydantic forward refs when this module is imported standalone.
ReasoningContract.model_rebuild()

"""VRNarrativeAgent -- long-form vulnerability-research writeup.

Separate artifact from the structured :class:`SynthesisAgent`. Where
synthesis emits the audit-committee card (headline verdict, points of
agreement / disagreement, unresolved questions, recommended next
actions), the narrative tells the whole investigation story from the
persona panel's first hypotheses through every tool-driven audit step
to the final verdict in a chosen voice.

Stored at ``payload["investigation_narrative"]`` on the canonical
outcome row alongside (never replacing) ``payload["panel_summary"]``
from the synthesis path. The two coexist; the narrative does not
overwrite the structured fields.

Canonical outcome resolution: ``inv.primary_outcome_id`` when set,
otherwise the earliest :class:`VRInvestigationOutcomeRecord` by
``created_at`` -- the same row synthesis and the claim verifier
already write against.

Reads four sources to build the chronology:
  * ``panel_contributions`` on the canonical outcome (per-persona
    terminal submission + reasoning).
  * ``panel_summary`` (if synthesis has already produced the
    consolidated verdict, the narrative leans on it as the spine).
  * ``verifier_report`` (if the claim verifier has already run).
  * :class:`VRInvestigationBranchRecord` rows -- the persona panel
    roster (persona_voice, turn_count, status).
  * :class:`VRInvestigationMessageRecord` rows -- the chronological
    conversation, summarized one line per row.

RFC #208 P2 (closes #112 + #137): the shared skeleton lives in
:class:`aila.platform.agents.narrative_agent.NarrativeAgentBase`.
This module keeps only the VR-specific query rules, the VR
message-payload summarizer, and the prompt registry pointed at the
module-local ``prompts/system_narrative.md``.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.platform.agents.narrative_agent import (
    NarrativeAgentBase,
    NarrativeLength,
    NarrativeOptions,
    NarrativePromptContext,
    NarrativeResponse,
    NarrativeTone,
)
from aila.platform.llm.sanitize import sanitize_input
from aila.platform.prompts import PromptRegistry
from aila.platform.uow import UnitOfWork

__all__ = [
    "NarrativeLength",
    "NarrativeOptions",
    "NarrativeResponse",
    "NarrativeTone",
    "VRNarrativeAgent",
]

_log = logging.getLogger(__name__)

_PROMPT_DIR = Path(__file__).parent / "prompts"
_PROMPT_REGISTRY = PromptRegistry(
    _PROMPT_DIR,
    module="vr",
    fallback_base="system_narrative.md",
)


def _load_system_prompt() -> str:
    """Return the VR narrative system prompt from the registry.

    Kept module-local because :mod:`aila.modules.vr.agents.vuln_researcher`
    lazily imports it for RFC-09 rule-58 migration seeding.
    """
    return _PROMPT_REGISTRY.load("narrative")


def _summarize_message_payload(
    payload_kind: str,
    payload: dict[str, Any],
) -> str:
    """Compress one VR message payload to a single line, per payload_kind.

    Keeps the tool name for tool_call rows, the reasoning head for text
    rows, the address / function name for decompiled_function rows, and
    the source-sink pair for taint_flow rows. Falls back to the first
    200 chars of the JSON dump when the payload doesn't match any known
    shape. Never raises: a malformed payload becomes an empty summary
    string so the chronology row still lands in the prompt.
    """
    if not isinstance(payload, dict):
        return str(payload)[:200]
    if payload_kind == "tool_call":
        command_raw = payload.get("command")
        try:
            cmd = (
                json.loads(command_raw)
                if isinstance(command_raw, str) and command_raw.strip()
                else (command_raw or {})
            )
        except (ValueError, TypeError):
            cmd = {}
        if not isinstance(cmd, dict):
            cmd = {}
        tool = cmd.get("tool") or ""
        args = cmd.get("args") or cmd.get("arguments") or {}
        reasoning = (payload.get("reasoning") or "")[:200]
        arg_head = json.dumps(args)[:160] if args else ""
        parts: list[str] = []
        if tool:
            parts.append(f"tool={tool}")
        if arg_head:
            parts.append(f"args={arg_head}")
        if reasoning:
            parts.append(f"why={reasoning}")
        return "; ".join(parts) if parts else json.dumps(payload)[:200]
    if payload_kind == "text":
        text = payload.get("text") or payload.get("reasoning") or ""
        return str(text)[:400]
    if payload_kind == "decompiled_function":
        name = payload.get("function_name") or payload.get("name") or ""
        addr = payload.get("address") or ""
        head = (payload.get("content") or payload.get("body") or "")[:120]
        pieces: list[str] = []
        if name:
            pieces.append(f"function={name}")
        if addr:
            pieces.append(f"address={addr}")
        if head:
            pieces.append(f"body_head={head}")
        return "; ".join(pieces) if pieces else json.dumps(payload)[:200]
    if payload_kind == "taint_flow":
        source = payload.get("source") or ""
        sink = payload.get("sink") or ""
        flow_count = payload.get("flow_count") or payload.get("count") or ""
        pieces = []
        if source:
            pieces.append(f"source={source}")
        if sink:
            pieces.append(f"sink={sink}")
        if flow_count:
            pieces.append(f"flows={flow_count}")
        return "; ".join(pieces) if pieces else json.dumps(payload)[:200]
    if payload_kind == "outcome_pending":
        answer = (payload.get("answer") or "")[:240]
        confidence = payload.get("confidence") or ""
        return f"confidence={confidence}; answer_head={answer}"
    return json.dumps(payload)[:200]


def _render_branch_roster_section(
    branch_roster: list[dict[str, Any]],
) -> str:
    """VR-specific persona-panel roster block, inserted before the
    message chronology."""
    if not branch_roster:
        return ""
    lines: list[str] = [f"## Persona panel ({len(branch_roster)} branches)"]
    for b in branch_roster:
        persona = sanitize_input(str(b.get("persona_voice") or "")).upper()
        branch_id = str(b.get("branch_id") or "")[:8]
        turn_count = b.get("turn_count") or 0
        branch_status = sanitize_input(str(b.get("status") or ""))
        lines.append(
            f"- {persona} (branch={branch_id}, turns={turn_count}, "
            f"status={branch_status})",
        )
    lines.append("")
    return "\n".join(lines)


def _render_message_chronology_section(
    messages: list[dict[str, Any]],
) -> str:
    """VR message chronology block. Cap at 400 rows to keep the prompt
    budget bounded; the truncation is called out explicitly."""
    if not messages:
        return ""
    lines: list[str] = [
        f"## Message chronology ({len(messages)} rows; chronological order)",
    ]
    for m in messages[:400]:
        line = (
            f"- [{sanitize_input(str(m.get('created_at') or ''))}] "
            f"kind={sanitize_input(str(m.get('payload_kind') or ''))} "
            f"sender={sanitize_input(str(m.get('sender_kind') or ''))} "
            f"branch={(m.get('branch_id') or '')[:8]} "
            f"turn={m.get('at_turn') or 0} "
            f"-- {sanitize_input(str(m.get('summary') or ''))[:240]}"
        )
        lines.append(line)
    if len(messages) > 400:
        lines.append(
            f"_(... {len(messages) - 400} more message rows "
            "truncated to keep prompt budget in check)_",
        )
    lines.append("")
    return "\n".join(lines)


class VRNarrativeAgent(
    NarrativeAgentBase[VRInvestigationRecord, VRInvestigationOutcomeRecord],
):
    """LLM-backed long-form vulnerability-research writeup for one
    investigation.
    """

    _TASK_TYPE = "vulnerability_research.narrative"
    _LOG_LABEL = "vr narrative"

    @property
    def _prompt_registry(self) -> PromptRegistry:
        return _PROMPT_REGISTRY

    async def _load_investigation(
        self, uow: UnitOfWork,
    ) -> VRInvestigationRecord | None:
        return (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == self.investigation_id,
            ),
        )).first()

    async def _load_canonical_outcome(
        self,
        uow: UnitOfWork,
        inv: VRInvestigationRecord,
    ) -> VRInvestigationOutcomeRecord | None:
        """Contract: prefer ``inv.primary_outcome_id`` when set; fall
        back to the earliest outcome by ``created_at``. This is the
        same row the synthesis agent, the claim verifier, and the
        operator UI all treat as the investigation's headline
        outcome."""
        if inv.primary_outcome_id:
            row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == inv.primary_outcome_id,
                ),
            )).first()
            if row is not None:
                return row
            # primary_outcome_id pointing at a deleted row is
            # anomalous; fall through so the narrative still produces
            # something.
            _log.debug(
                "narrative canonical: primary_outcome_id=%s missing "
                "for inv=%s -- falling back to earliest outcome",
                inv.primary_outcome_id, self.investigation_id,
            )
        return (await uow.session.exec(
            _select(VRInvestigationOutcomeRecord)
            .where(
                VRInvestigationOutcomeRecord.investigation_id
                == self.investigation_id,
            )
            .order_by(VRInvestigationOutcomeRecord.created_at.asc())
            .limit(1),
        )).first()

    async def _reload_canonical_locked(
        self, uow: UnitOfWork, canonical_id: str,
    ) -> VRInvestigationOutcomeRecord | None:
        return (await uow.session.exec(
            _select(VRInvestigationOutcomeRecord)
            .where(VRInvestigationOutcomeRecord.id == canonical_id)
            .with_for_update(),
        )).first()

    async def _build_prompt_context(
        self,
        uow: UnitOfWork,
        inv: VRInvestigationRecord,
        canonical: VRInvestigationOutcomeRecord,
        canonical_payload: dict[str, Any],
    ) -> NarrativePromptContext:
        """Assemble the VR-specific prompt context: spine (title,
        question, verdict, verifier report, panel summary, panel
        contributions) plus the branch-roster + message-chronology
        chronology sections."""
        contributions = canonical_payload.get("panel_contributions") or []
        panel_summary = canonical_payload.get("panel_summary") or {}
        verifier_report = canonical_payload.get("verifier_report") or {}

        branch_rows = (await uow.session.exec(
            _select(VRInvestigationBranchRecord)
            .where(
                VRInvestigationBranchRecord.investigation_id
                == self.investigation_id,
            )
            .order_by(VRInvestigationBranchRecord.created_at.asc()),
        )).all()
        branch_roster: list[dict[str, Any]] = [
            {
                "branch_id": b.id,
                "persona_voice": b.persona_voice or "unspecified",
                "turn_count": b.turn_count or 0,
                "status": b.status or "",
            }
            for b in branch_rows
        ]

        message_rows = (await uow.session.exec(
            _select(VRInvestigationMessageRecord)
            .where(
                VRInvestigationMessageRecord.investigation_id
                == self.investigation_id,
            )
            .order_by(VRInvestigationMessageRecord.created_at.asc()),
        )).all()
        message_chronology: list[dict[str, Any]] = []
        for m in message_rows:
            try:
                pl = json.loads(m.payload_json or "{}")
            except (ValueError, TypeError):
                pl = {}
            message_chronology.append({
                "payload_kind": m.payload_kind or "",
                "sender_kind": m.sender_kind or "",
                "branch_id": m.branch_id or "",
                "at_turn": m.at_turn or 0,
                "created_at": (
                    m.created_at.isoformat() if m.created_at else ""
                ),
                "summary": _summarize_message_payload(
                    m.payload_kind or "", pl,
                ),
            })

        verdict = canonical.outcome_kind or ""

        chronology_sections: list[str] = []
        roster_section = _render_branch_roster_section(branch_roster)
        if roster_section:
            chronology_sections.append(roster_section)
        chrono_section = _render_message_chronology_section(message_chronology)
        if chrono_section:
            chronology_sections.append(chrono_section)

        return NarrativePromptContext(
            investigation_id=self.investigation_id,
            options=self.options,
            inv_question=inv.initial_question or "",
            inv_title=inv.title or "",
            verdict=verdict or "",
            verifier_report=verifier_report if verifier_report else None,
            panel_summary=panel_summary if panel_summary else None,
            panel_contributions=list(contributions)
            if isinstance(contributions, list) else [],
            chronology_sections=chronology_sections,
        )

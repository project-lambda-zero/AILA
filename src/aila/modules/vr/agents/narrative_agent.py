"""NarrativeAgent -- long-form vulnerability-research writeup.

Separate artifact from the structured :class:`SynthesisAgent`. Where
synthesis emits the audit-committee card (headline verdict, points of
agreement / disagreement, unresolved questions, recommended next
actions), the narrative tells the whole investigation story from the
persona panel's first hypotheses through every tool-driven audit step
to the final verdict in a chosen voice: blog post, incident writeup,
RE thriller, academic paper, or casual community-post voice.

Stored at ``payload["investigation_narrative"]`` on the canonical
outcome row alongside (never replacing) ``payload["panel_summary"]``
from the synthesis path. The two coexist; the narrative does not
overwrite the structured fields.

Canonical outcome resolution: ``inv.primary_outcome_id`` when set,
otherwise the earliest ``VRInvestigationOutcomeRecord`` by
``created_at`` -- the same row synthesis and the claim verifier
already write against.

Reads four sources to build the chronology:
  * ``panel_contributions`` on the canonical outcome (per-persona
    terminal submission + reasoning, populated by the reasoning
    loop's ``land_panel_outcomes`` on quorum).
  * ``panel_summary`` (if synthesis has already produced the
    consolidated verdict, the narrative leans on it as the spine).
  * ``verifier_report`` (if the claim verifier has already run;
    surfaces confirmed / refuted verdicts).
  * ``VRInvestigationBranchRecord`` rows -- the persona panel roster
    (persona_voice, turn_count, status).
  * ``VRInvestigationMessageRecord`` rows -- the chronological
    conversation, summarized one line per row (tool_call / text /
    decompiled_function / taint_flow are the payload_kinds the VR
    reasoning loop emits).

The schema is loose on purpose: one long markdown string plus a few
metadata fields. Voice / length is enforced via the system prompt,
not the schema -- the narrative is meant to be read top-to-bottom by
a human, not parsed by another LLM.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import select as _select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.contracts import utc_now
from aila.platform.llm.errors import BudgetExceededError, LLMError
from aila.platform.llm.sanitize import sanitize_input, sanitize_output
from aila.platform.prompts import PromptRegistry
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

_PROMPT_DIR = Path(__file__).parent / "prompts"
_PROMPT_REGISTRY = PromptRegistry(
    _PROMPT_DIR,
    module="vr",
    fallback_base="system_narrative.md",
)


def _load_system_prompt() -> str:
    """Return the VR narrative system prompt from the registry.

    RFC-09 criterion 1: the body lives in ``prompts/system_narrative.md``
    resolved through :class:`PromptRegistry` so cost / seal rows carry
    the resolved ``prompt_content_hash`` + ``prompt_version`` stamp
    instead of a NULL attribution.
    """
    return _PROMPT_REGISTRY.load("narrative")

__all__ = [
    "NarrativeAgent",
    "NarrativeLength",
    "NarrativeOptions",
    "NarrativeResponse",
    "NarrativeTone",
]

_log = logging.getLogger(__name__)


def _build_narrative_payload(
    title: str,
    body: str,
    chapter_outline: list[str],
    tone: str,
    length: str,
) -> dict[str, Any]:
    """Build the persisted investigation_narrative dict, XSS-sanitized on persist.

    The narrative is LLM output over untrusted case data; sanitize_output
    strips script / js / handler / iframe patterns and control chars
    before the text lands in the durable payload, and records how many
    patterns were stripped for the evidence lineage.
    """
    title_clean, title_stripped = sanitize_output(title)
    body_clean, body_stripped = sanitize_output(body)
    outline_clean: list[str] = []
    outline_stripped = 0
    for chapter in chapter_outline:
        cleaned, n = sanitize_output(chapter)
        outline_clean.append(cleaned)
        outline_stripped += n
    words = len(body_clean.split())
    return {
        "title": title_clean,
        "body": body_clean,
        "chapter_outline": outline_clean,
        "tone_used": tone,
        "length_used": length,
        "narrative_words": words,
        "generated_at": utc_now().isoformat(),
        "sanitizer_counts": {
            "title": title_stripped,
            "body": body_stripped,
            "chapter_outline": outline_stripped,
        },
    }


NarrativeTone = Literal[
    "blog",
    "incident_report",
    "thriller",
    "academic",
    "casual",
]
NarrativeLength = Literal["short", "standard", "long"]


@dataclass(slots=True)
class NarrativeOptions:
    """Knobs for one narrative run."""

    force: bool = False
    """Re-run even when ``investigation_narrative`` already exists on
    the canonical payload. Manual endpoint defaults True; any future
    automated call site defaults False to preserve a previously
    generated narrative."""

    tone: NarrativeTone = "blog"
    length: NarrativeLength = "standard"
    operator_focus: str = ""


class NarrativeResponse(BaseModel):
    """LLM-emitted narrative. Loose schema; the body is one long
    markdown string the renderer surfaces verbatim.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        min_length=1,
        max_length=400,
        description=(
            "Headline / writeup title. 5-15 words. Punchy enough to "
            "stand alone on a research index page."
        ),
    )
    body: str = Field(
        min_length=4000,
        max_length=60000,
        description=(
            "The full narrative as a single markdown string. MUST be "
            "the complete writeup, not a placeholder or intro. Every "
            "section listed in ``chapter_outline`` MUST appear as a "
            "``##`` header in the body with its full content beneath; "
            "the outline is the plan, the body is the delivery. A "
            "submission where ``body`` is just the intro paragraph + "
            "a promise to cover the outline is a failure. Targets: "
            "short=1500-2500 words, standard=3500-5500 words, "
            "long=8000-15000 words. Tells the investigation's story "
            "from the initial question through the persona panel's "
            "competing hypotheses to the final verdict."
        ),
    )
    chapter_outline: list[str] = Field(
        default_factory=list,
        max_length=32,
        description=(
            "One-line summary per section header in ``body``. Lets "
            "the UI render a clickable table of contents without "
            "re-parsing the markdown."
        ),
    )
    tone_used: NarrativeTone = "blog"
    """Echoed back from the request so the UI can render the tone
    badge without remembering the request shape."""


_TONE_DIRECTIVES: dict[str, str] = {
    "blog": (
        "Mid-friction technical-blog voice. Second-person asides are "
        "fine (``If you've ever chased a taint flow through eight "
        "layers of dispatch, you know...``). Show the panel's thought "
        "process: false starts, dead ends, the moment a hypothesis "
        "clicked. Technical detail throughout, but readable to a "
        "reverse engineer or security researcher one or two levels "
        "less specialized than the panel personas."
    ),
    "incident_report": (
        "Vulnerability-research report voice. Chronological. Every "
        "claim cites the source (persona / tool call / decompiled "
        "function / taint path). No flourishes, no narrative tension "
        "-- the audience is the next reviewer who needs to validate "
        "the finding and pivot to remediation. Structure: initial "
        "question -> scope -> audit steps -> findings -> "
        "verifier verdict -> recommended actions."
    ),
    "thriller": (
        "Pulpy reverse-engineering long-read voice. Tension and "
        "reveal beats; treat the target codebase like a locked room, "
        "the panel like investigators walking through it. Section "
        "headers can be moody (``The Silent Sink``, ``Halvar's "
        "Doubt``) but every technical claim must still be precise "
        "-- this is RE writing for a research blog, not fiction. "
        "Name specific file:line citations, decompiled functions, "
        "and taint paths verbatim."
    ),
    "academic": (
        "Conference-paper voice. Passive constructions, dense "
        "citation, structured into abstract -> background -> method "
        "-> findings -> discussion -> future work. Each hypothesis "
        "cites the persona that surfaced it plus the tool evidence "
        "that supported or refuted it. Hedge appropriately on "
        "unresolved questions."
    ),
    "casual": (
        "Discord / Mastodon thread voice. Lower formality, "
        "contractions, occasional emoji are fine (sparingly). Still "
        "technically precise -- the audience is other vuln-research "
        "folks, not a general public. Length runs naturally to "
        "~5-15 paragraphs."
    ),
}


_LENGTH_DIRECTIVES: dict[str, str] = {
    "short": (
        "Target ~1500-2500 words. 5-7 sections. Cover every distinct "
        "finding the panel surfaced (every function reviewed, every "
        "sink identified, every taint path traced, every hypothesis "
        "raised, every CVE mentioned, every persona-driven "
        "disagreement) with one to two sentences per finding -- "
        "short means compact, NOT incomplete. Skip the turn-by-turn "
        "chronology but never skip a finding."
    ),
    "standard": (
        "Target ~3500-5500 words. 8-12 sections. Cover every "
        "panel-mentioned function, sink, taint path, hypothesis, CVE "
        "reference, and cross-persona disagreement with two to four "
        "sentences each: name WHAT was investigated, WHERE it was "
        "found (file:line / function name), WHO surfaced it (which "
        "persona), WHY it matters (why the panel argued about it). "
        "Cover the major audit phases (triage -> hypothesis "
        "generation -> tool-driven audit -> cross-persona review -> "
        "verdict). A reader new to the target must be able to "
        "reconstruct every concrete claim from this writeup alone."
    ),
    "long": (
        "Target ~8000-15000 words. 12-25 sections. The full archival "
        "writeup. Every distinct hypothesis gets its own paragraph "
        "or sub-section. Name the specific tool calls that drove "
        "each pivot (``halvar called audit_mcp.taint_paths_to(name="
        "'sink') and got 3 flows through parse_header``). Quote "
        "persona-level reasoning verbatim wherever it captures a "
        "key insight. Surface every rejected hypothesis and WHY it "
        "was rejected (sibling review, verifier refutation, missing "
        "evidence). Enumerate EVERY function read, EVERY sink "
        "traced, EVERY taint path, EVERY decompiled routine, EVERY "
        "CVE reference, EVERY hypothesis (live and rejected), EVERY "
        "cross-persona disagreement, EVERY variant-hunt order the "
        "panel raised. Nothing the panel surfaced may be silently "
        "dropped. If the panel raised 14 hypotheses across four "
        "branches, all 14 appear; if three sinks were audited, all "
        "three get their own paragraph or sub-section. Use the "
        "available 60000-char budget; this is the canonical "
        "publish-ready writeup an author would polish lightly "
        "before shipping."
    ),
}


class NarrativeAgent:
    """LLM-backed long-form vulnerability-research writeup for one
    investigation.
    """

    _TASK_TYPE = "vulnerability_research.narrative"

    def __init__(
        self,
        investigation_id: str,
        *,
        options: NarrativeOptions | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.options: NarrativeOptions = options or NarrativeOptions()

    async def _load_canonical_outcome(
        self,
        uow: UnitOfWork,
        inv: VRInvestigationRecord,
    ) -> VRInvestigationOutcomeRecord | None:
        """Resolve the canonical outcome row for this investigation.

        Contract: prefer ``inv.primary_outcome_id`` when set; fall back
        to the earliest outcome by ``created_at``. This is the same row
        the synthesis agent, the claim verifier, and the operator UI
        all treat as the investigation's headline outcome.
        """
        if inv.primary_outcome_id:
            row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == inv.primary_outcome_id,
                ),
            )).first()
            if row is not None:
                return row
            # primary_outcome_id pointing at a deleted row is
            # anomalous; fall through to the earliest-outcome path so
            # the narrative still produces something.
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

    async def run(self) -> dict[str, Any]:
        """Generate one narrative writeup and persist it under
        ``payload["investigation_narrative"]`` on the canonical outcome.

        Returns a dict with ``status`` + ``canonical_outcome_id`` +
        ``narrative_words`` (word count for the operator log).
        """
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                ),
            )).first()
            if inv is None:
                return {"status": "skipped", "reason": "investigation_not_found"}

            canonical = await self._load_canonical_outcome(uow, inv)
            if canonical is None:
                return {"status": "skipped", "reason": "no_canonical_outcome"}

            try:
                canonical_payload = json.loads(canonical.payload_json or "{}")
            except (ValueError, TypeError):
                canonical_payload = {}
            if (
                "investigation_narrative" in canonical_payload
                and not self.options.force
            ):
                return {
                    "status": "skipped",
                    "reason": "narrative_already_present",
                    "canonical_outcome_id": canonical.id,
                }

            contributions = canonical_payload.get("panel_contributions") or []
            panel_summary = canonical_payload.get("panel_summary") or {}
            verifier_report = canonical_payload.get("verifier_report") or {}
            verdict = canonical.outcome_kind or ""

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

        # Out-of-transaction LLM call.
        prompt_body = _render_narrative_prompt(
            investigation_id=self.investigation_id,
            inv_question=inv.initial_question or "",
            inv_title=inv.title or "",
            verdict=verdict,
            branch_roster=branch_roster,
            panel_contributions=contributions,
            panel_summary=panel_summary,
            verifier_report=verifier_report,
            messages=message_chronology,
            options=self.options,
        )
        services = ServiceFactory()
        try:
            response, _ = await idempotent_llm_call(
                services.llm_client,
                method="chat_structured",
                task_type=self._TASK_TYPE,
                messages=[
                    {"role": "system", "content": _load_system_prompt()},
                    {"role": "user", "content": prompt_body},
                ],
                model_class=NarrativeResponse,
                investigation_id=self.investigation_id,
            )
        except BudgetExceededError:
            raise
        except (
            httpx.HTTPError, LLMError, OSError, RuntimeError, ValueError,
            TypeError,
        ) as exc:
            _log.warning(
                "narrative LLM call failed for inv=%s err=%s",
                self.investigation_id, exc, exc_info=True,
            )
            return {
                "status": "failed",
                "reason": f"llm_error:{type(exc).__name__}",
            }
        if response.disabled:
            return {"status": "skipped", "reason": "llm_kill_switch_active"}
        try:
            parsed = NarrativeResponse.model_validate_json(response.content)
        except ValueError as exc:
            _log.warning(
                "narrative chat_structured content failed schema validation "
                "inv=%s err=%s",
                self.investigation_id, exc,
            )
            return {"status": "failed", "reason": "structured_parse_failed"}

        # Persist the narrative blob under a row lock so a concurrent
        # synthesis / claim-verifier commit cannot race the payload
        # write.
        async with UnitOfWork() as uow:
            canonical_row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.id == canonical.id)
                .with_for_update(),
            )).first()
            if canonical_row is None:
                return {"status": "skipped", "reason": "canonical_disappeared"}
            try:
                payload = json.loads(canonical_row.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            if (
                "investigation_narrative" in payload
                and not self.options.force
            ):
                return {
                    "status": "skipped",
                    "reason": "narrative_already_present_under_lock",
                    "canonical_outcome_id": canonical_row.id,
                }
            payload["investigation_narrative"] = _build_narrative_payload(
                parsed.title,
                parsed.body,
                list(parsed.chapter_outline),
                self.options.tone,
                self.options.length,
            )
            canonical_row.payload_json = json.dumps(payload)
            uow.session.add(canonical_row)
            await uow.commit()

        word_count = len(parsed.body.split())
        _log.info(
            "vr narrative DONE inv=%s tone=%s length=%s words=%d",
            self.investigation_id, self.options.tone,
            self.options.length, word_count,
        )
        return {
            "status": "ok",
            "canonical_outcome_id": canonical.id,
            "narrative_words": word_count,
            "tone": self.options.tone,
            "length": self.options.length,
        }


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
    # Everything else -- keep the shape visible for the LLM.
    return json.dumps(payload)[:200]


def _render_narrative_prompt(
    *,
    investigation_id: str,
    inv_question: str,
    inv_title: str,
    verdict: str,
    branch_roster: list[dict[str, Any]],
    panel_contributions: list[dict[str, Any]],
    panel_summary: dict[str, Any],
    verifier_report: dict[str, Any],
    messages: list[dict[str, Any]],
    options: NarrativeOptions,
) -> str:
    """Build the user message for the narrative LLM call.

    Layers (top to bottom):
      * Tone + length directives picked from the options.
      * Optional user focus block.
      * The investigation's title + initial question.
      * The final verdict (outcome_kind) + optional verifier report.
      * Structured-synthesis findings (if synthesis already ran).
      * Persona-branch roster + per-persona contribution summaries.
      * Compressed message chronology (one line per row).
    Every dynamic value is passed through ``sanitize_input`` to keep
    a malicious string in a tool result from steering the LLM into
    arbitrary behavior.
    """
    sections: list[str] = []
    sections.append(f"# Investigation {investigation_id}")
    sections.append("")
    sections.append(_TONE_DIRECTIVES.get(options.tone, _TONE_DIRECTIVES["blog"]))
    sections.append("")
    sections.append(
        _LENGTH_DIRECTIVES.get(options.length, _LENGTH_DIRECTIVES["standard"]),
    )
    sections.append("")
    if options.operator_focus:
        sections.append("## User focus")
        sections.append(sanitize_input(options.operator_focus.strip())[:2000])
        sections.append(
            "Lead the narrative around this focus -- it is the angle "
            "the writeup is being requested for.",
        )
        sections.append("")

    if inv_title:
        sections.append("## Investigation title")
        sections.append(sanitize_input(inv_title)[:800])
        sections.append("")

    if inv_question:
        sections.append("## Initial question")
        sections.append(sanitize_input(inv_question)[:4000])
        sections.append("")

    if verdict:
        sections.append("## Final verdict (outcome_kind)")
        sections.append(sanitize_input(verdict)[:120])
        sections.append(
            "This is the panel's terminal classification -- a "
            "``direct_finding`` means the audit confirmed a bug, "
            "``patch_present`` means the code was checked and the "
            "issue is already fixed, ``no_finding`` means the panel "
            "could not establish a vulnerability. The narrative MUST "
            "match this verdict and never claim a bug the panel "
            "did not confirm.",
        )
        sections.append("")

    if verifier_report:
        vr_verdict = sanitize_input(str(verifier_report.get("verdict") or ""))
        vr_conf = sanitize_input(str(verifier_report.get("confidence") or ""))
        vr_summary = sanitize_input(str(verifier_report.get("summary") or ""))[:2000]
        if vr_verdict or vr_summary:
            sections.append("## Claim verifier report")
            sections.append(
                f"verdict={vr_verdict} confidence={vr_conf}",
            )
            if vr_summary:
                sections.append(vr_summary)
            sections.append(
                "The claim verifier is an adversarial second pass on "
                "the panel's headline finding. Surface a "
                "``refuted`` verdict honestly -- if the verifier "
                "refuted the claim, the narrative names that outcome.",
            )
            sections.append("")

    if panel_summary:
        sections.append("## Synthesized findings (use as the spine)")
        narrative = panel_summary.get("narrative") or ""
        if isinstance(narrative, str) and narrative.strip():
            sections.append(sanitize_input(narrative)[:8000])
        sections.append("")

    if branch_roster:
        sections.append(f"## Persona panel ({len(branch_roster)} branches)")
        for b in branch_roster:
            persona = sanitize_input(str(b.get("persona_voice") or "")).upper()
            branch_id = str(b.get("branch_id") or "")[:8]
            turn_count = b.get("turn_count") or 0
            branch_status = sanitize_input(str(b.get("status") or ""))
            sections.append(
                f"- {persona} (branch={branch_id}, turns={turn_count}, "
                f"status={branch_status})",
            )
        sections.append("")

    if panel_contributions:
        sections.append(
            f"## Panel contributions ({len(panel_contributions)})",
        )
        for c in panel_contributions:
            if not isinstance(c, dict):
                continue
            persona = sanitize_input(str(c.get("persona") or "")).upper()
            at_turn = c.get("at_turn") or 0
            outcome_kind = sanitize_input(str(c.get("outcome_kind") or ""))
            confidence = sanitize_input(str(c.get("confidence") or ""))
            answer = sanitize_input(str(c.get("answer_brief") or ""))[:3000]
            sections.append(
                f"### {persona} (turn {at_turn}, "
                f"{outcome_kind}, confidence={confidence})",
            )
            sections.append(answer if answer else "(no answer recorded)")
            sections.append("")

    if messages:
        sections.append(
            f"## Message chronology ({len(messages)} rows; "
            "chronological order)",
        )
        for m in messages[:400]:
            line = (
                f"- [{sanitize_input(str(m.get('created_at') or ''))}] "
                f"kind={sanitize_input(str(m.get('payload_kind') or ''))} "
                f"sender={sanitize_input(str(m.get('sender_kind') or ''))} "
                f"branch={(m.get('branch_id') or '')[:8]} "
                f"turn={m.get('at_turn') or 0} "
                f"-- {sanitize_input(str(m.get('summary') or ''))[:240]}"
            )
            sections.append(line)
        if len(messages) > 400:
            sections.append(
                f"_(... {len(messages) - 400} more message rows "
                "truncated to keep prompt budget in check)_",
            )
        sections.append("")

    sections.append(
        "# Write the narrative\n\n"
        "Produce one NarrativeResponse. ``title`` is the writeup "
        "headline (5-15 words). ``chapter_outline`` is one line per "
        "``##`` section the body will contain -- think of it as the "
        "plan you commit to. **``body`` is the actual writeup and it "
        "MUST contain EVERY chapter you listed in chapter_outline, "
        "with full text under each ``##`` header**. The outline is a "
        "promise; the body delivers on it. Schema enforces "
        "body.min_length=4000 chars (~600 words) as the hard floor; "
        "the length directive above sets the actual target. A body "
        "that is just an intro paragraph plus a chapter list is a "
        "failure mode the schema will reject. ``tone_used`` "
        f"echoes ``{options.tone}``.\n\n"
        "## Non-negotiable: enumerate every panel-surfaced finding\n\n"
        "The narrative covers the full investigation. EVERY distinct "
        "hypothesis any persona raised, EVERY function the panel "
        "read, EVERY sink audited, EVERY taint path traced, EVERY "
        "decompiled routine, EVERY CVE reference, EVERY variant-hunt "
        "order, EVERY cross-persona disagreement, EVERY rejected "
        "hypothesis (and WHY it was rejected -- sibling review, "
        "verifier refutation, missing evidence) MUST appear in the "
        "body. Walk the panel contributions one persona at a time "
        "and confirm each distinct fact landed in at least one "
        "paragraph. If halvar named ``parse_request_line`` at "
        "``src/http.c:412``, the narrative names that function and "
        "that line. If maddie traced a taint flow from "
        "``recv_buffer`` to ``memcpy``, the narrative names both "
        "endpoints. If the panel rejected a hypothesis h7 because "
        "renzo showed the guard at line 340 covered the case, the "
        "narrative names h7 AND names the rejection reason.\n\n"
        "Tell the investigation's story in the chosen tone. Lean on "
        "the synthesized findings as the spine and the panel "
        "contributions + message chronology as the source. DO "
        "surface what was tried, what didn't work, where the pivots "
        "happened -- but do this on top of the full enumeration, not "
        "instead of it. A reader who finishes the narrative knows "
        "every concrete claim the panel made. Silent drops are a "
        "failure.\n\n"
        "Length compliance is enforced: hit the target word count "
        "from the length directive above. If you find yourself "
        "running short, you are dropping findings -- go back and "
        "enumerate.",
    )
    return "\n".join(sections)

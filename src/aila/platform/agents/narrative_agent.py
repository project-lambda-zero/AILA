"""Shared long-form narrative agent (RFC #208 P2, closes #112).

Both the VR (vulnerability-research) and malware modules used to carry
byte-similar ~600-800-line NarrativeAgent implementations that differ
only in which module DB rows they read for the chronology and which
task_type they attribute the LLM call to. Everything else -- the
NarrativeResponse schema, the NarrativeOptions surface, the tone /
length directive catalogs, the sanitize-on-persist payload builder,
the ``idempotent_llm_call`` invocation, and the load-canonical ->
render-prompt -> LLM -> persist-under-lock template -- was duplicated
verbatim.

This module lifts the shared skeleton to a platform base. Subclasses
supply only:

* ``_TASK_TYPE`` -- cost / seal attribution tag (per-module).
* ``_prompt_registry`` -- module-owned :class:`PromptRegistry`
  instance (prompts stay module-owned; the base never hardcodes a
  module prompt path).
* ``_load_investigation(uow)`` -- fetch the investigation row.
* ``_load_canonical_outcome(uow, inv)`` -- resolve the canonical
  outcome row for this investigation (module rules may include
  ``primary_outcome_id`` preference).
* ``_reload_canonical_locked(uow, canonical_id)`` -- re-select the
  same row with ``FOR UPDATE`` for the persist path.
* ``_build_prompt_context(uow, inv, canonical_payload)`` -- build the
  :class:`NarrativePromptContext` with the module-specific chronology
  sections (VR: branch roster + message chronology; malware:
  observation chronology). Called inside the read UoW so subclass
  queries participate in the same transaction as the outcome load.

Mirrors the existing :class:`AgentTurnRunnerBase` and
:class:`ToolExecutorHelpersBase` platform-base + module-subclass
pattern established in RFC-03 Phase 7.

Persist shape (single canonical wire format both modules now share)::

    payload["investigation_narrative"] = {
        "title": ...,
        "body": ...,
        "chapter_outline": [...],
        "tone_used": ...,        # echo of the requested tone
        "length_used": ...,      # echo of the requested length
        "narrative_words": int,  # cheap word count for the UI badge
        "generated_at": ISO-8601,
        "sanitizer_counts": {"title": n, "body": n, "chapter_outline": n},
    }
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Generic, Literal, TypeVar

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.contracts import utc_now
from aila.platform.llm.errors import BudgetExceededError, LLMError
from aila.platform.llm.sanitize import sanitize_input, sanitize_output
from aila.platform.prompts import PromptRegistry
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

__all__ = [
    "LENGTH_DIRECTIVES",
    "NarrativeAgentBase",
    "NarrativeLength",
    "NarrativeOptions",
    "NarrativePromptContext",
    "NarrativeResponse",
    "NarrativeTone",
    "TONE_DIRECTIVES",
    "build_narrative_payload",
    "render_narrative_prompt",
]

_log = logging.getLogger(__name__)


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
    the canonical payload. Manual endpoints default True; automated
    call sites default False to preserve a previously generated
    narrative."""

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
            "from the initial question / trigger through the panel "
            "reasoning to the final verdict."
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


TONE_DIRECTIVES: dict[str, str] = {
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
        "Chronological writeup voice. Every claim cites the source "
        "(persona / tool call / observation / decompiled function / "
        "taint path). No flourishes, no narrative tension -- the "
        "audience is the next reviewer who needs to validate the "
        "finding and pivot to remediation. Structure: initial "
        "question / trigger -> scope -> audit / investigation steps "
        "-> findings -> verifier verdict -> recommended actions."
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
        "technically precise -- the audience is other research "
        "folks, not a general public. Length runs naturally to "
        "~5-15 paragraphs."
    ),
}


LENGTH_DIRECTIVES: dict[str, str] = {
    "short": (
        "Target ~1500-2500 words. 5-7 sections. Cover every distinct "
        "finding the panel surfaced (every function reviewed, every "
        "sink identified, every taint path traced, every hypothesis "
        "raised, every CVE mentioned, every IOC / brand string / "
        "capability call-out, every persona-driven disagreement) "
        "with one to two sentences per finding -- short means "
        "compact, NOT incomplete. Skip the turn-by-turn chronology "
        "but never skip a finding."
    ),
    "standard": (
        "Target ~3500-5500 words. 8-12 sections. Cover every "
        "panel-mentioned function, sink, taint path, hypothesis, CVE "
        "reference, IOC / brand string / capability, and "
        "cross-persona disagreement with two to four sentences each: "
        "name WHAT was investigated, WHERE it was found (file:line "
        "/ function name / address), WHO surfaced it (which "
        "persona), WHY it matters (why the panel argued about it). "
        "Cover the major audit phases (triage -> hypothesis "
        "generation -> tool-driven audit -> cross-persona review -> "
        "verdict). A reader new to the target must be able to "
        "reconstruct every concrete claim from this writeup alone."
    ),
    "long": (
        "Target ~8000-15000 words. 12-25 sections. The full archival "
        "writeup. Every distinct hypothesis / finding gets its own "
        "paragraph or sub-section. Name the specific tool calls "
        "that drove each pivot. Quote persona-level reasoning "
        "verbatim wherever it captures a key insight. Surface every "
        "rejected hypothesis and WHY it was rejected (sibling "
        "review, verifier refutation, missing evidence). Enumerate "
        "EVERY function read, EVERY sink traced, EVERY taint path, "
        "EVERY decompiled routine, EVERY CVE reference, EVERY IOC, "
        "EVERY brand string, EVERY hypothesis (live and rejected), "
        "EVERY cross-persona disagreement, EVERY variant-hunt order "
        "the panel raised. Nothing the panel surfaced may be "
        "silently dropped. Use the available 60000-char budget; "
        "this is the canonical publish-ready writeup an author "
        "would polish lightly before shipping."
    ),
}


@dataclass(slots=True)
class NarrativePromptContext:
    """Everything the shared prompt renderer needs.

    The subclass builds this inside its read UoW and hands it to the
    base. Optional fields render only when non-empty, so a module that
    does not carry a given signal (malware has no ``verdict`` /
    ``verifier_report`` / ``inv_title`` today; VR has both a branch
    roster and a message chronology) does not have to overload the
    renderer -- it just leaves the unused fields at their defaults.

    ``chronology_sections`` is the escape hatch for module-specific
    content (VR branch roster + message chronology, malware
    observation chronology): each entry is a pre-rendered, already
    sanitized multi-line string dropped in verbatim between the
    panel-contributions block and the terminal write-the-narrative
    instruction, in order.
    """

    investigation_id: str
    options: NarrativeOptions
    inv_question: str = ""
    inv_title: str = ""
    verdict: str = ""
    verifier_report: dict[str, Any] | None = None
    panel_summary: dict[str, Any] | None = None
    panel_contributions: list[dict[str, Any]] = field(default_factory=list)
    chronology_sections: list[str] = field(default_factory=list)


def build_narrative_payload(
    title: str,
    body: str,
    chapter_outline: list[str],
    tone: str,
    length: str,
) -> dict[str, Any]:
    """Build the persisted ``investigation_narrative`` dict, XSS-sanitized.

    The narrative is LLM output over untrusted case data;
    :func:`sanitize_output` strips script / js / handler / iframe
    patterns and control chars before the text lands in the durable
    payload, and records how many patterns were stripped for the
    evidence lineage.

    Returns the single canonical wire shape both the VR and malware
    modules now persist (``tone_used`` / ``length_used`` /
    ``narrative_words``); the frontend renders these keys uniformly.
    """
    title_clean, title_stripped = sanitize_output(title)
    body_clean, body_stripped = sanitize_output(body)
    outline_clean: list[str] = []
    outline_stripped = 0
    for chapter in chapter_outline:
        cleaned, n = sanitize_output(chapter)
        outline_clean.append(cleaned)
        outline_stripped += n
    return {
        "title": title_clean,
        "body": body_clean,
        "chapter_outline": outline_clean,
        "tone_used": tone,
        "length_used": length,
        "narrative_words": len(body_clean.split()),
        "generated_at": utc_now().isoformat(),
        "sanitizer_counts": {
            "title": title_stripped,
            "body": body_stripped,
            "chapter_outline": outline_stripped,
        },
    }


def render_narrative_prompt(ctx: NarrativePromptContext) -> str:
    """Build the user message for the narrative LLM call.

    Layers (top to bottom, each rendered only when its input is
    non-empty):

    * Tone + length directives picked from the options.
    * Optional operator-focus block.
    * The investigation's title + initial question / trigger.
    * The final verdict (``outcome_kind``) + optional verifier report.
    * Structured-synthesis findings (spine).
    * Per-persona contribution summaries.
    * Subclass-supplied ``chronology_sections`` verbatim (VR branch
      roster + message chronology; malware observation chronology).
    * Terminal write-the-narrative instruction.

    Every dynamic value is passed through :func:`sanitize_input` to
    keep a malicious string in a tool result from steering the LLM
    into arbitrary behavior.
    """
    options = ctx.options
    sections: list[str] = []
    sections.append(f"# Investigation {ctx.investigation_id}")
    sections.append("")
    sections.append(TONE_DIRECTIVES.get(options.tone, TONE_DIRECTIVES["blog"]))
    sections.append("")
    sections.append(
        LENGTH_DIRECTIVES.get(options.length, LENGTH_DIRECTIVES["standard"]),
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

    if ctx.inv_title:
        sections.append("## Investigation title")
        sections.append(sanitize_input(ctx.inv_title)[:800])
        sections.append("")

    if ctx.inv_question:
        sections.append("## Initial question")
        sections.append(sanitize_input(ctx.inv_question)[:4000])
        sections.append("")

    if ctx.verdict:
        sections.append("## Final verdict (outcome_kind)")
        sections.append(sanitize_input(ctx.verdict)[:120])
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

    if ctx.verifier_report:
        vr_verdict = sanitize_input(str(ctx.verifier_report.get("verdict") or ""))
        vr_conf = sanitize_input(str(ctx.verifier_report.get("confidence") or ""))
        vr_summary = sanitize_input(
            str(ctx.verifier_report.get("summary") or ""),
        )[:2000]
        if vr_verdict or vr_summary:
            sections.append("## Claim verifier report")
            sections.append(f"verdict={vr_verdict} confidence={vr_conf}")
            if vr_summary:
                sections.append(vr_summary)
            sections.append(
                "The claim verifier is an adversarial second pass on "
                "the panel's headline finding. Surface a "
                "``refuted`` verdict honestly -- if the verifier "
                "refuted the claim, the narrative names that outcome.",
            )
            sections.append("")

    if ctx.panel_summary:
        sections.append("## Synthesized findings (use as the spine)")
        narrative = ctx.panel_summary.get("narrative") or ""
        if isinstance(narrative, str) and narrative.strip():
            sections.append(sanitize_input(narrative)[:8000])
        sections.append("")

    if ctx.panel_contributions:
        sections.append(
            f"## Panel contributions ({len(ctx.panel_contributions)})",
        )
        for c in ctx.panel_contributions:
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

    for extra in ctx.chronology_sections:
        if extra:
            sections.append(extra)

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
        "decompiled routine, EVERY CVE reference, EVERY IOC / brand "
        "string / capability call-out, EVERY variant-hunt order, "
        "EVERY cross-persona disagreement, EVERY rejected hypothesis "
        "(and WHY it was rejected -- sibling review, verifier "
        "refutation, missing evidence) MUST appear in the body. "
        "Walk the panel contributions one persona at a time and "
        "confirm each distinct fact landed in at least one "
        "paragraph.\n\n"
        "Tell the investigation's story in the chosen tone. Lean on "
        "the synthesized findings as the spine and the panel "
        "contributions + chronology sections as the source. DO "
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


InvT = TypeVar("InvT")
CanonicalT = TypeVar("CanonicalT")


class NarrativeAgentBase(ABC, Generic[InvT, CanonicalT]):
    """LLM-backed long-form narrative writeup shared by the module agents.

    Subclasses set :attr:`_TASK_TYPE`, bind :attr:`_prompt_registry`,
    and override the abstract DB seams. Everything else -- prompt
    rendering, ``idempotent_llm_call`` invocation, response
    validation, persist-under-lock, structured return -- lives here.
    """

    _TASK_TYPE: ClassVar[str] = ""
    """Cost / seal attribution tag for :func:`idempotent_llm_call`.
    Every concrete subclass MUST set this."""

    _LOG_LABEL: ClassVar[str] = "narrative"
    """Prefix for the DONE / failure log lines. Subclasses may
    override to distinguish "vr narrative" from "malware narrative"."""

    def __init__(
        self,
        investigation_id: str,
        *,
        options: NarrativeOptions | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.options: NarrativeOptions = options or NarrativeOptions()

    # ------------------------------------------------------------------ #
    #  Abstract seams -- subclass owns the module-specific DB + prompt.  #
    # ------------------------------------------------------------------ #

    @property
    @abstractmethod
    def _prompt_registry(self) -> PromptRegistry:
        """Module-owned :class:`PromptRegistry` -- the base never
        hardcodes a module prompt path (prompts stay module-owned)."""

    @abstractmethod
    async def _load_investigation(self, uow: UnitOfWork) -> InvT | None:
        """Fetch the investigation row keyed by ``self.investigation_id``."""

    @abstractmethod
    async def _load_canonical_outcome(
        self, uow: UnitOfWork, inv: InvT,
    ) -> CanonicalT | None:
        """Resolve the canonical outcome row for this investigation.

        Module rules apply (VR prefers ``inv.primary_outcome_id``
        when set; malware just takes the earliest by ``created_at``).
        The returned row MUST expose ``.id`` and ``.payload_json``.
        """

    @abstractmethod
    async def _reload_canonical_locked(
        self, uow: UnitOfWork, canonical_id: str,
    ) -> CanonicalT | None:
        """Re-select the canonical row with ``FOR UPDATE`` for the
        persist path so a concurrent synthesis / verifier commit
        cannot race the payload write."""

    @abstractmethod
    async def _build_prompt_context(
        self,
        uow: UnitOfWork,
        inv: InvT,
        canonical: CanonicalT,
        canonical_payload: dict[str, Any],
    ) -> NarrativePromptContext:
        """Build the :class:`NarrativePromptContext` with the
        module-specific ``chronology_sections`` (VR: branch roster +
        message chronology; malware: observation chronology). Called
        inside the read UoW so subclass queries participate in the
        same transaction as the outcome load. ``canonical`` is the
        row returned by :meth:`_load_canonical_outcome` so the
        subclass can read module-specific columns (VR reads
        ``outcome_kind`` for the verdict block) without a second
        query."""

    # ------------------------------------------------------------------ #
    #  Concrete template -- shared by every subclass.                    #
    # ------------------------------------------------------------------ #

    def _load_system_prompt(self) -> str:
        """RFC-09 criterion 1: body lives in
        ``prompts/system_narrative.md`` resolved via
        :class:`PromptRegistry` so cost / seal rows carry the resolved
        ``prompt_content_hash`` + ``prompt_version`` stamp instead of
        a NULL attribution."""
        return self._prompt_registry.load("narrative")

    def _render_narrative_prompt(self, ctx: NarrativePromptContext) -> str:
        """Delegates to the free :func:`render_narrative_prompt` --
        broken out so subclasses may specialize the prompt renderer
        without touching the ``run()`` template. Default: no
        specialization."""
        return render_narrative_prompt(ctx)

    async def run(self) -> dict[str, Any]:
        """Generate one narrative writeup and persist it under
        ``payload["investigation_narrative"]`` on the canonical outcome.

        Returns a dict with ``status`` + ``canonical_outcome_id`` +
        ``narrative_words`` (word count for the operator log). Return
        values from the skipped / failed paths carry a ``reason``
        string that operator dashboards render verbatim.
        """
        async with UnitOfWork() as uow:
            inv = await self._load_investigation(uow)
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

            ctx = await self._build_prompt_context(
                uow, inv, canonical, canonical_payload,
            )
            canonical_id = canonical.id

        # Out-of-transaction LLM call.
        prompt_body = self._render_narrative_prompt(ctx)
        services = ServiceFactory()
        try:
            response, _ = await idempotent_llm_call(
                services.llm_client,
                method="chat_structured",
                task_type=self._TASK_TYPE,
                messages=[
                    {"role": "system", "content": self._load_system_prompt()},
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
                "%s LLM call failed for inv=%s err=%s",
                self._LOG_LABEL, self.investigation_id, exc, exc_info=True,
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
                "%s chat_structured content failed schema validation "
                "inv=%s err=%s",
                self._LOG_LABEL, self.investigation_id, exc,
            )
            return {"status": "failed", "reason": "structured_parse_failed"}

        # Persist the narrative blob under a row lock so a concurrent
        # synthesis / claim-verifier commit cannot race the write.
        async with UnitOfWork() as uow:
            canonical_row = await self._reload_canonical_locked(uow, canonical_id)
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
            payload["investigation_narrative"] = build_narrative_payload(
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
            "%s DONE inv=%s tone=%s length=%s words=%d",
            self._LOG_LABEL, self.investigation_id, self.options.tone,
            self.options.length, word_count,
        )
        return {
            "status": "ok",
            "canonical_outcome_id": canonical_id,
            "narrative_words": word_count,
            "tone": self.options.tone,
            "length": self.options.length,
        }

"""Per-control report-section writer — the agent that synthesizes a
single MASVS control's report subsection from the auditor's raw
outcome, the control spec, and the APK context.

Replaces the dumb pass-through that dumped the auditor's free-text
``answer`` into the PDF verbatim. The writer agent reads the same
inputs a senior security auditor would (control intent + control
checklist + auditor's evidence + APK identity) and produces a
*decided*, *structured* section: headline verdict, the 2-3
load-bearing pieces of evidence with file:line citations, the
specific risk the finding exposes for THIS app, and the concrete
remediation step in the operator's voice.

Architectural decisions:

  - **One LLM call per control.** Caller is responsible for batching.
    The PDF endpoint runs them in parallel via ``asyncio.gather`` so
    a 53-control audit takes one round-trip per control instead of
    summing them.
  - **Lazy + cached.** The result is persisted into the outcome's
    payload_json under the ``_report_section`` key so subsequent PDF
    downloads reuse it. Re-generates when the outcome's
    ``updated_at`` newer than the cached section's ``generated_at``.
  - **Strict structured output.** Pydantic schema enforced by
    ``chat_structured`` so the renderer never has to parse free
    text. Fields are sized for direct rendering into the PDF
    template; the writer is told the budget per field.
  - **Voice match.** Operator-facing report style: concrete, present-
    tense, no hedging, no "as a senior auditor I conclude…", no
    catalog-template phrases. Operator audits this style.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.contracts.masvs import MasvsControlVerdict, MasvsVerdict
from aila.modules.vr.masvs.models import MasvsControl
from aila.platform.llm.client import AilaLLMClient

_log = logging.getLogger(__name__)


class ReportEvidence(BaseModel):
    """One citation under the AUDIT FINDINGS section. The writer picks
    2-4 of these per control — the most load-bearing pieces.
    """

    model_config = ConfigDict(extra="forbid")

    location: str = Field(
        max_length=300,
        description=(
            "Where the evidence lives in the APK. Format options: "
            "``<jadx-path>.java:<line>`` (preferred when line known), "
            "``<jadx-path>.java::<method>``, ``AndroidManifest.xml::<element-xpath>``, "
            "``lib/<abi>/<file>.so::<function>``, or a literal string like "
            "``allowBackup=\"true\"`` when the evidence is a manifest attribute. "
            "Be precise — operator will click this to open the file."
        ),
    )
    detail: str = Field(
        max_length=600,
        description=(
            "One sentence explaining what this location proves. Don't restate "
            "the location. Concrete, present-tense, names the actual values / "
            "calls / attributes that matter. Example: ``writes session token "
            "to plain SharedPreferences without Keystore wrapping`` (NOT ``this "
            "is where sensitive data is stored insecurely``)."
        ),
    )


class ReportSection(BaseModel):
    """The structured report-section the renderer prints under one
    MASVS control. Every field is sized for direct PDF rendering.
    """

    model_config = ConfigDict(extra="forbid")

    headline: str = Field(
        min_length=10,
        max_length=240,
        description=(
            "One sentence answering: 'What did the audit conclude for THIS "
            "control on THIS APK?'. Lead with the verdict word (Compliant / "
            "Vulnerable / Partial / Outside scope), then the 5-12 word "
            "specific reason. Example: ``Vulnerable: session tokens persisted "
            "to plain SharedPreferences in 3 call sites``. NEVER restate the "
            "control title. NEVER use 'we found' / 'the audit revealed' — "
            "just state the fact."
        ),
    )
    evidence: list[ReportEvidence] = Field(
        default_factory=list,
        max_length=6,
        description=(
            "2-4 load-bearing pieces of evidence. Pick the ones the operator "
            "would click first to verify. Drop padding evidence. For PASS "
            "verdicts, evidence proves the safe pattern is present (e.g. "
            "``EncryptedSharedPreferences usage at <file>:<line>``). For FAIL, "
            "evidence proves the broken pattern. Empty list is valid for "
            "REVIEW verdicts where the agent couldn't reach a conclusion."
        ),
    )
    risk: str = Field(
        max_length=600,
        description=(
            "ONE paragraph (2-4 sentences) naming what an unauthorized party "
            "can do IF this finding is exploited on this specific app. Be "
            "concrete to the app's domain: 'session-token theft enables "
            "account takeover on Vodafone Yanımda customer accounts' is "
            "right; 'attackers can access data' is wrong. For PASS verdicts, "
            "set this to an empty string. For REVIEW, write what would be "
            "tested if the audit could continue."
        ),
    )
    remediation: str = Field(
        max_length=800,
        description=(
            "Concrete next step(s) for the developer. Specify the API / "
            "library / config change with the actual class/method name when "
            "possible: 'Wrap SharedPreferences at <file>:<line> with "
            "EncryptedSharedPreferences.create() using a MasterKey backed by "
            "AndroidKeyStore'. Two-sentence max. For PASS, set to empty "
            "string. For REVIEW, list the specific blocker(s) (e.g., 'manual "
            "review of <file> required — agent timed out on symbolic "
            "execution after 8 turns')."
        ),
    )
    why_it_matters: str = Field(
        max_length=400,
        description=(
            "One sentence on why this control exists, in the operator's "
            "voice (NOT the catalog's). Drop standards-jargon like 'the "
            "verification target is…'. Example: ``Backed-up data lands in "
            "the user's Google Drive and is restored onto any device the "
            "user signs into — including a compromised one.``"
        ),
    )
    confidence_note: str | None = Field(
        default=None,
        max_length=300,
        description=(
            "Optional one-line caveat when the verdict has known limits. "
            "Use sparingly: e.g. ``Manual server-side review required to "
            "confirm input validation duplication`` (for ARCH-style "
            "controls). Leave empty for clear FAIL / PASS."
        ),
    )


_VERDICT_VOCABULARY = {
    MasvsVerdict.FINDING: "Vulnerable / Fails",
    MasvsVerdict.NO_FINDING: "Compliant / Passes",
    MasvsVerdict.INCONCLUSIVE: "Inconclusive — needs review",
    MasvsVerdict.NOT_APPLICABLE: "Not applicable to this app",
}


_SYSTEM_PROMPT = (
    "You are the report writer for a mobile app security audit. Your output "
    "renders directly into a PDF a security team and the app's developers "
    "will read. Voice: concrete, present-tense, no hedging, no padding, no "
    "catalog-template phrases like 'verification target' or 'control "
    "requires'. NEVER write 'we found' / 'audit revealed' / 'analysis "
    "shows'. State facts.\n\n"
    "You receive ONE MASVS control's audit data: the catalog text, the "
    "auditor agent's raw conclusion, the cited evidence locations, the "
    "verdict, and APK identity. Synthesize into a structured report "
    "section. Pick the 2-4 most load-bearing pieces of evidence (drop "
    "filler). Name the specific RISK in the app's domain (banking app → "
    "'session-token theft enables account takeover', not 'data leaks'). "
    "Give a CONCRETE remediation step with API/library names where the "
    "evidence supports it.\n\n"
    "If the auditor reached PASS / Compliant, write a short section "
    "proving the safe pattern is present and set risk + remediation to "
    "empty strings. If the auditor reached REVIEW / Inconclusive, name "
    "the specific blocker that prevented a verdict.\n\n"
    "Banned phrases (do not appear in your output): 'we found', 'audit "
    "revealed', 'this is what', 'essentially', 'leverage', 'in essence', "
    "'verification target', 'control requires that', 'it is worth noting'."
)


def _build_user_prompt(
    verdict: MasvsControlVerdict,
    control: MasvsControl | None,
    raw_answer: str,
    apk_context: dict[str, Any],
) -> str:
    """Compose the per-control LLM prompt. Operator-facing voice."""
    control_id = verdict.control_id
    verdict_label = _VERDICT_VOCABULARY.get(verdict.verdict, verdict.verdict.value)
    catalog_title = control.title if control is not None else "(no catalog entry)"
    catalog_description = (
        control.description if control is not None else "(no catalog entry)"
    )
    catalog_steps = (
        "\n".join(f"  - {step}" for step in (control.verification_steps or []))
        if control is not None and control.verification_steps
        else "(no catalog steps)"
    )
    evidence_block = (
        "\n".join(
            f"  - {loc.file} :: {loc.function}"
            for loc in verdict.evidence_locations
        )
        if verdict.evidence_locations
        else "(none — auditor did not cite evidence locations)"
    )
    apk_lines = "\n".join(
        f"  {k}: {v}" for k, v in apk_context.items() if v is not None
    ) or "(no APK context available)"

    raw_block = (raw_answer or "(no raw answer — agent produced no payload['answer'])").strip()
    if len(raw_block) > 7000:
        raw_block = raw_block[:7000] + "\n…(truncated)…"

    return (
        f"=== CONTROL ===\n"
        f"{control_id} — {catalog_title}\n\n"
        f"CATALOG DESCRIPTION:\n{catalog_description}\n\n"
        f"CATALOG VERIFICATION CHECKLIST:\n{catalog_steps}\n\n"
        f"=== APK ===\n{apk_lines}\n\n"
        f"=== AUDITOR'S RAW CONCLUSION ===\n{raw_block}\n\n"
        f"=== AUDITOR'S CITED EVIDENCE ===\n{evidence_block}\n\n"
        f"=== VERDICT REACHED ===\n{verdict_label}"
        + (f" ({int(round(verdict.confidence * 100))}% confidence)" if verdict.confidence else "")
        + (f"\nNote: {verdict.reason}" if verdict.reason else "")
        + "\n\nWrite the structured report section now."
    )


async def generate_section(
    *,
    verdict: MasvsControlVerdict,
    control: MasvsControl | None,
    raw_answer: str,
    apk_context: dict[str, Any],
    llm: AilaLLMClient,
    run_id: str | None = None,
    team_id: str | None = None,
) -> ReportSection | None:
    """Synthesize one ``ReportSection`` for one MASVS control verdict.

    Returns ``None`` when the LLM call fails (network, schema, budget).
    Caller falls back to rendering the raw ``agent_summary`` in that
    case so the PDF still ships — partial fidelity beats 500 errors.
    """
    user_prompt = _build_user_prompt(verdict, control, raw_answer, apk_context)
    try:
        response = await llm.chat_structured(
            task_type="vr.masvs.report_section_writer",
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            model_class=ReportSection,
            run_id=run_id,
            team_id=team_id,
        )
    except Exception as exc:  # noqa: BLE001
        # fix §350 — DEFENSIVE: section synthesis falls back to the raw
        # agent_summary so the PDF still ships; surface the traceback so
        # a recurring schema/auth break is grep-able in operator logs.
        _log.warning(
            "section_writer LLM call failed control=%s: %s",
            verdict.control_id, exc,
            exc_info=True,
        )
        return None
    if response.disabled or response.parsed is None:
        return None
    if not isinstance(response.parsed, ReportSection):
        _log.warning(
            "section_writer parsed object is not ReportSection control=%s type=%s",
            verdict.control_id, type(response.parsed).__name__,
        )
        return None
    return response.parsed


def cache_key_for(verdict: MasvsControlVerdict) -> str:
    """Stable key under outcome.payload_json[_report_section_cache] so
    the same verdict (= same control + same outcome) re-uses the
    generated section across PDF downloads.

    Caching contract: store under
    ``outcome.payload_json['_report_section_cache'][cache_key]`` with
    a ``generated_at`` timestamp. Caller invalidates by removing the
    key OR by checking ``outcome.updated_at > cached.generated_at``.
    """
    return f"v1:{verdict.control_id}:{verdict.verdict.value}"


def is_cache_fresh(
    cached_section: dict[str, Any] | None,
    outcome_updated_at: datetime | None,
) -> bool:
    """True iff the cached section is newer than the outcome it summarizes."""
    if not cached_section or not isinstance(cached_section, dict):
        return False
    cached_at_raw = cached_section.get("generated_at")
    if not cached_at_raw:
        return False
    try:
        cached_at = datetime.fromisoformat(cached_at_raw)
    except (ValueError, TypeError):
        return False
    if outcome_updated_at is None:
        return True
    if cached_at.tzinfo is None and outcome_updated_at.tzinfo is not None:
        cached_at = cached_at.replace(tzinfo=outcome_updated_at.tzinfo)
    return cached_at >= outcome_updated_at

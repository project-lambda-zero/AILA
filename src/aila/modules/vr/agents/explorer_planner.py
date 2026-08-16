"""Explorer / Planner decoupling for the VR agent loop (issue #95 Wave 3).

Waves 1-2 landed the lateral-discovery input channel:

* Wave 1: the tool-executor helper base runs a passive regex scan on
  every ``audit_mcp`` source-surfacing tool result and posts each
  matching pattern as an :class:`~aila.platform.services.ledger.LedgerService`
  ``discovery`` entry with ``payload['source'] == 'lateral_observation'``.
* Wave 2: the platform ``auto_steering`` layer optionally follows that
  scan with one cheap LLM proposal call gated on
  ``platform.vr_lateral_llm_enabled``; each proposal lands as a
  ``discovery`` entry with ``payload['source'] == 'lateral_llm'``.

Wave 3 (this file) closes the loop on the AGENT-facing side. Reading
the ledger doesn't itself change how the researcher picks its next
action -- the hub dispatches ledger discoveries into fresh child
branches, but the AUTHORING branch keeps chasing its current
hypothesis until it terminates. That is the "single-agent" shape the
RFC's DREA reference targets: exploration and planning collapse into
one persona whose current hypothesis biases everything.

The wave-3 slice decouples the two roles inside the same VR loop:

* **Explorer**: given the branch's live case state, walks the
  lateral-discovery ledger for entries this branch has NOT yet
  investigated (distinct from its own live hypotheses), ranks them by
  recency, and -- when the ``platform.vr_explorer_enabled`` flag is
  ON -- asks a cheap LLM (routed through
  :func:`~aila.platform.agents.idempotent_llm.idempotent_llm_call`) for
  ONE additional lateral direction it notices in the current case
  state that the ledger did not already surface.
* **Planner**: takes the ranked list, picks the top direction, and
  folds it into the next-action selection by injecting a
  ``_directive.explorer_top_lead`` observable that the researcher's
  prompt already renders (see
  :func:`~aila.modules.vr.agents.vuln_researcher._render_active_directives_section`).
  The directive names the lateral target + explains WHY it is distinct
  from the current hypothesis; the researcher then decides whether to
  fold it into ``tool_run`` / a fresh hypothesis / a variant-hunt
  ledger request. Advisory only; the researcher's own action selection
  stays the source of truth.

Byte-identity contract: with the flag OFF (default),
:func:`maybe_run_explorer_planner` returns before any DB read, any
LLM construction, and any observable write. The VR loop is
byte-identical to today; the entire wave-3 code path is dead code.

Wave 3 is intentionally kept single-persona -- it reuses the existing
researcher-agent context (case_state) and the existing lateral ledger
channel. A full persona split (a distinct explorer LLM run against a
distinct system prompt separate from the planner's decide-next-turn)
is a larger persona-dispatch change out of scope for this slice.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import SQLAlchemyError

if TYPE_CHECKING:
    from aila.platform.contracts.reasoning import ReasoningCaseState

__all__ = [
    "LateralDirection",
    "collect_ranked_directions",
    "explorer_pass",
    "maybe_run_explorer_planner",
    "planner_pass",
]

_log = logging.getLogger(__name__)

# LLM task-type key routed through the standard config chain
# (``llm_model_{task_type}``). An operator pins a specific model via
# ``PUT /config/platform/llm_model_vulnerability_research.explorer_planner``;
# otherwise the platform default handles it.
_EXPLORER_TASK_TYPE: str = "vulnerability_research.explorer_planner"

# Ledger ``payload['source']`` values that count as lateral input for
# the explorer. Wave 1 emits ``lateral_observation``, Wave 2 emits
# ``lateral_llm``; anything else on the ledger (recon hypotheses,
# specialist requests, quorum decisions, ...) is out-of-scope for
# lateral exploration and skipped.
_LATERAL_SOURCES: frozenset[str] = frozenset(
    {"lateral_observation", "lateral_llm"},
)

# Cap on ledger candidates carried through to the planner + LLM prompt.
# Kept small so the LLM prompt stays cheap and the top-lead directive
# only names ONE concrete lead per turn.
_MAX_LEDGER_CANDIDATES: int = 8

# Character budget for the LLM prompt's live-hypothesis + ledger
# summary. Both slices share a soft cap so a large branch state cannot
# balloon the one-shot prompt.
_PROMPT_HYPOTHESIS_BUDGET: int = 1200
_PROMPT_LEDGER_BUDGET: int = 1600

# Observable key the planner writes into ``case_state.observables``.
# The VR ``_render_active_directives_section`` helper lifts every
# ``_directive.*`` value into the prompt's PROMPT POSITION 2 slot
# right under operator steering -- the researcher's next turn sees
# the lead as a labelled directive block.
_TOP_LEAD_KEY: str = "_directive.explorer_top_lead"


# ─────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class LateralDirection:
    """One ranked lateral direction the explorer surfaces.

    ``score`` is the planner's ordering signal; higher wins. Ledger
    entries score off recency (their integer id); an LLM-proposed
    direction gets a fixed high score so it lands at the top when
    present. ``origin`` tags the source so the planner-rendered
    directive can attribute the lead honestly ("from the shared
    ledger" vs "proposed by the explorer LLM this turn").

    All fields are plain strings / ints -- the object is only carried
    inside one turn's run and never persisted; keeping it dataclass +
    slots avoids Pydantic overhead for a hot per-turn path.
    """

    score: int
    origin: str  # "ledger" | "llm"
    source: str  # payload['source'] for ledger; "explorer_llm" for llm
    file: str
    function: str
    reason: str
    discovery_id: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────
# Gate
# ─────────────────────────────────────────────────────────────────


async def _explorer_enabled() -> bool:
    """Read the ``vr_explorer_enabled`` gate through :class:`ConfigRegistry`.

    Env > cache > DB > schema default (False). Deferred import keeps
    the module load cheap when the flag is off. A registry failure
    collapses to False so a broken registry never silently turns on a
    paid LLM path.
    """
    try:
        from aila.storage.registry import ConfigRegistry
    except ImportError:
        return False
    try:
        raw = await ConfigRegistry().get("platform", "vr_explorer_enabled")
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return False


# ─────────────────────────────────────────────────────────────────
# Explorer
# ─────────────────────────────────────────────────────────────────


def _live_focus_tokens(case_state: ReasoningCaseState) -> set[str]:
    """Return a set of lowercased identifier-ish tokens the branch's
    live hypotheses already target.

    Used to filter the ledger candidate list: a lateral discovery whose
    ``file`` or ``function`` overlaps the current focus is NOT lateral
    for this branch -- it's the same road the researcher is already
    walking, and re-suggesting it as a "lateral" lead is noise.

    Token extraction is deliberately permissive: any alphanumeric /
    underscore / slash / dot run of length >= 3 in a hypothesis
    claim / why_plausible / kill_criterion counts. That includes
    function names, file paths, macro names, and CVE ids without
    depending on the researcher having filled a structured focus
    field (hypotheses don't carry one today).
    """
    focus_text_parts: list[str] = []
    for h in case_state.hypotheses or ():
        for field_val in (
            getattr(h, "claim", ""),
            getattr(h, "why_plausible", ""),
            getattr(h, "kill_criterion", ""),
        ):
            if isinstance(field_val, str) and field_val.strip():
                focus_text_parts.append(field_val)
    if not focus_text_parts:
        return set()
    focus_text = " ".join(focus_text_parts).lower()
    return set(re.findall(r"[a-z0-9_./]{3,}", focus_text))


def _direction_is_lateral(
    file: str, function: str, focus_tokens: set[str],
) -> bool:
    """True when neither the file nor the function overlaps the
    branch's current focus tokens -- i.e. the discovery genuinely
    points somewhere the branch is not already looking.
    """
    if not focus_tokens:
        return True
    hay = f"{file} {function}".lower()
    return not any(tok in hay for tok in focus_tokens)


async def _read_lateral_ledger(
    investigation_id: str,
) -> list[dict[str, Any]]:
    """Read every ``discovery`` entry authored on this investigation and
    filter to the wave-1 / wave-2 lateral sources.

    Deferred import: ``LedgerService`` is a leaf service but pulling it
    at module load would drag the DB models into every VR loop
    initialisation even with the flag OFF -- keeping it lazy preserves
    the byte-identity contract without needing a separate gate check
    at the top of every helper.
    """
    from aila.platform.services.ledger import LedgerService

    entries = await LedgerService().read_general(
        investigation_id, kinds=["discovery"],
    )
    lateral: list[dict[str, Any]] = []
    for entry in entries:
        payload = entry.get("payload") or {}
        source = str(payload.get("source") or "")
        if source not in _LATERAL_SOURCES:
            continue
        lateral.append(entry)
    return lateral


def _ledger_direction(
    entry: dict[str, Any], focus_tokens: set[str],
) -> LateralDirection | None:
    """Turn a ledger row into a :class:`LateralDirection`, or return
    ``None`` when the row lacks a usable target OR the target
    overlaps the current focus.
    """
    payload = entry.get("payload") or {}
    source = str(payload.get("source") or "")
    if source not in _LATERAL_SOURCES:
        # Defense in depth -- ``_read_lateral_ledger`` already filters,
        # but callers of :func:`collect_ranked_directions` (tests,
        # future consumers) may hand in an unfiltered ledger slice.
        return None
    file = str(payload.get("file") or "").strip()
    function = str(payload.get("function") or "").strip()
    if not file and not function:
        return None
    if not _direction_is_lateral(file, function, focus_tokens):
        return None
    # Wave 1 stores a matching source snippet under ``snippet``; Wave 2
    # stores the LLM's proposal under ``proposal``. Fall through both
    # so the planner's directive can carry the actual reason.
    reason = str(
        payload.get("proposal")
        or payload.get("snippet")
        or payload.get("pattern")
        or "",
    ).strip()
    return LateralDirection(
        # Score by ledger id -- newer discoveries win. Adding a fixed
        # LLM boost later ensures a live LLM proposal outranks a stale
        # regex hit from turn 4.
        score=int(entry.get("id") or 0),
        origin="ledger",
        source=source,
        file=file,
        function=function,
        reason=reason,
        discovery_id=int(entry.get("id") or 0),
    )


def collect_ranked_directions(
    ledger_entries: list[dict[str, Any]],
    case_state: ReasoningCaseState,
) -> list[LateralDirection]:
    """Explorer's pure-Python core: turn ledger rows + case state into
    a ranked list of :class:`LateralDirection`.

    Split from :func:`explorer_pass` so tests can exercise the ranking
    without touching the DB or the LLM.

    The list is truncated to :data:`_MAX_LEDGER_CANDIDATES` so the
    planner (and the optional LLM prompt) can eyeball every candidate
    without paying an unbounded token cost on a busy investigation.
    """
    focus_tokens = _live_focus_tokens(case_state)
    ranked: list[LateralDirection] = []
    for entry in ledger_entries:
        direction = _ledger_direction(entry, focus_tokens)
        if direction is not None:
            ranked.append(direction)
    ranked.sort(key=lambda d: d.score, reverse=True)
    return ranked[:_MAX_LEDGER_CANDIDATES]


async def explorer_pass(
    *,
    investigation_id: str,
    branch_id: str,
    case_state: ReasoningCaseState,
) -> list[LateralDirection]:
    """Explorer: read the lateral ledger + (when configured) ask the
    cheap explorer LLM for one additional direction distinct from the
    current hypothesis.

    Returns the ranked list of candidate directions -- pure explorer
    output; the planner turns it into a directive.

    ``branch_id`` rides through to the LLM idempotency key so a
    per-branch retry replays the cached proposal instead of re-paying.
    """
    ledger_entries = await _read_lateral_ledger(investigation_id)
    ranked = collect_ranked_directions(ledger_entries, case_state)

    llm_direction = await _llm_propose_direction(
        investigation_id=investigation_id,
        branch_id=branch_id,
        case_state=case_state,
        ledger_candidates=ranked,
    )
    if llm_direction is not None:
        # Boost the LLM proposal above every ledger candidate. Ledger
        # scores are ledger ids (int-monotonic per investigation);
        # 10**12 is a comfortable ceiling above any plausible ledger
        # id and keeps the LLM row on top without shadowing the raw
        # id when tests inspect the ordering.
        llm_direction.score = 10**12
        return [llm_direction, *ranked]
    return ranked


async def _llm_propose_direction(
    *,
    investigation_id: str,
    branch_id: str,
    case_state: ReasoningCaseState,
    ledger_candidates: list[LateralDirection],
) -> LateralDirection | None:
    """Cheap one-shot LLM call: given the branch's live hypotheses +
    the ledger's top candidates, propose ONE additional lateral
    direction the ledger did not surface, or ``NONE``.

    Runs ONLY when there is at least one live hypothesis on the
    branch -- with no active hypothesis the "distinct from active"
    framing has no anchor and the ledger candidates already stand
    on their own. Routed through
    :func:`~aila.platform.agents.idempotent_llm.idempotent_llm_call` so
    a worker retry replays the cached proposal instead of re-paying.

    Best-effort: any import / registry / LLM / parse failure logs at
    WARNING and returns ``None`` -- the planner then falls back to the
    ledger-only ranking.
    """
    hypotheses = [h for h in (case_state.hypotheses or ()) if getattr(h, "claim", "")]
    if not hypotheses:
        return None

    # Deferred imports: the disabled path never touches these, and the
    # heavy AilaLLMClient bootstrap (config registry + secret store)
    # only fires when the flag is ON. Same pattern the wave-2 helper
    # in ``platform/agents/auto_steering.py`` already uses.
    try:
        from aila.platform.agents.idempotent_llm import idempotent_llm_call
        from aila.platform.llm.client import AilaLLMClient
        from aila.platform.llm.errors import LLMError
        from aila.storage.registry import ConfigRegistry
        from aila.storage.secrets import SecretStore
    except ImportError as exc:
        _log.warning(
            "explorer_planner: deferred import failed inv=%s err=%s",
            investigation_id, exc,
        )
        return None

    hypothesis_lines: list[str] = []
    used = 0
    for h in hypotheses:
        claim = str(getattr(h, "claim", "") or "").strip()
        if not claim:
            continue
        line = f"- {h.id or '?'}: {claim}"
        if used + len(line) > _PROMPT_HYPOTHESIS_BUDGET:
            break
        hypothesis_lines.append(line)
        used += len(line) + 1
    if not hypothesis_lines:
        return None

    ledger_lines: list[str] = []
    used = 0
    for direction in ledger_candidates:
        target = f"{direction.function or '?'} @ {direction.file or '?'}"
        line = f"- [{direction.source}] {target} :: {direction.reason[:200]}"
        if used + len(line) > _PROMPT_LEDGER_BUDGET:
            break
        ledger_lines.append(line)
        used += len(line) + 1

    ledger_block = "\n".join(ledger_lines) if ledger_lines else "(none)"
    hypothesis_block = "\n".join(hypothesis_lines)

    prompt = (
        "You are the explorer half of a decoupled explorer/planner pair "
        "for a vulnerability-research branch. Your job is to spot ONE "
        "LATERAL direction the planner should also consider on its next "
        "turn -- something DISTINCT from the branch's active hypothesis "
        "and NOT already named on the lateral-discovery ledger.\n\n"
        "Active hypotheses on this branch:\n"
        f"{hypothesis_block}\n\n"
        "Lateral discoveries already on the shared ledger (skip these; "
        "the planner already sees them):\n"
        f"{ledger_block}\n\n"
        "Propose ONE new lateral direction as a single line formatted "
        "exactly `<file>|<function>|<one-sentence reason>`. Use `?` for "
        "any field you cannot ground. Reply exactly NONE if nothing new "
        "stands out."
    )

    try:
        client = AilaLLMClient(
            registry=ConfigRegistry(), secret_store=SecretStore(),
        )
        response, _cache_hit = await idempotent_llm_call(
            client,
            method="chat",
            task_type=_EXPLORER_TASK_TYPE,
            messages=[{"role": "user", "content": prompt}],
            investigation_id=investigation_id,
            branch_id=branch_id,
        )
    except (
        OSError, RuntimeError, ValueError, TypeError, AttributeError,
        LLMError,
    ) as exc:
        _log.warning(
            "explorer_planner: LLM chat failed inv=%s err=%s",
            investigation_id, exc,
        )
        return None

    if getattr(response, "disabled", False):
        return None
    return _parse_llm_direction(getattr(response, "content", "") or "")


def _parse_llm_direction(reply: str) -> LateralDirection | None:
    """Parse the explorer LLM reply into a :class:`LateralDirection`.

    Contract with the prompt: one line, ``<file>|<function>|<reason>``,
    or bare ``NONE`` (case-insensitive) when nothing stands out. Any
    other shape returns ``None`` -- the planner then falls back to the
    ledger ranking. The score is set by the caller so ranking policy
    stays in one place.
    """
    if not reply:
        return None
    line = reply.strip().splitlines()[0].strip() if reply.strip() else ""
    if not line or line.upper() == "NONE":
        return None
    # Strip common list-marker prefixes the model likes to emit even
    # when instructed otherwise; ``lstrip`` handles ``-``, ``*``, ``1.``,
    # ``1)``, and their surrounding whitespace.
    line = line.lstrip("-*0123456789.) ").strip()
    parts = [p.strip() for p in line.split("|", 2)]
    if len(parts) != 3:
        return None
    file, function, reason = parts
    if not reason:
        return None
    return LateralDirection(
        score=0,  # caller sets the boost score
        origin="llm",
        source="explorer_llm",
        file=file if file and file != "?" else "",
        function=function if function and function != "?" else "",
        reason=reason[:240],
    )


# ─────────────────────────────────────────────────────────────────
# Planner
# ─────────────────────────────────────────────────────────────────


def planner_pass(
    directions: list[LateralDirection],
    case_state: ReasoningCaseState,
) -> str | None:
    """Planner: pick the top direction and fold it into the next-action
    selection via a ``_directive.explorer_top_lead`` observable.

    Returns the directive text that was written (for logging /
    testing) or ``None`` when no directions were surfaced. Mutates
    ``case_state.observables`` in place.

    Self-clearing contract: the planner ALWAYS pops the prior directive
    at entry so a turn that used to have candidates but no longer does
    (branch pivoted, ledger exhausted) drops the stale lead from the
    next prompt rather than freezing on it.
    """
    prior_key = _TOP_LEAD_KEY
    if prior_key in case_state.observables:
        case_state.observables.pop(prior_key, None)

    if not directions:
        return None

    top = directions[0]
    origin_label = (
        "proposed by the explorer LLM this turn"
        if top.origin == "llm"
        else f"from the shared lateral-discovery ledger (source={top.source}"
        + (f", discovery #{top.discovery_id}" if top.discovery_id else "")
        + ")"
    )
    target_line = " ".join(
        part for part in (
            f"function={top.function}" if top.function else "",
            f"file={top.file}" if top.file else "",
        )
        if part
    ) or "(unspecified target)"
    other_leads = ""
    if len(directions) > 1:
        # Cap the surfaced other-leads block so a busy ledger doesn't
        # blow up the directive. Two is enough to hint alternatives
        # without shouting the whole ranking at the researcher.
        extras = directions[1:3]
        rendered = "\n".join(
            f"  - {d.function or '?'} @ {d.file or '?'} :: "
            f"{d.reason[:160] if d.reason else '(no reason recorded)'}"
            for d in extras
        )
        other_leads = f"\nOther ranked leads:\n{rendered}"

    directive = (
        "*** EXPLORER TOP LEAD (advisory, not a mandate) ***\n"
        f"Origin: {origin_label}.\n"
        f"Lateral target: {target_line}.\n"
        f"Reason: {top.reason or '(no reason recorded)'}\n"
        "\n"
        "This is DISTINCT from the current active hypothesis on this "
        "branch. On the next turn, consider folding it into your action "
        "selection -- read the named function, add a competing hypothesis, "
        "file a variant_hunt ledger request, or explicitly reject it in "
        "your reasoning. You may also stay on the current hypothesis if "
        "the lead is off-target; the planner will re-rank next turn."
        f"{other_leads}"
    )
    case_state.observables[_TOP_LEAD_KEY] = directive
    return directive


# ─────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────


async def maybe_run_explorer_planner(
    *,
    investigation_id: str,
    branch_id: str,
    case_state: ReasoningCaseState,
) -> str | None:
    """Top-level Wave-3 entry point called from the VR turn loop.

    Byte-identity contract: when the ``platform.vr_explorer_enabled``
    flag is OFF (default) this returns ``None`` immediately -- no DB
    read, no LLM construction, no observable write. The disabled path
    is behaviourally byte-identical to today.

    When the flag is ON, runs the explorer pass, then the planner
    pass, and returns the rendered directive text (or ``None`` if the
    explorer surfaced no candidates).

    Best-effort: every failure branch logs at WARNING and returns
    ``None`` so the caller's turn loop never observes an exception
    raised from here.
    """
    if not await _explorer_enabled():
        return None
    try:
        directions = await explorer_pass(
            investigation_id=investigation_id,
            branch_id=branch_id,
            case_state=case_state,
        )
    except (
        OSError, RuntimeError, ValueError, TypeError, AttributeError,
        SQLAlchemyError,
    ) as exc:
        _log.warning(
            "explorer_planner: explorer_pass failed inv=%s branch=%s err=%s",
            investigation_id, branch_id, exc,
        )
        return None
    directive = planner_pass(directions, case_state)
    if directive:
        _log.info(
            "explorer_planner: injected top lead inv=%s branch=%s "
            "candidates=%d top_origin=%s",
            investigation_id, branch_id, len(directions),
            directions[0].origin,
        )
    return directive

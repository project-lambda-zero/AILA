"""RFC-24 context-assembler tests.

Every test operates on the pure-Python assembler + the
CyberReasoningEngine ``build_user_prompt`` integration, so nothing here
touches the DB or ARQ. Runs in-process, fast, hermetic.
"""

from __future__ import annotations

import pytest

from aila.platform.contracts.reasoning import (
    ReasoningOperatorSteering,
    ReasoningPromptContext,
)
from aila.platform.services.context_assembler import (
    AssembledContext,
    ContextAssembler,
    ContextSection,
    ContextTier,
    PinnedOverflowError,
    estimate_tokens,
)
from aila.platform.services.reasoning import CyberReasoningEngine


class _NullLLMClient:
    """Placeholder for the engine constructor -- the tests only exercise
    the deterministic ``build_user_prompt`` path, never the LLM."""

    async def chat_structured(self, **_kwargs: object) -> object:  # pragma: no cover
        raise AssertionError("LLM must not be called in assembler tests")


# --------------------------------------------------------------------------- #
# unit tests for the assembler itself
# --------------------------------------------------------------------------- #


def test_zero_budget_keeps_every_section_verbatim() -> None:
    """``budget_tokens=0`` disables the budget; every non-empty section
    renders at its full body, preserving insertion order."""
    sections = [
        ContextSection(ContextTier.PINNED, "hdr", "header body", droppable=False),
        ContextSection(ContextTier.LIVE, "case", "case body"),
        ContextSection(ContextTier.RECENT, "prev", "recent body"),
    ]
    result = ContextAssembler().assemble(sections)

    assert isinstance(result, AssembledContext)
    assert result.budget_tokens == 0
    assert result.sections_kept == ["hdr", "case", "prev"]
    assert result.sections_summarized == []
    assert result.sections_dropped == []
    assert result.text == "header body\n\ncase body\n\nrecent body"


def test_generous_budget_still_keeps_everything() -> None:
    """A budget large enough for every full body keeps every section
    (regression against the assembler over-aggressively evicting)."""
    sections = [
        ContextSection(ContextTier.PINNED, "hdr", "H" * 40, droppable=False),
        ContextSection(ContextTier.LIVE, "case", "L" * 40),
        ContextSection(ContextTier.RECENT, "prev", "R" * 40),
    ]
    result = ContextAssembler().assemble(sections, budget_tokens=10_000)
    assert result.sections_kept == ["hdr", "case", "prev"]
    assert result.sections_dropped == []


def test_over_budget_drops_recent_before_live() -> None:
    """RFC-24: LIVE outranks RECENT. Under budget pressure the RECENT
    tier is evicted first while LIVE and PINNED survive."""
    pinned_body = "P" * 100
    live_body = "L" * 400  # ~100 tokens
    recent_body = "R" * 1200  # ~300 tokens

    sections = [
        ContextSection(ContextTier.PINNED, "hdr", pinned_body, droppable=False),
        ContextSection(ContextTier.LIVE, "case", live_body),
        ContextSection(ContextTier.RECENT, "prev", recent_body),
    ]
    # ~150 tokens: enough for pinned (~25) + live (~100), but not
    # pinned + live + recent (~450).
    result = ContextAssembler().assemble(sections, budget_tokens=150)

    assert "hdr" in result.sections_kept
    assert "case" in result.sections_kept
    assert "prev" in result.sections_dropped
    assert result.total_tokens <= 150
    assert pinned_body in result.text
    assert live_body in result.text
    assert recent_body not in result.text


def test_summarizable_section_falls_back_to_summary() -> None:
    """A RECENT section carrying a ``summary`` is swapped for that
    shorter form under pressure instead of being dropped -- keeps a
    breadcrumb for the agent that the block existed."""
    live_body = "L" * 400  # ~100 tokens
    recent_body = "R" * 4000  # ~1000 tokens
    recent_summary = "recent: elided"  # ~4 tokens

    sections = [
        ContextSection(ContextTier.PINNED, "hdr", "H" * 40, droppable=False),
        ContextSection(ContextTier.LIVE, "case", live_body),
        ContextSection(
            ContextTier.RECENT, "prev", recent_body, summary=recent_summary,
        ),
    ]
    # Big enough for pinned + live + the summary, but not the full body.
    result = ContextAssembler().assemble(sections, budget_tokens=140)

    assert result.sections_kept == ["hdr", "case"]
    assert result.sections_summarized == ["prev"]
    assert result.sections_dropped == []
    assert live_body in result.text
    assert recent_summary in result.text
    assert recent_body not in result.text


def test_pinned_overflow_raises() -> None:
    """PINNED alone exceeding the budget is the caller's bug -- raise
    rather than silently drop operator-authoritative content."""
    huge_pinned = "P" * 4000  # ~1000 tokens
    sections = [
        ContextSection(ContextTier.PINNED, "hdr", huge_pinned, droppable=False),
    ]
    with pytest.raises(PinnedOverflowError, match="pinned tier requires"):
        ContextAssembler().assemble(sections, budget_tokens=50)


def test_pinned_section_requires_non_droppable() -> None:
    """PINNED + droppable=True is a construction error, not silently
    demoted; keeps the tier meaning honest."""
    with pytest.raises(ValueError, match="PINNED tier requires"):
        ContextSection(ContextTier.PINNED, "hdr", "x")


def test_reserved_tokens_shrink_effective_budget() -> None:
    """``reserved_tokens`` accounts for a caller's separately-sent
    payload (e.g. the system message) so the assembler leaves that
    much of the total budget available."""
    sections = [
        ContextSection(ContextTier.PINNED, "hdr", "H" * 40, droppable=False),
        ContextSection(ContextTier.LIVE, "case", "L" * 400),  # ~100 tokens
        ContextSection(ContextTier.RECENT, "prev", "R" * 1200),  # ~300 tokens
    ]
    # 500 total, but 350 reserved for the system message => 150 for us.
    result = ContextAssembler().assemble(
        sections, budget_tokens=500, reserved_tokens=350,
    )
    assert "prev" in result.sections_dropped


def test_reserved_over_budget_raises_value_error() -> None:
    """A reservation that consumes the whole budget is a caller bug."""
    with pytest.raises(ValueError, match="consumed the entire"):
        ContextAssembler().assemble(
            [ContextSection(ContextTier.PINNED, "hdr", "x", droppable=False)],
            budget_tokens=100,
            reserved_tokens=100,
        )


def test_negative_inputs_rejected() -> None:
    """Symmetry: negative budgets are a caller bug."""
    with pytest.raises(ValueError, match=">= 0"):
        ContextAssembler().assemble([], budget_tokens=-1)
    with pytest.raises(ValueError, match=">= 0"):
        ContextAssembler().assemble([], budget_tokens=100, reserved_tokens=-5)


def test_same_tier_oldest_evicted_first() -> None:
    """Within a tier, insertion order (oldest first) is the tiebreak
    for eviction -- matches the rolling-recent-window intuition
    RFC-24 sketches for the RECENT tier."""
    sections = [
        ContextSection(ContextTier.PINNED, "hdr", "H" * 20, droppable=False),
        ContextSection(ContextTier.RECENT, "prev_old", "R" * 400),   # ~100
        ContextSection(ContextTier.RECENT, "prev_mid", "R" * 400),   # ~100
        ContextSection(ContextTier.RECENT, "prev_new", "R" * 400),   # ~100
    ]
    # ~150 tokens: enough for pinned + roughly one recent block.
    result = ContextAssembler().assemble(sections, budget_tokens=150)
    # The OLDEST recent block should be dropped first, so the newest
    # ("prev_new") must survive. At least one recent block dropped;
    # the earliest-dropped is prev_old.
    assert "prev_new" in result.sections_kept
    assert "prev_old" in result.sections_dropped


def test_insertion_order_preserved_after_eviction() -> None:
    """Dropping a middle section must NOT reorder the survivors."""
    sections = [
        ContextSection(ContextTier.PINNED, "a", "AAA", droppable=False),
        ContextSection(ContextTier.RECENT, "b", "B" * 800),  # ~200 tokens
        ContextSection(ContextTier.PINNED, "c", "CCC", droppable=False),
    ]
    # Small budget: b must be dropped, a + c should render in order.
    result = ContextAssembler().assemble(sections, budget_tokens=100)
    assert result.sections_dropped == ["b"]
    assert result.text == "AAA\n\nCCC"


def test_empty_sections_are_ignored() -> None:
    """Sections with an empty body render nothing and never count
    against telemetry -- avoids ``build_user_prompt`` emitting
    a hanging separator for optional blocks (e.g. steering off)."""
    sections = [
        ContextSection(ContextTier.PINNED, "hdr", "H", droppable=False),
        ContextSection(ContextTier.RECENT, "empty", ""),
        ContextSection(ContextTier.PINNED, "tail", "T", droppable=False),
    ]
    result = ContextAssembler().assemble(sections)
    assert result.text == "H\n\nT"
    assert result.sections_dropped == []
    assert result.sections_kept == ["hdr", "tail"]


def test_estimate_tokens_matches_char_over_four() -> None:
    """Public re-exported helper matches the ``turn_runner``
    PROMPT_SIZE_DIAG heuristic (regression against a future change
    silently drifting the operator-visible size log)."""
    assert estimate_tokens("") == 0
    assert estimate_tokens("x") == 1
    assert estimate_tokens("a" * 8) == 2
    assert estimate_tokens("a" * 4000) == 1000


# --------------------------------------------------------------------------- #
# integration: CyberReasoningEngine.build_user_prompt through the assembler
# --------------------------------------------------------------------------- #


def _base_context(**overrides: object) -> ReasoningPromptContext:
    kwargs: dict[str, object] = {
        "turn": 3,
        "max_turns": 30,
        "question": "Does malware.exe persist via a Run key?",
        "evidence_dir": "/evidence/inv-1",
        "evidence_listing": "\n".join(f"file_{i}.bin" for i in range(20)),
        "project_kind": "raw_directory",
        "case_model": "\n".join(f"case line {i}" for i in range(20)),
        "artifacts": "\n== artefact 1\n" + ("A" * 300),
        "previous": "\n".join(f"[turn {i}] tool_run" for i in range(30)),
        "domain_profile": "dfir",
        "operator_steering": ReasoningOperatorSteering(
            confirmed_facts=["persistence hunt in scope"],
            guidance=["prefer registry over service persistence"],
        ),
        "strategy_family": "persistence_hunt",
    }
    kwargs.update(overrides)
    return ReasoningPromptContext(**kwargs)


def test_build_user_prompt_zero_budget_produces_full_prompt() -> None:
    """Zero-budget path preserves the historical unbounded concat --
    the transcript, evidence listing, case model, and artifacts all
    render at full body."""
    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    ctx = _base_context()

    prompt = engine.build_user_prompt(ctx)

    assert "Turn 3/30. User question:" in prompt
    assert "Does malware.exe persist via a Run key?" in prompt
    assert "OPERATOR STEERING:" in prompt
    assert "confirmed_fact = persistence hunt in scope" in prompt
    assert "PROJECT KIND: raw_directory" in prompt
    assert "Evidence directory: /evidence/inv-1" in prompt
    assert "file_19.bin" in prompt
    assert "case line 19" in prompt
    assert "[turn 29] tool_run" in prompt
    assert "Return a single JSON object" in prompt


def test_build_user_prompt_tight_budget_drops_low_priority_tiers() -> None:
    """A tight budget forces the assembler to drop or summarise the
    RECENT tier (evidence listing, artifacts, transcript) while the
    PINNED tier (question, steering, project kind, response contract)
    and the LIVE tier (case model) survive.

    This is the RFC-24 acceptance test: budget-bounded, tier-prioritised
    context that preserves high-priority directives when over budget."""
    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    ctx = _base_context(context_budget_tokens=250)

    prompt = engine.build_user_prompt(ctx)
    prompt_tokens = estimate_tokens(prompt)

    # Fits in budget.
    assert prompt_tokens <= 250, f"assembler exceeded budget: {prompt_tokens}"
    # PINNED content survives.
    assert "Turn 3/30. User question:" in prompt
    assert "Does malware.exe persist via a Run key?" in prompt
    assert "OPERATOR STEERING:" in prompt
    assert "confirmed_fact = persistence hunt in scope" in prompt
    assert "PROJECT KIND: raw_directory" in prompt
    assert "Return a single JSON object" in prompt
    # LIVE content survives (may be dropped only if pinned + case model
    # alone still overflow -- with this budget we expect it to survive).
    assert "Case model so far:" in prompt
    # RECENT tier content is elided: the full transcript, artifact
    # body, and last evidence file entry are gone. Their summary
    # placeholders may or may not appear depending on how many
    # tiers were dropped, but the last transcript entry MUST be
    # absent (it's the surest RECENT-only marker).
    assert "[turn 29] tool_run" not in prompt


def test_build_user_prompt_extreme_budget_drops_live_before_pinned() -> None:
    """An extreme budget forces even the LIVE case model out, but the
    PINNED tier is inviolable and still renders in full."""
    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    # Make the case model heavy enough that even after every RECENT
    # section is gone we still need to drop LIVE.
    heavy_case = "\n".join(f"case line {i}" for i in range(500))
    ctx = _base_context(
        case_model=heavy_case,
        context_budget_tokens=200,
    )

    prompt = engine.build_user_prompt(ctx)
    assert estimate_tokens(prompt) <= 200
    # PINNED content still there.
    assert "OPERATOR STEERING:" in prompt
    assert "Return a single JSON object" in prompt
    # LIVE case model gone.
    assert "Case model so far:" not in prompt


def test_build_user_prompt_pinned_overflow_raises() -> None:
    """When PINNED content alone exceeds budget, the caller sees a
    :class:`PinnedOverflowError` rather than a silently-truncated
    prompt with dropped operator steering."""
    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    # Massive operator steering pushes PINNED tier past a small budget.
    huge_guidance = ["G" * 400 for _ in range(20)]  # ~2000 tokens of pinned
    ctx = _base_context(
        operator_steering=ReasoningOperatorSteering(guidance=huge_guidance),
        context_budget_tokens=100,
    )
    with pytest.raises(PinnedOverflowError):
        engine.build_user_prompt(ctx)


def test_build_user_prompt_zero_budget_matches_historical_shape() -> None:
    """Regression: the zero-budget path must keep the every-line
    ordering the modules' existing regexes and log parsers depend on."""
    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    ctx = _base_context()
    prompt = engine.build_user_prompt(ctx)

    lines = prompt.splitlines()
    # Header first, response contract last -- keeps the operator-visible
    # top of the prompt where operators expect to see the question.
    assert lines[0] == "Turn 3/30. User question:"
    assert lines[-1] == "Return a single JSON object matching the response contract."
    # OPERATOR STEERING appears before Evidence directory (steering
    # is PINNED, evidence is RECENT; both survive at zero budget and
    # the assembler preserves original insertion order).
    steer_idx = lines.index("OPERATOR STEERING:")
    ev_idx = next(
        i for i, ln in enumerate(lines) if ln.startswith("Evidence directory:")
    )
    assert steer_idx < ev_idx

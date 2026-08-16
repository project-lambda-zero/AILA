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
    SummaryProducer,
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
    tier is evicted first while LIVE and PINNED survive. RFC-24 step 2:
    the evicted RECENT section is FOLDED into a synthesized SUMMARY
    entry instead of vanishing, so its label lands in
    ``sections_folded_into_summary`` rather than ``sections_dropped``."""
    pinned_body = "P" * 100
    live_body = "L" * 400  # ~100 tokens
    recent_body = "R" * 1200  # ~300 tokens

    sections = [
        ContextSection(ContextTier.PINNED, "hdr", pinned_body, droppable=False),
        ContextSection(ContextTier.LIVE, "case", live_body),
        ContextSection(ContextTier.RECENT, "prev", recent_body),
    ]
    # ~200 tokens: enough for pinned (~25) + live (~100) + one
    # SUMMARY bullet (~60), but not pinned + live + recent (~450).
    result = ContextAssembler().assemble(sections, budget_tokens=200)

    assert "hdr" in result.sections_kept
    assert "case" in result.sections_kept
    assert "prev" in result.sections_folded_into_summary
    assert "prev" not in result.sections_dropped
    assert "rolling_summary" in result.sections_kept
    assert result.total_tokens <= 200
    assert pinned_body in result.text
    assert live_body in result.text
    # The 1200-char recent body is gone verbatim; the SUMMARY bullet
    # only carries a stance (<= 140 chars) + anchors, and this body
    # has neither meaningful anchors nor a prose stance longer than
    # its stance cap, so the full body substring is absent.
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
    # Reserved-space eviction evicts the RECENT section (folded into
    # SUMMARY if the fold fits, otherwise dropped plainly). This test
    # only proves the reservation shrinks the effective budget.
    evicted = (
        set(result.sections_folded_into_summary)
        | set(result.sections_dropped)
    )
    assert "prev" in evicted


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
    # The OLDEST recent block MUST be evicted first (the tiebreak is
    # insertion order), so the newest ("prev_new") survives. The
    # earliest-evicted section is either folded into SUMMARY or
    # (when even the SUMMARY entry cannot fit) dropped plainly --
    # this test only asserts the eviction ORDER, not the disposition.
    assert "prev_new" in result.sections_kept
    evicted = (
        set(result.sections_folded_into_summary)
        | set(result.sections_dropped)
    )
    assert "prev_old" in evicted


def test_insertion_order_preserved_after_eviction() -> None:
    """Evicting a middle RECENT section must NOT reorder the survivors.

    RFC-24 step 2: the evicted RECENT block is folded into a
    synthesized SUMMARY entry positioned "below RECENT" -- right after
    the last RECENT-tier slot in the caller's insertion order, above
    any trailing PINNED (response contract / instruction) sections."""
    sections = [
        ContextSection(ContextTier.PINNED, "a", "AAA", droppable=False),
        ContextSection(ContextTier.RECENT, "b", "B" * 800),  # ~200 tokens
        ContextSection(ContextTier.PINNED, "c", "CCC", droppable=False),
    ]
    # Small budget: b must be evicted, a + c must render in order,
    # and the synthesized SUMMARY sits between b's original slot and
    # the trailing PINNED c.
    result = ContextAssembler().assemble(sections, budget_tokens=100)
    assert result.sections_folded_into_summary == ["b"]
    assert result.sections_dropped == []
    # a first, SUMMARY next (b's slot), c last -- PINNED trailer
    # survives at the very bottom.
    a_idx = result.text.index("AAA")
    c_idx = result.text.index("CCC")
    summary_idx = result.text.index("# Rolling summary")
    assert a_idx < summary_idx < c_idx


def test_insertion_order_preserved_when_summary_disabled() -> None:
    """Regression: passing ``summary_producer=None`` restores the
    pre-step-2 behaviour where an evicted middle RECENT section is
    dropped outright and the surviving PINNED blocks butt up
    against each other."""
    sections = [
        ContextSection(ContextTier.PINNED, "a", "AAA", droppable=False),
        ContextSection(ContextTier.RECENT, "b", "B" * 800),  # ~200 tokens
        ContextSection(ContextTier.PINNED, "c", "CCC", droppable=False),
    ]
    result = ContextAssembler(summary_producer=None).assemble(
        sections, budget_tokens=100,
    )
    assert result.sections_dropped == ["b"]
    assert result.sections_folded_into_summary == []
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
# RFC-24 step 2: rolling SUMMARY producer + anchor-preservation guardrail
# --------------------------------------------------------------------------- #


def test_summary_producer_extracts_anchors_verbatim() -> None:
    """The producer copies file:line anchors from the source body
    without any transformation -- normalisation, separator rewrite,
    or line-number arithmetic would violate the RFC-24 audit-chain
    guardrail."""
    body = (
        "The parser at src/aila/x.py:42 dispatches through "
        "src/aila/x.py:42-88, then falls into "
        "C:\\Users\\a\\y.c:120:10 for the fast path. "
        "URL http://example:8080/foo must NOT match."
    )
    sec = ContextSection(ContextTier.RECENT, "trace", body)
    produced = SummaryProducer().fold([sec])
    assert produced is not None
    text = produced.body

    for anchor in (
        "src/aila/x.py:42",
        "src/aila/x.py:42-88",
        "C:\\Users\\a\\y.c:120:10",
    ):
        assert anchor in text, f"missing anchor {anchor!r} in {text!r}"
    # URL port pattern must be absent (regex would misclassify it).
    assert "example:8080" not in text


def test_summary_producer_bullet_has_kind_and_stance() -> None:
    """Each bullet carries the source tier/label + a one-line stance
    extracted from the body -- gives the reader a directional cue
    without paraphrasing the underlying anchors."""
    body = "This is the first meaningful line.\nsrc/aila/x.py:42 is the anchor."
    sec = ContextSection(ContextTier.RECENT, "hypothesis_note", body)
    produced = SummaryProducer().fold([sec])
    assert produced is not None
    assert produced.tier == ContextTier.SUMMARY
    assert produced.label == "rolling_summary"
    assert "- [RECENT/hypothesis_note]" in produced.body
    assert "This is the first meaningful line." in produced.body
    assert "src/aila/x.py:42" in produced.body


def test_summary_producer_empty_input_returns_none() -> None:
    """No evictions -> no synthesized section -> caller sees no
    SUMMARY tier entry in the assembled result."""
    assert SummaryProducer().fold([]) is None


def test_summary_producer_caps_anchor_list_never_the_string() -> None:
    """A runaway body cannot inflate the summary past
    ``max_anchors_per_section`` bullets -- but the anchors that DO
    make it in are still VERBATIM (never truncated at the string
    level)."""
    body = "\n".join(f"path/to/file_{i}.c:{i}" for i in range(60))
    sec = ContextSection(ContextTier.RECENT, "many_anchors", body)
    produced = SummaryProducer(max_anchors_per_section=10).fold([sec])
    assert produced is not None
    # first 10 anchors kept verbatim, plus a "(+50 more)" cue.
    for i in range(10):
        assert f"path/to/file_{i}.c:{i}" in produced.body
    assert "(+50 more)" in produced.body


def test_folded_summary_preserves_anchors_in_assembled_text() -> None:
    """End-to-end: an over-budget RECENT section carrying file:line
    anchors gets folded, and the anchors survive VERBATIM in the
    fitted prompt even though the prose is gone -- the RFC-24
    audit-chain guardrail."""
    prose_marker = "MARKER_XYZZY_UNIQUE"
    prose_line = f"prose line {prose_marker} " * 20
    prose = "\n".join(prose_line for _ in range(30))
    anchored_body = (
        prose
        + "\nsrc/aila/x.py:42 is the site the branch consulted; "
        + "see also plugins/foo/bar.c:120-133 for the caller."
    )
    sections = [
        ContextSection(
            ContextTier.PINNED, "hdr", "H" * 40, droppable=False,
        ),
        ContextSection(ContextTier.LIVE, "case", "L" * 400),  # ~100 tok
        ContextSection(ContextTier.RECENT, "trace", anchored_body),
    ]
    # Budget: enough for PINNED + LIVE + a SUMMARY bullet, but not
    # for the full anchored_body.
    result = ContextAssembler().assemble(sections, budget_tokens=200)

    assert "trace" in result.sections_folded_into_summary
    # Anchors survived VERBATIM.
    assert "src/aila/x.py:42" in result.text
    assert "plugins/foo/bar.c:120-133" in result.text
    # Prose collapsed to at most one truncated stance line: 600
    # repetitions of the marker on 30 lines are gone; only what
    # fits in a single ~140-char stance survives.
    assert result.text.count(prose_marker) <= 15


def test_summary_dropped_when_it_would_still_overflow_budget() -> None:
    """If the synthesized SUMMARY entry itself cannot fit, the
    assembler falls back to the pre-step-2 behaviour (plain drop)
    rather than silently violating the budget."""
    # Small budget: no room for anything past the PINNED header.
    sections = [
        ContextSection(ContextTier.PINNED, "hdr", "H" * 40, droppable=False),
        ContextSection(
            ContextTier.RECENT, "big",
            "\n".join(f"path/to/f{i}.c:{i}" for i in range(500)),
        ),
    ]
    # Effective budget ~15 tokens -- big-anchor body summary needs
    # far more, so the fold has to be reverted.
    result = ContextAssembler().assemble(sections, budget_tokens=15)
    assert "big" in result.sections_dropped
    assert "big" not in result.sections_folded_into_summary
    assert result.total_tokens <= 15


def test_no_eviction_produces_no_summary_and_is_byte_identical() -> None:
    """Behaviour-preservation guarantee: with a generous budget, the
    assembler MUST produce byte-identical output to the same call
    with ``summary_producer=None``. RFC-24 step 2 changes on-drop
    behaviour ONLY."""
    sections = [
        ContextSection(ContextTier.PINNED, "hdr", "header body", droppable=False),
        ContextSection(ContextTier.LIVE, "case", "case body"),
        ContextSection(ContextTier.RECENT, "prev", "recent body"),
    ]
    with_producer = ContextAssembler().assemble(sections, budget_tokens=10_000)
    without = ContextAssembler(summary_producer=None).assemble(
        sections, budget_tokens=10_000,
    )
    assert with_producer.text == without.text
    assert with_producer.sections_kept == without.sections_kept
    assert with_producer.sections_folded_into_summary == []
    assert without.sections_folded_into_summary == []


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


# --------------------------------------------------------------------------- #
# module-shape prebuilt_sections + config-resolved default budget
# --------------------------------------------------------------------------- #


def _vr_shape_sections(
    *,
    directive: str = "",
    case_model: str = "observables: (none)",
    tools_body: str = "# Available tools\naudit_mcp.read_function(name: str [required])",
    priors: str = "",
    siblings: str = "",
) -> list[ContextSection]:
    """Build the exact tiered section list VR emits after the routing
    change: PINNED operator/directive/header/target/tools/instruction,
    LIVE case_model, RECENT priors/siblings.

    Kept local so the test asserts the shared assembler behaviour
    against the SAME tier map VR's ``_build_user_prompt`` uses; a
    future drift between the two would surface as a test failure.
    """
    sections: list[ContextSection] = [
        ContextSection(
            tier=ContextTier.PINNED,
            label="operator_messages",
            body="# *** OPERATOR STEERING -- MANDATORY OVERRIDE ***\nMSG-1: run",
            droppable=False,
        ),
    ]
    if directive:
        sections.append(ContextSection(
            tier=ContextTier.PINNED,
            label="active_directives",
            body=directive,
            droppable=False,
        ))
    sections.append(ContextSection(
        tier=ContextTier.PINNED,
        label="investigation_header",
        body="# Investigation\n\nQuestion: is CVE-2026-1234 exploitable?",
        droppable=False,
    ))
    sections.append(ContextSection(
        tier=ContextTier.PINNED,
        label="target_snapshot",
        body="# Primary target snapshot\nkind: source_repo",
        droppable=False,
    ))
    sections.append(ContextSection(
        tier=ContextTier.LIVE,
        label="case_model",
        body="# Current case state\n\n" + case_model,
    ))
    if priors:
        sections.append(ContextSection(
            tier=ContextTier.RECENT,
            label="prior_submissions",
            body=priors,
            summary="# Prior submissions: elided for budget",
        ))
    if siblings:
        sections.append(ContextSection(
            tier=ContextTier.RECENT,
            label="sibling_context",
            body=siblings,
            summary="# Sibling deliberations: elided for budget",
        ))
    sections.append(ContextSection(
        tier=ContextTier.PINNED,
        label="available_tools",
        body=tools_body,
        droppable=False,
    ))
    sections.append(ContextSection(
        tier=ContextTier.PINNED,
        label="instruction",
        body="# Instruction\n\nProduce the next reasoning turn as a JSON object per the system prompt schema.",
        droppable=False,
    ))
    return sections


def _vr_context(
    sections: list[ContextSection], budget: int = 0,
) -> ReasoningPromptContext:
    return ReasoningPromptContext(
        turn=3,
        max_turns=30,
        question="is CVE-2026-1234 exploitable?",
        prebuilt_sections=sections,
        context_budget_tokens=budget,
    )


def test_vr_shape_large_budget_preserves_every_section_in_order() -> None:
    """Acceptance (a): a VR-shaped ReasoningPromptContext assembled
    with a large budget contains every section in insertion order --
    materially equivalent to the pre-change hand-rolled f-string."""
    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    sections = _vr_shape_sections(
        directive="# *** ACTIVE DIRECTIVES ***\ndirective: pivot to xssdrop.c:412",
        case_model="Live hypotheses (1):\n  - H1: CVE-2026-1234 hits parse_frame",
        priors="# Prior submissions\nAssessmentReport (medium)",
        siblings="# Sibling deliberations\nMaddie: agrees with H1",
    )
    ctx = _vr_context(sections, budget=100_000)

    prompt = engine.build_user_prompt(ctx)

    # Every section renders at full body.
    expected_labels = [
        "# *** OPERATOR STEERING -- MANDATORY OVERRIDE ***",
        "# *** ACTIVE DIRECTIVES ***",
        "# Investigation",
        "# Primary target snapshot",
        "# Current case state",
        "# Prior submissions",
        "# Sibling deliberations",
        "# Available tools",
        "# Instruction",
    ]
    for label in expected_labels:
        assert label in prompt, f"missing block: {label!r}"

    # Insertion order matches the historical concatenation.
    positions = [prompt.index(label) for label in expected_labels]
    assert positions == sorted(positions), (
        f"section order drifted: {positions}"
    )


def test_vr_shape_small_budget_keeps_pinned_drops_or_summarizes_recent() -> None:
    """Acceptance (b): under budget pressure, PINNED (operator,
    directives, header, target, tools, instruction) survive intact
    while RECENT (priors, siblings) drop or fall back to summary --
    operator-authoritative and kill-criterion content is NEVER
    truncated."""
    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    heavy_priors = "# Prior submissions\n" + "P" * 4000  # ~1000 tokens
    heavy_siblings = "# Sibling deliberations\n" + "S" * 4000  # ~1000 tokens
    heavy_case = "# Current case state -- heavy\n" + "L" * 4000  # ~1000 tokens
    sections = _vr_shape_sections(
        directive="# *** ACTIVE DIRECTIVES ***\nkill hypothesis when parse_frame returns 0",
        case_model=heavy_case,
        priors=heavy_priors,
        siblings=heavy_siblings,
    )
    # Tight budget: keeps pinned tier + drops or summarises RECENT.
    ctx = _vr_context(sections, budget=400)

    prompt = engine.build_user_prompt(ctx)

    # PINNED tier survives verbatim.
    assert "# *** OPERATOR STEERING -- MANDATORY OVERRIDE ***" in prompt
    assert "# *** ACTIVE DIRECTIVES ***" in prompt
    assert "kill hypothesis when parse_frame returns 0" in prompt
    assert "# Investigation" in prompt
    assert "# Primary target snapshot" in prompt
    assert "# Available tools" in prompt
    assert "# Instruction" in prompt
    # RECENT tier is elided: either dropped outright, swapped for its
    # per-section summary, or folded into the rolling SUMMARY entry.
    # In every case the FULL heavy body is gone -- at most a truncated
    # ~140-char stance line survives inside a SUMMARY bullet, so an
    # order-of-magnitude longer run of the marker char must be absent.
    assert "P" * 500 not in prompt
    assert "S" * 500 not in prompt


def test_build_user_prompt_zero_budget_applies_config_default() -> None:
    """Acceptance (d): a caller passing ``context_budget_tokens=0``
    still gets a real budget applied -- forensics + malware + any
    hand-build path that still runs through ``build_user_prompt``
    cannot regress into an unbounded prompt after
    ``render_case_model``'s display caps were removed."""
    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    # Force a small budget through the platform config -- proves the
    # engine reads the config and uses it as the fallback (rather
    # than silently defaulting to unbounded on zero).
    class _StubRegistry:
        def get_sync(self, namespace: str, key: str) -> object:
            assert namespace == "platform"
            if key == "reasoning_context_budget_tokens":
                return 400
            return None

    engine._config_registry = _StubRegistry()  # type: ignore[attr-defined]

    heavy_priors = "# Prior submissions\n" + "P" * 4000
    sections = _vr_shape_sections(priors=heavy_priors)
    ctx = _vr_context(sections, budget=0)

    prompt = engine.build_user_prompt(ctx)

    # Prompt fits the config-resolved fallback budget (400 tokens),
    # confirming zero != unbounded. The heavy priors block is
    # elided; PINNED content survives.
    assert estimate_tokens(prompt) <= 400
    assert "# *** OPERATOR STEERING -- MANDATORY OVERRIDE ***" in prompt
    assert "PPPPPPPPP" not in prompt


def test_build_user_prompt_default_budget_fallback_when_no_registry() -> None:
    """Regression: with no ConfigRegistry wired (narrow unit-test
    construction), the engine falls back to the module-level
    ``_DEFAULT_CONTEXT_BUDGET_TOKENS`` constant. Small VR prompts
    still assemble in full because the default (180K) dwarfs them.
    """
    from aila.platform.services.reasoning import (
        _DEFAULT_CONTEXT_BUDGET_TOKENS,
    )

    engine = CyberReasoningEngine(_NullLLMClient())  # type: ignore[arg-type]
    assert engine.resolve_context_budget_tokens() == _DEFAULT_CONTEXT_BUDGET_TOKENS
    ctx = _vr_context(_vr_shape_sections(), budget=0)

    prompt = engine.build_user_prompt(ctx)

    # Small prompt fits comfortably; every PINNED block survives.
    assert "# *** OPERATOR STEERING -- MANDATORY OVERRIDE ***" in prompt
    assert "# Investigation" in prompt
    assert "# Available tools" in prompt
    assert "# Instruction" in prompt

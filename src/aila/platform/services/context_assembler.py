"""RFC-24 tiered, budget-aware context assembler.

The reasoning engine used to concatenate its per-turn prompt as an
unbounded flat block: system prompt + operator steering + tools spec +
case model + evidence listing + transcript. The only size control was
the observable cap inside ``render_case_model``. On slow providers, a
first-turn prompt could exceed the model's context window and kill the
branch at turn 0 before any progress. RFC-24 requires the assembler to
fit the prompt to a token budget while preserving the highest-priority
content (system directives, operator steering, kill criteria).

Design
------

* Every piece of the per-turn prompt is a :class:`ContextSection`
  tagged with a :class:`ContextTier` and (optionally) a summarised
  fallback body.
* Tiers are ordered by priority, highest first: ``PINNED > LIVE >
  RECENT > RETRIEVED > SUMMARY``. ``PINNED`` sections are never
  evicted -- if they alone exceed the budget the assembler raises
  :class:`PinnedOverflowError` rather than silently dropping
  operator-authoritative content.
* When the remaining tiers exceed the budget, the assembler walks
  lower-priority sections in reverse-priority order and either
  swaps in the section's ``summary`` (if provided) or drops the
  section entirely, until everything fits.
* Section INSERTION ORDER is preserved in the final text: dropping a
  RECENT block never reorders the surviving PINNED blocks. This
  matches how :func:`CyberReasoningEngine.build_user_prompt`
  currently reads top-to-bottom.

The current step delivers RFC-24's first increment (tiered assembler +
recent/pinned tiers). The store-backed ``RETRIEVED`` and rolling
``SUMMARY`` tiers land later; leaving them in the enum here means those
increments only need to add a new :class:`ContextSection` producer, not
another assembler.

The token estimator is intentionally the same ``len(text) // 4``
heuristic used by ``turn_runner.PROMPT_SIZE_DIAG``. A precise
tokenizer would tie the engine to one provider; the heuristic is
per-tier stable and matches how the operator-visible size log
already accounts prompt bytes.

Observable-cap coordination
---------------------------

``CyberReasoningEngine.absorb`` still owns the per-turn observable
caps (10 new agent keys per turn, 150-key ceiling, tool-prefix keys
never evicted) and ``render_case_model`` still owns tool-reading
partitioning + the recent/recalled full-body render. The assembler
consumes the ALREADY-CAPPED case model as one ``LIVE`` section; it
does not re-cap observables. This preserves the RFC-24 guardrail
that summarisation must not paraphrase file:line anchors: the case
model text is the audit-preserving surface and the assembler either
keeps it verbatim or drops it wholesale.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import IntEnum

__all__ = [
    "AssembledContext",
    "ContextAssembler",
    "ContextSection",
    "ContextTier",
    "PinnedOverflowError",
    "estimate_tokens",
]


class ContextTier(IntEnum):
    """Priority tier for a :class:`ContextSection`.

    Lower integer value = HIGHER retention priority. ``PINNED`` is
    inviolable; the remaining tiers are evicted or summarised in
    reverse priority order (``SUMMARY`` first, ``PINNED`` last).
    """

    PINNED = 0
    LIVE = 1
    RECENT = 2
    RETRIEVED = 3
    SUMMARY = 4


@dataclass(frozen=True, slots=True)
class ContextSection:
    """One labelled block of prompt text.

    ``body`` is the full-detail rendering. ``summary`` -- if set -- is
    a compressed fallback the assembler substitutes when the full body
    does not fit. Set ``summary`` for sections where a shorter form
    still carries useful signal (the last-turns transcript, for
    example, can be trimmed to a running summary); leave it ``None``
    for sections that are either fully-rendered or dropped (a stray
    evidence listing block, an artifacts catalogue).

    ``droppable`` is a hard safety flag: the assembler refuses to
    drop or summarise a section with ``droppable=False`` and treats it
    like a PINNED item regardless of its tier. Every ``ContextTier.PINNED``
    section is validated as ``droppable=False``.
    """

    tier: ContextTier
    label: str
    body: str
    summary: str | None = None
    droppable: bool = True

    def __post_init__(self) -> None:
        if self.tier == ContextTier.PINNED and self.droppable:
            # PINNED == inviolable. A "droppable pinned" section is
            # a caller bug: either it belongs to a lower tier or the
            # caller meant droppable=False. Fail closed so the mistake
            # surfaces during prompt build rather than silently in a
            # production turn.
            raise ValueError(
                f"context section {self.label!r}: PINNED tier requires "
                "droppable=False",
            )


class PinnedOverflowError(RuntimeError):
    """Raised when :class:`ContextTier.PINNED` sections alone exceed budget.

    PINNED content is the system prompt, operator steering, and kill
    criteria -- the RFC-24 guardrail says we never evict them. If the
    caller's declared pinned content is already over the budget, the
    caller has to shrink the pinned content or grow the budget; the
    assembler cannot silently truncate.
    """


@dataclass(slots=True)
class AssembledContext:
    """Result of one :meth:`ContextAssembler.assemble` call.

    ``text`` is the fitted prompt body. The three label lists carry the
    per-section disposition so callers (and tests) can assert the
    assembler kept the right things: ``sections_kept`` = full-body,
    ``sections_summarized`` = swapped for their ``summary`` fallback,
    ``sections_dropped`` = omitted entirely.
    """

    text: str
    total_tokens: int
    budget_tokens: int
    sections_kept: list[str] = field(default_factory=list)
    sections_summarized: list[str] = field(default_factory=list)
    sections_dropped: list[str] = field(default_factory=list)


def estimate_tokens(text: str) -> int:
    """Approximate token count using the same heuristic as
    ``turn_runner.PROMPT_SIZE_DIAG``.

    ``len(text) // 4`` matches Anthropic's public rough guidance and
    stays consistent with the per-component size logs the operator
    already reads. A precise tokenizer would tie the engine to one
    provider; this heuristic is stable per-tier and cheap enough to
    run on every candidate rendering during assembly.

    ``max(1, ...)`` for a non-empty string keeps a very short section
    (one word) from being accounted as 0 tokens -- avoids a class of
    "assembler thought it was free" foot-guns when many tiny sections
    stack up.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


@dataclass(slots=True)
class ContextAssembler:
    """RFC-24 tiered, budget-aware prompt assembler.

    Construct once per reasoning engine (or per turn) and reuse. The
    assembler is stateless between :meth:`assemble` calls; the state
    lives on the input :class:`ContextSection` sequence.
    """

    separator: str = "\n\n"

    def assemble(
        self,
        sections: Sequence[ContextSection],
        *,
        budget_tokens: int = 0,
        reserved_tokens: int = 0,
    ) -> AssembledContext:
        """Fit ``sections`` into ``budget_tokens`` and return the result.

        ``budget_tokens=0`` disables the budget: every section renders
        at full body. ``reserved_tokens`` subtracts a caller-declared
        overhead (e.g. the system message the caller sends alongside
        the assembled user prompt) so the assembler leaves that many
        tokens available for content it does not itself see.

        Raises :class:`PinnedOverflowError` when the PINNED tier alone
        exceeds the effective budget (``budget_tokens - reserved_tokens``).
        Raises :class:`ValueError` on a negative effective budget.
        """
        if budget_tokens < 0 or reserved_tokens < 0:
            raise ValueError(
                "budget_tokens and reserved_tokens must both be >= 0"
            )
        effective = budget_tokens - reserved_tokens if budget_tokens else 0
        if budget_tokens and effective <= 0:
            raise ValueError(
                f"reserved_tokens={reserved_tokens} consumed the entire "
                f"budget_tokens={budget_tokens}; grow the budget"
            )

        # Freeze the caller's insertion order so we can restore it at
        # render time -- the reverse-priority walk below only decides
        # WHICH sections stay, never their position.
        ordered = list(enumerate(sections))
        # Per-slot decision: True = keep body, False = keep summary,
        # None = drop. Start with every non-empty section as "keep body";
        # empty bodies are dropped up front so they do not clutter the
        # kept list or eat separators.
        keep_body: dict[int, bool | None] = {}
        for idx, sec in ordered:
            keep_body[idx] = True if sec.body else None

        def _rendered_text(idx: int, section: ContextSection) -> str:
            state = keep_body[idx]
            if state is None:
                return ""
            if state:
                return section.body
            return section.summary or ""

        def _current_tokens() -> int:
            pieces = [
                _rendered_text(idx, sec)
                for idx, sec in ordered
                if keep_body[idx] is not None and _rendered_text(idx, sec)
            ]
            if not pieces:
                return 0
            joined = self.separator.join(pieces)
            return estimate_tokens(joined)

        # RFC-24 guardrail: PINNED content is inviolable. If the
        # pinned tier alone blows the budget the caller is holding a
        # bug (or the model window is smaller than the persona brief);
        # either way the correct signal is a raised error, not a
        # silent drop of operator-authoritative content.
        if effective:
            pinned_pieces = [
                sec.body for _, sec in ordered
                if sec.tier == ContextTier.PINNED and sec.body
            ]
            if pinned_pieces:
                pinned_tokens = estimate_tokens(
                    self.separator.join(pinned_pieces)
                )
                if pinned_tokens > effective:
                    raise PinnedOverflowError(
                        f"pinned tier requires {pinned_tokens} tokens but "
                        f"only {effective} available "
                        f"(budget={budget_tokens}, reserved={reserved_tokens})"
                    )

        # Fit lower-priority tiers by walking sections in
        # reverse-priority order (SUMMARY tier first, PINNED tier
        # last). Same-tier ties break by insertion order -- the
        # OLDEST section in a tier evicts first, matching the
        # rolling-window intuition RFC-24 sketches for RECENT. Two
        # passes guarantee that a RECENT summary evicts BEFORE any
        # LIVE body is dropped: pass 1 summarises, pass 2 drops.
        # Without the split, a heavy RECENT block would be swapped
        # to its summary and then the loop would move on to LIVE
        # (which has no summary) and drop it -- inverting the tier
        # priority the RFC-24 acceptance test asserts.
        if effective:
            eviction_order = sorted(
                ordered,
                # Highest tier value (== lowest retention priority)
                # first; oldest insertion index first within a tier.
                key=lambda item: (-item[1].tier.value, item[0]),
            )
            # Pass 1: swap body -> summary where a summary exists.
            for idx, section in eviction_order:
                if _current_tokens() <= effective:
                    break
                if not section.droppable:
                    continue
                if section.tier == ContextTier.PINNED:
                    # Defensive: droppable=False is already enforced
                    # in ContextSection.__post_init__, but skip PINNED
                    # here too so a future refactor cannot regress.
                    continue
                if keep_body[idx] is not True:
                    continue
                if section.summary:
                    keep_body[idx] = False
            # Pass 2: still over budget -- drop from lowest priority,
            # including sections already reduced to their summary.
            # Dropping a RECENT summary before touching a LIVE body
            # preserves the RFC-24 tier ordering.
            for idx, section in eviction_order:
                if _current_tokens() <= effective:
                    break
                if not section.droppable:
                    continue
                if section.tier == ContextTier.PINNED:
                    continue
                if keep_body[idx] is None:
                    continue
                keep_body[idx] = None

        # Compose the final text in ORIGINAL order, using each slot's
        # current decision. Compute telemetry alongside so callers can
        # verify what stayed vs what got summarised vs dropped.
        rendered: list[str] = []
        kept: list[str] = []
        summarized: list[str] = []
        dropped: list[str] = []
        for idx, section in ordered:
            state = keep_body[idx]
            if state is None:
                if section.body:
                    dropped.append(section.label)
                continue
            if state:
                kept.append(section.label)
                rendered.append(section.body)
            else:
                summarized.append(section.label)
                rendered.append(section.summary or "")

        text = self.separator.join(rendered)
        return AssembledContext(
            text=text,
            total_tokens=estimate_tokens(text),
            budget_tokens=budget_tokens,
            sections_kept=kept,
            sections_summarized=summarized,
            sections_dropped=dropped,
        )

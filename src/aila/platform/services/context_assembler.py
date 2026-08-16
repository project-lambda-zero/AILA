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

Rolling SUMMARY tier (RFC-24 step 2)
------------------------------------

Steps 1 delivered the tiered assembler + recent/pinned tiers. Step 2 --
the rolling SUMMARY producer -- lands here: when a ``RECENT`` (or
``RETRIEVED``) section would be DROPPED to fit the budget, the
assembler instead folds it into a single synthesized ``SUMMARY``-tier
section that preserves the section's file:line anchors VERBATIM. The
RFC-24 guardrail is explicit -- summarisation must not paraphrase a
``path:line`` anchor -- so the producer uses a regex extraction over
the original body, never an LLM, and joins the extracted substrings
straight into the summary bullet.

The producer is deterministic and pluggable. The platform default is
:class:`SummaryProducer`, which emits one bullet per evicted section
with ``kind`` (tier/label), a one-line stance from the original body,
and the extracted anchor list verbatim. An LLM-backed producer can be
supplied via the ``summary_producer`` field, but it MUST route through
``platform.agents.idempotent_llm_call`` (RFC-09 retry replay) and
remain OFF by default -- the deterministic producer is the shipping
path so a retried worker never re-pays for a summary and every
anchor stays byte-identical to the source. The store-backed
``RETRIEVED`` tier + shared cross-branch pool land in a later step;
leaving ``RETRIEVED`` in the enum means those increments only need to
add a new producer, not another assembler.

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

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import IntEnum

__all__ = [
    "AssembledContext",
    "ContextAssembler",
    "ContextSection",
    "ContextTier",
    "PinnedOverflowError",
    "SummaryProducer",
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

    ``text`` is the fitted prompt body. The label lists carry the
    per-section disposition so callers (and tests) can assert the
    assembler kept the right things: ``sections_kept`` = full-body,
    ``sections_summarized`` = swapped for their caller-supplied
    ``summary`` fallback (pass 1), ``sections_folded_into_summary`` =
    dropped from the ``RECENT``/``RETRIEVED`` tiers but rolled into the
    synthesized ``SUMMARY`` tier entry (pass 3 -- RFC-24 step 2),
    ``sections_dropped`` = omitted entirely (either the caller marked
    them non-foldable, or the synthesized SUMMARY entry itself could
    not fit and the fold was reverted).

    Every RECENT/RETRIEVED section ever removed lands in exactly ONE
    of the three non-kept lists; the union of the four lists is a
    partition of the caller's non-empty section labels plus (when
    present) the synthesized rolling-summary label.
    """

    text: str
    total_tokens: int
    budget_tokens: int
    sections_kept: list[str] = field(default_factory=list)
    sections_summarized: list[str] = field(default_factory=list)
    sections_dropped: list[str] = field(default_factory=list)
    sections_folded_into_summary: list[str] = field(default_factory=list)


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


# RFC-24 file:line anchor pattern for the rolling SUMMARY producer.
#
# The guardrail: anchors carry the audit chain (a reader can go from a
# reasoning turn back to the exact source line the branch consulted) and
# MUST NOT be paraphrased away when a section is folded into SUMMARY.
# This regex extracts the ``path:line[:col]`` or ``path:line-line``
# substrings the reasoning engines produce (VR bridge readings, forensics
# report references, malware IDA anchors, evidence catalogues) so the
# producer can splice them straight into the summary text without any
# lossy transformation.
#
# Matches:
#   src/aila/x.py:42
#   src/aila/x.py:42-88
#   C:\\Users\\a\\x.py:42:10
#   /tmp/report.md:1
#   plugins/foo/bar.c:120-133
#
# Deliberately misses (avoids false positives):
#   bare "line 42"       -- no path context
#   http://host:8080/... -- URL, port pattern would collide
#   name:value           -- no path separator
# Two variants:
#   * Windows drive path: ``C:\Users\a\y.c:120`` -- drive + sep + 1+ segments.
#   * POSIX / relative path: ``src/aila/x.py:42`` or ``/tmp/x.md:1`` --
#     optional leading sep + 2+ segments (the mandatory second segment
#     is what distinguishes a real path from a bare ``word:42`` token).
#
# The leading ``(?<![:/\\])`` lookbehind rejects URL ports
# (``http://example:8080``) and other pseudo-paths whose match start
# would otherwise slide inside a URL scheme separator.
_ANCHOR_RX = re.compile(
    r"(?<![:/\\])"
    r"(?:"
        r"[A-Za-z]:[/\\][A-Za-z0-9_.\-@+]+"       # windows drive + first seg
        r"(?:[/\\][A-Za-z0-9_.\-@+]+)*"           # 0+ more segments
        r"|"
        r"[/\\]?[A-Za-z0-9_.\-@+]+"               # bare start (opt. leading sep)
        r"(?:[/\\][A-Za-z0-9_.\-@+]+)+"           # 1+ more segments (mandatory)
    r")"
    r":\d+(?:[-:]\d+)?"                            # :line, :line-line, or :line:col
)


@dataclass(slots=True)
class SummaryProducer:
    """Deterministic RFC-24 rolling SUMMARY producer.

    Called by :class:`ContextAssembler` at eviction time. Given the
    ordered list of ``RECENT``/``RETRIEVED`` sections the assembler
    would otherwise drop, ``fold`` returns a single synthesized
    ``SUMMARY``-tier :class:`ContextSection` containing one bullet per
    evicted section. Each bullet carries:

    * The tier + label of the evicted section (``kind``), so the reader
      can see which block was folded.
    * A ONE-line stance extracted from the original body -- the first
      non-empty, non-heading line, truncated to ``stance_max_chars``.
      This is the prose that gets summarised away; the RFC accepts this
      because a one-line cue is a rough directional signal, not an
      audit anchor.
    * The FULL LIST of ``path:line`` anchors extracted from the
      original body by :data:`_ANCHOR_RX`. Anchors are the RFC-24
      guardrail -- they are copied VERBATIM from the source body
      without any transformation, dedup only, and never truncated
      individually. If a body carries more than ``max_anchors_per_section``
      anchors the producer keeps the FIRST that-many and appends a
      ``(+N more)`` cue so operators know some anchors were elided at
      the LIST level (never at the STRING level).

    An LLM-backed producer can subclass or replace this one, but the
    default is deterministic and no-LLM: RFC-24 requires the SUMMARY
    tier be behaviour-preserving in the no-eviction case (it is) and
    stresses that an LLM path must go through
    :func:`aila.platform.agents.idempotent_llm.idempotent_llm_call` so
    a retried worker replays a cached summary instead of re-paying.
    Making the platform default deterministic sidesteps that concern
    entirely for the shipping path.
    """

    label: str = "rolling_summary"
    """Label the synthesized SUMMARY section carries.

    Callers can override to disambiguate multiple assemblers in the
    same telemetry stream (per-branch summary vs per-panel summary
    once the shared cross-branch pool lands)."""

    heading: str = "# Rolling summary (folded from evicted sections)"
    """First line of the synthesized SUMMARY body.

    Kept as a Markdown H1 so the summary block sits visually apart
    from the surrounding prompt sections. Downstream regexes / log
    parsers can locate it by this exact string."""

    max_anchors_per_section: int = 40
    """Cap on the anchor LIST per bullet.

    The individual anchor strings are always copied verbatim (RFC-24
    guardrail). This cap only bounds the LIST length so a runaway
    body (e.g. an evidence listing with hundreds of file references)
    cannot make the summary itself blow the budget. The excess count
    is reported as ``(+N more)`` so operators can see what was
    dropped at the list level."""

    stance_max_chars: int = 140
    """Cap on the extracted stance line."""

    def fold(
        self, evicted: Sequence[ContextSection],
    ) -> ContextSection | None:
        """Return one ``SUMMARY``-tier section rolling every ``evicted``
        section, or ``None`` when the input is empty.

        The returned section is itself ``droppable=True`` so the
        assembler can drop the entire summary if adding it would
        exceed the budget -- the RFC prefers "some content lost" over
        "budget silently violated".
        """
        if not evicted:
            return None
        bullets = [self._render_entry(sec) for sec in evicted]
        body = "\n".join([self.heading, *bullets])
        return ContextSection(
            tier=ContextTier.SUMMARY,
            label=self.label,
            body=body,
        )

    def _render_entry(self, section: ContextSection) -> str:
        anchors = _extract_anchors(section.body)
        stance = _one_line_stance(section.body, self.stance_max_chars)
        anchor_count = len(anchors)
        if anchor_count > self.max_anchors_per_section:
            kept = anchors[: self.max_anchors_per_section]
            elided = anchor_count - self.max_anchors_per_section
            anchor_str = ", ".join(kept) + f" (+{elided} more)"
        elif anchors:
            anchor_str = ", ".join(anchors)
        else:
            anchor_str = "(no file:line anchors)"
        kind = f"{section.tier.name}/{section.label}"
        return f"- [{kind}] {stance} :: {anchor_count} anchors: {anchor_str}"


def _extract_anchors(text: str) -> list[str]:
    """Return every ``path:line`` anchor in ``text`` in first-seen order.

    Dedup preserves first-seen index (a repeated anchor is redundant
    for the summary reader). Anchor strings are returned VERBATIM
    from the source body -- no case normalisation, no separator
    rewrite, no line-number arithmetic. This is the RFC-24 guardrail
    that summarisation MUST NOT paraphrase away.
    """
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for match in _ANCHOR_RX.finditer(text):
        anchor = match.group(0)
        if anchor in seen:
            continue
        seen.add(anchor)
        out.append(anchor)
    return out


def _one_line_stance(text: str, max_chars: int) -> str:
    """Extract a single-line prose cue from ``text``.

    Skips empty lines, Markdown headings (``#``), and the ``== `` /
    ``--`` structural markers the reasoning modules use as block
    dividers, then returns the first surviving line trimmed to
    ``max_chars``. Falls back to ``"(no prose)"`` if the whole body
    was headings / dividers.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith("== ") or line.startswith("--"):
            continue
        if len(line) > max_chars:
            return line[: max_chars - 3] + "..."
        return line
    return "(no prose)"


@dataclass(slots=True)
class ContextAssembler:
    """RFC-24 tiered, budget-aware prompt assembler.

    Construct once per reasoning engine (or per turn) and reuse. The
    assembler is stateless between :meth:`assemble` calls; the state
    lives on the input :class:`ContextSection` sequence.

    The ``summary_producer`` seam lets a caller swap the deterministic
    rolling-summary producer for a different implementation (or
    disable it entirely by passing ``None``). Disabling the producer
    restores the pre-step-2 behaviour: over-budget RECENT/RETRIEVED
    sections are dropped outright with no fold.
    """

    separator: str = "\n\n"
    summary_producer: SummaryProducer | None = field(
        default_factory=SummaryProducer,
    )

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
        evicted_foldable: list[ContextSection] = []
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
            # preserves the RFC-24 tier ordering. Track the drop
            # ORDER so the pass-3 SUMMARY producer sees the RECENT
            # sections in the order they were evicted (oldest first),
            # matching the rolling-window intuition RFC-24 sketches.
            for idx, section in eviction_order:
                if _current_tokens() <= effective:
                    break
                if not section.droppable:
                    continue
                if section.tier == ContextTier.PINNED:
                    continue
                if keep_body[idx] is None:
                    continue
                # SUMMARY-tier sections are not themselves foldable --
                # folding a summary into a summary is a no-op that
                # would just eat tokens. Drop them plainly.
                if section.tier in (
                    ContextTier.RECENT, ContextTier.RETRIEVED,
                ):
                    evicted_foldable.append(section)
                keep_body[idx] = None

        # Pass 3 (RFC-24 step 2): fold every dropped RECENT/RETRIEVED
        # section into a single synthesized SUMMARY-tier entry. The
        # producer preserves file:line anchors VERBATIM (the RFC
        # guardrail); the caller-visible effect is that the fitted
        # prompt still carries the audit chain of the dropped blocks
        # even though their prose is gone.
        summary_section: ContextSection | None = None
        summary_labels: list[str] = []
        summary_insert_after_ordered_pos = -1
        if (
            effective
            and evicted_foldable
            and self.summary_producer is not None
        ):
            candidate = self.summary_producer.fold(evicted_foldable)
            if candidate is not None and candidate.body:
                # Position: right after the LAST section in ORDERED
                # whose tier is RECENT or RETRIEVED. That places the
                # summary "below RECENT" in the assembled text (per
                # the RFC ordering) while keeping the caller's PINNED
                # trailing sections -- e.g. the response contract --
                # at the very bottom.
                last_recent_pos = -1
                for pos, (_idx, sec) in enumerate(ordered):
                    if sec.tier in (
                        ContextTier.RECENT, ContextTier.RETRIEVED,
                    ):
                        last_recent_pos = pos
                # Try to fit the candidate. If it does not fit,
                # revert -- the folded sections remain plain drops.
                # Walk the same way the render loop below does: the
                # SUMMARY splice must be checked at ``last_recent_pos``
                # EVEN WHEN that slot is dropped, because the render
                # loop will splice the summary in there regardless.
                candidate_pieces: list[str] = []
                for pos, (i, sec) in enumerate(ordered):
                    state = keep_body[i]
                    if state is True and sec.body:
                        candidate_pieces.append(sec.body)
                    elif state is False and sec.summary:
                        candidate_pieces.append(sec.summary)
                    if pos == last_recent_pos:
                        candidate_pieces.append(candidate.body)
                candidate_text = self.separator.join(
                    p for p in candidate_pieces if p
                )
                if estimate_tokens(candidate_text) <= effective:
                    summary_section = candidate
                    summary_labels = [s.label for s in evicted_foldable]
                    summary_insert_after_ordered_pos = last_recent_pos

        # Compose the final text in ORIGINAL order, using each slot's
        # current decision. Compute telemetry alongside so callers can
        # verify what stayed vs what got summarised vs dropped vs
        # folded into the rolling SUMMARY entry.
        rendered: list[str] = []
        kept: list[str] = []
        summarized: list[str] = []
        dropped: list[str] = []
        folded_label_set = set(summary_labels)
        for pos, (idx, section) in enumerate(ordered):
            state = keep_body[idx]
            if state is None:
                if section.body:
                    if section.label in folded_label_set:
                        # Accounted separately below; do NOT add to
                        # sections_dropped -- the label is reported in
                        # sections_folded_into_summary instead.
                        pass
                    else:
                        dropped.append(section.label)
            elif state:
                kept.append(section.label)
                rendered.append(section.body)
            else:
                summarized.append(section.label)
                rendered.append(section.summary or "")
            # Splice the synthesized SUMMARY entry in right after the
            # last RECENT/RETRIEVED tier slot -- keeps the SUMMARY
            # visually adjacent to the tiers it condenses and above
            # any trailing PINNED sections (response contract etc).
            if (
                summary_section is not None
                and pos == summary_insert_after_ordered_pos
            ):
                rendered.append(summary_section.body)
                kept.append(summary_section.label)

        text = self.separator.join(rendered)
        return AssembledContext(
            text=text,
            total_tokens=estimate_tokens(text),
            budget_tokens=budget_tokens,
            sections_kept=kept,
            sections_summarized=summarized,
            sections_dropped=dropped,
            sections_folded_into_summary=summary_labels,
        )

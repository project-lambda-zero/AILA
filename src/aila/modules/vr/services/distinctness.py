"""Distinctness scoring for VR findings (issue #10 / #256 / #010).

The panel that produces a finding has no natural pressure toward
distinctness: once one persona lands a plausible answer, siblings
often coalesce on it and the terminal submit repeats the seed
question or a prior known finding. Stamping a cheap distance signal
on the outcome payload lets the operator (and the aggregator) see at
a glance whether the branch actually extended the knowledge frontier
or just restated it.

Contract
--------
:func:`compute_distinctness_score` returns a float in ``[0.0, 1.0]``:

* ``1.0`` -- the candidate shares no meaningful tokens with any
  corpus entry (novel result).
* ``0.0`` -- the candidate is a byte-identical restatement of some
  corpus entry (pure duplication).

The score is deterministic: no embeddings, no randomness, no
external service. Two identical inputs always score the same, so
the value stamped on ``VRInvestigationOutcomeRecord.payload_json``
is auditable in the ledger and reproducible offline.

Metric
------
Score = ``1.0 - max(weighted_jaccard(cand, e) for e in corpus)``,
with the max over an empty corpus defined as ``0.0`` (novel by
default). Tokens are lowercased alphanumeric runs of length >= 3.
A small English stopword set drops the usual glue words so the
denominator reflects content, not scaffolding. When either side
has fewer than 4 content tokens the pair scores as inconclusive
(``0.5``): a two-word finding claim cannot be meaningfully compared
to a full seed hypothesis by set overlap.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = [
    "compute_distinctness_score",
    "extract_candidate_text",
    "extract_corpus_texts",
    "tokenize",
]

# Small, deliberately-boring English stopword set. Only high-frequency
# glue words that add no discriminating signal. Kept short so the
# metric stays predictable; expanding it changes every historical
# score and MUST be a considered contract change, not a drive-by tune.
_STOPWORDS: frozenset[str] = frozenset({
    "the", "and", "for", "with", "this", "that", "from", "into",
    "when", "where", "which", "there", "here", "have", "has", "had",
    "was", "were", "are", "not", "but", "any", "all", "will", "would",
    "can", "may", "might", "should", "could", "does", "did", "done",
    "one", "two", "some", "such", "than", "then", "them", "they",
    "their", "these", "those", "over", "under", "also", "only",
    "very", "much", "more", "less", "own", "out", "our", "you",
    "your", "its", "his", "her",
})

_TOKEN_RE = re.compile(r"[a-z0-9_]{3,}")

_MIN_TOKENS_FOR_COMPARE = 4
_INCONCLUSIVE = 0.5


def tokenize(text: str) -> set[str]:
    """Return the set of content tokens for ``text``.

    Lowercased alphanumeric-with-underscore runs of length >= 3,
    minus the stopword set. Deterministic and order-independent so
    two texts sharing content but reordered still overlap fully.
    """
    if not text:
        return set()
    return {
        tok for tok in _TOKEN_RE.findall(text.lower())
        if tok not in _STOPWORDS
    }


def _weighted_jaccard(a: set[str], b: set[str]) -> float:
    """Symmetric Jaccard similarity on token sets.

    Returns 0.0 on either-empty input so ``compute_distinctness_score``
    treats "no corpus" or "no candidate content" as maximally distinct
    rather than degenerate-similar.
    """
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if inter == 0:
        return 0.0
    return inter / float(len(a | b))


def extract_candidate_text(payload: dict[str, Any]) -> str:
    """Concatenate the finding-relevant text fields from an outcome payload.

    Reads ``answer``, ``reasoning``, and ``provenance.primary_artifact``.
    Missing / non-string fields skip cleanly. The concatenation order
    is fixed so the token set is deterministic across calls.
    """
    parts: list[str] = []
    for key in ("answer", "reasoning"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(val)
    provenance = payload.get("provenance")
    if isinstance(provenance, dict):
        primary = provenance.get("primary_artifact")
        if isinstance(primary, str) and primary.strip():
            parts.append(primary)
    return "\n".join(parts)


def extract_corpus_texts(
    *,
    seed_hypotheses: list[dict[str, Any]] | None = None,
    prior_outcomes: list[dict[str, Any]] | None = None,
    known_findings: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Assemble the corpus the candidate is scored against.

    The corpus is the set of texts a novel finding should NOT
    restate: the seed hypotheses that opened the investigation,
    every prior submitted outcome on this investigation (from the
    caller's ``_load_prior_outcomes`` output), and any known
    findings the caller wants to guard against duplicating.

    Empty / non-string entries are skipped so a partially-typed
    input list still contributes what it can.
    """
    corpus: list[str] = []
    for h in (seed_hypotheses or []):
        claim = h.get("claim") if isinstance(h, dict) else None
        if isinstance(claim, str) and claim.strip():
            corpus.append(claim)
    for o in (prior_outcomes or []):
        if not isinstance(o, dict):
            continue
        ans = o.get("answer")
        if isinstance(ans, str) and ans.strip():
            corpus.append(ans)
    for f in (known_findings or []):
        if not isinstance(f, dict):
            continue
        for key in ("title", "answer", "summary"):
            val = f.get(key)
            if isinstance(val, str) and val.strip():
                corpus.append(val)
    return corpus


def compute_distinctness_score(
    candidate_text: str, corpus: list[str],
) -> float:
    """Return ``1.0 - max Jaccard overlap`` of ``candidate_text`` against
    ``corpus``.

    Score interpretation:

    * ``1.0``  -- no meaningful token overlap with any corpus entry.
    * ``0.0``  -- token set equal to some corpus entry.
    * ``0.5``  -- inconclusive: candidate or every corpus entry has
      fewer than :data:`_MIN_TOKENS_FOR_COMPARE` content tokens, so
      a set-overlap metric cannot separate real duplication from
      naturally-short claims.

    Empty corpus scores ``1.0`` (novel by definition -- nothing to
    match). Empty candidate scores ``0.5`` (nothing meaningful to
    compare).
    """
    cand_tokens = tokenize(candidate_text)
    if len(cand_tokens) < _MIN_TOKENS_FOR_COMPARE:
        return _INCONCLUSIVE
    if not corpus:
        return 1.0
    max_overlap = 0.0
    comparable = False
    for entry in corpus:
        entry_tokens = tokenize(entry)
        if len(entry_tokens) < _MIN_TOKENS_FOR_COMPARE:
            continue
        comparable = True
        sim = _weighted_jaccard(cand_tokens, entry_tokens)
        if sim > max_overlap:
            max_overlap = sim
    if not comparable:
        return _INCONCLUSIVE
    score = 1.0 - max_overlap
    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return score

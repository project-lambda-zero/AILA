"""Adaptive retrieval router -- RFC-12 criterion 4.

Classifies a knowledge query into one of three retrieval paths so the
cheapest adequate strategy runs on every request. The three routes come
straight from the RFC design pseudocode:

* :data:`Route.STABLE_CORE` -- the query targets the small, hot, stable
  corpus preloaded into memory (rubrics, accept-bar policies, verified
  prior verdicts). Served from the CAG cache without a vector call.
* :data:`Route.SIMPLE` -- the default single-shot hybrid path
  (:meth:`KnowledgeService.retrieve`): pgvector + FTS merged and floored.
* :data:`Route.GRAPH` -- multi-hop questions whose answer lives in the
  relations between entries. Served by :class:`KnowledgeGraph.traverse`
  seeded from a small hybrid lookup.

The classifier is a rule-based heuristic keyed on lexical shape, not a
learned model -- the RFC design admits this explicitly: "adaptive
routing" here means a real dispatch that measurably differs across
inputs, not an ML classifier we haven't paid to train. Each route below
carries the exact rule that fires it so operators (and later tests) can
audit the decision without reading Python.
"""

from __future__ import annotations

import re
from enum import StrEnum

from .knowledge_stable_core import STABLE_CORE_TOKEN_PREFIX

__all__ = [
    "GRAPH_KEYWORDS",
    "KnowledgeRouter",
    "Route",
    "STABLE_CORE_KEYWORDS",
]


class Route(StrEnum):
    """Retrieval strategy chosen for a query.

    :class:`~enum.StrEnum` so the enum member serialises cleanly into
    JSON payloads (the tool return dict) without a bespoke encoder.
    """

    STABLE_CORE = "stable_core"
    SIMPLE = "simple"
    GRAPH = "graph"


# Tokens that mark a query as targeting the CAG-preloaded stable core.
# Kept ASCII lowercase so the matcher can lowercase the query once. Each
# entry maps to a real class of stable content: rubrics/policies/checklists
# already live in the platform stable-core namespace, so a query naming any
# of them is a stable-core lookup by definition.
STABLE_CORE_KEYWORDS: frozenset[str] = frozenset({
    "rubric",
    "accept-bar",
    "policy",
    "checklist",
    "playbook",
    "guideline",
    "standard",
})

# Single-word graph markers matched against the tokenised query
# (whole word, not substring) so an unrelated substring hit does not
# route to the expensive graph path. fix §126 -- ``between`` /
# ``path`` / ``how does`` were substring-matched and fired on ordinary
# security queries ("difference between CVE-A and CVE-B", "attack path
# from input to RCE", "how does the auth bypass work") that the flat
# hybrid path handles correctly. Retained tokens are ones that only
# appear naturally in genuine multi-hop questions.
_GRAPH_WORD_MARKERS: frozenset[str] = frozenset({
    "relate",
    "related",
    "relates",
    "relationship",
    "connection",
    "connections",
    "connected",
    "trace",
    "chain",
    "hops",
    "linked",
})

# Compound graph markers matched by substring so multi-word shapes are
# still routable. Each phrase names an explicit graph query -- a bare
# ``path`` or ``between`` would over-fire, but ``path between`` /
# ``link between`` are unambiguous multi-hop asks.
_GRAPH_PHRASE_MARKERS: tuple[str, ...] = (
    "link between",
    "path between",
    "paths between",
    "chain between",
    "connected to",
    "relate to",
    "relates to",
    "related to",
)

# Public union kept for backwards compatibility with callers that
# introspect the marker set (tests, tooling). New code should treat
# the split above as authoritative.
GRAPH_KEYWORDS: frozenset[str] = _GRAPH_WORD_MARKERS | frozenset(
    _GRAPH_PHRASE_MARKERS,
)

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")


class KnowledgeRouter:
    """Rule-based query -> :class:`Route` classifier.

    The class exists (rather than a bare function) so a caller can
    subclass it -- swapping ``classify`` for a learned model later --
    without every call-site changing. The default implementation is
    pure text, deterministic, and cheap enough to run on every
    retrieve without measuring: one lowercase, one regex tokenise, and
    a handful of substring checks.
    """

    def classify(self, query: str) -> Route:
        """Return the retrieval :class:`Route` for ``query``.

        Precedence (an earlier rule wins over any later one):

        1. Explicit ``stable-core:`` / ``stable_core:`` prefix -- the
           caller is naming the CAG core directly.
        2. A :data:`STABLE_CORE_KEYWORDS` token appears as a whole word.
        3. A single-word graph marker (:data:`_GRAPH_WORD_MARKERS`)
           appears as a whole word, OR a compound graph marker
           (:data:`_GRAPH_PHRASE_MARKERS`) appears as a substring.
           Whole-word matching keeps ``path`` / ``between`` from
           firing on ordinary security queries like "attack path from
           input to RCE" or "difference between CVE-A and CVE-B"
           (fix §126).
        4. Fall through to :data:`Route.SIMPLE`.
        """
        cleaned = (query or "").strip().lower()
        if not cleaned:
            return Route.SIMPLE

        if cleaned.startswith(STABLE_CORE_TOKEN_PREFIX):
            return Route.STABLE_CORE

        tokens = set(_WORD_RE.findall(cleaned))
        if tokens & STABLE_CORE_KEYWORDS:
            return Route.STABLE_CORE

        if tokens & _GRAPH_WORD_MARKERS:
            return Route.GRAPH

        for phrase in _GRAPH_PHRASE_MARKERS:
            if phrase in cleaned:
                return Route.GRAPH

        return Route.SIMPLE

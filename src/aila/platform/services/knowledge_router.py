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

# Lexical markers that point at a multi-hop question. A knowledge base
# populated with an edge graph is the right home for these; the flat
# hybrid path can only return one hit per hop and cannot recover the
# chain. "how does X relate to Y" and "trace/path/chain between ..."
# are the two canonical shapes; the rest are close synonyms that the
# audit-mcp log traffic shows agents actually type.
GRAPH_KEYWORDS: frozenset[str] = frozenset({
    "relate",
    "related",
    "relates",
    "relationship",
    "connection",
    "connections",
    "connected",
    "trace",
    "chain",
    "path",
    "hops",
    "linked",
    "link between",
    "how does",
    "between",
})

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
        3. A :data:`GRAPH_KEYWORDS` marker appears (substring so
           multi-word markers like ``"how does"`` match). A single
           marker is enough because these words are rare outside
           genuine multi-hop questions.
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

        for marker in GRAPH_KEYWORDS:
            if marker in cleaned:
                return Route.GRAPH

        return Route.SIMPLE

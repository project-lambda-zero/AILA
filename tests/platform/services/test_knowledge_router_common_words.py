"""fix §126 -- knowledge_router routes ordinary common-word queries to
the cheap :data:`Route.SIMPLE` path.

Regression guard for the pre-fix behaviour where ``GRAPH_KEYWORDS``
included ``'between'``, ``'path'``, and ``'how does'`` and matched by
substring, so ordinary security queries routed to the expensive graph
path (BFS induction + Personalised PageRank) even though the flat
hybrid path answers them correctly.

Also asserts that the retained multi-hop shapes (``'link between'`` /
``'path between'`` / ``'chain'`` / ``'relate'``) still route to
:data:`Route.GRAPH` so the tightening did not over-shoot and starve
genuine graph queries.
"""
from __future__ import annotations

import pytest

from aila.platform.services.knowledge_router import KnowledgeRouter, Route


# The queries below all contain a former graph substring marker
# (``'between'`` / ``'path'`` / ``'how does'``) but are ordinary
# hybrid-path questions. Each one used to burn a graph traversal per
# request under the pre-fix router; they must now stay on SIMPLE.
@pytest.mark.parametrize(
    "query",
    [
        "difference between CVE-A and CVE-B",
        "attack path from input to RCE",
        "how does the auth bypass work",
        "shortest path in the sample graph algorithm",
        "any difference between two nginx builds?",
    ],
)
def test_common_word_queries_route_to_simple(query: str) -> None:
    """Ordinary security queries no longer waste the graph traversal."""
    assert KnowledgeRouter().classify(query) is Route.SIMPLE


# The queries below are genuine multi-hop asks; the tightening must
# preserve graph routing for them.
@pytest.mark.parametrize(
    "query",
    [
        "how does entry X relate to Y?",
        "trace the chain from CVE-2024-1 to nginx",
        "show me the path between findings A and B",
        "what is the link between the injection sink and the tainted source?",
        "which entries are connected to CVE-2024-1?",
    ],
)
def test_genuine_multi_hop_queries_route_to_graph(query: str) -> None:
    """The tightening does not starve genuine graph queries."""
    assert KnowledgeRouter().classify(query) is Route.GRAPH

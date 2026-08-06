"""Deterministic security-entity extraction for knowledge metadata (RFC-12).

A knowledge entry becomes intelligently retrievable when its content is
tagged with the security identifiers it references, so a caller can scope
retrieval to "everything touching CVE-2024-1234" or "every entry mapped to
ATT&CK T1055" instead of hoping cosine similarity surfaces them. This
module extracts those identifiers with a fixed regex pass -- no model, no
cost, and the same text always yields the same tags -- covering the
identifier families the platform's security corpus actually carries: CVE,
CWE, CAPEC, ATT&CK techniques, and MASVS / MSTG control ids.

The extracted list lands under ``entry_metadata["entities"]`` at ingest
(opt-in via ``KnowledgeService.store(extract_entities=True)``) and is
queried through ``KnowledgeService.retrieve(metadata_filter=...)``.
"""
from __future__ import annotations

import re

__all__ = ["extract_entities"]

# Each pattern matches one security-identifier family. ATT&CK technique ids
# stay case-sensitive on the leading ``T`` so a lowercase word like "t1055"
# in prose is not mistaken for a technique; every match is uppercased on
# the way out so the stored tag is canonical regardless of source casing.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE),
    re.compile(r"\bCAPEC-\d{1,5}\b", re.IGNORECASE),
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    re.compile(r"\bM(?:ASVS|STG)-[A-Za-z]+-\d+\b", re.IGNORECASE),
)


def extract_entities(text: str) -> list[str]:
    """Return sorted, de-duplicated, uppercased security ids found in *text*.

    Deterministic: the same text always yields the same list, and the list
    is empty when the text carries no recognized identifier. Uppercasing
    plus sorting makes the tag set canonical so re-ingesting the same
    content rewrites identical metadata.
    """
    if not text:
        return []
    found: set[str] = set()
    for pattern in _PATTERNS:
        for match in pattern.findall(text):
            found.add(match.upper())
    return sorted(found)

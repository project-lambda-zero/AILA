"""MASVS catalog data model — one control per row, immutable.

A MASVS control encodes a single OWASP Mobile Application Security
Verification Standard verification requirement. The catalog (in
``catalog.py``) holds a tuple of ``MasvsControl`` instances spanning
the eight v2.1.0 groups. Each control feeds one child VR
investigation when the operator triggers a MASVS audit against an
``android_apk`` target.

Fields are immutable (``frozen=True, slots=True``) so the catalog can
be shared across worker processes and persona prompt builders without
copy-on-write hazards or accidental mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "MasvsControl",
    "MasvsGroup",
    "MasvsLevel",
]


class MasvsLevel(StrEnum):
    """OWASP MASVS verification level.

    L1 is the baseline that applies to every mobile app. L2 adds
    defense-in-depth requirements for apps handling sensitive data.
    R covers resilience requirements for apps that face client-side
    reverse engineering and tampering. The L1 set is the loop's
    current scope; L2 and R entries may appear in the catalog for
    completeness but downstream dispatch filters on ``level == L1``.
    """

    L1 = "L1"
    L2 = "L2"
    R = "R"


class MasvsGroup(StrEnum):
    """The eight MASVS v2.1.0 control groups.

    Catalog ids follow the OWASP convention ``MSTG-<GROUP>-<N>``, so
    the group enum values match the second segment of every id.
    """

    STORAGE = "STORAGE"
    CRYPTO = "CRYPTO"
    AUTH = "AUTH"
    NETWORK = "NETWORK"
    PLATFORM = "PLATFORM"
    CODE = "CODE"
    RESILIENCE = "RESILIENCE"
    PRIVACY = "PRIVACY"


@dataclass(frozen=True, slots=True)
class MasvsControl:
    """One MASVS verification requirement.

    Populated from OWASP MASVS v2.1.0 source text. Each control
    becomes one child ``VRInvestigation`` (``kind=masvs_audit``) when
    the parent audit is dispatched.

    Attributes
    ----------
    id:
        OWASP-assigned control id, e.g. ``"MSTG-STORAGE-1"``.
    group:
        Which of the eight MASVS groups this control belongs to.
    level:
        Verification level — ``L1`` / ``L2`` / ``R``.
    title:
        Short single-sentence requirement statement from the spec.
    description:
        Paragraph describing the requirement and its rationale.
    verification_steps:
        Concrete actions a verifier performs to evaluate compliance.
        The persona prompt builder feeds these directly into the
        ``initial_question`` of the child investigation.
    relevant_apis:
        Android / Java / native APIs whose presence (or absence) is
        load-bearing for this control's verdict.
    evidence_hints:
        Source-text search strings the auditor persona feeds into
        ``audit_mcp.semantic_search`` / ``audit_mcp.search_functions``
        against the decompiled jadx index to find call sites or
        configuration relevant to the control.
    """

    id: str
    group: MasvsGroup
    level: MasvsLevel
    title: str
    description: str
    verification_steps: tuple[str, ...]
    relevant_apis: tuple[str, ...]
    evidence_hints: tuple[str, ...]

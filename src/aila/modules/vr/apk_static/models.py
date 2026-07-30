"""APK static-analysis check catalog data model -- one check per row, immutable.

An :class:`ApkStaticCheck` encodes a single concrete, statically-answerable
investigation against a decompiled Android APK. Unlike a MASVS *control*
(a broad compliance requirement, some of which cannot be answered from an
APK at all), a check names a definite evidence source the ingestion
pipeline already produces (AndroidManifest, jadx-decompiled Java tree,
androguard summary, ``res/``, ``assets/``) or a named extractor stage the
pipeline would need.

The catalog (in ``catalog.py``) holds a tuple of ``ApkStaticCheck``
instances. Each :attr:`ApkStaticMode.STATIC` check feeds one child VR
investigation (``kind=audit``) when the operator triggers an APK static
audit against an ``android_apk`` target. :attr:`ApkStaticMode.EXTRACTOR`
checks are catalogued for the roadmap but NOT dispatched -- they depend on
a pipeline stage not yet built (native ``.so`` analysis, Flutter Dart-AOT
decompile, full SBOM). The dynamic tier is intentionally absent from this
catalog: runtime instrumentation ships in a later release.

Fields are immutable (``frozen=True, slots=True``) so the catalog can be
shared across worker processes and prompt builders without copy-on-write
hazards or accidental mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "ApkStaticCheck",
    "ApkStaticGroup",
    "ApkStaticMode",
]


class ApkStaticMode(StrEnum):
    """Whether a check is answerable from the current pipeline.

    STATIC:
        Evidence is already extracted by the android_apk ingestion
        stages; the check needs only a catalog entry + a targeted prompt.
        These are the rows the audit dispatcher fans out.
    EXTRACTOR:
        Needs a new pipeline stage that has not shipped yet (native
        ``.so`` analysis via ida-headless, Flutter ``libapp.so`` Dart-AOT
        decompile, or a full software bill of materials). Catalogued for
        the roadmap; the dispatcher skips these so no child is asked a
        question the current pipeline cannot answer.
    """

    STATIC = "static"
    EXTRACTOR = "extractor"


class ApkStaticGroup(StrEnum):
    """Category of the APK static-analysis surface a check belongs to.

    Mirrors the section layout of the APK investigation catalog. Groups
    are coarser than MASVS control groups because they follow the shape
    of the evidence source (manifest, code sink class, native binary)
    rather than a compliance taxonomy.
    """

    MANIFEST = "MANIFEST"
    SIGNING = "SIGNING"
    PERMISSIONS = "PERMISSIONS"
    SECRETS = "SECRETS"
    CRYPTO = "CRYPTO"
    NETWORK = "NETWORK"
    WEBVIEW = "WEBVIEW"
    STORAGE = "STORAGE"
    IPC = "IPC"
    INJECTION = "INJECTION"
    DESERIALIZATION = "DESERIALIZATION"
    CODELOAD = "CODELOAD"
    RESILIENCE = "RESILIENCE"
    PRIVACY = "PRIVACY"
    SBOM = "SBOM"
    CHAINS = "CHAINS"
    AUTH_LOCAL = "AUTH_LOCAL"
    NATIVE = "NATIVE"
    FLUTTER = "FLUTTER"


@dataclass(frozen=True, slots=True)
class ApkStaticCheck:
    """One concrete APK static-analysis investigation.

    Attributes
    ----------
    id:
        Stable check id, ``APK-<GROUP>-<SLUG>`` (e.g.
        ``"APK-CRYPTO-WEAK-CIPHER"``). Persisted on each child
        investigation's ``secondary_target_refs_json`` so the reconciler
        and any future aggregator can trace a verdict back to its check.
    group:
        Which :class:`ApkStaticGroup` this check belongs to.
    mode:
        :class:`ApkStaticMode` -- STATIC checks are dispatched; EXTRACTOR
        checks are catalogued only (roadmap).
    title:
        Short single-sentence statement of what the check hunts for.
    description:
        Paragraph describing the weakness and why it matters.
    verification_steps:
        Concrete actions the auditor persona performs to settle the
        check. Fed directly into the child investigation's
        ``initial_question`` by :class:`ApkStaticSeedBuilder`.
    relevant_apis:
        Android / Java / manifest APIs or attributes whose presence (or
        absence) is load-bearing for this check's verdict.
    evidence_hints:
        Source-text search strings the persona feeds into
        ``audit_mcp.semantic_search`` / ``search_functions`` /
        ``search_constants`` against the decompiled index (and
        ``read_lines`` for manifest / resources) to find the call sites
        or configuration the check turns on.
    cwe:
        Zero or more CWE ids the finding maps to (MASTG v2 stamps a CWE
        on every test; this keeps AILA output aligned with
        MASTG/MASWE traceability). Empty tuple when no clean CWE applies.
    masvs_refs:
        Zero or more OWASP MASVS v2.1.0 control ids this check provides
        evidence for (e.g. ``("MASVS-STORAGE-1",)``), for cross-framework
        reporting. Empty when the check has no direct MASVS mapping.
    """

    id: str
    group: ApkStaticGroup
    mode: ApkStaticMode
    title: str
    description: str
    verification_steps: tuple[str, ...]
    relevant_apis: tuple[str, ...]
    evidence_hints: tuple[str, ...]
    cwe: tuple[str, ...]
    masvs_refs: tuple[str, ...]

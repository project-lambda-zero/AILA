"""Per-check ``initial_question`` builder for APK static-audit children.

An APK static audit (``InvestigationKind.APK_STATIC_AUDIT`` on the parent
record, ``InvestigationKind.AUDIT`` on every child) fans out into one
child :class:`VRInvestigation` per :attr:`ApkStaticMode.STATIC` check.
Each child runs the *unchanged* vuln_researcher scout / critic / verifier
chain -- the apk_static layer only swaps the ``initial_question`` so the
scout knows which concrete weakness to hunt for.

:class:`ApkStaticSeedBuilder` produces that string from one
:class:`ApkStaticCheck` (loaded from
:mod:`aila.modules.vr.apk_static.catalog`) plus the parent target's
``apk_overview`` projection. The output is a plain-markdown prompt body
consumed verbatim by the audit-only system prompt at
:mod:`aila.modules.vr.agents.prompts.system_audit`; there is no template
engine and no late binding -- what the builder emits is what the scout
receives. Unlike a MASVS control, an APK static check names a definite
sink/config, so the bug-hunting audit persona is a direct fit.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aila.modules.vr.apk_static.models import ApkStaticCheck, ApkStaticGroup
from aila.platform.prompts import PromptRegistry

__all__ = [
    "ApkStaticSeedBuilder",
]

_PROMPT_DIR = Path(__file__).parent / "prompts"
_PROMPT_REGISTRY = PromptRegistry(
    _PROMPT_DIR,
    module="vr",
    fallback_base="apk_static_seed_template.md",
)


def _load_prompt_template() -> str:
    """Return the APK-static seed template body from the registry.

    RFC-09 criterion 1: template lives in
    ``prompts/apk_static_seed_template.md`` resolved via
    :class:`PromptRegistry` so the child investigation's initial_question
    is derived from a versioned source of truth rather than an inline
    module constant that silently drifts.
    """
    return _PROMPT_REGISTRY.load("apk_static_seed")


_UNKNOWN = "<unknown>"


class ApkStaticSeedBuilder:
    """Stateless builder producing one child's ``initial_question``.

    Wraps a single static method (:meth:`build`) -- there is no instance
    state. The class shape mirrors
    :class:`aila.modules.vr.masvs.seed.MasvsSeedBuilder` so a future
    iteration can register alternative builders behind the same callsite.
    """

    @staticmethod
    def build(
        check: ApkStaticCheck,
        apk_overview: Mapping[str, Any] | None,
    ) -> str:
        """Render the child investigation's ``initial_question``.

        Parameters
        ----------
        check:
            The APK static-analysis check this child investigates. Every
            field is rendered into the prompt; empty ``relevant_apis`` /
            ``evidence_hints`` / ``cwe`` / ``masvs_refs`` tuples degrade
            to a ``"(none catalogued)"`` line rather than raising.
        apk_overview:
            The parent target's ``apk_overview`` projection
            (``dict[str, Any] | None``). When ``None`` or missing keys,
            the corresponding context cells render as ``"<unknown>"`` so a
            dispatcher dry-run can preview the prompt without crashing. In
            production the dispatcher only fires after STATIC_SUMMARY has
            completed, so every key consulted here is populated.

        Returns
        -------
        str
            Markdown-formatted prompt body suitable for direct use as
            ``VRInvestigationRecord.initial_question``.
        """
        overview: Mapping[str, Any] = apk_overview or {}
        static_summary_raw = overview.get("static_summary")
        static_summary: Mapping[str, Any] = (
            static_summary_raw
            if isinstance(static_summary_raw, Mapping)
            else {}
        )

        package = _text_or_unknown(static_summary.get("package"))
        version_name = _text_or_unknown(static_summary.get("version_name"))
        sha256_full = _text_or_unknown(overview.get("sha256"))
        sha256 = sha256_full[:16] if sha256_full != _UNKNOWN else sha256_full
        index_id = _text_or_unknown(overview.get("audit_mcp_index_id"))
        jadx_class_count = _text_or_unknown(overview.get("jadx_class_count"))

        steps_block = (
            "\n".join(
                f"{idx}. {step}"
                for idx, step in enumerate(check.verification_steps, start=1)
            )
            or "(none catalogued -- use evidence hints below)"
        )
        hints_block = (
            "\n".join(f"  - {hint}" for hint in check.evidence_hints)
            or "  - (none catalogued)"
        )
        apis_block = (
            "\n".join(f"  - {api}" for api in check.relevant_apis)
            or "  - (none catalogued)"
        )
        cwe_block = ", ".join(check.cwe) or "(none)"
        masvs_block = ", ".join(check.masvs_refs) or "(none)"
        evidence_block = _group_evidence_block(check, static_summary)
        polarity_block = _polarity_block(check)

        return _load_prompt_template().format(
            evidence_block=evidence_block,
            polarity_block=polarity_block,
            check_id=check.id,
            group=check.group.value,
            title=check.title.strip(),
            description=check.description.strip(),
            package=package,
            version_name=version_name,
            sha256=sha256,
            index_id=index_id,
            jadx_class_count=jadx_class_count,
            steps_block=steps_block,
            hints_block=hints_block,
            apis_block=apis_block,
            cwe_block=cwe_block,
            masvs_block=masvs_block,
        )


def _polarity_block(check: ApkStaticCheck) -> str:
    """Finding-polarity clause for defense-presence checks.

    Most apk_static checks hunt for a weakness: finding the weakness IS the
    finding, so a ``direct_finding`` is correct. RESILIENCE checks invert
    that -- they audit whether a *defensive* control is present, and the
    control being present and reachable is the good state, i.e. a cited
    NEGATIVE, not a vulnerability. Without stating this the scout emits a
    ``direct_finding`` for a working defense (the verdict mapper then
    projects it to ``MasvsVerdict.FINDING``, wrongly flagging a present
    control as a failing one). Returns an empty string for every other
    group so weakness-hunting checks keep the default polarity.
    """
    if check.group is not ApkStaticGroup.RESILIENCE:
        return ""
    return (
        "\n## Finding polarity (RESILIENCE / defense-presence check)\n\n"
        "This check audits whether a defensive control is present, not "
        "whether a weakness exists. Invert the usual polarity: a control "
        "that is PRESENT and reachable is a cited NEGATIVE -- submit a "
        "no_finding that documents the mechanism with file:line evidence. "
        "Reserve a direct_finding for the ABSENCE of the control, control "
        "code that is dead / unreachable, or a trivially defeated control. "
        "Documenting a working defense is NOT a vulnerability and must not "
        "be submitted as one. If the control is present but weak (e.g. a "
        "local-only check with no server-side attestation), that nuance "
        "belongs in the no_finding evidence, not a direct_finding.\n"
    )


def _group_evidence_block(
    check: ApkStaticCheck,
    static_summary: Mapping[str, Any],
) -> str:
    """Render the pre-extracted evidence a NATIVE / SBOM check needs.

    The native and SBOM checks are answered from data the ingestion
    pipeline computes (LIEF over the bundled ``.so`` files, a component
    inventory), not from the jadx tree the audit_mcp tools reach. That
    data rides on ``static_summary`` under ``native_analysis`` / ``sbom``;
    this helper renders the relevant slice directly into the child prompt
    so the auditor reasons over real facts instead of guessing. Returns
    an empty string for every other group.
    """
    if check.group is ApkStaticGroup.NATIVE:
        na = static_summary.get("native_analysis")
        if not isinstance(na, Mapping) or not na.get("present"):
            return (
                "\n## Native analysis\n\nNo native libraries were found in "
                "this APK (no lib/<abi>/*.so). This check is a clean "
                "negative unless the audit surfaces native code elsewhere.\n"
            )
        lines = [
            "\n## Native analysis (LIEF over lib/<abi>/*.so)\n",
            f"libraries: {na.get('lib_count')} | abis: "
            f"{', '.join(na.get('abis') or [])}\n",
        ]
        for lib in (na.get("libraries") or []):
            if not isinstance(lib, Mapping):
                continue
            if lib.get("error"):
                lines.append(f"- {lib.get('path')}: ({lib['error']})")
                continue
            vh = lib.get("version_hints") or {}
            vh_s = (
                "; vers=" + ", ".join(f"{k}={v}" for k, v in vh.items())
                if vh else ""
            )
            env = lib.get("jni_env_calls") or []
            unsafe = lib.get("unsafe_libc_imports") or []
            extra = ""
            if env:
                extra += f"; jni_env={', '.join(env)}"
            if unsafe:
                extra += f"; unsafe_libc={', '.join(unsafe)}"
            lines.append(
                f"- {lib.get('path')}: nx={lib.get('nx')} pie={lib.get('pie')} "
                f"relro={lib.get('relro')} canary={lib.get('stack_canary')} "
                f"fortify={lib.get('fortify')} stripped={lib.get('stripped')} "
                f"jni_exports={lib.get('jni_export_count')}{vh_s}{extra}",
            )
        gaps = na.get("hardening_gaps") or []
        if gaps:
            lines.append("\nhardening gaps:")
            lines.extend(f"  - {g}" for g in gaps)
        return "\n".join(lines) + "\n"
    if check.group is ApkStaticGroup.SBOM:
        sb = static_summary.get("sbom")
        if not isinstance(sb, Mapping):
            return ""
        lines = [
            "\n## Component inventory (static SBOM)\n",
            f"components: {sb.get('component_count')} | frameworks: "
            f"{', '.join(sb.get('frameworks') or []) or 'none'}\n",
        ]
        for comp in (sb.get("components") or []):
            if not isinstance(comp, Mapping):
                continue
            ver = comp.get("version") or "?"
            lines.append(
                f"- [{comp.get('type')}] {comp.get('name')} {ver} "
                f"(from {comp.get('source')})",
            )
        return "\n".join(lines) + "\n"
    return ""


def _text_or_unknown(value: object) -> str:
    """Stringify a context cell or fall back to ``"<unknown>"``.

    Treats ``None`` and the empty string as missing so a partially
    populated ``apk_overview`` renders cleanly without leaking ``"None"``
    literals into the prompt body.
    """
    if value is None:
        return _UNKNOWN
    text = str(value)
    if not text:
        return _UNKNOWN
    return text



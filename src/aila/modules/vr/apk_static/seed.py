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
from typing import Any

from aila.modules.vr.apk_static.models import ApkStaticCheck, ApkStaticGroup

__all__ = [
    "ApkStaticSeedBuilder",
]


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

        return _PROMPT_TEMPLATE.format(
            evidence_block=evidence_block,
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


# Doubled braces escape literal `{` / `}` for ``str.format``; every named
# placeholder below is filled by :meth:`ApkStaticSeedBuilder.build`. Kept
# lean: vuln_researcher already injects the persona system prompt, the
# tool surface, and the audit-kind outcome contract, so the seed carries
# only the irreducible per-check payload.
_PROMPT_TEMPLATE = """\
Audit APK static check **{check_id}** ({group}) on APK `{package}`
(versionName {version_name}, sha256 {sha256}...). Use audit_mcp index
`{index_id}` for the jadx-decompiled tree ({jadx_class_count} classes);
`read_lines` also reaches AndroidManifest.xml + res/ under that index.

## {title}

{description}

This is a concrete, statically-answerable check -- a definite finding or a
cited negative, not a compliance opinion. A clean result is valid ONLY
after the evidence below is examined; cite `file:line` for every claim.

## Verification steps

{steps_block}
{evidence_block}
## Evidence hints (seed `mcp__audit_mcp_semantic_search` / `search_functions` / `search_constants`)

{hints_block}

## Load-bearing APIs / manifest attributes

{apis_block}

## Mapping

- CWE: {cwe_block}
- OWASP MASVS v2.1.0: {masvs_block}
"""

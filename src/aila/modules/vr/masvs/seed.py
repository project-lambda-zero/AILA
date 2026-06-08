"""Per-control ``initial_question`` builder for MASVS audit children.

A MASVS audit (``InvestigationKind.MASVS_AUDIT`` on the parent record,
``InvestigationKind.AUDIT`` on every child) fans out into one child
:class:`VRInvestigation` per L1 control. Each child runs the *unchanged*
vuln_researcher scout / critic / verifier chain — the MASVS layer only
swaps the ``initial_question`` so the scout knows which OWASP
requirement to evaluate.

:class:`MasvsSeedBuilder` produces that string from one
:class:`MasvsControl` (loaded from :mod:`aila.modules.vr.masvs.catalog`)
plus the parent target's ``apk_overview`` projection. The output is a
plain-markdown prompt body consumed verbatim by the audit-only system
prompt at :mod:`aila.modules.vr.agents.prompts.system_audit`; there is
no template engine and no late binding — what the builder emits is what
the scout receives.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aila.modules.vr.masvs.models import MasvsControl

__all__ = [
    "MasvsSeedBuilder",
]


_UNKNOWN = "<unknown>"


class MasvsSeedBuilder:
    """Stateless builder producing one child's ``initial_question``.

    The class wraps a single static method (:meth:`build`) for naming
    parity with the project IMPLEMENTATION_PLAN (S-2) — there is no
    instance state. The class shape is preserved so a future iteration
    can register alternative builders (iOS-side MASVS, MASTG profile
    prompts, customer-bespoke audit templates) behind the same callsite
    without churning every dispatcher import.
    """

    @staticmethod
    def build(
        control: MasvsControl,
        apk_overview: Mapping[str, Any] | None,
    ) -> str:
        """Render the child investigation's ``initial_question``.

        Parameters
        ----------
        control:
            The OWASP MASVS requirement this child investigates. Every
            field on :class:`MasvsControl` is rendered into the prompt;
            empty ``relevant_apis`` or ``evidence_hints`` tuples
            degrade to ``"(none catalogued)"`` rather than raising.
        apk_overview:
            The parent :class:`VRTargetSummary`'s ``apk_overview``
            projection (``dict[str, Any] | None``). When ``None`` or
            missing keys, the corresponding context cells render as
            ``"<unknown>"`` so a dispatcher dry-run can preview the
            prompt without crashing. In production the dispatcher only
            fires after STATIC_SUMMARY has completed, so every key
            consulted here is populated.

        Returns
        -------
        str
            Markdown-formatted prompt body suitable for direct use as
            ``VRInvestigationRecord.initial_question``.
        """
        overview: Mapping[str, Any] = apk_overview or {}
        static_summary: Mapping[str, Any] = (
            overview.get("static_summary") or {}
        )

        package = _text_or_unknown(static_summary.get("package"))
        version_name = _text_or_unknown(static_summary.get("version_name"))
        version_code = _text_or_unknown(static_summary.get("version_code"))
        sha256 = _text_or_unknown(overview.get("sha256"))
        index_id = _text_or_unknown(overview.get("audit_mcp_index_id"))
        decompiled_dir = _text_or_unknown(overview.get("decompiled_dir"))
        jadx_class_count = _text_or_unknown(overview.get("jadx_class_count"))

        steps_block = "\n".join(
            f"{idx}. {step}"
            for idx, step in enumerate(control.verification_steps, start=1)
        )
        hints_block = (
            "\n".join(f"  - {hint}" for hint in control.evidence_hints)
            or "  - (none catalogued)"
        )
        apis_block = (
            "\n".join(f"  - {api}" for api in control.relevant_apis)
            or "  - (none catalogued)"
        )

        return _PROMPT_TEMPLATE.format(
            control_id=control.id,
            group=control.group.value,
            level=control.level.value,
            title=control.title.strip(),
            description=control.description.strip(),
            package=package,
            version_name=version_name,
            version_code=version_code,
            sha256=sha256,
            index_id=index_id,
            decompiled_dir=decompiled_dir,
            jadx_class_count=jadx_class_count,
            steps_block=steps_block,
            hints_block=hints_block,
            apis_block=apis_block,
        )


def _text_or_unknown(value: object) -> str:
    """Stringify a context cell or fall back to ``"<unknown>"``.

    Treats ``None`` and the empty string as missing so a partially-
    populated ``apk_overview`` (mid-pipeline, or a hand-rolled fixture)
    renders cleanly without leaking ``"None"`` literals into the
    prompt body.
    """
    if value is None:
        return _UNKNOWN
    text = str(value)
    if not text:
        return _UNKNOWN
    return text


# Doubled braces escape literal `{` / `}` for ``str.format``; every
# named placeholder below is filled by :meth:`MasvsSeedBuilder.build`.
_PROMPT_TEMPLATE = """\
You are auditing the OWASP MASVS control **{control_id}** against the Android APK
package `{package}` (versionName {version_name}, versionCode {version_code}, sha-256
{sha256}). This investigation evaluates ONE control end-to-end — do not pivot
into other MASVS groups, even when you happen across an unrelated finding.

# Control: {control_id} (group={group}, level={level})

{title}

{description}

# Verification steps

Walk these in order. For each step record the call sites you inspected and
whether they satisfy the requirement before moving to the next.

{steps_block}

# Evidence hints

Use these literal substrings as seed queries against the audit_mcp index
listed below — start with `semantic_search`, then drill in with
`search_functions` / `read_function` / `callers_of` on the most promising
hits:

{hints_block}

# Relevant APIs

The presence (or provable absence) of these symbols is load-bearing for the
verdict on this control:

{apis_block}

# Tool surface (this child)

  - audit_mcp index id : `{index_id}` — covers the jadx-decompiled Java
    tree. Use `mcp__audit_mcp_semantic_search`, `mcp__audit_mcp_read_function`,
    `mcp__audit_mcp_search_functions`, `mcp__audit_mcp_callers_of`,
    `mcp__audit_mcp_xrefs_to`, and `mcp__audit_mcp_search_constants`.
  - decompiled tree    : `{decompiled_dir}` ({jadx_class_count} classes).
  - android_mcp tools  : the parsed AndroidManifest, the static_summary
    (permissions, exported components, native libs, certificates,
    signing scheme), and the MobSF scan result when one ran. Reach for
    these when the control depends on manifest / signing / native-binary
    metadata rather than Java source.

# Outcome contract — how this child maps to a MASVS verdict

Return exactly one primary outcome. The MASVS aggregator at
`aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict` reads it
verbatim and never invents a verdict — silence becomes `inconclusive`,
not `no_finding`:

  - `direct_finding` (confidence >= 0.6) — only when you can cite a
    concrete code excerpt with file path + line range that shows the
    control is violated. Without that citation the finding is rejected.
  - `refuted` — you walked every verification step above and can
    affirmatively show the control is met (cite the satisfying code
    pattern or the manifest declaration).
  - explicit `not_applicable` tag — the underlying capability is absent
    in this APK (e.g. native-binary controls when
    `static_summary.native_libs` is empty). Cite the absence.
  - anything else (timeout, cost cap, ambiguous evidence) — emit
    `inconclusive` with a one-line reason describing what stopped you.
"""

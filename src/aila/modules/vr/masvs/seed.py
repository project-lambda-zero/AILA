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
        # fix §223 — ``overview.get('static_summary')`` may legitimately
        # return ``None`` (covered by the ``or {}``) but a partially-built
        # apk_overview from a buggy upstream stage could also stash a list,
        # string, or other non-Mapping. ``.get('package')`` on those raises
        # AttributeError; guard the type so this seed builder never crashes
        # on a malformed overview.
        static_summary_raw = overview.get("static_summary")
        static_summary: Mapping[str, Any] = (
            static_summary_raw if isinstance(static_summary_raw, Mapping) else {}
        )

        package = _text_or_unknown(static_summary.get("package"))
        version_name = _text_or_unknown(static_summary.get("version_name"))
        version_code = _text_or_unknown(static_summary.get("version_code"))
        sha256_full = _text_or_unknown(overview.get("sha256"))
        sha256 = sha256_full[:16] if sha256_full != _UNKNOWN else sha256_full
        index_id = _text_or_unknown(overview.get("audit_mcp_index_id"))
        jadx_class_count = _text_or_unknown(overview.get("jadx_class_count"))

        # fix §222 — match the hints_block/apis_block pattern: empty
        # verification_steps would otherwise render as a blank section
        # heading with no body, telling the scout nothing.
        steps_block = (
            "\n".join(
                f"{idx}. {step}"
                for idx, step in enumerate(control.verification_steps, start=1)
            )
            or "(none catalogued — use evidence hints below)"
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
#
# Aggressively trimmed (was ~4500 chars → now ~1200 chars). vuln_researcher
# already injects: (a) the persona system prompt, (b) the full tool
# surface declaration, (c) the audit-kind outcome contract. Repeating
# them in the seed bloated each child's per-turn context by ~3x with
# zero added information — drop them. What stays is the irreducible
# per-control payload: which MASVS control to audit, which APK, which
# audit-mcp index to query, and the catalog's evidence hints.
_PROMPT_TEMPLATE = """\
Audit MASVS control **{control_id}** ({group} L{level}) on APK `{package}`
(versionName {version_name}, sha256 {sha256}...). Use audit_mcp index
`{index_id}` for the jadx-decompiled Java tree ({jadx_class_count} classes).

## {title}

{description}

## Verification steps

{steps_block}

## Evidence hints (seed `mcp__audit_mcp_semantic_search` with these)

{hints_block}

## Load-bearing APIs

{apis_block}
"""

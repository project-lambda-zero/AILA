"""Capability profile builder — D-51 dispatcher.

Routes by target kind to the appropriate MCP, collects orientation +
classification signals, and merges them through a rule engine into
``TargetCapabilityProfile``. Same dispatcher pattern as
``function_ranker.py`` — no heuristics in Python beyond rule lookups;
the MCPs do the actual classification.

  source target  → audit-mcp ``detect_languages`` + ``attack_surface``
                   + ``preanalysis`` → language + framework + entrypoint
                   classifications

  binary target  → IDA ``binary_survey`` + ``checksec`` + ``classify_behavior``
                   + ``verify_capabilities`` + ``capa_scan`` → mitigations +
                   ATT&CK behavior categories + CAPA matches

Rule engine maps (target_kind, primary_language) onto the D-51
``applicable_*`` lists. Operator overrides take precedence over rule
output (overrides persist as ``capability_profile_json.overrides``).

Haiku finalize for ambiguous target_class is wired as an optional
hook on the dispatcher constructor — pass an LLM callable to enable
the fallback. Without it the builder emits the rule-engine output
directly. Deferred to when the rule engine actually produces a tie.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.enrichment import (
    MitigationFlags,
    TargetCapabilityProfile,
)
from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.contracts.target_stages import StageName
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.enrichment.services.function_ranker import (
    McpCallable,
)
from aila.modules.vr.services.stage_tracker import (
    StageAlreadyDoneError,
    StageInFlightError,
    StageTracker,
)
from aila.platform.uow import UnitOfWork

__all__ = [
    "CapabilityProfileBuilder",
    "ProfileBuilderError",
]

_log = logging.getLogger(__name__)


# Rule tables: which MCP servers apply per target_kind. Drives the
# capability_profile.applicable_mcp_servers list and downstream
# orchestration (which bridge to call for follow-up enrichment).
_APPLICABLE_MCP_BY_KIND: dict[str, list[str]] = {
    TargetKind.NATIVE_BINARY.value:   ["ida_headless", "audit_mcp"],
    TargetKind.SOURCE_REPO.value:     ["audit_mcp"],
    TargetKind.APK.value:             ["ida_headless"],
    TargetKind.IPA.value:             ["ida_headless"],
    TargetKind.JAR.value:             ["ida_headless", "audit_mcp"],
    TargetKind.DOTNET_ASSEMBLY.value: ["ida_headless"],
    TargetKind.CVE.value:             ["audit_mcp"],
    TargetKind.PROTOCOL_CAPTURE.value: [],
    TargetKind.CRASH_INPUT.value:     ["ida_headless"],
    TargetKind.PATCH_DIFF.value:      ["audit_mcp"],
    # v0.5 GA-54 — kernel + hypervisor
    TargetKind.KERNEL_IMAGE.value:    ["ida_headless", "audit_mcp"],
    TargetKind.KERNEL_MODULE.value:   ["ida_headless"],
    TargetKind.HYPERVISOR_IMAGE.value: ["ida_headless", "audit_mcp"],
}

# (target_kind, primary_language) → applicable fuzzing engines. Source
# missing OR language missing falls back to NATIVE_BINARY defaults.
_APPLICABLE_FUZZING_ENGINES: dict[tuple[str, str], list[str]] = {
    # v0.3 — single-target engines per (kind, language)
    (TargetKind.NATIVE_BINARY.value, "c"):          ["afl++_qemu", "libfuzzer"],
    (TargetKind.NATIVE_BINARY.value, "c++"):        ["afl++_qemu", "libfuzzer"],
    (TargetKind.NATIVE_BINARY.value, "javascript"): ["fuzzilli_v8"],
    (TargetKind.NATIVE_BINARY.value, "rust"):       ["afl++_qemu"],
    (TargetKind.NATIVE_BINARY.value, "go"):         ["afl++_qemu"],
    (TargetKind.SOURCE_REPO.value, "c"):            ["afl++", "libfuzzer", "honggfuzz"],
    (TargetKind.SOURCE_REPO.value, "c++"):          ["afl++", "libfuzzer", "honggfuzz"],
    (TargetKind.SOURCE_REPO.value, "rust"):         ["cargo-fuzz", "honggfuzz"],
    (TargetKind.SOURCE_REPO.value, "go"):           ["go-fuzz", "syzkaller"],
    (TargetKind.SOURCE_REPO.value, "java"):         ["jazzer"],
    (TargetKind.SOURCE_REPO.value, "kotlin"):       ["jazzer"],
    (TargetKind.SOURCE_REPO.value, "python"):       ["atheris"],
    (TargetKind.SOURCE_REPO.value, "javascript"):   ["fuzzilli_v8", "jsfuzz"],
    (TargetKind.SOURCE_REPO.value, "node"):         ["jsfuzz"],
    (TargetKind.APK.value, "kotlin"):               ["jazzer"],
    (TargetKind.APK.value, "java"):                 ["jazzer"],
    (TargetKind.JAR.value, "java"):                 ["jazzer"],
    (TargetKind.JAR.value, "kotlin"):               ["jazzer"],

    # v0.4 GA-53 — expanded profile coverage
    # PHP / Ruby are audit-only — no usable fuzzer ecosystem
    (TargetKind.SOURCE_REPO.value, "php"):          [],
    (TargetKind.SOURCE_REPO.value, "ruby"):         [],
    # Swift / Objective-C — IPA + native paths
    (TargetKind.SOURCE_REPO.value, "swift"):        ["libfuzzer-swift"],
    (TargetKind.IPA.value, "swift"):                ["libfuzzer-swift"],
    (TargetKind.IPA.value, "objc"):                 ["libfuzzer"],
    # Android extension — libFuzzer-Android for native libs in APK
    (TargetKind.APK.value, "c++"):                  ["libfuzzer-android"],
    (TargetKind.APK.value, "c"):                    ["libfuzzer-android"],
    # .NET — sharpfuzz coverage-guided fuzzer
    (TargetKind.DOTNET_ASSEMBLY.value, "c#"):       ["sharpfuzz"],
    (TargetKind.DOTNET_ASSEMBLY.value, "f#"):       ["sharpfuzz"],

    # v0.5 GA-56 — kernel + hypervisor fuzzers
    (TargetKind.KERNEL_IMAGE.value, "c"):           ["syzkaller", "kafl"],
    (TargetKind.KERNEL_MODULE.value, "c"):          ["syzkaller", "kafl"],
    (TargetKind.HYPERVISOR_IMAGE.value, "c"):       ["afl++", "qemu-fuzz"],
    (TargetKind.HYPERVISOR_IMAGE.value, "c++"):     ["afl++", "qemu-fuzz"],
}

# (target_kind, primary_language) → reasoning strategy family default
_DEFAULT_REASONING_STRATEGY: dict[tuple[str, str], str] = {
    (TargetKind.NATIVE_BINARY.value, "javascript"): "vulnerability_research.discovery_research",
    (TargetKind.NATIVE_BINARY.value, "c"):          "vulnerability_research.discovery_research",
    (TargetKind.NATIVE_BINARY.value, "c++"):        "vulnerability_research.discovery_research",
    (TargetKind.CVE.value, "*"):                    "vulnerability_research.variant_hunt",
    (TargetKind.PATCH_DIFF.value, "*"):             "vulnerability_research.patch_diff_analysis",
    (TargetKind.CRASH_INPUT.value, "*"):            "vulnerability_research.crash_triage",
    # v0.4 GA-53 — audit-only and mobile source-audit defaults
    (TargetKind.SOURCE_REPO.value, "php"):          "vulnerability_research.source_audit",
    (TargetKind.SOURCE_REPO.value, "ruby"):         "vulnerability_research.source_audit",
    (TargetKind.SOURCE_REPO.value, "python"):       "vulnerability_research.source_audit",
    (TargetKind.SOURCE_REPO.value, "java"):         "vulnerability_research.source_audit",
    (TargetKind.SOURCE_REPO.value, "kotlin"):       "vulnerability_research.source_audit",
    (TargetKind.APK.value, "*"):                    "vulnerability_research.discovery_research",
    (TargetKind.IPA.value, "*"):                    "vulnerability_research.discovery_research",
    (TargetKind.DOTNET_ASSEMBLY.value, "*"):        "vulnerability_research.discovery_research",
    # v0.5 GA-56 — kernel-first audit; fuzz invoked from narrowed surface
    (TargetKind.KERNEL_IMAGE.value, "*"):           "vulnerability_research.kernel_audit",
    (TargetKind.KERNEL_MODULE.value, "*"):          "vulnerability_research.kernel_audit",
    (TargetKind.HYPERVISOR_IMAGE.value, "*"):       "vulnerability_research.hypervisor_audit",
}

# target_kind → default disclosure tracks suggested at finding promotion.
# Workspace-level overrides land in M3.D-* disclosure orchestrator (D-49 +
# VR_V03_DISCLOSURE_LIFECYCLE_PLAN.md). These are the per-target priors.
_DEFAULT_DISCLOSURE_TRACKS: dict[str, list[str]] = {
    TargetKind.NATIVE_BINARY.value:   ["vendor_direct", "blog_post"],
    TargetKind.SOURCE_REPO.value:     ["cna_github_gsa", "vendor_direct", "blog_post"],
    TargetKind.APK.value:             ["vendor_direct", "blog_post"],
    TargetKind.IPA.value:             ["apple_security", "blog_post"],
    TargetKind.JAR.value:             ["vendor_direct", "blog_post"],
    TargetKind.DOTNET_ASSEMBLY.value: ["msrc", "vendor_direct", "blog_post"],
    TargetKind.CVE.value:             ["blog_post"],
    TargetKind.PROTOCOL_CAPTURE.value: ["cert_cc", "vendor_direct"],
    TargetKind.CRASH_INPUT.value:     ["vendor_direct", "blog_post"],
    TargetKind.PATCH_DIFF.value:      ["blog_post"],
    # v0.5 GA-57 — kernel + hypervisor disclosure
    # Linux kernel finding → kernel_org_security primary, linux_distros for
    # distro coordination, oss_security for public after embargo, plus the
    # researcher's blog post.
    TargetKind.KERNEL_IMAGE.value:    [
        "kernel_org_security", "linux_distros", "oss_security", "blog_post",
    ],
    TargetKind.KERNEL_MODULE.value:   [
        "kernel_org_security", "linux_distros", "oss_security", "blog_post",
    ],
    TargetKind.HYPERVISOR_IMAGE.value: [
        "cert_cc", "vendor_direct", "oss_security", "blog_post",
    ],
}

# All pattern kinds defined in VR_V03_KNOWLEDGE_TRANSFER_PLAN.md GA-41 apply
# to most binary + source targets. Refine when usage feedback warrants.
_DEFAULT_PATTERN_KINDS = [
    "exploitation_technique",
    "fuzzing_strategy",
    "search_heuristic",
    "tool_recipe",
    "triage_rule",
]

# Per-target_kind baseline cost; tuned over time from real investigation
# spend reports.
_DEFAULT_COST_USD: dict[str, float] = {
    TargetKind.NATIVE_BINARY.value:   30.0,
    TargetKind.SOURCE_REPO.value:     20.0,
    TargetKind.APK.value:             25.0,
    TargetKind.IPA.value:             25.0,
    TargetKind.JAR.value:             20.0,
    TargetKind.DOTNET_ASSEMBLY.value: 25.0,
    TargetKind.CVE.value:             10.0,
    TargetKind.PROTOCOL_CAPTURE.value: 15.0,
    TargetKind.CRASH_INPUT.value:     15.0,
    TargetKind.PATCH_DIFF.value:      15.0,
    # v0.5 — kernel work involves syzkaller campaigns + more turns
    TargetKind.KERNEL_IMAGE.value:    60.0,
    TargetKind.KERNEL_MODULE.value:   45.0,
    TargetKind.HYPERVISOR_IMAGE.value: 75.0,
}


class ProfileBuilderError(Exception):
    """Raised on fatal capability-profile dispatch failures."""


class CapabilityProfileBuilder:
    """Builds D-51 capability_profile for one target.

    Construction injects both MCP bridges so the builder can route by
    target kind. Optional ``llm_finalize`` callable enables Haiku
    finalization for ambiguous target classifications — when None,
    builder emits rule-engine output directly.
    """

    def __init__(
        self,
        ida: McpCallable,
        audit_mcp: McpCallable,
    ) -> None:
        self._ida = ida
        self._audit_mcp = audit_mcp


    async def _load(self, target_id: str) -> VRTargetRecord:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
            )).first()
            if row is None:
                raise ProfileBuilderError(f"target {target_id} not found")
            return row

    async def build(self, target_id: str) -> TargetCapabilityProfile | None:
        """Build capability_profile for one target. Persists into vr_targets.

        Reads MCP handles (binary_id, audit_mcp_index_id) from the
        target's private ``_mcp_handles_json`` column populated by
        TargetAnalysisService. Refuses to run when handles are missing
        — operator gets a clear 'target not analyzed yet' message.

        Wrapped in StageTracker (stage = CAPABILITY_PROFILE). Returns
        None when the stage is skipped (already DONE or in flight) so
        the caller can detect a no-op vs a fresh build.
        """
        try:
            async with StageTracker(target_id, StageName.CAPABILITY_PROFILE) as tracker:
                target_row = await self._load(target_id)
                handles = json.loads(target_row.mcp_handles_json or "{}")
                descriptor = json.loads(target_row.descriptor_json or "{}")
                kind_str = target_row.kind

                if kind_str == TargetKind.SOURCE_REPO.value:
                    signals = await self._gather_source_signals(handles)
                elif kind_str in {
                    TargetKind.NATIVE_BINARY.value,
                    TargetKind.APK.value,
                    TargetKind.IPA.value,
                    TargetKind.JAR.value,
                    TargetKind.DOTNET_ASSEMBLY.value,
                    TargetKind.KERNEL_IMAGE.value,
                    TargetKind.KERNEL_MODULE.value,
                    TargetKind.HYPERVISOR_IMAGE.value,
                }:
                    signals = await self._gather_binary_signals(handles)
                else:
                    # Unsupported kinds (cve / protocol_capture / crash_input /
                    # patch_diff) — no MCP gather. Operator can still drive
                    # investigations from descriptor alone.
                    signals = {
                        "primary_language": descriptor.get("primary_language") or "",
                    }

                # Rule engine produces applicable_* lists deterministically
                # from (kind, language) tuples. No MCP calls in this step.
                profile = self._compose_profile(target_row, signals)

                # Build the merged capability_profile_json that the persist
                # helper used to write — but write it via the tracker's
                # record_output so it lands in the same commit as the
                # stage's DONE transition.
                existing = json.loads(target_row.capability_profile_json or "{}")
                preserved_keys = ("function_ranking", "enrichment_errors", "overrides")
                preserved = {k: existing[k] for k in preserved_keys if k in existing}
                merged = profile.model_dump(mode="json")
                merged.update(preserved)
                merged["raw_signals"] = {
                    k: v for k, v in signals.items() if k.startswith("raw_")
                }
                tracker.record_output(
                    capability_profile_json=json.dumps(merged),
                    secondary_languages_json=json.dumps(profile.secondary_languages),
                )
                if profile.primary_language and not target_row.primary_language:
                    tracker.record_output(primary_language=profile.primary_language)

                _log.info(
                    "profile_builder COMPLETE target_id=%s kind=%s language=%s engines=%d strategies=%d",
                    target_id, kind_str, profile.primary_language,
                    len(profile.applicable_fuzzing_engines),
                    len(profile.applicable_strategies),
                )
                return profile
        except StageAlreadyDoneError:
            _log.info("profile_builder: target %s already built — skip", target_id)
            return None
        except StageInFlightError:
            _log.info("profile_builder: target %s in-flight — skip", target_id)
            return None

    async def _gather_source_signals(self, handles: dict[str, Any]) -> dict[str, Any]:
        index_id = handles.get("audit_mcp_index_id")
        if not index_id:
            raise ProfileBuilderError(
                "target not analyzed yet — call POST /vr/targets/{id}/analyze "
                "or wait for the auto-ingestion to complete",
            )

        signals: dict[str, Any] = {}
        langs_resp = await self._audit_mcp.forward(action="detect_languages", index_id=index_id)
        if langs_resp.get("status") == "ready":
            signals["primary_language"] = langs_resp.get("primary") or ""
            signals["secondary_languages"] = list(langs_resp.get("secondary") or [])
            signals["raw_detect_languages"] = langs_resp

        surface_resp = await self._audit_mcp.forward(action="attack_surface", index_id=index_id)
        if surface_resp.get("status") == "ready":
            signals["frameworks"] = list(surface_resp.get("frameworks") or [])
            signals["entrypoint_count"] = int(surface_resp.get("entrypoint_count") or 0)
            signals["raw_attack_surface"] = surface_resp

        prean_resp = await self._audit_mcp.forward(action="preanalysis", index_id=index_id)
        if prean_resp.get("status") == "ready":
            signals["blast_radius_top"] = prean_resp.get("blast_radius_top") or []
            signals["raw_preanalysis"] = prean_resp

        return signals

    async def _gather_binary_signals(self, handles: dict[str, Any]) -> dict[str, Any]:
        binary_id = handles.get("binary_id")
        if not binary_id:
            raise ProfileBuilderError(
                "target not analyzed yet — call POST /vr/targets/{id}/analyze "
                "or wait for the auto-ingestion to complete",
            )

        signals: dict[str, Any] = {}
        survey_resp = await self._ida.forward(action="binary_survey", binary_id=binary_id)
        if survey_resp.get("status") == "ready":
            signals["primary_language"] = (
                survey_resp.get("primary_language") or _infer_language_from_survey(survey_resp)
            )
            signals["arch"] = survey_resp.get("arch") or ""
            signals["entry_points"] = survey_resp.get("entry_points") or []
            signals["raw_binary_survey"] = survey_resp

        checksec_resp = await self._ida.forward(action="checksec", binary_id=binary_id)
        if checksec_resp.get("status") == "ready":
            signals["mitigations"] = {
                k: v for k, v in checksec_resp.items()
                if k not in ("status", "binary_id")
            }

        behavior_resp = await self._ida.forward(action="classify_behavior", binary_id=binary_id)
        if behavior_resp.get("status") == "ready":
            signals["behavior_categories"] = behavior_resp.get("categories") or []
            signals["raw_classify_behavior"] = behavior_resp

        caps_resp = await self._ida.forward(action="verify_capabilities", binary_id=binary_id)
        if caps_resp.get("status") == "ready":
            signals["verified_capabilities"] = caps_resp.get("capabilities") or []
            signals["raw_verify_capabilities"] = caps_resp

        capa_resp = await self._ida.forward(action="capa_scan", binary_id=binary_id)
        if capa_resp.get("status") == "ready":
            signals["capa_matches"] = capa_resp.get("matches") or []
            signals["raw_capa_scan"] = capa_resp

        # §1.4 — Imports + Exports tabs read these signals directly.
        imports_resp = await self._ida.forward(
            action="imports", binary_id=binary_id,
        )
        if imports_resp.get("status") == "ready":
            signals["imports"] = imports_resp.get("imports") or []
        exports_resp = await self._ida.forward(
            action="exports", binary_id=binary_id,
        )
        if exports_resp.get("status") == "ready":
            signals["exports"] = exports_resp.get("exports") or []

        return signals

    def _compose_profile(
        self,
        target_row: VRTargetRecord,
        signals: dict[str, Any],
    ) -> TargetCapabilityProfile:
        kind = TargetKind(target_row.kind)
        primary_language = (
            signals.get("primary_language")
            or target_row.primary_language
            or ""
        )

        secondary_languages: list[str] = list(
            signals.get("secondary_languages")
            or json.loads(target_row.secondary_languages_json or "[]")
        )

        mitigation_dict = signals.get("mitigations") or {}
        mitigations = _mitigations_from_dict(mitigation_dict)

        applicable_mcp_servers = list(_APPLICABLE_MCP_BY_KIND.get(target_row.kind, []))

        engines_key = (target_row.kind, primary_language.lower())
        applicable_fuzzing_engines = list(
            _APPLICABLE_FUZZING_ENGINES.get(engines_key, [])
        )

        default_reasoning_strategy = (
            _DEFAULT_REASONING_STRATEGY.get(engines_key)
            or _DEFAULT_REASONING_STRATEGY.get((target_row.kind, "*"))
            or "vulnerability_research.discovery_research"
        )

        default_disclosure_tracks = list(
            _DEFAULT_DISCLOSURE_TRACKS.get(target_row.kind, ["vendor_direct", "blog_post"])
        )

        estimated_cost = _DEFAULT_COST_USD.get(target_row.kind, 30.0)

        applicable_strategies: list[str] = []
        if applicable_fuzzing_engines:
            applicable_strategies.append("mutational")
            if "fuzzilli_v8" in applicable_fuzzing_engines:
                applicable_strategies.extend(["differential", "fuzzilli", "v8MapInference"])

        # §1.4 — Attack surface tab projects:
        # source targets → audit-mcp `frameworks` + entrypoint summary,
        # binary targets → IDA `behavior_categories` + checksec hints.
        attack_surface_items: list[dict[str, Any]] = []
        for fw in (signals.get("frameworks") or []):
            attack_surface_items.append({
                "kind": "framework",
                "name": str(fw),
                "location": "",
                "severity_hint": "info",
            })
        for cat in (signals.get("behavior_categories") or []):
            attack_surface_items.append({
                "kind": "behavior",
                "name": str(cat),
                "location": "",
                "severity_hint": "medium",
            })
        # Entry points (binary targets) collapse to a single row when
        # large — the operator drills into the IDA MCP for the full list.
        entry_points = signals.get("entry_points") or []
        if entry_points:
            attack_surface_items.append({
                "kind": "entry_points",
                "name": f"{len(entry_points)} entry point(s)",
                "location": "binary header",
                "severity_hint": "info",
            })

        return TargetCapabilityProfile(
            target_kind=kind,
            primary_language=primary_language,
            secondary_languages=secondary_languages,
            applicable_mcp_servers=applicable_mcp_servers,
            applicable_fuzzing_engines=applicable_fuzzing_engines,
            applicable_strategies=applicable_strategies,
            applicable_pattern_kinds=list(_DEFAULT_PATTERN_KINDS),
            default_reasoning_strategy=default_reasoning_strategy,
            default_disclosure_tracks=default_disclosure_tracks,
            estimated_cost_per_investigation_usd=estimated_cost,
            mitigations=mitigations,
            attack_surface=attack_surface_items,
            imports=list(signals.get("imports") or []),
            exports=list(signals.get("exports") or []),
        )


def _mitigations_from_dict(raw):
    """Map a flat checksec-style dict into MitigationFlags. Tristate-safe."""
    field_values = {}
    for field in ('nx', 'aslr', 'canary', 'cet', 'cfi', 'pie'):
        v = raw.get(field)
        if v in (True, False):
            field_values[field] = v
        elif isinstance(v, str):
            field_values[field] = v.lower() in ('true', '1', 'enabled', 'on', 'yes')
        else:
            field_values[field] = None
    return MitigationFlags(**field_values)


def _infer_language_from_survey(survey):
    """Map IDA binary_survey output to a primary_language string."""
    if not isinstance(survey, dict):
        return ''
    # Best-effort heuristic from common audit-mcp/IDA survey fields.
    for key in ('primary_language', 'language', 'detected_language'):
        v = survey.get(key)
        if isinstance(v, str) and v:
            return v
    return ''

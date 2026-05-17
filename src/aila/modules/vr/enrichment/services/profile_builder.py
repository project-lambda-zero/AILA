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
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.enrichment.services.function_ranker import (
    McpCallable,
)
from aila.platform.contracts._common import utc_now
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

    async def build(self, target_id: str) -> TargetCapabilityProfile:
        """Build capability_profile for one target. Persists into vr_targets.

        Sets ``enrichment_status='running'`` at entry; transitions to
        ``complete`` on success or ``failed`` on dispatch failure.
        Raises ``ProfileBuilderError`` on fatal infrastructure failures.
        """
        target_row = await self._load_and_mark_running(target_id)
        descriptor = json.loads(target_row.descriptor_json or "{}")
        kind_str = target_row.kind

        try:
            if kind_str == TargetKind.SOURCE_REPO.value:
                signals = await self._gather_source_signals(descriptor)
            elif kind_str in {
                TargetKind.NATIVE_BINARY.value,
                TargetKind.APK.value,
                TargetKind.IPA.value,
                TargetKind.JAR.value,
                TargetKind.DOTNET_ASSEMBLY.value,
            }:
                signals = await self._gather_binary_signals(descriptor)
            else:
                # Unsupported kinds get a minimal profile from descriptor + rules,
                # no MCP gather. Operator can still drive investigations.
                signals = {"primary_language": descriptor.get("primary_language") or ""}
        except ProfileBuilderError:
            raise
        except (OSError, TimeoutError, RuntimeError) as exc:
            await self._mark_failed(target_id, f"profile gather raised: {exc}")
            raise ProfileBuilderError(
                f"capability profile build failed for target_id={target_id}: {exc}",
            ) from exc

        # Rule engine produces applicable_* lists deterministically from
        # (kind, language) tuples. No MCP calls in this step.
        profile = self._compose_profile(target_row, signals)

        await self._persist(target_id, profile, signals)
        _log.info(
            "profile_builder COMPLETE target_id=%s kind=%s language=%s engines=%d strategies=%d",
            target_id, kind_str, profile.primary_language,
            len(profile.applicable_fuzzing_engines), len(profile.applicable_strategies),
        )
        return profile

    async def _gather_source_signals(self, descriptor: dict[str, Any]) -> dict[str, Any]:
        index_id = descriptor.get("audit_mcp_index_id")
        if not index_id:
            raise ProfileBuilderError(
                "source target descriptor missing audit_mcp_index_id — run "
                "audit-mcp index_codebase before profile build",
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

    async def _gather_binary_signals(self, descriptor: dict[str, Any]) -> dict[str, Any]:
        binary_id = descriptor.get("binary_id")
        if not binary_id:
            raise ProfileBuilderError(
                "binary target descriptor missing binary_id — upload + analyze "
                "in IDA MCP before profile build",
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
        )

    async def _load_and_mark_running(self, target_id: str) -> VRTargetRecord:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                raise ProfileBuilderError(f"target {target_id} not found")
            row.enrichment_status = "running"
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()
            await uow.session.refresh(row)
            return row

    async def _mark_failed(self, target_id: str, message: str) -> None:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                return
            capability = json.loads(row.capability_profile_json or "{}")
            errors = capability.setdefault("enrichment_errors", [])
            errors.append({"step": "profile_builder", "message": message})
            row.capability_profile_json = json.dumps(capability)
            row.enrichment_status = "failed"
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()

    async def _persist(
        self,
        target_id: str,
        profile: TargetCapabilityProfile,
        signals: dict[str, Any],
    ) -> None:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                raise ProfileBuilderError(
                    f"target {target_id} disappeared during profile build",
                )
            existing = json.loads(row.capability_profile_json or "{}")
            # Preserve any existing function_ranking from M3.T-3 + enrichment_errors
            preserved_keys = ("function_ranking", "enrichment_errors", "overrides")
            preserved = {k: existing[k] for k in preserved_keys if k in existing}

            merged = profile.model_dump(mode="json")
            merged.update(preserved)
            merged["raw_signals"] = {
                k: v for k, v in signals.items() if k.startswith("raw_")
            }

            row.capability_profile_json = json.dumps(merged)
            row.primary_language = profile.primary_language or row.primary_language
            row.secondary_languages_json = json.dumps(profile.secondary_languages)
            row.enrichment_status = "complete"
            row.last_enriched_at = utc_now()
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()


def _mitigations_from_dict(raw: dict[str, Any]) -> MitigationFlags:
    """Map a flat checksec-style dict into MitigationFlags. Tristate-safe."""
    field_values: dict[str, Any] = {}
    for field in ("nx", "aslr", "canary", "cet", "cfi", "pie"):
        value = raw.get(field)
        if isinstance(value, bool):
            field_values[field] = value

    relro = raw.get("relro")
    if isinstance(relro, str):
        norm = relro.strip().lower()
        if norm in {"no", "none", "false", ""}:
            field_values["relro_partial"] = False
            field_values["relro_full"] = False
        elif norm == "partial":
            field_values["relro_partial"] = True
            field_values["relro_full"] = False
        elif norm == "full":
            field_values["relro_partial"] = True
            field_values["relro_full"] = True

    sanitizers_raw = raw.get("sanitizers")
    if isinstance(sanitizers_raw, list):
        field_values["sanitizers"] = [str(s) for s in sanitizers_raw if isinstance(s, str)]

    notes = raw.get("notes")
    if isinstance(notes, str):
        field_values["notes"] = notes

    return MitigationFlags(**field_values)


def _infer_language_from_survey(survey: dict[str, Any]) -> str:
    """Best-effort language guess from a binary_survey response.

    binary_survey may or may not include a primary_language field
    depending on MCP version. Fall back to inspecting the imports list
    or compiler hints. Returns empty string when we can't tell —
    consumer code must handle missing language by widening engine
    applicability rules.
    """
    compiler = (survey.get("compiler") or "").lower()
    if "rustc" in compiler:
        return "rust"
    if "go" in compiler and "compiler" in compiler:
        return "go"
    if "msvc" in compiler or "g++" in compiler or "clang++" in compiler:
        return "c++"
    if "gcc" in compiler or "clang" in compiler:
        return "c"

    imports = [s.lower() for s in (survey.get("imports") or []) if isinstance(s, str)]
    if any("rt_init" in i or "go." in i for i in imports):
        return "go"
    if any(i.startswith("_zn") for i in imports):
        return "c++"

    return ""

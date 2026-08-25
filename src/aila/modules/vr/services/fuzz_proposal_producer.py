"""Deterministic fuzz-campaign proposal producer (req 9 / AC1).

After the function ranker persists a ``FunctionRanking`` into the
target's ``capability_profile_json``, this producer synthesizes one
``VRFuzzCampaignProposalRecord`` per top-ranked function so the operator
sees actionable proposals populate on the campaigns page WITHOUT
waiting for an investigation to declare a CAMPAIGN_LAUNCH outcome.

Producer-generated proposals are keyed by
``investigation_id IS NULL AND target_id == target.id`` so re-ranking
is idempotent (existing producer rows are wiped before re-writing).

Every emitted ``harness_build_command`` clears
``validate_harness_build_command`` (allowlisted tool head, no shell
metacharacters, no path in the head token). Every ``harness_source`` is
a valid fuzz-harness scaffold for the chosen language that references
the ranked function by name + source location.
"""
from __future__ import annotations

import json
import logging

from sqlmodel import col
from sqlmodel import delete as _delete
from sqlmodel.ext.asyncio.session import AsyncSession

from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.db_models.fuzz_proposal import (
    VRFuzzCampaignProposalRecord,
)
from aila.modules.vr.enrichment.contracts import FunctionRanking, RankedFunction

__all__ = ["produce_fuzz_proposals"]

_log = logging.getLogger(__name__)

_MAX_PROPOSALS = 8

# Language / engine / build-command mapping. Keys are lowercased forms
# of ``capability_profile.primary_language`` (with common aliases like
# "c++" mapping to "cpp"). Every build command below returns None from
# ``validate_harness_build_command`` (allowlisted head, no shell
# metacharacters).
_LANG_MAP: dict[str, tuple[str, str]] = {
    "c":    ("c",    "clang -g -O1 -fsanitize=fuzzer,address -o harness harness.c"),
    "cpp":  ("cpp",  "clang++ -g -O1 -fsanitize=fuzzer,address -o harness harness.cc"),
    "c++":  ("cpp",  "clang++ -g -O1 -fsanitize=fuzzer,address -o harness harness.cc"),
    "cxx":  ("cpp",  "clang++ -g -O1 -fsanitize=fuzzer,address -o harness harness.cc"),
    "rust": ("rust", "cargo fuzz build"),
    "go":   ("go",   "go test -fuzz Fuzz"),
}

_DEFAULT_LANG_KEY = "c"

# Preferred engine per language head; only used when the target's
# capability profile did not declare ``applicable_fuzzing_engines``.
_ENGINE_FALLBACK: dict[str, str] = {
    "c":    "libfuzzer",
    "cpp":  "libfuzzer",
    "rust": "cargo-fuzz",
    "go":   "go-fuzz",
}


def _pick_language(profile: dict) -> tuple[str, str, str]:
    """Return (language_key, harness_language, build_command)."""
    primary = (profile.get("primary_language") or "").strip().lower()
    key = primary if primary in _LANG_MAP else _DEFAULT_LANG_KEY
    lang, cmd = _LANG_MAP[key]
    return key, lang, cmd


def _pick_engine(profile: dict, lang_key: str) -> str:
    engines = profile.get("applicable_fuzzing_engines") or []
    if engines and isinstance(engines, list) and isinstance(engines[0], str):
        return engines[0]
    return _ENGINE_FALLBACK.get(lang_key, "libfuzzer")


def _confidence_for(score: float) -> str:
    if score >= 0.66:
        return "high"
    if score >= 0.33:
        return "medium"
    return "low"


def _rationale_for(func: RankedFunction) -> str:
    reasons = [r for r in (func.reasons or []) if isinstance(r, str) and r.strip()]
    head = f"Ranked #{func.rank} (score={func.score:.2f}) by function ranker"
    if not reasons:
        return head
    return head + " -- " + "; ".join(reasons[:6])


def _location_comment(func: RankedFunction) -> str:
    loc_bits: list[str] = []
    if func.file_path:
        if func.line:
            loc_bits.append(f"{func.file_path}:{func.line}")
        else:
            loc_bits.append(func.file_path)
    if func.address:
        loc_bits.append(f"va={func.address}")
    return ", ".join(loc_bits) if loc_bits else "location unknown"


def _harness_source(func: RankedFunction, lang: str) -> str:
    """Synthesize a real fuzz-harness scaffold for the ranked function.

    Each scaffold is a compilable skeleton that:
      * names the ranked function in a comment (name + source location),
      * exposes the standard fuzz-entry symbol for the chosen engine,
      * leaves a single ``Refine:`` note where the operator or reasoning
        agent wires the fuzzer input into ``<func>``.
    """
    name = func.name
    loc = _location_comment(func)
    if lang == "c":
        return (
            f"// Auto-generated fuzz harness scaffold for {name}\n"
            f"// Source: {loc}\n"
            "// Refine: pass fuzzer input to " + name + "\n"
            "#include <stddef.h>\n"
            "#include <stdint.h>\n"
            "\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "    (void)data;\n"
            "    (void)size;\n"
            "    return 0;\n"
            "}\n"
        )
    if lang == "cpp":
        return (
            f"// Auto-generated fuzz harness scaffold for {name}\n"
            f"// Source: {loc}\n"
            "// Refine: pass fuzzer input to " + name + "\n"
            "#include <cstddef>\n"
            "#include <cstdint>\n"
            "\n"
            "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {\n"
            "    (void)data;\n"
            "    (void)size;\n"
            "    return 0;\n"
            "}\n"
        )
    if lang == "rust":
        return (
            f"// Auto-generated cargo-fuzz harness scaffold for {name}\n"
            f"// Source: {loc}\n"
            "// Refine: pass fuzzer input to " + name + "\n"
            "#![no_main]\n"
            "use libfuzzer_sys::fuzz_target;\n"
            "\n"
            "fuzz_target!(|data: &[u8]| {\n"
            "    let _ = data;\n"
            "});\n"
        )
    if lang == "go":
        return (
            f"// Auto-generated go-fuzz harness scaffold for {name}\n"
            f"// Source: {loc}\n"
            "// Refine: pass fuzzer input to " + name + "\n"
            "package fuzz\n"
            "\n"
            "import \"testing\"\n"
            "\n"
            "func Fuzz(f *testing.F) {\n"
            "    f.Fuzz(func(t *testing.T, data []byte) {\n"
            "        _ = data\n"
            "    })\n"
            "}\n"
        )
    # Should not happen -- _pick_language falls back to "c".
    return (
        f"// Auto-generated fuzz harness scaffold for {name}\n"
        f"// Source: {loc}\n"
        "int main(void) { return 0; }\n"
    )


async def produce_fuzz_proposals(
    session: AsyncSession,
    target: VRTargetRecord,
    ranking: FunctionRanking,
) -> int:
    """Persist deterministic fuzz proposals for the top-ranked functions.

    Returns the number of proposal rows written. Idempotent: prior
    producer rows (``investigation_id IS NULL`` for this target) are
    deleted first so re-ranking does not accumulate duplicates.
    """
    if ranking is None or not ranking.top_k:
        return 0

    try:
        profile = json.loads(target.capability_profile_json or "{}")
    except (ValueError, TypeError):
        profile = {}
    if not isinstance(profile, dict):
        profile = {}

    lang_key, harness_language, build_command = _pick_language(profile)
    engine_id = _pick_engine(profile, lang_key)

    # Idempotency -- wipe prior producer rows for this target.
    await session.exec(
        _delete(VRFuzzCampaignProposalRecord).where(
            VRFuzzCampaignProposalRecord.target_id == target.id,
            col(VRFuzzCampaignProposalRecord.investigation_id).is_(None),
        ),
    )

    ordered = sorted(ranking.top_k, key=lambda f: f.rank)[:_MAX_PROPOSALS]
    written = 0
    for func in ordered:
        try:
            profile_label = f"{engine_id}:{func.name}"[:128]
            descriptor = {
                "function": {
                    "name": func.name,
                    "file_path": func.file_path,
                    "line": func.line,
                    "address": func.address,
                },
                "ranking": {
                    "rank": func.rank,
                    "score": func.score,
                    "source": ranking.source.value,
                },
            }
            row = VRFuzzCampaignProposalRecord(
                investigation_id=None,
                outcome_id=None,
                target_id=target.id,
                workspace_id=target.workspace_id,
                team_id=target.team_id,
                profile=profile_label or engine_id[:128],
                rationale=_rationale_for(func),
                confidence=_confidence_for(func.score),
                target_descriptor_json=json.dumps(descriptor),
                suggested_engine_id=engine_id[:32],
                harness_source=_harness_source(func, harness_language),
                harness_language=harness_language,
                harness_build_command=build_command,
                status="pending",
            )
            session.add(row)
            written += 1
        except (ValueError, TypeError, KeyError) as exc:
            _log.warning(
                "fuzz_proposal_producer: skipping ranked function %r: %s",
                func.name, exc,
            )
    return written

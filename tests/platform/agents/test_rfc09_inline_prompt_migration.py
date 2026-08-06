"""Tests for RFC-09 rule-58/59 inline prompt migration (G1).

The eight rule-58 sites (``_*_PROMPT*`` module-level literals) and the
three rule-59 sites (untagged ``.chat*`` calls) named on Tier B were
migrated to file-backed :class:`PromptRegistry` resolution + version-store
registration + ``correlation_scope`` tagging.

These tests assert three things without requiring the LLM path to run:

1. Each migrated prompt loads from its ``.md`` file via
   :class:`PromptRegistry` and returns a non-empty body (registry wiring
   is live).
2. After ``seed_prompt_versions`` runs, the version store carries the
   platform + VR + malware migration keys with a production alias whose
   ``body`` matches the file-backed body byte-identically (round-trip
   preserved, criterion 1 of the rule).
3. The three rule-59 sites' enclosing functions now reference
   ``correlation_scope`` in their AST body so rule 59 is satisfied
   without a whitelist entry (criterion 2 of the rule).
"""
from __future__ import annotations

import ast
import pathlib

import pytest

pytestmark = pytest.mark.usefixtures("test_db")


# ---------------------------------------------------------------- loaders


def test_platform_claim_verifier_prompts_load_from_registry() -> None:
    from aila.platform.agents.claim_verifier import (
        _load_extractor_prompt,
        _load_verdict_prompt,
    )

    extractor = _load_extractor_prompt()
    verdict = _load_verdict_prompt()
    assert extractor.startswith("You are an adversarial vulnerability-finding verifier.")
    assert "adversarial verifier producing a" in verdict
    # Both prompts are load-bearing multi-line documents; verify size to
    # catch a truncated .md file at import time.
    assert extractor.count("\n") > 50
    assert verdict.count("\n") > 50


def test_vr_migrated_prompts_load_from_registry() -> None:
    from aila.modules.vr.agents.narrative_agent import (
        _load_system_prompt as vr_narrative_prompt,
    )
    from aila.modules.vr.agents.nday_researcher import (
        _load_system_prompt as vr_nday_prompt,
    )
    from aila.modules.vr.agents.synthesis_agent import (
        _load_system_prompt as vr_synthesis_prompt,
    )
    from aila.modules.vr.apk_static.seed import _load_prompt_template as apk_seed
    from aila.modules.vr.masvs.seed import _load_prompt_template as masvs_seed

    assert vr_narrative_prompt().startswith(
        "You are the narrative writer for the AILA vulnerability-research",
    )
    assert vr_nday_prompt().startswith(
        "You are an autonomous N-day vulnerability researcher.",
    )
    assert vr_synthesis_prompt().startswith(
        "You are the synthesiser for a vulnerability-research deliberation ",
    )
    # Templates carry str.format placeholders -- verify they survived
    # the migration unchanged so downstream ``.format`` still resolves.
    assert "{check_id}" in apk_seed()
    assert "{control_id}" in masvs_seed()


def test_malware_migrated_prompts_load_from_registry() -> None:
    from aila.modules.malware.agents.narrative_agent import (
        _load_system_prompt as mw_narrative_prompt,
    )
    from aila.modules.malware.agents.synthesis_agent import (
        _load_system_prompt as mw_synthesis_prompt,
    )

    assert mw_narrative_prompt().startswith(
        "You are the narrative writer for the AILA malware-analysis",
    )
    assert mw_synthesis_prompt().startswith(
        "You are the synthesizer for a malware-analysis deliberation panel.",
    )


def test_rule59_report_writer_prompts_load_from_registry() -> None:
    from aila.modules.forensics.workflow.states.collectors.network import (
        _load_commentary_system_prompt,
    )
    from aila.modules.vr.reporting.poc_writer import PocWriter
    from aila.modules.vr.reporting.writer_agent import ReportWriter

    poc = PocWriter._system_prompt()
    rep = ReportWriter._system_prompt()
    comm = _load_commentary_system_prompt()
    assert poc.startswith("You are a senior exploit developer.")
    assert rep.startswith("You are a senior security report writer")
    assert comm.startswith("You are a senior network-forensics analyst.")


# -------------------------------------------------------- seed round-trip


async def test_vr_seed_registers_rule58_migration_keys() -> None:
    from aila.modules.vr.agents.narrative_agent import (
        _load_system_prompt as vr_narrative_prompt,
    )
    from aila.modules.vr.agents.nday_researcher import (
        _load_system_prompt as vr_nday_prompt,
    )
    from aila.modules.vr.agents.synthesis_agent import (
        _load_system_prompt as vr_synthesis_prompt,
    )
    from aila.modules.vr.agents.vuln_researcher import (
        _PROMPT_VERSION_STORE,
        seed_prompt_versions,
    )
    from aila.modules.vr.apk_static.seed import _load_prompt_template as apk_seed
    from aila.modules.vr.masvs.seed import _load_prompt_template as masvs_seed

    await seed_prompt_versions()

    expected: tuple[tuple[str, str], ...] = (
        ("vr/narrative/base", vr_narrative_prompt()),
        ("vr/nday/base", vr_nday_prompt()),
        ("vr/synthesis/base", vr_synthesis_prompt()),
        ("vr/apk_static_seed/base", apk_seed()),
        ("vr/masvs_seed/base", masvs_seed()),
    )
    for key, body in expected:
        rec = await _PROMPT_VERSION_STORE.resolve(key, alias="production")
        assert rec is not None, f"no production alias for {key}"
        assert rec.body == body, f"body drift on {key}"


async def test_malware_seed_registers_rule58_migration_keys() -> None:
    from aila.modules.malware.agents.malware_researcher import (
        _PROMPT_VERSION_STORE,
        seed_prompt_versions,
    )
    from aila.modules.malware.agents.narrative_agent import (
        _load_system_prompt as mw_narrative_prompt,
    )
    from aila.modules.malware.agents.synthesis_agent import (
        _load_system_prompt as mw_synthesis_prompt,
    )

    await seed_prompt_versions()

    expected: tuple[tuple[str, str], ...] = (
        ("malware/narrative/base", mw_narrative_prompt()),
        ("malware/synthesis/base", mw_synthesis_prompt()),
    )
    for key, body in expected:
        rec = await _PROMPT_VERSION_STORE.resolve(key, alias="production")
        assert rec is not None, f"no production alias for {key}"
        assert rec.body == body, f"body drift on {key}"


async def test_platform_claim_verifier_prompts_land_via_module_seed() -> None:
    """The platform-owned prompts are seeded by EITHER module's hook.

    Content-hash dedup on ``register`` makes the double-call safe.
    """
    from aila.modules.vr.agents.vuln_researcher import (
        _PROMPT_VERSION_STORE,
        seed_prompt_versions,
    )
    from aila.platform.agents.claim_verifier import (
        _load_extractor_prompt,
        _load_verdict_prompt,
    )

    await seed_prompt_versions()
    ext = await _PROMPT_VERSION_STORE.resolve(
        "platform/claim_verifier/extractor", alias="production",
    )
    verd = await _PROMPT_VERSION_STORE.resolve(
        "platform/claim_verifier/verdict", alias="production",
    )
    assert ext is not None and ext.body == _load_extractor_prompt()
    assert verd is not None and verd.body == _load_verdict_prompt()


# ------------------------------------------------ rule 59 static AST check


def _function_names_referencing_correlation_scope(
    path: str, target_funcs: set[str],
) -> set[str]:
    """Return the subset of ``target_funcs`` whose body references
    ``correlation_scope`` -- mirrors the honesty audit's rule-59 marker
    check.
    """
    tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
    hits: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in target_funcs:
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id == "correlation_scope":
                hits.add(node.name)
                break
    return hits


def test_rule59_sites_now_wrap_llm_call_in_correlation_scope() -> None:
    poc = _function_names_referencing_correlation_scope(
        "src/aila/modules/vr/reporting/poc_writer.py", {"write"},
    )
    rep = _function_names_referencing_correlation_scope(
        "src/aila/modules/vr/reporting/writer_agent.py", {"write"},
    )
    comm = _function_names_referencing_correlation_scope(
        "src/aila/modules/forensics/workflow/states/collectors/network.py",
        {"_try_llm_commentary"},
    )
    assert "write" in poc, "poc_writer.write must wrap chat_structured in correlation_scope"
    assert "write" in rep, "writer_agent.write must wrap chat_structured in correlation_scope"
    assert "_try_llm_commentary" in comm, (
        "network._try_llm_commentary must wrap chat_json in correlation_scope"
    )

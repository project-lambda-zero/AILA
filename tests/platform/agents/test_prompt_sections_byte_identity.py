"""Pre-lift byte snapshots for the RFC-290 prompt-helper consolidation.

The expected JSON was generated from the original module-local VR and malware
implementations before any source edits. Never regenerate it as part of the
consolidation: these bytes protect the idempotency-cache prompt identity.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from aila.modules.malware.agents import malware_researcher as malware
from aila.modules.vr.agents import vuln_researcher as vr
from aila.platform.agents import prompt_sections
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    ReasoningTurnDecision,
)
from aila.platform.services.reasoning import CyberReasoningEngine

_EXPECTED = json.loads(
    Path(__file__).with_name("prompt_sections_pre_lift.json").read_text(
        encoding="utf-8",
    ),
)
_MODULES = {"vr": vr, "malware": malware}
_SECTIONS = (
    "operator_messages",
    "active_directives",
    "format_param",
    "available_tools",
    "pattern",
    "pattern_budget",
    "retrieved_knowledge",
    "retrieved_knowledge_budget",
    "target_snapshot",
    "prior_submissions",
    "sibling_context",
    "applicable_servers",
    "outcome_payload",
    "full_user_prompt",
)


class _FixedBudgetEngine(CyberReasoningEngine):
    def __init__(self) -> None:
        super().__init__(llm_client=cast(Any, SimpleNamespace()))

    def resolve_context_budget_tokens(self) -> int:
        return 100_000


def _fixed_inputs(module_name: str) -> dict[str, Any]:
    is_vr = module_name == "vr"
    target_snapshot = {
        "kind": "source_repo" if is_vr else "native_binary",
        "display_name": "fixture-target",
        "primary_language": "c",
        "secondary_languages": ["cpp"],
        "analysis_state": "ready",
        "descriptor": {
            "repo_url": "https://example.invalid/repo.git",
            "vulnerable_ref": "v1.2.3",
            "upload_filename": "fixture.bin",
            "sample_path": "C:/fixtures/fixture.bin",
            "apk_path": "C:/fixtures/fixture.apk",
            "download_url": "https://example.invalid/fixture.bin",
        },
        "mcp_handles": (
            {"audit_mcp_index_id": "idx-fixture", "binary_id": "bin-fixture"}
            if is_vr
            else {"sample_path": "C:/fixtures/fixture.bin", "binary_id": "bin-fixture"}
        ),
        "applicable_mcp_servers": ["audit_mcp", "knowledge"],
        "applicable_fuzzing_engines": ["libfuzzer"],
        "applicable_strategies": ["audit"],
        "functions_of_interest": [
            {"name": "parse_header", "score": 9.75, "reasons": ["attacker input", "copy"]},
            {"function_name": "decode_body", "score": 8, "reasons": ["size field"]},
        ],
        "attack_surface": [
            {
                "kind": "parser",
                "name": "parse_header",
                "location": "src/parser.c:42",
                "severity_hint": "high",
            },
        ],
    }
    tool_specs = {
        "audit_mcp" if is_vr else "rea": [
            {
                "name": "read_function" if is_vr else "procedure_pseudo_code",
                "params": [
                    {"name": "index_id" if is_vr else "procedure", "type": "string", "required": True},
                    {"name": "limit", "type": "integer", "default": 200},
                ],
            },
        ],
        "knowledge": [
            {
                "name": "search",
                "params": [{"name": "query", "type": "string", "required": True}],
            },
        ],
    }
    return {
        "messages": [
            {"id": "op-2", "intent": "redirect", "text": "Inspect the parser first."},
            {"id": "op-1", "intent": None, "text": "Cite src/parser.c:42."},
        ],
        "case_state": ReasoningCaseState(
            contract=ReasoningContract(
                answer_type="security_finding",
                answer_format="markdown",
                evidence_domain="source",
                depends_on=["parser"],
            ),
            hypotheses=[
                Hypothesis(
                    id="h1",
                    claim="The length field reaches an unchecked copy.",
                    why_plausible="The field is attacker controlled.",
                    kill_criterion="A bounds check rejects oversized input.",
                    opened_at_turn=1,
                ),
            ],
            observables={
                "_directive.zeta": "Resolve h1 before submitting.\n",
                "_directive.alpha": "Read src/parser.c:42.\n",
                "audit_mcp:read_function.parse_header": "42: memcpy(dst, src, len);",
                "scratch": "fixed observable",
            },
        ),
        "target_snapshot": target_snapshot,
        "prior_outcomes": [
            {
                "created_at": "2026-01-02T03:04:05.123456+00:00",
                "outcome_kind": "direct_finding",
                "confidence": "strong",
                "answer": "Earlier VR answer at src/old.c:10.",
                "claim_text": "Earlier malware claim at offset 0x10.",
                "variant_hunt_orders": [{"function": "old_call"}],
                "affected_components": ["src/old.c:10"],
            },
        ],
        "siblings": [
            {
                "persona_voice": "renzo",
                "turn_count": 4,
                "hypotheses": [{"id": "r1", "claim": "The sibling suspects a size confusion."}],
                "rejected": [{"id": "r0", "claim": "The sibling rejected a format string."}],
                "key_observables": {"sibling_key": "sibling value"},
                "tool_observables": {"rea:binary_overview": "fixed sibling reading"},
                "recent_activity": [
                    {
                        "created_at": "2026-01-02T03:04:05+00:00",
                        "at_turn": 4,
                        "payload_kind": "tool_call",
                        "tool_name": "rea.procedure_pseudo_code",
                    },
                    {
                        "created_at": "2026-01-02T03:03:04+00:00",
                        "at_turn": 3,
                        "payload_kind": "tool_result",
                        "summary": "parser pseudocode",
                        "is_error": False,
                    },
                ],
                "terminal_outcome": {
                    "outcome_kind": "assessment_report",
                    "confidence": "medium",
                    "answer": "VR sibling terminal answer.",
                    "claim_text": "Malware sibling terminal claim.",
                    "variant_hunt_orders_count": 2,
                },
            },
        ],
        "patterns": [
            {
                "summary": "Check size propagation",
                "kind": "audit_heuristic",
                "body": "Trace the size from input to the copy at src/parser.c:42.",
            },
        ],
        "retrieved": [
            {
                "namespace": "vr.finding.previous" if is_vr else "malware.finding.previous",
                "content": "Prior finding with an anchor at src/old.c:10.",
                "score": 0.875,
            },
        ],
        "tool_specs": tool_specs,
        "inv": SimpleNamespace(
            title="Fixture investigation",
            kind="variant_hunt" if is_vr else "full_analysis",
            initial_question="Is the parser memory safe?",
            target_id="target-1",
            secondary_target_refs_json='["target-2", 7]',
            strategy_family="vulnerability_research.audit" if is_vr else "default",
        ),
        "branch": SimpleNamespace(id="branch-fixture", persona_voice="halvar"),
        "cve_intel": [
            {
                "cve_id": "CVE-2026-0001",
                "status": "found",
                "description": "Fixture advisory.",
                "cwe_ids": ["CWE-120"],
                "cvss_score": 9.8,
                "base_severity": "CRITICAL",
                "kev_listed": True,
                "kev_date_added": "2026-01-01",
                "epss_score": 0.5,
                "epss_percentile": 0.9,
                "affected_products": ["Fixture 1.0"],
                "notes": ["Corroborate locally."],
            },
        ],
    }


def _full_user_prompt(module_name: str) -> str:
    data = _fixed_inputs(module_name)
    engine = _FixedBudgetEngine()
    common = {
        "inv": data["inv"],
        "branch": data["branch"],
        "case_state": data["case_state"],
        "turn": 7,
        "pending_operator_messages": data["messages"],
        "target_snapshot": data["target_snapshot"],
        "tool_specs": data["tool_specs"],
        "prior_outcomes": data["prior_outcomes"],
        "sibling_context": data["siblings"],
        "applicable_patterns": data["patterns"],
        "retrieved_knowledge": data["retrieved"],
    }
    if module_name == "vr":
        researcher = vr.HonestVulnResearcher(
            engine,
            "inv-fixture",
            "branch-fixture",
            cve_intel=data["cve_intel"],
            applicable_patterns=data["patterns"],
            retrieved_knowledge=data["retrieved"],
        )
        with patch.object(vr, "_is_prompt_layout_enabled", lambda _: False):
            return researcher._build_user_prompt(cve_intel=data["cve_intel"], **common)
    researcher = malware.HonestMalwareResearcher(
        engine,
        "inv-fixture",
        "branch-fixture",
        applicable_patterns=data["patterns"],
        retrieved_knowledge=data["retrieved"],
    )
    return researcher._build_user_prompt(**common)


@lru_cache(maxsize=2)
def _capture_current(module_name: str) -> dict[str, Any]:
    """Render the fixed cases; dispatch changes homes, never expected bytes."""
    module = _MODULES[module_name]
    data = _fixed_inputs(module_name)
    decision = ReasoningTurnDecision(
        reasoning="fixed reasoning",
        action="submit",
        answer="fixed answer",
        confidence="strong",
        contract=ReasoningContract(answer_type="finding", answer_format="markdown"),
        payload={"answer": "structured answer wins", "affected_components": ["src/parser.c:42"]},
    )
    long_patterns = [
        *data["patterns"],
        {"summary": "Budget sentinel", "kind": "audit_heuristic", "body": "P" * 4000},
    ]
    long_retrieved = [
        *data["retrieved"],
        {"namespace": "shared.knowledge.long", "content": "R" * 5000, "score": 0.25},
    ]
    prior = (
        module._render_prior_submissions_section(data["prior_outcomes"], data["inv"].kind)
        if module_name == "vr"
        else module._render_prior_submissions_section(data["prior_outcomes"])
    )
    return {
        "operator_messages": prompt_sections.render_operator_messages_section(data["messages"]),
        "active_directives": prompt_sections.render_active_directives_section(data["case_state"]),
        "format_param": prompt_sections.format_param({"name": "options", "type": "object", "default": {"deep": "x" * 80}}),
        "available_tools": module._render_available_tools_section(
            data["target_snapshot"]["kind"],
            data["tool_specs"],
            "c",
        ),
        "pattern": prompt_sections.render_pattern_section(data["patterns"]),
        "pattern_budget": prompt_sections.render_pattern_section(long_patterns),
        "retrieved_knowledge": module._render_retrieved_knowledge_section(data["retrieved"]),
        "retrieved_knowledge_budget": module._render_retrieved_knowledge_section(long_retrieved),
        "target_snapshot": module._render_target_snapshot_section(data["target_snapshot"]),
        "prior_submissions": prior,
        "sibling_context": module._render_sibling_context_section(
            data["siblings"], this_persona="halvar",
        ),
        "applicable_servers": sorted(module._applicable_servers_for_kind(data["target_snapshot"]["kind"])),
        "outcome_payload": prompt_sections.outcome_payload(decision),
        "full_user_prompt": _full_user_prompt(module_name),
    }


@pytest.mark.parametrize("module_name", ("vr", "malware"))
@pytest.mark.parametrize("section", _SECTIONS)
def test_prompt_bytes_match_pre_lift_snapshots(module_name: str, section: str) -> None:
    assert _capture_current(module_name)[section] == _EXPECTED[module_name][section]

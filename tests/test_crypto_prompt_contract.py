"""Regression tests for the live crypto MCP prompt contract."""

from __future__ import annotations

from pathlib import Path

_PROMPT_ROOTS = (
    Path(__file__).parents[1] / "src" / "aila" / "modules" / "vr" / "agents" / "prompts",
    Path(__file__).parents[1] / "src" / "aila" / "modules" / "malware" / "agents" / "prompts",
)
_SYSTEM_PROMPTS = (
    _PROMPT_ROOTS[0] / "system_audit.md",
    _PROMPT_ROOTS[1] / "system_malware_analysis.md",
)


def _prompt_files() -> list[Path]:
    return sorted(path for root in _PROMPT_ROOTS for path in root.rglob("*.md"))


def test_prompts_use_only_the_live_crypto_tool_name() -> None:
    prompts = _prompt_files()
    assert prompts

    for path in prompts:
        body = path.read_text(encoding="utf-8")
        assert "find_crypto_constants" not in body, path

    for path in _SYSTEM_PROMPTS:
        body = path.read_text(encoding="utf-8")
        assert "reverser_belt.detect_crypto_primitives" in body


def test_malware_prompt_does_not_treat_duplicate_crypto_scans_as_independent() -> None:
    body = (_PROMPT_ROOTS[1] / "system_malware_analysis.md").read_text(
        encoding="utf-8",
    )
    crypto_question = next(
        (
            line
            for line in body.splitlines()
            if '"Is this routine a known crypto primitive?"' in line
        ),
        "",
    )

    assert crypto_question
    assert crypto_question.count("reverser_belt.detect_crypto_primitives") == 1
    assert "find_crypto_constants" not in crypto_question

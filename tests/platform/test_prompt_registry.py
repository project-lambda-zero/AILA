"""Unit tests for the platform PromptRegistry (RFC-09 step 0).

File-backed resolution, behavior-identical to the module _load_prompt it
replaced: strategy-specific base, fallback base, missing-prompt error, and
persona prepend.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aila.platform.prompts import PromptNotFoundError, PromptRegistry


def _reg(tmp_path: Path, fallback_base: str = "system_audit.md") -> PromptRegistry:
    return PromptRegistry(tmp_path, fallback_base=fallback_base)


def test_strategy_specific_base_is_preferred(tmp_path: Path) -> None:
    (tmp_path / "system_discovery.md").write_text("DISCOVERY BASE", encoding="utf-8")
    (tmp_path / "system_audit.md").write_text("FALLBACK BASE", encoding="utf-8")
    reg = _reg(tmp_path)
    assert reg.load("vulnerability_research.discovery") == "DISCOVERY BASE"


def test_falls_back_to_base_when_no_strategy_file(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("FALLBACK BASE", encoding="utf-8")
    reg = _reg(tmp_path)
    assert reg.load("vulnerability_research.no_such_strategy") == "FALLBACK BASE"


def test_uses_last_dotted_segment_as_leaf(tmp_path: Path) -> None:
    (tmp_path / "system_memory_forensics.md").write_text("LEAF", encoding="utf-8")
    (tmp_path / "system_audit.md").write_text("FALLBACK", encoding="utf-8")
    reg = _reg(tmp_path)
    assert reg.load("forensics.deep.memory_forensics") == "LEAF"


def test_missing_base_and_fallback_raises(tmp_path: Path) -> None:
    reg = _reg(tmp_path)
    with pytest.raises(PromptNotFoundError):
        reg.load("vulnerability_research.discovery")


def test_persona_is_prepended_to_base(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("BASE BODY", encoding="utf-8")
    (tmp_path / "persona_halvar.md").write_text("HALVAR ROLE", encoding="utf-8")
    reg = _reg(tmp_path)
    out = reg.load("vulnerability_research.audit", persona_voice="halvar")
    assert out == "HALVAR ROLE\n\n---\n\nBASE BODY"


def test_persona_case_insensitive_filename(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("BASE", encoding="utf-8")
    (tmp_path / "persona_halvar.md").write_text("ROLE", encoding="utf-8")
    reg = _reg(tmp_path)
    out = reg.load("vulnerability_research.audit", persona_voice="HALVAR")
    assert out == "ROLE\n\n---\n\nBASE"


def test_missing_persona_file_returns_base_only(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("BASE", encoding="utf-8")
    reg = _reg(tmp_path)
    out = reg.load("vulnerability_research.audit", persona_voice="nonexistent")
    assert out == "BASE"


def test_malware_fallback_base_name(tmp_path: Path) -> None:
    (tmp_path / "system_malware_analysis.md").write_text("MALWARE BASE", encoding="utf-8")
    reg = _reg(tmp_path, fallback_base="system_malware_analysis.md")
    assert reg.load("malware_analysis.triage") == "MALWARE BASE"

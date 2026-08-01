"""Unit tests for the platform PromptRegistry (RFC-09).

Covers file-backed resolution (strategy-specific base, fallback base,
missing-prompt error, persona prepend), the model_family key element
(family-specific file variant preferred, default fallback when the
family file is missing), and the DB-override path -- a bound version
store wins over the on-disk file, with the store's family-specific
row preferred and a graceful fallback to the file on a store fault.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aila.platform.prompts import (
    LoadedPrompt,
    PromptNotFoundError,
    PromptRegistry,
    normalize_model_family,
)


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


# ------------------------------------------------------------------ family


def test_family_specific_base_is_preferred_when_present(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("GENERIC BASE", encoding="utf-8")
    (tmp_path / "system_audit__claude.md").write_text("CLAUDE BASE", encoding="utf-8")
    reg = _reg(tmp_path)
    assert reg.load("vulnerability_research.audit", model_family="claude") == "CLAUDE BASE"
    # Missing family variant -> generic base (default fallback).
    assert reg.load("vulnerability_research.audit", model_family="gpt") == "GENERIC BASE"


def test_family_none_never_reads_family_specific_file(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("GENERIC BASE", encoding="utf-8")
    (tmp_path / "system_audit__claude.md").write_text("CLAUDE BASE", encoding="utf-8")
    reg = _reg(tmp_path)
    # No model_family passed -> generic variant, never the family file.
    assert reg.load("vulnerability_research.audit") == "GENERIC BASE"


def test_family_specific_fallback_base_used_when_no_leaf_file(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("GENERIC FALLBACK", encoding="utf-8")
    (tmp_path / "system_audit__claude.md").write_text("CLAUDE FALLBACK", encoding="utf-8")
    reg = _reg(tmp_path)
    # No system_<leaf>.md exists -- the family-specific fallback wins.
    assert reg.load(
        "vulnerability_research.no_such_strategy", model_family="claude",
    ) == "CLAUDE FALLBACK"


def test_family_specific_persona_wins_over_generic(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("BASE", encoding="utf-8")
    (tmp_path / "persona_halvar.md").write_text("GENERIC ROLE", encoding="utf-8")
    (tmp_path / "persona_halvar__claude.md").write_text("CLAUDE ROLE", encoding="utf-8")
    reg = _reg(tmp_path)
    out = reg.load(
        "vulnerability_research.audit", persona_voice="halvar", model_family="claude",
    )
    assert out == "CLAUDE ROLE\n\n---\n\nBASE"
    # Fallback path: family with no family-specific persona uses the generic.
    out = reg.load(
        "vulnerability_research.audit", persona_voice="halvar", model_family="gpt",
    )
    assert out == "GENERIC ROLE\n\n---\n\nBASE"


def test_build_key_composes_module_role_strategy_family(tmp_path: Path) -> None:
    reg = PromptRegistry(tmp_path, fallback_base="system_audit.md", module="vr")
    assert reg.build_key(
        "vulnerability_research.audit",
        persona_voice="Halvar",
        model_family="Claude",
    ) == "vr/halvar/vulnerability_research.audit/claude"
    # Missing model_family / persona normalise to "default" / "base".
    assert reg.build_key(
        "vulnerability_research.audit",
    ) == "vr/base/vulnerability_research.audit/default"


def test_build_key_defaults_module_to_prompt_dir_name(tmp_path: Path) -> None:
    (tmp_path / "prompts").mkdir()
    reg = PromptRegistry(tmp_path / "prompts", fallback_base="system_audit.md")
    key = reg.build_key("strat", persona_voice=None, model_family="claude")
    assert key == "prompts/base/strat/claude"


# ---------------------------------------------------------------- normalize


@pytest.mark.parametrize(
    "model_id,expected",
    [
        ("anthropic/claude-opus-4-7", "claude"),
        ("anthropic/claude-haiku-4-5-20251001", "claude"),
        ("antigravity/claude-opus-4-6-thinking", "claude"),
        ("openai/gpt-4o", "gpt"),
        ("openai/gpt-4o-mini", "gpt"),
        ("google/gemini-1.5-pro", "gemini"),
        ("meta-llama/llama-3-70b", "llama"),
        ("mistralai/mistral-large", "mistral"),
        ("mistralai/mixtral-8x22b", "mixtral"),
        ("deepseek/deepseek-chat", "deepseek"),
        ("qwen/qwen-2.5-72b", "qwen"),
        ("openai/o1-mini", "o1"),
        ("unknown-provider/some-model", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_model_family(model_id: str | None, expected: str | None) -> None:
    assert normalize_model_family(model_id) == expected


# --------------------------------------------------------------- DB override


class _StubRow:
    def __init__(self, body: str, version: str) -> None:
        self.body = body
        self.version = version


class _StubStore:
    """In-memory PromptVersionStore stand-in.

    Reproduces the (key, model_family) resolution shape: rows can be
    registered under either ``key`` alone (default variant) or ``key`` +
    ``model_family`` (per-family variant). ``resolve(alias=...)`` picks
    the family-specific row when present, else falls back to the
    default-variant row on the bare key. ``fail=True`` simulates a
    store fault so the registry must fall through to the file.
    """

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str | None], _StubRow] = {}
        self.fail: bool = False
        self.calls: list[dict[str, Any]] = []

    def put(self, key: str, body: str, version: str,
            model_family: str | None = None) -> None:
        self.rows[(key, (model_family or "").lower() or None)] = _StubRow(body, version)

    async def resolve(
        self,
        key: str,
        *,
        alias: str | None = None,
        version: str | None = None,
        model_family: str | None = None,
    ) -> _StubRow | None:
        self.calls.append({
            "key": key, "alias": alias, "version": version,
            "model_family": model_family,
        })
        if self.fail:
            raise RuntimeError("boom")
        family = (model_family or "").lower() or None
        if family is not None:
            row = self.rows.get((key, family))
            if row is not None:
                return row
        return self.rows.get((key, None))


@pytest.mark.asyncio
async def test_resolve_prefers_db_over_file(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("FILE BASE", encoding="utf-8")
    store = _StubStore()
    reg = PromptRegistry(
        tmp_path, fallback_base="system_audit.md", module="vr", version_store=store,
    )
    key = reg.build_key("vulnerability_research.audit", persona_voice=None,
                       model_family="claude")
    store.put(key, "DB BASE FROM CLAUDE", "1.0.3", model_family="claude")
    result = await reg.resolve(
        "vulnerability_research.audit", persona_voice=None, model_family="claude",
    )
    assert result == LoadedPrompt(body="DB BASE FROM CLAUDE", version="1.0.3")
    assert store.calls[0]["model_family"] == "claude"
    assert store.calls[0]["alias"] == "production"


@pytest.mark.asyncio
async def test_resolve_falls_back_to_file_when_store_empty(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("FILE BASE", encoding="utf-8")
    store = _StubStore()
    reg = PromptRegistry(
        tmp_path, fallback_base="system_audit.md", module="vr", version_store=store,
    )
    result = await reg.resolve("vulnerability_research.audit", model_family="claude")
    assert result == LoadedPrompt(body="FILE BASE", version=None)


@pytest.mark.asyncio
async def test_resolve_missing_family_falls_back_to_default_variant(
    tmp_path: Path,
) -> None:
    (tmp_path / "system_audit.md").write_text("FILE BASE", encoding="utf-8")
    store = _StubStore()
    reg = PromptRegistry(
        tmp_path, fallback_base="system_audit.md", module="vr", version_store=store,
    )
    # Only a default-variant row exists.
    default_key = reg.build_key("vulnerability_research.audit", persona_voice=None)
    store.put(default_key, "DEFAULT DB BASE", "1.0.0")
    result = await reg.resolve(
        "vulnerability_research.audit", model_family="gpt",
    )
    assert result == LoadedPrompt(body="DEFAULT DB BASE", version="1.0.0")


@pytest.mark.asyncio
async def test_resolve_falls_back_to_file_on_store_fault(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("FILE BASE", encoding="utf-8")
    store = _StubStore()
    store.fail = True
    reg = PromptRegistry(
        tmp_path, fallback_base="system_audit.md", module="vr", version_store=store,
    )
    result = await reg.resolve("vulnerability_research.audit", model_family="claude")
    assert result == LoadedPrompt(body="FILE BASE", version=None)


@pytest.mark.asyncio
async def test_resolve_persona_prepend_applies_to_file_fallback(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("BASE", encoding="utf-8")
    (tmp_path / "persona_halvar.md").write_text("ROLE", encoding="utf-8")
    store = _StubStore()
    reg = PromptRegistry(
        tmp_path, fallback_base="system_audit.md", module="vr", version_store=store,
    )
    result = await reg.resolve(
        "vulnerability_research.audit", persona_voice="halvar", model_family="claude",
    )
    # Store empty -> file with persona prepend.
    assert result == LoadedPrompt(body="ROLE\n\n---\n\nBASE", version=None)


@pytest.mark.asyncio
async def test_resolve_without_store_is_file_only(tmp_path: Path) -> None:
    (tmp_path / "system_audit.md").write_text("BASE", encoding="utf-8")
    reg = PromptRegistry(tmp_path, fallback_base="system_audit.md", module="vr")
    result = await reg.resolve("vulnerability_research.audit")
    assert result == LoadedPrompt(body="BASE", version=None)

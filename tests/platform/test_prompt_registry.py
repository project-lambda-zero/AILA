"""Unit tests for the platform PromptRegistry (RFC-09, req 20 DB-only cutover).

Covers DB-only resolution, model_family variants, candidate key construction,
model family normalization, bundle decoding, exemplar folding, and missing prompt
errors.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from aila.platform.prompts import (
    LoadedPrompt,
    PromptNotFoundError,
    PromptRegistry,
    normalize_model_family,
)


class _StubRow:
    def __init__(
        self,
        body: str,
        version: str,
        *,
        roster_json: str | None = None,
        routing_json: str | None = None,
        exemplars_json: str | None = None,
    ) -> None:
        self.body = body
        self.version = version
        self.roster_json = roster_json
        self.routing_json = routing_json
        self.exemplars_json = exemplars_json


class _StubStore:
    """In-memory PromptVersionStore stand-in for unit tests."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str | None], _StubRow] = {}
        self.fail: bool = False
        self.calls: list[dict[str, Any]] = []

    def put(
        self,
        key: str,
        body: str,
        version: str,
        *,
        model_family: str | None = None,
        roster: dict[str, Any] | None = None,
        routing: dict[str, Any] | None = None,
        exemplars: list[Any] | None = None,
    ) -> None:
        self.rows[(key, (model_family or "").lower() or None)] = _StubRow(
            body,
            version,
            roster_json=json.dumps(roster) if roster is not None else None,
            routing_json=json.dumps(routing) if routing is not None else None,
            exemplars_json=json.dumps(exemplars) if exemplars is not None else None,
        )

    def resolve_sync(
        self,
        key: str,
        *,
        alias: str = "production",
        model_family: str | None = None,
    ) -> _StubRow | None:
        self.calls.append({
            "key": key, "alias": alias, "model_family": model_family, "sync": True,
        })
        if self.fail:
            raise RuntimeError("store fault")
        family = (model_family or "").lower() or None
        if family is not None:
            row = self.rows.get((key, family))
            if row is not None:
                return row
        return self.rows.get((key, None))

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
            "model_family": model_family, "sync": False,
        })
        if self.fail:
            raise RuntimeError("store fault")
        family = (model_family or "").lower() or None
        if family is not None:
            row = self.rows.get((key, family))
            if row is not None:
                return row
        return self.rows.get((key, None))


# ---------------------------------------------------------------- keys


def test_build_key_composes_module_role_strategy_family() -> None:
    reg = PromptRegistry(module="vr")
    assert reg.build_key(
        "vulnerability_research.audit",
        persona_voice="Halvar",
        model_family="Claude",
    ) == "vr/halvar/vulnerability_research.audit/claude"
    # Missing model_family / persona normalise to "default" / "base".
    assert reg.build_key(
        "vulnerability_research.audit",
    ) == "vr/base/vulnerability_research.audit/default"


def test_build_key_defaults_module_to_prompt_dir_name() -> None:
    reg = PromptRegistry("/path/to/prompts")
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


# ---------------------------------------------------------------- sync load


def test_load_resolves_from_version_store() -> None:
    store = _StubStore()
    reg = PromptRegistry(module="platform", version_store=store)
    key = reg.build_key("dante")
    store.put(key, "DANTE PROMPT TEXT", "1.0.0")

    result = reg.load("dante")
    assert result == "DANTE PROMPT TEXT"
    assert store.calls[0]["key"] == "platform/base/dante/default"
    assert store.calls[0]["alias"] == "production"


def test_load_folds_exemplars() -> None:
    store = _StubStore()
    reg = PromptRegistry(module="platform", version_store=store)
    key = reg.build_key("claim_verifier_extractor")
    store.put(
        key,
        "EXTRACTOR BASE",
        "1.0.0",
        exemplars=["Exemplar 1 text", {"id": "E2", "probe": "audit_mcp"}],
    )

    result = reg.load("claim_verifier_extractor")
    assert "EXTRACTOR BASE" in result
    assert "## Exemplars" in result
    assert "Exemplar 1 text" in result
    assert '"id": "E2"' in result


def test_load_missing_key_raises_prompt_not_found() -> None:
    store = _StubStore()
    reg = PromptRegistry(module="platform", version_store=store)
    with pytest.raises(PromptNotFoundError, match="no version-store row"):
        reg.load("nonexistent_strategy")


def test_load_model_family_fallback_to_default() -> None:
    store = _StubStore()
    reg = PromptRegistry(module="vr", version_store=store)
    default_key = reg.build_key("audit", "halvar")
    store.put(default_key, "HALVAR DEFAULT", "1.0.0")

    # Asking for "claude" family falls back to default variant
    result = reg.load("audit", "halvar", model_family="claude")
    assert result == "HALVAR DEFAULT"


# ---------------------------------------------------------------- async resolve


@pytest.mark.asyncio
async def test_resolve_resolves_from_version_store() -> None:
    store = _StubStore()
    reg = PromptRegistry(module="platform", version_store=store)
    key = reg.build_key("dante")
    store.put(key, "DANTE ASYNC TEXT", "1.0.1", roster={"dante": "console"})

    result = await reg.resolve("dante")
    assert isinstance(result, LoadedPrompt)
    assert result.body == "DANTE ASYNC TEXT"
    assert result.version == "1.0.1"
    assert result.roster == {"dante": "console"}


@pytest.mark.asyncio
async def test_resolve_prefers_family_specific_variant() -> None:
    store = _StubStore()
    reg = PromptRegistry(module="vr", version_store=store)
    family_key = reg.build_key("audit", "halvar", model_family="claude")
    default_key = reg.build_key("audit", "halvar")
    store.put(family_key, "HALVAR CLAUDE VARIANT", "1.0.2", model_family="claude")
    store.put(default_key, "HALVAR DEFAULT", "1.0.0")

    result = await reg.resolve("audit", "halvar", model_family="claude")
    assert result.body == "HALVAR CLAUDE VARIANT"
    assert result.version == "1.0.2"


@pytest.mark.asyncio
async def test_resolve_missing_key_raises_prompt_not_found() -> None:
    store = _StubStore()
    reg = PromptRegistry(module="platform", version_store=store)
    with pytest.raises(PromptNotFoundError, match="no version-store row"):
        await reg.resolve("nonexistent_strategy")

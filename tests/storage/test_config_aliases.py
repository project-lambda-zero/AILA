"""ConfigRegistry exact-key alias mechanism (``__config_aliases__``).

Covers canonicalisation and registration-time validation only. Accepted
``register`` calls write defaults to the DB and are not exercised here.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field

from aila.storage.registry import ConfigRegistry


class _Schema(BaseModel):
    __config_aliases__ = {"demo.limit": "limit"}

    limit: int = Field(default=3, ge=1, le=10)
    name: str = "x"


@pytest.fixture
def registry() -> ConfigRegistry:
    reg = ConfigRegistry()
    reg._schemas["demo"] = _Schema
    return reg


def test_alias_maps_to_canonical(registry: ConfigRegistry) -> None:
    assert registry._canonical_key("demo", "demo.limit") == "limit"


def test_canonical_and_unknown_keys_pass_through(registry: ConfigRegistry) -> None:
    assert registry._canonical_key("demo", "limit") == "limit"
    assert registry._canonical_key("demo", "other") == "other"


def test_alias_lookup_is_exact_only(registry: ConfigRegistry) -> None:
    assert registry._canonical_key("demo", "demo") == "demo"
    assert registry._canonical_key("demo", "demo.limit.extra") == "demo.limit.extra"
    assert registry._canonical_key("demo", "DEMO.LIMIT") == "DEMO.LIMIT"


def test_no_schema_passes_through() -> None:
    reg = ConfigRegistry()
    assert reg._canonical_key("unregistered", "demo.limit") == "demo.limit"


def test_schema_without_aliases_passes_through() -> None:
    class _Plain(BaseModel):
        limit: int = 3

    reg = ConfigRegistry()
    reg._schemas["plain"] = _Plain
    assert reg._canonical_key("plain", "demo.limit") == "demo.limit"


def test_env_read_through_alias_uses_canonical_env_name(
    registry: ConfigRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AILA_DEMO_LIMIT", "7")
    assert registry.get_sync("demo", "demo.limit") == 7
    resolution = registry.describe_resolution("demo", "demo.limit", db_value=None)
    assert resolution.env_key == "AILA_DEMO_LIMIT"
    assert resolution.source == "env"


async def test_register_rejects_alias_shadowing_a_field() -> None:
    class _Shadow(BaseModel):
        __config_aliases__ = {"limit": "name"}

        limit: int = 3
        name: str = "x"

    reg = ConfigRegistry()
    with pytest.raises(ValueError, match="shadows a canonical field"):
        await reg.register("shadow", _Shadow)
    assert "shadow" not in reg._schemas


async def test_register_rejects_alias_to_unknown_field() -> None:
    class _Dangling(BaseModel):
        __config_aliases__ = {"demo.limit": "missing"}

        limit: int = 3

    reg = ConfigRegistry()
    with pytest.raises(ValueError, match="targets unknown field 'missing'"):
        await reg.register("dangling", _Dangling)
    assert "dangling" not in reg._schemas


async def test_register_rejects_dependency_map_key_not_a_field() -> None:
    class _UnknownKey(BaseModel):
        __config_dependencies__ = {"ghost": ("limit",)}

        limit: int = 3

    reg = ConfigRegistry()
    with pytest.raises(ValueError, match="names unknown field 'ghost'"):
        await reg.register("unknown_key", _UnknownKey)
    assert "unknown_key" not in reg._schemas


async def test_register_rejects_dependency_on_unknown_or_self_field() -> None:
    class _BadDep(BaseModel):
        __config_dependencies__ = {"limit": ("missing", "limit")}

        limit: int = 3

    reg = ConfigRegistry()
    with pytest.raises(ValueError, match="must be a different declared field"):
        await reg.register("bad_dep", _BadDep)
    assert "bad_dep" not in reg._schemas

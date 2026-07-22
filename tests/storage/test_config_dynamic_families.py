"""#45 -- ConfigRegistry dynamic-key families resolve per-task-type keys.

Pure resolver test (no DB): a namespace schema declares typed key families in
``__dynamic_families__``, and ``ConfigRegistry._resolve_field`` maps an open key
space (e.g. ``llm_model_{task_type}``) to the right type. Static fields win by
exact match, the longest matching family wins on overlap, and an unknown key
resolves to None so ``set`` rejects it.
"""
from __future__ import annotations

from typing import ClassVar

import pytest
from pydantic import BaseModel

from aila.storage.registry import (
    ConfigRegistry,
    DynamicKeyFamily,
    _cast_value,
    _field_type_name,
)

__all__: list[str] = []


class _Schema(BaseModel):
    __dynamic_families__: ClassVar[tuple[DynamicKeyFamily, ...]] = (
        DynamicKeyFamily("llm_model_", str),
        DynamicKeyFamily("llm_max_tokens_", int),
        DynamicKeyFamily("llm_pipeline_gate_high_threshold_", float),
        DynamicKeyFamily("llm_pipeline_", str),  # generic -- loses to the specific one
    )
    llm_default_model: str = "m"
    llm_budget_max_total_tokens_default: int = 0


def _type_of(reg: ConfigRegistry, key: str) -> str | None:
    field = reg._resolve_field("ns", key)
    return None if field is None else _field_type_name(field)


@pytest.fixture
def reg() -> ConfigRegistry:
    registry = ConfigRegistry()
    registry._schemas["ns"] = _Schema
    return registry


def test_static_field_exact_match_wins(reg: ConfigRegistry) -> None:
    assert _type_of(reg, "llm_default_model") == "str"
    # A key that also prefix-matches no family but IS a static field.
    assert _type_of(reg, "llm_budget_max_total_tokens_default") == "int"


def test_dynamic_family_typing(reg: ConfigRegistry) -> None:
    assert _type_of(reg, "llm_model_scoring") == "str"
    assert _type_of(reg, "llm_max_tokens_scoring") == "int"


def test_longest_prefix_wins(reg: ConfigRegistry) -> None:
    # llm_pipeline_gate_high_threshold_ and the generic llm_pipeline_ both match;
    # the longer, more specific family must win.
    assert _type_of(reg, "llm_pipeline_gate_high_threshold_scoring") == "float"
    assert _type_of(reg, "llm_pipeline_classify_scoring") == "str"


def test_unknown_key_rejected(reg: ConfigRegistry) -> None:
    assert _type_of(reg, "totally_unknown_key") is None


def test_family_value_validates_and_casts(reg: ConfigRegistry) -> None:
    field = reg._resolve_field("ns", "llm_pipeline_gate_high_threshold_scoring")
    assert _cast_value("0.8", field) == pytest.approx(0.8)
    with pytest.raises(ValueError):
        _cast_value("not-a-float", field)

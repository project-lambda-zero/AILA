"""RFC-04/RFC-05: _template scaffold demonstrates the platform primitives.

The template module is the reference a copier starts from. A new module
copied from ``src/aila/modules/_template/`` must inherit a boundary-clean
shape by construction: its config schema subclasses
:class:`aila.platform.config_base.ModuleConfigBase` (rule 37, so
``extra='forbid'`` is inherited), its ``ModuleProtocol`` registry methods
return the typed shapes the platform expects, and none of its public
imports reach into another module or a platform-private path.

This test locks the scaffold down so a copier cannot lose those
guarantees without a failing test.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from aila.modules._template.config_schema import TemplateConfigSchema
from aila.modules._template.module import TemplateModule, create_module
from aila.platform.config_base import ModuleConfigBase
from aila.platform.contracts.reasoning import (
    ReasoningDomainProfile,
    ReasoningStrategyDeclaration,
)
from aila.platform.modules.protocol import ModuleProtocol

__all__ = ["TestTemplateScaffold"]


class TestTemplateScaffold:
    """Lock the _template scaffold's platform-primitive surface."""

    def test_module_imports_and_instantiates(self) -> None:
        """create_module() returns a TemplateModule satisfying ModuleProtocol."""
        module = create_module()
        assert isinstance(module, TemplateModule)
        assert isinstance(module, ModuleProtocol)
        assert module.module_id == "_template"

    def test_config_schema_subclasses_module_config_base(self) -> None:
        """RFC-04: honesty rule 37 requires the module schema to subclass
        ModuleConfigBase so ``extra='forbid'`` is inherited."""
        assert issubclass(TemplateConfigSchema, ModuleConfigBase)

    def test_config_schema_defaults_construct(self) -> None:
        """The example fields carry safe defaults and round-trip through
        the model."""
        schema = TemplateConfigSchema()
        assert schema.example_timeout_seconds == 30.0
        assert schema.example_max_retries == 3

    def test_config_schema_rejects_unknown_field(self) -> None:
        """extra='forbid' -- an undeclared key raises at construction time
        instead of silently passing through (the drift RFC-04 closed for
        vulnerability)."""
        with pytest.raises(ValidationError) as exc_info:
            TemplateConfigSchema(unknown_field="oops")  # type: ignore[call-arg]
        message = str(exc_info.value)
        assert "unknown_field" in message
        assert "extra" in message.lower()

    def test_reasoning_strategies_returns_typed_list(self) -> None:
        """RFC-05 (d): reasoning_strategies() returns a list -- empty means
        the module publishes no strategy family and the engine falls back
        to the platform ``generic`` family."""
        module = create_module()
        result = module.reasoning_strategies()
        assert isinstance(result, list)
        assert all(isinstance(item, ReasoningStrategyDeclaration) for item in result)

    def test_reasoning_domain_profiles_returns_typed_list(self) -> None:
        """RFC-05 (d): reasoning_domain_profiles() returns a list -- empty
        means the module carries no reasoning surface."""
        module = create_module()
        result = module.reasoning_domain_profiles()
        assert isinstance(result, list)
        assert all(isinstance(item, ReasoningDomainProfile) for item in result)

    def test_workflow_definitions_returns_typed_dict(self) -> None:
        """workflow_definitions() returns a dict -- empty means the module
        contributes no lifecycle state machine."""
        module = create_module()
        result = module.workflow_definitions()
        assert isinstance(result, dict)
        for workflow_id, definition in result.items():
            assert isinstance(workflow_id, str)
            assert isinstance(definition, dict)

    def test_capability_profiles_shape_survives(self) -> None:
        """capability_profiles() still returns one profile with the
        expected fields -- guard against a copier regressing the entrypoint
        while touching the registry methods."""
        module = create_module()
        profiles = module.capability_profiles()
        assert len(profiles) == 1
        profile = profiles[0]
        assert profile.module_id == "_template"
        assert profile.action_id == "_template.run"
        assert profile.tools
        assert profile.examples

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


    def test_config_schema_rejects_unknown_field(self) -> None:
        """extra='forbid' -- an undeclared key raises at construction time
        instead of silently passing through (the drift RFC-04 closed for
        vulnerability)."""
        with pytest.raises(ValidationError) as exc_info:
            TemplateConfigSchema(unknown_field="oops")  # type: ignore[call-arg]
        message = str(exc_info.value)
        assert "unknown_field" in message
        assert "extra" in message.lower()


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

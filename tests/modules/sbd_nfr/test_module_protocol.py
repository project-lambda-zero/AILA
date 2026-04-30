"""Tests for SbdNfrModule protocol compliance (PLAT-01).

Verifies that create_module() returns an object satisfying ModuleProtocol:
- module_id is correct
- capability_profiles() returns non-empty list
- route_specs() returns list with the /sbd_nfr prefix
- health_checks() returns a dict

These tests import only the module entrypoint — no DB, no network.
"""

from __future__ import annotations

from aila.modules.sbd_nfr.module import MODULE_ID, SEED_VERSION, create_module


def test_create_module_returns_correct_module_id() -> None:
    module = create_module()
    assert module.module_id == "sbd_nfr"
    assert module.module_id == MODULE_ID


def test_capability_profiles_non_empty() -> None:
    module = create_module()
    profiles = module.capability_profiles()
    assert isinstance(profiles, list)
    assert len(profiles) >= 1
    profile = profiles[0]
    assert profile.module_id == "sbd_nfr"
    assert isinstance(profile.description, str)
    assert len(profile.description) > 0
    assert isinstance(profile.examples, list)
    assert len(profile.examples) >= 1


def test_route_specs_has_sbd_nfr_prefix() -> None:
    module = create_module()
    specs = module.route_specs()
    assert isinstance(specs, list)
    assert len(specs) >= 1
    prefixes = [spec.prefix for spec in specs]
    assert "/sbd_nfr" in prefixes


def test_health_checks_returns_dict() -> None:
    module = create_module()
    result = module.health_checks()
    assert isinstance(result, dict)


def test_seed_version_is_3_0() -> None:
    """Seed version must be 3.0 for the v3.0 STRIDE-grounded schema."""
    assert SEED_VERSION == "3.0"


def test_required_tools_returns_list() -> None:
    module = create_module()
    tools = module.required_tools()
    assert isinstance(tools, list)


def test_report_filter_keys_returns_list() -> None:
    module = create_module()
    keys = module.report_filter_keys()
    assert isinstance(keys, list)


def test_filter_report_rows_passthrough() -> None:
    """filter_report_rows with no filters returns all rows unchanged."""
    module = create_module()
    rows = [{"id": "HYGN-01", "value": "Yes"}, {"id": "SCOPE-01", "value": "New service"}]
    result = module.filter_report_rows(rows)
    assert result == rows


def test_action_id_contains_assess_nfr() -> None:
    module = create_module()
    assert "assess_nfr" in module.action_id
    assert module.action_id == "sbd_nfr.assess_nfr"

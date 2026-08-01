"""Tests for RFC-09/10 activation: startup prompt-version seeding.

``seed_prompt_versions`` registers each file-backed prompt into the version
store and points the ``production`` alias at it ONLY when the key has none
yet. This makes the pin-per-investigation and canary-routing paths run by
default (RFC-09/10) while never clobbering an operator-promoted or
canary-routed version on restart (alias-if-absent).

The VR and malware researchers share the identical seed body; both are
exercised here because they are separate module-level functions keyed to
different strategy families and prompt directories.
"""
from __future__ import annotations

import pytest

from aila.modules.malware.agents import malware_researcher
from aila.modules.vr.agents.vuln_researcher import (
    _PROMPT_REGISTRY,
    _PROMPT_VERSION_STORE,
    _prompt_key,
    seed_prompt_versions,
)

pytestmark = pytest.mark.usefixtures("test_db")

_AUDIT_KEY = _prompt_key("vulnerability_research.audit", None)


async def test_seed_sets_production_alias_from_file_body() -> None:
    count = await seed_prompt_versions()
    assert count > 0
    rec = await _PROMPT_VERSION_STORE.resolve(_AUDIT_KEY, alias="production")
    assert rec is not None
    assert rec.body == _PROMPT_REGISTRY.load("vulnerability_research.audit", None)


async def test_seed_is_idempotent() -> None:
    first = await seed_prompt_versions()
    assert first > 0
    # A second run finds every alias already set: nothing new, no duplicate
    # version rows for an unchanged file body.
    second = await seed_prompt_versions()
    assert second == 0
    versions = await _PROMPT_VERSION_STORE.list_versions(_AUDIT_KEY)
    assert len(versions) == 1


async def test_seed_preserves_operator_promoted_alias() -> None:
    # Operator promotes a hand-authored version before any seed runs.
    v_custom = await _PROMPT_VERSION_STORE.register(
        _AUDIT_KEY, "OPERATOR CUSTOM BODY", author="op",
    )
    await _PROMPT_VERSION_STORE.set_alias(
        _AUDIT_KEY, "production", v_custom, actor="op",
    )
    # A restart re-seeds: the file body is registered as a new version but
    # the production alias must stay pointed at the operator's version.
    await seed_prompt_versions()
    rec = await _PROMPT_VERSION_STORE.resolve(_AUDIT_KEY, alias="production")
    assert rec is not None
    assert rec.body == "OPERATOR CUSTOM BODY"


async def test_malware_seed_sets_production_alias() -> None:
    count = await malware_researcher.seed_prompt_versions()
    assert count > 0
    key = malware_researcher._prompt_key("default", None)
    rec = await malware_researcher._PROMPT_VERSION_STORE.resolve(
        key, alias="production",
    )
    assert rec is not None

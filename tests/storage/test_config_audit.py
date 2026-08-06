"""Unit tests for ConfigRegistry config change audit logging.

Tests that ConfigRegistry.set() emits config_security_change PlatformEvent
for security-relevant keys, does not emit for non-security keys, and
handles emitter=None gracefully.

ConfigRegistry.register/set/get are async and run against the Postgres test DB
(D-48/D-49: no SQLite); the storage_db fixture creates the schema and isolates
each test.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from aila.platform.events.event import PlatformEvent
from aila.storage.registry import ConfigRegistry

# ---------------------------------------------------------------------------
# Test schema with security-relevant and non-security keys
# ---------------------------------------------------------------------------

class _AuditTestSchema(BaseModel):
    llm_kill_switch: str = "false"
    llm_model_scoring: str = "gpt-4o-mini"
    llm_pipeline_classify_restricted_behavior_scoring: str = "fail"
    llm_pipeline_gate_threshold_scoring: str = "0.7"
    llm_seal_hmac_key: str = "default-key"
    llm_pipeline_validate_fail_mode_scoring: str = "open"
    scan_timeout: int = 300
    verbose: bool = False


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeEmitter:
    """Captures emitted PlatformEvents for assertion."""

    def __init__(self) -> None:
        self.events: list[PlatformEvent] = []

    def emit(self, event: PlatformEvent) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def emitter() -> FakeEmitter:
    return FakeEmitter()


@pytest.fixture()
async def registry(storage_db, emitter) -> ConfigRegistry:
    """ConfigRegistry wired to the Postgres test DB with a FakeEmitter.

    register() persists the schema defaults but does not emit (it is initial
    setup, not a change), so the per-test event count reflects only set() calls.
    """
    reg = ConfigRegistry(emitter=emitter)
    await reg.register("platform", _AuditTestSchema)
    return reg


# ---------------------------------------------------------------------------
# TestConfigAuditLogging
# ---------------------------------------------------------------------------

class TestConfigAuditLogging:
    """ConfigRegistry.set() emits config_security_change for security-relevant keys."""

    async def test_llm_kill_switch_emits_event(self, registry, emitter) -> None:
        await registry.set("platform", "llm_kill_switch", "true")
        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.stage == "config_security_change"
        assert event.action == "update"
        assert "llm_kill_switch" in event.key

    async def test_llm_model_scoring_emits_event(self, registry, emitter) -> None:
        await registry.set("platform", "llm_model_scoring", "gpt-4o")
        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.stage == "config_security_change"

    async def test_llm_pipeline_classify_emits_event(self, registry, emitter) -> None:
        await registry.set("platform", "llm_pipeline_classify_restricted_behavior_scoring", "redact")
        assert len(emitter.events) == 1

    async def test_llm_pipeline_gate_emits_event(self, registry, emitter) -> None:
        await registry.set("platform", "llm_pipeline_gate_threshold_scoring", "0.9")
        assert len(emitter.events) == 1

    async def test_llm_seal_hmac_key_emits_event(self, registry, emitter) -> None:
        await registry.set("platform", "llm_seal_hmac_key", "new-secret-key")
        assert len(emitter.events) == 1

    async def test_fail_mode_pattern_emits_event(self, registry, emitter) -> None:
        """Keys containing _fail_mode_ trigger audit (D-11 fail_mode pattern)."""
        await registry.set("platform", "llm_pipeline_validate_fail_mode_scoring", "closed")
        assert len(emitter.events) == 1

    async def test_event_contains_old_and_new_values(self, registry, emitter) -> None:
        """Audit event details contain old_value and new_value."""
        await registry.set("platform", "llm_kill_switch", "true")
        event = emitter.events[0]
        assert "old_value" in event.details
        assert "new_value" in event.details
        assert event.details["old_value"] == "false"
        assert event.details["new_value"] == "true"

    async def test_event_contains_namespace_and_key(self, registry, emitter) -> None:
        """Audit event details contain namespace and key."""
        await registry.set("platform", "llm_kill_switch", "true")
        event = emitter.events[0]
        assert event.details["namespace"] == "platform"
        assert event.details["key"] == "llm_kill_switch"

    async def test_event_message_descriptive(self, registry, emitter) -> None:
        """Audit event message mentions the config change."""
        await registry.set("platform", "llm_kill_switch", "true")
        event = emitter.events[0]
        assert "platform" in event.message
        assert "llm_kill_switch" in event.message


# ---------------------------------------------------------------------------
# TestConfigAuditSkip
# ---------------------------------------------------------------------------

class TestConfigAuditSkip:
    """Non-security config keys do NOT emit audit events."""

    async def test_scan_timeout_no_event(self, registry, emitter) -> None:
        await registry.set("platform", "scan_timeout", "600")
        assert len(emitter.events) == 0

    async def test_verbose_no_event(self, registry, emitter) -> None:
        await registry.set("platform", "verbose", "true")
        assert len(emitter.events) == 0


# ---------------------------------------------------------------------------
# TestConfigAuditNoEmitter
# ---------------------------------------------------------------------------

class TestConfigAuditNoEmitter:
    """ConfigRegistry with emitter=None does not crash on security-relevant set()."""

    async def test_no_emitter_no_crash(self, storage_db) -> None:
        reg = ConfigRegistry(emitter=None)
        await reg.register("platform", _AuditTestSchema)
        # Should not raise
        await reg.set("platform", "llm_kill_switch", "true")
        assert await reg.get("platform", "llm_kill_switch") == "true"

    async def test_no_emitter_default_init(self, storage_db) -> None:
        """ConfigRegistry() with no emitter argument works (backwards compat)."""
        reg = ConfigRegistry()
        await reg.register("platform", _AuditTestSchema)
        await reg.set("platform", "llm_kill_switch", "true")
        assert await reg.get("platform", "llm_kill_switch") == "true"


# ---------------------------------------------------------------------------
# TestConfigAuditValidationError
# ---------------------------------------------------------------------------

class TestConfigAuditValidationError:
    """If set() raises ValueError (bad type), no audit event is emitted."""

    async def test_no_event_on_invalid_value(self, registry, emitter) -> None:
        """ValueError from bad type does not produce an audit event."""
        with pytest.raises(ValueError):
            await registry.set("platform", "scan_timeout", "not_a_number")
        assert len(emitter.events) == 0

    async def test_no_event_on_unknown_key(self, registry, emitter) -> None:
        """ValueError from unknown key does not produce an audit event."""
        with pytest.raises(ValueError):
            await registry.set("platform", "nonexistent_key", "value")
        assert len(emitter.events) == 0

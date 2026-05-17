"""Unit tests for ConfigRegistry config change audit logging.

Tests that ConfigRegistry.set() emits config_security_change PlatformEvent
for security-relevant keys, does not emit for non-security keys, and
handles emitter=None gracefully.

All tests use an in-memory SQLite engine via monkeypatched session_scope.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from pydantic import BaseModel
from sqlmodel import Session, SQLModel, create_engine

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
def mem_engine():
    """Create an in-memory SQLite engine with all tables."""
    engine = create_engine("sqlite://", echo=False)
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture()
def _patch_session(mem_engine, monkeypatch):
    """Monkeypatch session_scope to use the in-memory engine."""

    @contextmanager
    def _test_session_scope(settings=None):
        with Session(mem_engine) as session:
            yield session

    monkeypatch.setattr("aila.storage.registry.session_scope", _test_session_scope)


@pytest.fixture()
def emitter() -> FakeEmitter:
    return FakeEmitter()


@pytest.fixture()
def registry(_patch_session, emitter) -> ConfigRegistry:
    """ConfigRegistry wired to in-memory DB with a FakeEmitter."""
    reg = ConfigRegistry(emitter=emitter)
    reg.register("platform", _AuditTestSchema)
    return reg


# ---------------------------------------------------------------------------
# TestConfigAuditLogging
# ---------------------------------------------------------------------------

class TestConfigAuditLogging:
    """ConfigRegistry.set() emits config_security_change for security-relevant keys."""

    def test_llm_kill_switch_emits_event(self, registry, emitter) -> None:
        registry.set("platform", "llm_kill_switch", "true")
        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.stage == "config_security_change"
        assert event.action == "update"
        assert "llm_kill_switch" in event.key

    def test_llm_model_scoring_emits_event(self, registry, emitter) -> None:
        registry.set("platform", "llm_model_scoring", "gpt-4o")
        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.stage == "config_security_change"

    def test_llm_pipeline_classify_emits_event(self, registry, emitter) -> None:
        registry.set("platform", "llm_pipeline_classify_restricted_behavior_scoring", "redact")
        assert len(emitter.events) == 1

    def test_llm_pipeline_gate_emits_event(self, registry, emitter) -> None:
        registry.set("platform", "llm_pipeline_gate_threshold_scoring", "0.9")
        assert len(emitter.events) == 1

    def test_llm_seal_hmac_key_emits_event(self, registry, emitter) -> None:
        registry.set("platform", "llm_seal_hmac_key", "new-secret-key")
        assert len(emitter.events) == 1

    def test_fail_mode_pattern_emits_event(self, registry, emitter) -> None:
        """Keys containing _fail_mode_ trigger audit (D-11 fail_mode pattern)."""
        registry.set("platform", "llm_pipeline_validate_fail_mode_scoring", "closed")
        assert len(emitter.events) == 1

    def test_event_contains_old_and_new_values(self, registry, emitter) -> None:
        """Audit event details contain old_value and new_value."""
        registry.set("platform", "llm_kill_switch", "true")
        event = emitter.events[0]
        assert "old_value" in event.details
        assert "new_value" in event.details
        assert event.details["old_value"] == "false"
        assert event.details["new_value"] == "true"

    def test_event_contains_namespace_and_key(self, registry, emitter) -> None:
        """Audit event details contain namespace and key."""
        registry.set("platform", "llm_kill_switch", "true")
        event = emitter.events[0]
        assert event.details["namespace"] == "platform"
        assert event.details["key"] == "llm_kill_switch"

    def test_event_message_descriptive(self, registry, emitter) -> None:
        """Audit event message mentions the config change."""
        registry.set("platform", "llm_kill_switch", "true")
        event = emitter.events[0]
        assert "platform" in event.message
        assert "llm_kill_switch" in event.message


# ---------------------------------------------------------------------------
# TestConfigAuditSkip
# ---------------------------------------------------------------------------

class TestConfigAuditSkip:
    """Non-security config keys do NOT emit audit events."""

    def test_scan_timeout_no_event(self, registry, emitter) -> None:
        registry.set("platform", "scan_timeout", "600")
        assert len(emitter.events) == 0

    def test_verbose_no_event(self, registry, emitter) -> None:
        registry.set("platform", "verbose", "true")
        assert len(emitter.events) == 0


# ---------------------------------------------------------------------------
# TestConfigAuditNoEmitter
# ---------------------------------------------------------------------------

class TestConfigAuditNoEmitter:
    """ConfigRegistry with emitter=None does not crash on security-relevant set()."""

    def test_no_emitter_no_crash(self, _patch_session) -> None:
        reg = ConfigRegistry(emitter=None)
        reg.register("platform", _AuditTestSchema)
        # Should not raise
        reg.set("platform", "llm_kill_switch", "true")
        assert reg.get("platform", "llm_kill_switch") == "true"

    def test_no_emitter_default_init(self, _patch_session) -> None:
        """ConfigRegistry() with no emitter argument works (backwards compat)."""
        reg = ConfigRegistry()
        reg.register("platform", _AuditTestSchema)
        reg.set("platform", "llm_kill_switch", "true")
        assert reg.get("platform", "llm_kill_switch") == "true"


# ---------------------------------------------------------------------------
# TestConfigAuditValidationError
# ---------------------------------------------------------------------------

class TestConfigAuditValidationError:
    """If set() raises ValueError (bad type), no audit event is emitted."""

    def test_no_event_on_invalid_value(self, registry, emitter) -> None:
        """ValueError from bad type does not produce an audit event."""
        with pytest.raises(ValueError):
            registry.set("platform", "scan_timeout", "not_a_number")
        assert len(emitter.events) == 0

    def test_no_event_on_unknown_key(self, registry, emitter) -> None:
        """ValueError from unknown key does not produce an audit event."""
        with pytest.raises(ValueError):
            registry.set("platform", "nonexistent_key", "value")
        assert len(emitter.events) == 0

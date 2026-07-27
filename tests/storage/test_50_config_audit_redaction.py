"""#50 -- ConfigRegistry redacts secret values in the audit event.

A change to a secret-classed config key (D-11 security-relevant AND
matching a token in :data:`_SECRET_KEY_TOKENS`) writes ``[REDACTED]`` as
both ``old_value`` and ``new_value`` in the emitted
``config_security_change`` PlatformEvent, and records a sha256 of the
old->new transition so a rotation stays auditable without persisting the
secret. Non-secret security-relevant keys keep cleartext (verified by
:mod:`tests.storage.test_config_audit`), so the redaction gate cannot
regress into swallowing every change into ``[REDACTED]``.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from aila.platform.events.event import PlatformEvent
from aila.storage.registry import ConfigRegistry


class _SecretsSchema(BaseModel):
    """Schema mixing a secret key with a non-secret one under the same prefix."""

    llm_seal_hmac_key: str = "default-key"
    llm_kill_switch: str = "false"


class _CapturingEmitter:
    """Captures emitted events for assertion (no ordering guarantees needed)."""

    def __init__(self) -> None:
        self.events: list[PlatformEvent] = []

    def emit(self, event: PlatformEvent) -> None:
        self.events.append(event)


@pytest.fixture()
def emitter() -> _CapturingEmitter:
    return _CapturingEmitter()


@pytest.fixture()
async def registry(storage_db, emitter) -> ConfigRegistry:
    reg = ConfigRegistry(emitter=emitter)
    await reg.register("platform", _SecretsSchema)
    return reg


class TestSecretConfigRedactedInAudit:
    """Secret config keys emit an audit event without leaking the plaintext."""

    async def test_secret_old_and_new_values_redacted(
        self, registry: ConfigRegistry, emitter: _CapturingEmitter
    ) -> None:
        """Old and new plaintext values MUST NOT appear in the audit event."""
        await registry.set("platform", "llm_seal_hmac_key", "post-rotation-secret")

        assert len(emitter.events) == 1, "one audit event per set() call"
        event = emitter.events[0]
        assert event.details["old_value"] == "[REDACTED]"
        assert event.details["new_value"] == "[REDACTED]"
        # The plaintext MUST NOT leak into any details field or message.
        rendered = repr(event.details) + " " + event.message
        assert "post-rotation-secret" not in rendered
        assert "default-key" not in rendered

    async def test_secret_change_records_transition_hash(
        self, registry: ConfigRegistry, emitter: _CapturingEmitter
    ) -> None:
        """A sha256 of old->new persists so a rotation stays auditable."""
        await registry.set("platform", "llm_seal_hmac_key", "post-rotation-secret")

        event = emitter.events[0]
        assert event.details.get("value_hash_sha256") is not None
        assert len(event.details["value_hash_sha256"]) == 64  # sha256 hex length

    async def test_nonsecret_security_relevant_key_keeps_plaintext(
        self, registry: ConfigRegistry, emitter: _CapturingEmitter
    ) -> None:
        """Non-secret security-relevant keys must remain readable in the audit.

        This is the guard against a naive fix that redacts every audit event.
        Only keys whose name matches a secret token (``hmac_key`` here) are
        redacted; a policy flag like ``llm_kill_switch`` still records its
        old and new plaintext so an operator can see what changed.
        """
        await registry.set("platform", "llm_kill_switch", "true")

        event = emitter.events[0]
        assert event.details["old_value"] == "false"
        assert event.details["new_value"] == "true"
        assert event.details.get("value_hash_sha256") is None

"""#50 write-path secret redaction for ConfigRegistry.set emit.

A change to a secret-classed config key (llm_seal_hmac_key, *_api_key, etc.)
previously wrote the old and new plaintext values into the config_security_change
PlatformEvent, which fans out to the immutable audit trail. The emit now redacts
both values and records a sha256 of the transition so a rotation stays auditable
without persisting the secret. Non-secret keys keep cleartext.
"""
from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel

from aila.platform.events.event import PlatformEvent
from aila.storage.registry import ConfigRegistry


class _Schema(BaseModel):
    llm_seal_hmac_key: str = "default-key"
    llm_kill_switch: str = "false"


class _FakeEmitter:
    def __init__(self) -> None:
        self.events: list[PlatformEvent] = []

    def emit(self, event: PlatformEvent) -> None:
        self.events.append(event)


async def test_set_redacts_secret_key_in_emitted_event(test_db) -> None:
    ns = f"testcfg{uuid4().hex[:8]}"
    emitter = _FakeEmitter()
    reg = ConfigRegistry(emitter=emitter)
    await reg.register(ns, _Schema)

    secret_value = f"s3cr3t-{uuid4().hex}"
    await reg.set(ns, "llm_seal_hmac_key", secret_value)

    assert len(emitter.events) == 1
    details = emitter.events[0].details
    assert details["new_value"] == "[REDACTED]"
    assert details["old_value"] == "[REDACTED]"
    # Rotation stays auditable via the transition hash.
    assert details["value_hash_sha256"]
    # The plaintext must appear nowhere in the emitted event details.
    assert secret_value not in str(details)


async def test_set_nonsecret_key_keeps_cleartext(test_db) -> None:
    ns = f"testcfg{uuid4().hex[:8]}"
    emitter = _FakeEmitter()
    reg = ConfigRegistry(emitter=emitter)
    await reg.register(ns, _Schema)

    await reg.set(ns, "llm_kill_switch", "true")

    assert len(emitter.events) == 1
    details = emitter.events[0].details
    assert details["new_value"] == "true"
    assert details["old_value"] == "false"
    assert details.get("value_hash_sha256") is None

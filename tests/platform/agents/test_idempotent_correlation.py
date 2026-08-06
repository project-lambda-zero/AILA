"""RFC-09 R1: idempotent_llm_call stamps prompt attribution into the
correlation scope so the cost + seal writers can record it.

Covers the set-if-unset precedence (explicit arg > outer scope > derived
from the system prompt) and the new current_prompt_version accessor.
"""
from __future__ import annotations

import hashlib

import pytest

from aila.platform.agents.idempotent_llm import (
    _system_prompt_hash,
    idempotent_llm_call,
)
from aila.platform.llm.client import LLMResponse
from aila.platform.llm.correlation import (
    correlation_scope,
    current_prompt_content_hash,
    current_prompt_version,
)

pytestmark = pytest.mark.usefixtures("test_db")


class _CapturingClient:
    """Fake LLM client that records the ambient correlation at call time."""

    def __init__(self) -> None:
        self.seen_hash: str | None = None
        self.seen_version: str | None = None

    async def chat(self, task_type, messages, *, run_id=None, team_id=None):
        del task_type, messages, run_id, team_id
        self.seen_hash = current_prompt_content_hash()
        self.seen_version = current_prompt_version()
        return LLMResponse(
            content="ok", model="m", usage={}, disabled=False,
            finish_reason="stop",
        )


def _messages(system_text: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system_text},
        {"role": "user", "content": "hi"},
    ]


def test_system_prompt_hash_matches_sha256() -> None:
    got = _system_prompt_hash(_messages("hello prompt"))
    assert got == hashlib.sha256(b"hello prompt").hexdigest()


def test_system_prompt_hash_none_without_system_message() -> None:
    assert _system_prompt_hash([{"role": "user", "content": "hi"}]) is None


def test_current_prompt_version_none_outside_scope() -> None:
    assert current_prompt_version() is None


def test_current_prompt_version_inside_scope() -> None:
    with correlation_scope(prompt_version="vr/audit/base@2"):
        assert current_prompt_version() == "vr/audit/base@2"
    assert current_prompt_version() is None


async def test_derives_content_hash_from_system_prompt() -> None:
    client = _CapturingClient()
    await idempotent_llm_call(
        client, method="chat", task_type="t",
        messages=_messages("audit system prompt"), investigation_id="inv-1",
    )
    assert client.seen_hash == hashlib.sha256(b"audit system prompt").hexdigest()
    assert client.seen_version is None


async def test_explicit_version_is_stamped() -> None:
    client = _CapturingClient()
    await idempotent_llm_call(
        client, method="chat", task_type="t",
        messages=_messages("p"), investigation_id="inv-2",
        prompt_version="malware/panel/halvar@5",
    )
    assert client.seen_version == "malware/panel/halvar@5"


async def test_outer_scope_version_preserved_when_arg_absent() -> None:
    client = _CapturingClient()
    with correlation_scope(
        investigation_id="inv-3", prompt_content_hash="outerhash",
        prompt_version="outer@1",
    ):
        await idempotent_llm_call(
            client, method="chat", task_type="t",
            messages=_messages("inner"), investigation_id="inv-3",
        )
    assert client.seen_version == "outer@1"
    assert client.seen_hash == "outerhash"

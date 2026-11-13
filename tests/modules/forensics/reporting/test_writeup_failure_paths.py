"""Writeup failure-path and step-log truncation behaviour (#441).

The kill-switch test drives ``state_writeup`` end to end up to the point
where the LLM response is rejected; the fake client and artefact loader
stand in for the LLM and the database, so no DB or network is touched.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from aila.modules.forensics.reporting import writeup_builder
from aila.modules.forensics.workflow.states.writeup import state_writeup
from aila.platform.llm.client import LLMResponse
from aila.platform.llm.errors import LLMDisabledError


class _Emitter:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    async def emit(self, stream: str, message: str, meta: dict[str, Any] | None = None) -> None:
        self.events.append((stream, message, meta or {}))


class _DisabledClient:
    """Fake LLM client that answers every call with the kill-switch response."""

    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, **_kwargs: Any) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            content="LLM disabled by operator", model="", usage={},
            disabled=True, finish_reason="",
        )


async def test_kill_switch_fails_writeup_state_with_typed_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _DisabledClient()
    monkeypatch.setattr(
        writeup_builder, "ServiceFactory", lambda: SimpleNamespace(llm_client=client),
    )

    async def _no_artefacts(_project_id: str) -> dict[str, list[dict[str, Any]]]:
        return {}

    monkeypatch.setattr(writeup_builder, "_load_artefacts_by_family", _no_artefacts)
    # The prompt is resolved from the version store, which is not seeded in
    # the unit-test database; this test is about the failure path, not the
    # prompt lookup.
    monkeypatch.setattr(writeup_builder, "_load_writeup_prompt", lambda: "system prompt")

    emitter = _Emitter()
    services = SimpleNamespace(emitter=emitter)

    with pytest.raises(LLMDisabledError) as excinfo:
        await state_writeup(
            {"project_id": "p-1", "investigation_id": "inv-1", "steps": [], "question": "q"},
            services,
        )

    assert excinfo.value.message == "LLM disabled by operator"
    assert client.calls == 1
    stages = [meta.get("stage") for _, _, meta in emitter.events]
    assert stages[-1] == "writeup_llm_disabled"
    failure_meta = emitter.events[-1][2]
    assert failure_meta["reason"] == "LLM disabled by operator"


def _step(stdout: str, reasoning: str) -> dict[str, Any]:
    return {
        "step_number": 1,
        "action": "tool_run",
        "command": "strings sample.bin",
        "reasoning": reasoning,
        "stdout": stdout,
        "stderr": "",
    }


def test_capped_step_fields_keep_capped_text_and_show_marker() -> None:
    section = writeup_builder._section_step_log(
        [_step(stdout="o" * 1000, reasoning="r" * 1000)],
    )
    lines = section.splitlines()
    stdout_line = next(ln for ln in lines if ln.startswith("stdout_head: "))
    reasoning_line = next(ln for ln in lines if ln.startswith("reasoning: "))

    assert stdout_line.startswith("stdout_head: " + "o" * 400)
    assert "o" * 401 not in stdout_line
    assert "[truncated]" in stdout_line
    assert reasoning_line.startswith("reasoning: " + "r" * 400)
    assert "r" * 401 not in reasoning_line
    assert "[truncated]" in reasoning_line


def test_uncapped_step_fields_carry_no_marker() -> None:
    section = writeup_builder._section_step_log(
        [_step(stdout="short output", reasoning="short reasoning")],
    )

    assert "stdout_head: short output" in section.splitlines()
    assert "reasoning: short reasoning" in section.splitlines()
    assert "[truncated]" not in section

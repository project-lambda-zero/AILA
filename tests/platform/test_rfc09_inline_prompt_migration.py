"""RFC-09 criteria 1+2: inline system-prompt literals migrated to file-
backed PromptRegistry entries, with a correlation_scope stamping the
resolved prompt's content hash around each LLM call.

Covers the sites called out in the RFC-09 audit follow-up that do NOT
route through :func:`aila.platform.agents.idempotent_llm.idempotent_llm_call`
(which R1 already made stamp content_hash on its own). Each site's test
asserts:

  (a) the ``.md`` file exists under a ``prompts/`` directory the site's
      module reads, and its content matches what the code used to inline;
  (b) the LLM call runs inside a ``correlation_scope`` carrying the sha256
      of the resolved system prompt, observed via ``current_prompt_content_hash()``
      inside a fake client (same pattern as
      ``tests/platform/agents/test_idempotent_correlation.py``).

Scope: MASVS report-section writer, forensics writeup builder, and the
platform ``human_cost`` estimator. The remaining sites migrated in the
same slice (forensics investigator freeflow turn, VR advisory narrative,
VR PoC development) are exercised through their ``_load_*_prompt`` /
``_load_freeflow_prompt`` accessors -- the byte-identity check plus the
compile-level presence of ``correlation_scope`` around each call is
sufficient here; end-to-end coverage lives with each site's existing
behavioural tests.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from aila.platform.llm.client import LLMResponse
from aila.platform.llm.correlation import (
    correlation_scope,
    current_join_keys,
    current_prompt_content_hash,
    current_prompt_version,
)


# ---------------------------------------------------------------------------
# Fake LLM client: captures the ambient correlation content-hash at call time.
# Mirrors _CapturingClient from tests/platform/agents/test_idempotent_correlation.py
# but exposes each method the migrated sites reach through.
# ---------------------------------------------------------------------------


class _StructuredResponse:
    """Duck-typed stand-in for ``AilaLLMClient.chat_structured``'s
    ``LLMResponse``. Section-writer et al reach for a ``.parsed`` attribute
    that the frozen ``LLMResponse`` slot dataclass does not expose, so a
    :class:`SimpleNamespace`-shaped double keeps the fake honest without
    coupling this test to the current frozen-dataclass shape.
    """

    def __init__(
        self,
        *,
        content: str = "{}",
        disabled: bool = False,
        parsed: Any = None,
    ) -> None:
        self.content = content
        self.model = "m"
        self.usage: dict[str, int] = {}
        self.disabled = disabled
        self.finish_reason = "stop"
        self.parsed = parsed


class _CapturingClient:
    """Fake AilaLLMClient recording the ambient prompt-content-hash."""

    def __init__(
        self,
        *,
        structured_content: str = "{}",
        structured_parsed: Any = None,
    ) -> None:
        self.seen_hash: str | None = None
        self.seen_version: str | None = None
        self.seen_join: tuple[str | None, str | None, int | None] = (None, None, None)
        self.seen_task_type: str | None = None
        self.seen_messages: list[dict[str, Any]] | None = None
        self._structured_content = structured_content
        self._structured_parsed = structured_parsed

    def _capture(self) -> None:
        self.seen_hash = current_prompt_content_hash()
        self.seen_version = current_prompt_version()
        self.seen_join = current_join_keys()

    async def chat(
        self, task_type: str, messages: list[dict[str, Any]], **kwargs: Any,
    ) -> LLMResponse:
        del kwargs
        self._capture()
        self.seen_task_type = task_type
        self.seen_messages = messages
        return LLMResponse(
            content="ok", model="m", usage={}, disabled=False,
            finish_reason="stop",
        )

    async def chat_structured(
        self,
        task_type: str,
        messages: list[dict[str, Any]],
        model_class: Any,
        **kwargs: Any,
    ) -> _StructuredResponse:
        del model_class, kwargs
        self._capture()
        self.seen_task_type = task_type
        self.seen_messages = messages
        return _StructuredResponse(
            content=self._structured_content,
            parsed=self._structured_parsed,
        )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# VR MASVS report-section writer
# ---------------------------------------------------------------------------


def test_section_writer_prompt_file_exists_and_matches_loader() -> None:
    from aila.modules.vr.reporting import section_writer

    body = section_writer._load_system_prompt()
    prompt_path = (
        Path(section_writer.__file__).parent
        / "prompts" / "system_section_writer.md"
    )
    assert prompt_path.exists(), f"prompt file missing: {prompt_path}"
    on_disk = prompt_path.read_text(encoding="utf-8")
    assert body == on_disk
    # Sanity: matches the pre-migration voice.
    assert body.startswith("You are the report writer for a mobile app security audit.")


async def test_section_writer_call_runs_inside_correlation_scope() -> None:
    from aila.modules.vr.contracts.masvs import (
        MasvsControlVerdict,
        MasvsVerdict,
    )
    from aila.modules.vr.reporting.section_writer import (
        ReportSection,
        _load_system_prompt,
        generate_section,
    )

    verdict = MasvsControlVerdict(
        control_id="MSTG-STORAGE-1",
        child_investigation_id="child-1",
        verdict=MasvsVerdict.FINDING,
        confidence=0.9,
        reason="",
        evidence_locations=[],
    )
    parsed_section = ReportSection(
        headline="Vulnerable: token storage in plain SharedPreferences",
        evidence=[],
        risk="session-token theft enables account takeover",
        remediation="Use EncryptedSharedPreferences",
        why_it_matters="Persisted tokens survive process death.",
    )
    client = _CapturingClient(
        structured_content=parsed_section.model_dump_json(),
        structured_parsed=parsed_section,
    )

    section = await generate_section(
        verdict=verdict,
        control=None,
        raw_answer="agent raw text",
        apk_context={"package": "com.example.app"},
        llm=client,
        run_id=None,
        team_id=None,
    )

    assert section is not None
    assert client.seen_hash == _sha256(_load_system_prompt())
    assert client.seen_task_type == "vr.masvs.report_section_writer"


# ---------------------------------------------------------------------------
# Forensics writeup builder
# ---------------------------------------------------------------------------


def test_writeup_builder_prompt_file_exists_and_matches_loader() -> None:
    from aila.modules.forensics.reporting import writeup_builder

    body = writeup_builder._load_writeup_prompt()
    prompt_path = (
        Path(writeup_builder.__file__).parent
        / "prompts" / "system_writeup.md"
    )
    assert prompt_path.exists(), f"prompt file missing: {prompt_path}"
    on_disk = prompt_path.read_text(encoding="utf-8")
    assert body == on_disk
    assert body.startswith("You are a senior DFIR")


async def test_writeup_builder_call_runs_inside_correlation_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aila.modules.forensics.reporting import writeup_builder

    client = _CapturingClient()

    class _FakeFactory:
        llm_client = client

    monkeypatch.setattr(
        writeup_builder, "ServiceFactory", lambda: _FakeFactory(),
    )
    # Skip the DB round-trip for artefacts -- the writeup happy path here
    # only cares that the LLM call gets the resolved prompt + hash.
    async def _no_artefacts(_project_id: str) -> dict[str, list[dict[str, Any]]]:
        return {}

    monkeypatch.setattr(
        writeup_builder, "_load_artefacts_by_family", _no_artefacts,
    )

    out = await writeup_builder._generate_writeup_content(
        project_id="p-1",
        investigation_id="inv-1",
        question="What is the C2?",
        answer="1.2.3.4",
        confidence="strong",
        steps=[],
        tools_used=[],
        observables={},
        contract={"answer_type": "ip:port"},
        hypotheses=[],
        rejected=[],
    )
    assert out == "ok"
    assert client.seen_hash == _sha256(writeup_builder._load_writeup_prompt())
    assert client.seen_task_type == "forensics_writeup"
    # First message MUST be the file-resolved system prompt, not an inline
    # literal.
    assert client.seen_messages is not None
    assert client.seen_messages[0]["role"] == "system"
    assert client.seen_messages[0]["content"] == writeup_builder._load_writeup_prompt()


# ---------------------------------------------------------------------------
# Platform human-cost estimator
# ---------------------------------------------------------------------------


def test_human_cost_prompt_file_exists_and_matches_loader() -> None:
    from aila.platform.llm import human_cost

    body = human_cost._load_human_cost_prompt()
    prompt_path = (
        Path(human_cost.__file__).resolve().parents[1]
        / "prompts" / "system_human_cost.md"
    )
    assert prompt_path.exists(), f"prompt file missing: {prompt_path}"
    on_disk = prompt_path.read_text(encoding="utf-8")
    assert body == on_disk
    assert body.startswith("You are a security consulting cost estimator.")


async def test_human_cost_call_runs_inside_correlation_scope(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    del test_db
    from aila.platform.llm import human_cost

    parsed_est = human_cost.HumanCostEstimate(
        estimated_hours=12.5,
        reasoning="benchmark",
        confidence="medium",
    )
    client = _CapturingClient(
        structured_content=parsed_est.model_dump_json(),
        structured_parsed=parsed_est,
    )

    class _StubRegistry:
        async def get(self, module: str, key: str) -> Any:
            del module, key
            return None

    # No records for the fake run_id => the SQL branch returns None early
    # after the LLM call, but the seen_hash was captured before that.
    est = await human_cost.estimate_human_cost(
        llm_client=client,
        registry=_StubRegistry(),
        team_id=None,
        run_id="run-does-not-exist",
        target_count=1,
        finding_count=0,
        task_types_performed=["scoring"],
        scan_duration_minutes=1.0,
    )
    # No cost records for that run_id -> estimate_human_cost swallows and
    # returns None, but the correlation-scope capture happened during the
    # LLM call itself.
    assert est is None
    assert client.seen_hash == _sha256(human_cost._load_human_cost_prompt())
    assert client.seen_task_type == "cost_estimation"


# ---------------------------------------------------------------------------
# Forensics investigator: base + OS-hint assembly stays honest.
# ---------------------------------------------------------------------------


def test_forensics_freeflow_prompt_assembles_from_base_plus_os_hint() -> None:
    from aila.modules.forensics.agents import investigator

    prompts_dir = Path(investigator.__file__).parent / "prompts"
    base = (prompts_dir / "system_base.md").read_text(encoding="utf-8")
    linux = (prompts_dir / "os_hint_linux.md").read_text(encoding="utf-8")
    windows = (prompts_dir / "os_hint_windows.md").read_text(encoding="utf-8")

    assert investigator._load_freeflow_prompt("linux") == base + linux
    assert investigator._load_freeflow_prompt("windows") == base + windows
    # Fallback (unknown analyzer OS) mirrors the pre-RFC-09 behaviour: any
    # value other than "windows" gets the Linux hint.
    assert investigator._load_freeflow_prompt("darwin") == base + linux


# ---------------------------------------------------------------------------
# VR advisory + PoC prompts: file-backed accessors match the migrated bytes.
# ---------------------------------------------------------------------------


def test_advisory_prompt_file_matches_loader() -> None:
    from aila.modules.vr.workflow.states import advisory

    body = advisory._load_narrative_prompt()
    prompt_path = (
        Path(advisory.__file__).resolve().parent.parent
        / "prompts" / "system_advisory_narrative.md"
    )
    assert prompt_path.exists(), f"prompt file missing: {prompt_path}"
    assert body == prompt_path.read_text(encoding="utf-8")
    assert body.startswith("You are writing a coordinated-disclosure advisory")


def test_poc_development_prompt_file_matches_loader() -> None:
    from aila.modules.vr.workflow.states import poc_development

    body = poc_development._load_system_prompt()
    prompt_path = (
        Path(poc_development.__file__).resolve().parent.parent
        / "prompts" / "system_poc_development.md"
    )
    assert prompt_path.exists(), f"prompt file missing: {prompt_path}"
    assert body == prompt_path.read_text(encoding="utf-8")
    assert body.startswith("You write proof-of-concept exploits")


# ---------------------------------------------------------------------------
# Outer-scope preservation: content-hash stamping must NOT clobber an
# investigation/branch/turn attribution the caller already established.
# ---------------------------------------------------------------------------


async def test_writeup_call_preserves_outer_correlation_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aila.modules.forensics.reporting import writeup_builder

    client = _CapturingClient()

    class _FakeFactory:
        llm_client = client

    monkeypatch.setattr(
        writeup_builder, "ServiceFactory", lambda: _FakeFactory(),
    )

    async def _no_artefacts(_project_id: str) -> dict[str, list[dict[str, Any]]]:
        return {}

    monkeypatch.setattr(
        writeup_builder, "_load_artefacts_by_family", _no_artefacts,
    )

    with correlation_scope(
        investigation_id="inv-abc",
        branch_id="br-1",
        turn_number=7,
        prompt_version="outer/v@2",
    ):
        await writeup_builder._generate_writeup_content(
            project_id="p-1",
            investigation_id="inv-abc",
            question="q",
            answer="a",
            confidence="strong",
            steps=[],
            tools_used=[],
            observables={},
            contract={},
            hypotheses=[],
            rejected=[],
        )

    # The stamped content hash comes from the writeup prompt file, but the
    # outer investigation/branch/turn/prompt_version survive the nested scope.
    assert client.seen_hash == _sha256(writeup_builder._load_writeup_prompt())
    assert client.seen_join == ("inv-abc", "br-1", 7)
    assert client.seen_version == "outer/v@2"

"""Unit tests for aila.platform.llm.validate.

Tests the evidence validation pipeline step: EvidenceValidator Protocol,
CitationResult/ValidationResult/EvidenceValidationReport frozen dataclasses,
make_validate_step factory, _merge_results aggregation, _emit_validation_event
audit emission, and _enrich_response propagation of evidence_validation.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aila.modules.vulnerability.evidence_validator import VulnEvidenceValidator
from aila.platform.events.event import PlatformEvent
from aila.platform.llm.classify import make_classify_step
from aila.platform.llm.client import AilaLLMClient, LLMResponse, _enrich_response
from aila.platform.llm.config import LLMRouting
from aila.platform.llm.errors import LLMError
from aila.platform.llm.validate import (
    CitationResult,
    EvidenceValidationReport,
    EvidenceValidator,
    ValidationResult,
    _emit_validation_event,
    _merge_results,
    make_validate_step,
)

# ---------------------------------------------------------------------------
# Fakes (same patterns as test_classify.py)
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
def routing() -> LLMRouting:
    return LLMRouting(
        model_id="test-model",
        base_url="http://test",
        api_key="sk-test",
        max_tokens=100,
        temperature=0.0,
        max_tool_steps=0,
        task_type="scoring",
    )


# ---------------------------------------------------------------------------
# Protocol tests
# ---------------------------------------------------------------------------

class TestEvidenceValidatorProtocol:
    """Verify EvidenceValidator is runtime_checkable and accepts compliant classes."""

    def test_protocol_is_runtime_checkable(self) -> None:

        class _Good:
            async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult:
                return ValidationResult(validator_name="test")

        assert isinstance(_Good(), EvidenceValidator)

    def test_non_compliant_class_rejected(self) -> None:

        class _Bad:
            def not_validate(self) -> None:
                pass

        assert not isinstance(_Bad(), EvidenceValidator)


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------

class TestDataclasses:
    """Verify frozen dataclasses have correct fields and defaults."""

    def test_citation_result_fields(self) -> None:

        cr = CitationResult(
            citation_id="CVE-2024-1234",
            citation_type="cve_id",
            status="valid",
            detail="found in store",
        )
        assert cr.citation_id == "CVE-2024-1234"
        assert cr.citation_type == "cve_id"
        assert cr.status == "valid"
        assert cr.detail == "found in store"

    def test_citation_result_default_detail(self) -> None:

        cr = CitationResult(citation_id="CVE-2024-1234", citation_type="cve_id", status="valid")
        assert cr.detail == ""

    def test_citation_result_frozen(self) -> None:

        cr = CitationResult(citation_id="CVE-2024-1234", citation_type="cve_id", status="valid")
        with pytest.raises(AttributeError):
            cr.status = "invalid"  # type: ignore[misc]

    def test_validation_result_fields(self) -> None:

        vr = ValidationResult(validator_name="vuln", citations=[], hallucination_count=0, overall_pass=True)
        assert vr.validator_name == "vuln"
        assert vr.citations == []
        assert vr.hallucination_count == 0
        assert vr.overall_pass is True

    def test_validation_result_defaults(self) -> None:

        vr = ValidationResult(validator_name="vuln")
        assert vr.citations == []
        assert vr.hallucination_count == 0
        assert vr.overall_pass is True

    def test_evidence_validation_report_fields(self) -> None:

        report = EvidenceValidationReport(
            citations_found=3,
            citations_valid=2,
            citations_hallucinated=1,
            hallucinated_ids=["CVE-2099-9999"],
            overall_pass=False,
            results=[],
        )
        assert report.citations_found == 3
        assert report.citations_valid == 2
        assert report.citations_hallucinated == 1
        assert report.hallucinated_ids == ["CVE-2099-9999"]
        assert report.overall_pass is False

    def test_evidence_validation_report_defaults(self) -> None:

        report = EvidenceValidationReport()
        assert report.citations_found == 0
        assert report.citations_valid == 0
        assert report.citations_hallucinated == 0
        assert report.hallucinated_ids == []
        assert report.overall_pass is True
        assert report.results == []


# ---------------------------------------------------------------------------
# _merge_results tests
# ---------------------------------------------------------------------------

class TestMergeResults:
    """Verify _merge_results aggregation logic."""

    def test_merge_empty(self) -> None:

        report = _merge_results([])
        assert report.citations_found == 0
        assert report.citations_valid == 0
        assert report.citations_hallucinated == 0
        assert report.hallucinated_ids == []
        assert report.overall_pass is True

    def test_merge_single_passing(self) -> None:

        result = ValidationResult(
            validator_name="test",
            citations=[
                CitationResult(citation_id="CVE-2024-0001", citation_type="cve_id", status="valid"),
                CitationResult(citation_id="CVE-2024-0002", citation_type="cve_id", status="valid"),
            ],
            hallucination_count=0,
            overall_pass=True,
        )
        report = _merge_results([result])
        assert report.citations_found == 2
        assert report.citations_valid == 2
        assert report.citations_hallucinated == 0
        assert report.hallucinated_ids == []
        assert report.overall_pass is True

    def test_merge_with_hallucinations(self) -> None:

        result = ValidationResult(
            validator_name="test",
            citations=[
                CitationResult(citation_id="CVE-2024-0001", citation_type="cve_id", status="valid"),
                CitationResult(citation_id="CVE-2099-9999", citation_type="cve_id", status="hallucinated"),
            ],
            hallucination_count=1,
            overall_pass=False,
        )
        report = _merge_results([result])
        assert report.citations_found == 2
        assert report.citations_hallucinated == 1
        assert report.hallucinated_ids == ["CVE-2099-9999"]
        assert report.overall_pass is False

    def test_merge_multiple_results(self) -> None:

        r1 = ValidationResult(
            validator_name="v1",
            citations=[
                CitationResult(citation_id="CVE-2024-0001", citation_type="cve_id", status="valid"),
            ],
            hallucination_count=0,
            overall_pass=True,
        )
        r2 = ValidationResult(
            validator_name="v2",
            citations=[
                CitationResult(citation_id="CVE-2099-8888", citation_type="cve_id", status="hallucinated"),
            ],
            hallucination_count=1,
            overall_pass=False,
        )
        report = _merge_results([r1, r2])
        assert report.citations_found == 2
        assert report.citations_valid == 1
        assert report.citations_hallucinated == 1
        assert report.hallucinated_ids == ["CVE-2099-8888"]
        assert report.overall_pass is False

    def test_merge_deduplicates_hallucinated_ids(self) -> None:

        # Same CVE cited as hallucinated in two sub-assertions
        r1 = ValidationResult(
            validator_name="v1",
            citations=[
                CitationResult(citation_id="CVE-2099-9999", citation_type="cve_id", status="hallucinated"),
                CitationResult(citation_id="CVE-2099-9999", citation_type="epss_score", status="hallucinated"),
            ],
            hallucination_count=1,
            overall_pass=False,
        )
        report = _merge_results([r1])
        # Only one unique hallucinated ID
        assert report.hallucinated_ids == ["CVE-2099-9999"]

    def test_merge_counts_cve_id_type_only_for_found(self) -> None:

        result = ValidationResult(
            validator_name="test",
            citations=[
                CitationResult(citation_id="CVE-2024-0001", citation_type="cve_id", status="valid"),
                CitationResult(citation_id="CVE-2024-0001", citation_type="epss_score", status="valid"),
                CitationResult(citation_id="CVE-2024-0001", citation_type="kev_status", status="valid"),
            ],
            hallucination_count=0,
            overall_pass=True,
        )
        report = _merge_results([result])
        # Only cve_id citations counted for citations_found
        assert report.citations_found == 1


# ---------------------------------------------------------------------------
# _emit_validation_event tests
# ---------------------------------------------------------------------------

class TestEmitValidationEvent:
    """Verify audit event emission."""

    def test_emit_with_emitter(self, routing: LLMRouting) -> None:

        emitter = FakeEmitter()
        ctx: dict[str, Any] = {"task_type": "scoring"}
        report = EvidenceValidationReport(
            citations_found=2,
            citations_valid=1,
            citations_hallucinated=1,
            hallucinated_ids=["CVE-2099-9999"],
            overall_pass=False,
        )
        _emit_validation_event(ctx, routing, report, emitter)

        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.stage == "llm_evidence_validation"
        assert event.action == "validate"
        assert event.key == "llm.validate.scoring"
        assert event.details["citations_found"] == 2
        assert event.details["citations_hallucinated"] == 1
        assert event.details["hallucinated_ids"] == ["CVE-2099-9999"]
        assert event.details["overall_pass"] is False

    def test_emit_with_none_emitter(self, routing: LLMRouting) -> None:

        ctx: dict[str, Any] = {"task_type": "scoring"}
        report = EvidenceValidationReport()
        # Should not raise
        _emit_validation_event(ctx, routing, report, None)


# ---------------------------------------------------------------------------
# make_validate_step factory tests
# ---------------------------------------------------------------------------

class TestMakeValidateStep:
    """Verify factory closure behavior."""

    @pytest.mark.asyncio
    async def test_factory_runs_validator_and_writes_ctx(self, routing: LLMRouting) -> None:

        class FakeValidator:
            async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult:
                return ValidationResult(
                    validator_name="fake",
                    citations=[
                        CitationResult(citation_id="CVE-2024-0001", citation_type="cve_id", status="valid"),
                    ],
                    hallucination_count=0,
                    overall_pass=True,
                )

        step = make_validate_step([FakeValidator()])
        ctx: dict[str, Any] = {
            "task_type": "scoring",
            "response": LLMResponse(content="CVE-2024-0001 is critical"),
        }
        messages: list[dict[str, Any]] = []
        await step(ctx, messages, routing)

        assert "evidence_validation" in ctx
        ev = ctx["evidence_validation"]
        assert isinstance(ev, dict)
        assert ev["citations_found"] == 1
        assert ev["overall_pass"] is True

    @pytest.mark.asyncio
    async def test_factory_no_response_returns_without_error(self, routing: LLMRouting) -> None:

        step = make_validate_step([])
        ctx: dict[str, Any] = {"task_type": "scoring"}
        messages: list[dict[str, Any]] = []
        # No response in ctx -> should not raise
        await step(ctx, messages, routing)
        assert "evidence_validation" not in ctx

    @pytest.mark.asyncio
    async def test_factory_empty_content_writes_passing_report(self, routing: LLMRouting) -> None:

        step = make_validate_step([])
        ctx: dict[str, Any] = {
            "task_type": "scoring",
            "response": LLMResponse(content=""),
        }
        messages: list[dict[str, Any]] = []
        await step(ctx, messages, routing)

        assert "evidence_validation" in ctx
        ev = ctx["evidence_validation"]
        assert ev["overall_pass"] is True
        assert ev["citations_found"] == 0

    @pytest.mark.asyncio
    async def test_factory_emits_audit_event(self, routing: LLMRouting) -> None:

        emitter = FakeEmitter()
        step = make_validate_step([], emitter=emitter)
        ctx: dict[str, Any] = {
            "task_type": "scoring",
            "response": LLMResponse(content="some content"),
        }
        messages: list[dict[str, Any]] = []
        await step(ctx, messages, routing)

        assert len(emitter.events) == 1
        assert emitter.events[0].stage == "llm_evidence_validation"


# ---------------------------------------------------------------------------
# _enrich_response tests
# ---------------------------------------------------------------------------

class TestEnrichResponse:
    """Verify _enrich_response propagates evidence_validation."""

    def test_propagates_evidence_validation(self) -> None:

        response = LLMResponse(content="test", model="test-model")
        ev_data = {"citations_found": 2, "overall_pass": True}
        ctx: dict[str, Any] = {"evidence_validation": ev_data}
        enriched = _enrich_response(response, ctx)

        assert enriched.pipeline_metadata is not None
        assert enriched.pipeline_metadata["evidence_validation"] == ev_data

    def test_no_evidence_validation_unchanged(self) -> None:

        response = LLMResponse(content="test", model="test-model")
        ctx: dict[str, Any] = {}
        enriched = _enrich_response(response, ctx)

        # No pipeline_metadata should be set
        assert enriched.pipeline_metadata is None

    def test_merges_with_existing_metadata(self) -> None:

        response = LLMResponse(content="test", model="test-model")
        ev_data = {"citations_found": 1, "overall_pass": True}
        ctx: dict[str, Any] = {
            "pipeline_metadata": {"seal_id": "abc"},
            "evidence_validation": ev_data,
        }
        enriched = _enrich_response(response, ctx)

        assert enriched.pipeline_metadata is not None
        assert enriched.pipeline_metadata["evidence_validation"] == ev_data
        assert enriched.pipeline_metadata["seal_id"] == "abc"

    def test_does_not_mutate_original_metadata(self) -> None:

        response = LLMResponse(content="test", model="test-model")
        original_metadata = {"seal_id": "abc"}
        ev_data = {"citations_found": 1, "overall_pass": True}
        ctx: dict[str, Any] = {
            "pipeline_metadata": original_metadata,
            "evidence_validation": ev_data,
        }
        _enrich_response(response, ctx)

        # Original metadata should not be mutated
        assert "evidence_validation" not in original_metadata


# ===========================================================================
# Task 2: VulnEvidenceValidator tests
# ===========================================================================

class _FakeRow:
    """Simulates a CacheRecord row returned by session.exec()."""

    def __init__(self, cache_key: str, payload_json: str) -> None:
        self.namespace = "cve_intel"
        self.cache_key = cache_key
        self.payload_json = payload_json


def _make_payload(
    cve_id: str,
    *,
    epss_score: float | None = None,
    kev_listed: bool = False,
) -> str:
    """Build a JSON payload matching CVEKnowledge shape."""
    return json.dumps({
        "cve_id": cve_id,
        "description": f"Test vulnerability {cve_id}",
        "epss_score": epss_score,
        "kev_listed": kev_listed,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    })


def _fake_batch_lookup(rows: list[_FakeRow]):
    """Return an async replacement for VulnEvidenceValidator._batch_lookup.

    Production _batch_lookup issues an async SQL query against
    ServiceFactory().storage.fetch_all(CacheRecord, ...) and returns
    dict[cve_id -> parsed payload dict], filtered by cve_ids. This fake
    reproduces that shape from an in-memory _FakeRow list so the tests
    exercise the validator's parsing/citation logic without a DB.
    """

    async def _lookup(_self: Any, cve_ids: list[str]) -> dict[str, dict]:
        wanted = set(cve_ids)
        result: dict[str, dict] = {}
        for row in rows:
            if row.cache_key not in wanted:
                continue
            try:
                payload = json.loads(row.payload_json)
            except json.JSONDecodeError:
                payload = {}
            if isinstance(payload, dict):
                result[row.cache_key] = payload
        return result

    return _lookup


# Standard test rows
_REAL_CVE_ROW = _FakeRow(
    cache_key="CVE-2024-1234",
    payload_json=_make_payload("CVE-2024-1234", epss_score=0.85, kev_listed=True),
)

_REAL_CVE_ROW_NO_KEV = _FakeRow(
    cache_key="CVE-2024-5678",
    payload_json=_make_payload("CVE-2024-5678", epss_score=0.50, kev_listed=False),
)


class TestVulnValidator:
    """Tests for VulnEvidenceValidator hallucination, EPSS, KEV validation."""

    @pytest.mark.asyncio
    async def test_hallucinated_cve_not_in_store(self) -> None:

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([])  # no rows -> CVE not found
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            result = await validator.validate("CVE-2099-9999 is critical", {})

        assert result.hallucination_count == 1
        assert result.overall_pass is False
        hallucinated = [c for c in result.citations if c.status == "hallucinated"]
        assert len(hallucinated) == 1
        assert hallucinated[0].citation_id == "CVE-2099-9999"

    @pytest.mark.asyncio
    async def test_valid_cve_in_store(self) -> None:

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([_REAL_CVE_ROW])
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            result = await validator.validate("CVE-2024-1234 is critical", {})

        valid_cve = [c for c in result.citations if c.citation_type == "cve_id" and c.status == "valid"]
        assert len(valid_cve) == 1
        assert valid_cve[0].citation_id == "CVE-2024-1234"

    @pytest.mark.asyncio
    async def test_mixed_real_and_fake_cves(self) -> None:

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([_REAL_CVE_ROW])
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            result = await validator.validate(
                "CVE-2024-1234 is real, CVE-2099-9999 is fake", {}
            )

        valid = [c for c in result.citations if c.citation_type == "cve_id" and c.status == "valid"]
        hallucinated = [c for c in result.citations if c.status == "hallucinated"]
        assert len(valid) == 1
        assert len(hallucinated) == 1
        assert hallucinated[0].citation_id == "CVE-2099-9999"
        assert result.hallucination_count == 1
        assert result.overall_pass is False

    @pytest.mark.asyncio
    async def test_case_normalization(self) -> None:

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([_REAL_CVE_ROW])
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            # Lowercase cve in content -- CVE_PATTERN only matches uppercase,
            # but validator should handle uppercase matches from regex
            result = await validator.validate("CVE-2024-1234 found", {})

        valid_cve = [c for c in result.citations if c.citation_type == "cve_id" and c.status == "valid"]
        assert len(valid_cve) == 1
        assert valid_cve[0].citation_id == "CVE-2024-1234"

    @pytest.mark.asyncio
    async def test_no_cves_in_content(self) -> None:

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([])
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            result = await validator.validate("no vulnerabilities found", {})

        assert result.overall_pass is True
        assert result.hallucination_count == 0
        assert result.citations == []

    @pytest.mark.asyncio
    async def test_epss_valid_small_delta(self) -> None:
        """EPSS delta 0.01 < 0.1 threshold -> valid."""

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([_REAL_CVE_ROW])  # stored epss=0.85
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            result = await validator.validate(
                "CVE-2024-1234 has EPSS score 0.84", {}
            )

        epss = [c for c in result.citations if c.citation_type == "epss_score"]
        assert len(epss) == 1
        assert epss[0].status == "valid"

    @pytest.mark.asyncio
    async def test_epss_invalid_large_delta(self) -> None:
        """EPSS delta 0.55 > 0.1 threshold -> invalid."""

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([_REAL_CVE_ROW])  # stored epss=0.85
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            result = await validator.validate(
                "CVE-2024-1234 has EPSS score 0.30", {}
            )

        epss = [c for c in result.citations if c.citation_type == "epss_score"]
        assert len(epss) == 1
        assert epss[0].status == "invalid"
        assert "0.30" in epss[0].detail or "0.3" in epss[0].detail

    @pytest.mark.asyncio
    async def test_kev_valid_listed(self) -> None:
        """LLM claims KEV, stored kev_listed=True -> valid."""

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([_REAL_CVE_ROW])  # kev_listed=True
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            result = await validator.validate(
                "CVE-2024-1234 is in CISA KEV", {}
            )

        kev = [c for c in result.citations if c.citation_type == "kev_status"]
        assert len(kev) == 1
        assert kev[0].status == "valid"

    @pytest.mark.asyncio
    async def test_kev_invalid_not_listed(self) -> None:
        """LLM claims KEV, stored kev_listed=False -> invalid."""

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([_REAL_CVE_ROW_NO_KEV])  # kev_listed=False
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            result = await validator.validate(
                "CVE-2024-5678 is in KEV", {}
            )

        kev = [c for c in result.citations if c.citation_type == "kev_status"]
        assert len(kev) == 1
        assert kev[0].status == "invalid"


class TestValidatePipelineStep:
    """Integration test: make_validate_step with VulnEvidenceValidator."""

    @pytest.mark.asyncio
    async def test_end_to_end_with_vuln_validator(self, routing: LLMRouting) -> None:

        with patch(
            "aila.modules.vulnerability.evidence_validator.VulnEvidenceValidator._batch_lookup",
            _fake_batch_lookup([_REAL_CVE_ROW])
        ):
            validator = VulnEvidenceValidator(settings=MagicMock())
            step = make_validate_step([validator])
            ctx: dict[str, Any] = {
                "task_type": "scoring",
                "response": LLMResponse(content="CVE-2024-1234 is critical"),
            }
            messages: list[dict[str, Any]] = []
            await step(ctx, messages, routing)

        assert "evidence_validation" in ctx
        ev = ctx["evidence_validation"]
        assert isinstance(ev, dict)
        assert "citations_found" in ev
        assert "overall_pass" in ev
        assert "hallucinated_ids" in ev
        assert ev["overall_pass"] is True


# ===========================================================================
# Pipeline Integration Tests -- AilaLLMClient with validate step registered
# ===========================================================================

class _IntFakeRegistry:
    """In-memory ConfigRegistry fake for integration tests."""

    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}

    async def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")


class _IntFakeSecretStore:
    """In-memory SecretStore fake for integration tests."""

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = secrets or {}

    async def resolve_provider_secret(self, secret_key: str) -> str | None:
        return self._secrets.get(secret_key)


def _make_completion(
    content: str = "Hello",
    finish_reason: str = "stop",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> MagicMock:
    """Build a mock ChatCompletion response."""
    usage = MagicMock()
    usage.prompt_tokens = prompt_tokens
    usage.completion_tokens = completion_tokens
    usage.total_tokens = prompt_tokens + completion_tokens

    message = MagicMock()
    message.content = content
    message.tool_calls = []

    choice = MagicMock()
    choice.message = message
    choice.finish_reason = finish_reason

    completion = MagicMock()
    completion.choices = [choice]
    completion.usage = usage
    return completion


class TestValidatePipelineIntegration:
    """End-to-end: validate step registered on AilaLLMClient.

    These tests verify the validate step works through the real AilaLLMClient
    with a mocked AsyncOpenAI backend. Covers: validate runs after API call
    and populates pipeline_metadata, config toggle disable, fail-open/closed
    behavior, and full classify + validate pipeline chain.
    """

    @pytest.mark.asyncio
    async def test_validate_runs_after_api_call_and_populates_metadata(self) -> None:
        """AilaLLMClient with registered validate step runs validate after
        API call and populates pipeline_metadata['evidence_validation']."""
        registry = _IntFakeRegistry({
            "platform.llm_default_model": "test-model",
        })
        secret_store = _IntFakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )

        # Create a FakeValidator that returns a known ValidationResult

        class FakeValidator:
            async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult:
                return ValidationResult(
                    validator_name="fake",
                    citations=[
                        CitationResult(
                            citation_id="CVE-2024-1234",
                            citation_type="cve_id",
                            status="valid",
                        ),
                    ],
                    hallucination_count=0,
                    overall_pass=True,
                )

        fake_validator = FakeValidator()
        step = make_validate_step([fake_validator])
        client.pipeline.register("validate", step)

        mock_completion = _make_completion(content="CVE-2024-1234 is critical")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_openai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_openai.return_value = mock_instance

            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "Score CVE-2024-1234"}],
            )

        assert response.pipeline_metadata is not None
        assert "evidence_validation" in response.pipeline_metadata
        ev = response.pipeline_metadata["evidence_validation"]
        assert ev["citations_found"] == 1
        assert ev["overall_pass"] is True
        assert ev["citations_hallucinated"] == 0

    @pytest.mark.asyncio
    async def test_validate_skipped_when_config_disables(self) -> None:
        """Validate step disabled via config: pipeline_metadata should NOT
        contain evidence_validation (step was skipped)."""
        registry = _IntFakeRegistry({
            "platform.llm_default_model": "test-model",
            "platform.llm_pipeline_validate_scoring": "false",
        })
        secret_store = _IntFakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )


        class FakeValidator:
            async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult:
                return ValidationResult(
                    validator_name="fake",
                    citations=[
                        CitationResult(citation_id="CVE-2024-1234", citation_type="cve_id", status="valid"),
                    ],
                    hallucination_count=0,
                    overall_pass=True,
                )

        step = make_validate_step([FakeValidator()])
        client.pipeline.register("validate", step)

        mock_completion = _make_completion(content="CVE-2024-1234 analysis")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_openai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_openai.return_value = mock_instance

            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "Score CVE-2024-1234"}],
            )

        # Validate step was skipped, no evidence_validation in metadata
        if response.pipeline_metadata is not None:
            assert "evidence_validation" not in response.pipeline_metadata

    @pytest.mark.asyncio
    async def test_fail_open_logs_warning_on_validator_exception(self) -> None:
        """Validate step in fail-open mode: validator exception is logged but
        does not raise. Response is returned successfully.

        fix §156 flipped the default fail_mode for security-critical steps
        (validate/gate/verify/classify/seal/sanitize) to "closed", so this
        test must opt into "open" explicitly to exercise the fail-open path.
        See LLMConfigProvider._SECURITY_CRITICAL_STEPS and resolve_fail_mode.
        """
        registry = _IntFakeRegistry({
            "platform.llm_default_model": "test-model",
            # Opt into fail-open (default is now "closed" for validate per \u00a7156)
            "platform.llm_pipeline_validate_fail_mode_scoring": "open",
        })
        secret_store = _IntFakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )


        class ExplodingValidator:
            async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult:
                raise RuntimeError("validator boom")

        step = make_validate_step([ExplodingValidator()])
        client.pipeline.register("validate", step)

        mock_completion = _make_completion(content="Some analysis result")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_openai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_openai.return_value = mock_instance

            # Should NOT raise -- fail-open swallows the error
            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "Score something"}],
            )

        assert response.content == "Some analysis result"

    @pytest.mark.asyncio
    async def test_fail_closed_wraps_validator_exception_in_llm_error(self) -> None:
        """Validate step in fail-closed mode: validator exception is wrapped
        in LLMError and raised to the caller."""
        registry = _IntFakeRegistry({
            "platform.llm_default_model": "test-model",
            "platform.llm_pipeline_validate_fail_mode_scoring": "closed",
        })
        secret_store = _IntFakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )


        class ExplodingValidator:
            async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult:
                raise RuntimeError("validator exploded")

        step = make_validate_step([ExplodingValidator()])
        client.pipeline.register("validate", step)

        mock_completion = _make_completion(content="Some result")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_openai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_openai.return_value = mock_instance

            with pytest.raises(LLMError, match="fail-closed"):
                await client.chat(
                    "scoring",
                    [{"role": "user", "content": "Score something"}],
                )

    @pytest.mark.asyncio
    async def test_full_pipeline_chain_classify_and_validate(self) -> None:
        """Full pipeline chain: classify (pre-call) -> API call -> validate
        (post-call). Both steps run in correct order and populate response."""

        registry = _IntFakeRegistry({
            "platform.llm_default_model": "test-model",
            # Classify restricted behavior = redact (so it doesn't block)
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "redact",
        })
        secret_store = _IntFakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )

        # Register classify step
        classify_step = make_classify_step(registry=registry, emitter=None)  # type: ignore[arg-type]
        client.pipeline.register("classify", classify_step)

        # Register validate step with a FakeValidator
        class FakeValidator:
            async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult:
                return ValidationResult(
                    validator_name="fake",
                    citations=[
                        CitationResult(
                            citation_id="CVE-2024-1234",
                            citation_type="cve_id",
                            status="valid",
                        ),
                    ],
                    hallucination_count=0,
                    overall_pass=True,
                )

        validate_step = make_validate_step([FakeValidator()])
        client.pipeline.register("validate", validate_step)

        # Content with IP + CVE ID -- classify will detect INTERNAL (public IP)
        mock_completion = _make_completion(
            content="CVE-2024-1234 on 8.8.8.8 scored HIGH"
        )
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_openai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_openai.return_value = mock_instance

            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "Score CVE-2024-1234 on 8.8.8.8"}],
            )

        # Classify ran (pre-call)
        assert response.classification is not None

        # Validate ran (post-call)
        assert response.pipeline_metadata is not None
        assert "evidence_validation" in response.pipeline_metadata
        ev = response.pipeline_metadata["evidence_validation"]
        assert ev["overall_pass"] is True
        assert ev["citations_found"] == 1

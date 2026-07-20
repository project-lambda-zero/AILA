"""Unit tests for aila.platform.llm.classify.

Tests the data classification pipeline step: pattern detection, classification
levels, RESTRICTED behavior (fail-closed/redact), audit event emission,
pipeline integration, and the ClassificationBlockedError mechanism.

Also contains integration tests (TestClassifyPipelineIntegration) that verify
the classify step works end-to-end when registered on a real AilaLLMClient
with a mocked AsyncOpenAI backend.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aila.platform.events.event import PlatformEvent
from aila.platform.llm.classify import (
    _PATTERNS,
    ClassificationLevel,
    classify_messages,
    make_classify_step,
    register_pattern,
)
from aila.platform.llm.client import AilaLLMClient
from aila.platform.llm.config import LLMConfigProvider, LLMRouting
from aila.platform.llm.errors import ClassificationBlockedError, LLMError
from aila.platform.llm.pipeline import PipelineRunner

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeRegistry:
    """In-memory ConfigRegistry fake.

    ``get`` is async to match the real ConfigRegistry (config resolvers
    and the classify pipeline step await ``registry.get``).
    """

    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}

    async def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")

    def set(self, namespace: str, key: str, value: str) -> None:
        self._data[f"{namespace}.{key}"] = value


class FakeSecretStore:
    """In-memory SecretStore fake.

    ``resolve_provider_secret`` is async to match the real SecretStore
    (LLMConfigProvider.resolve_api_key awaits it).
    """

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = secrets or {}

    async def resolve_provider_secret(self, secret_key: str) -> str | None:
        return self._secrets.get(secret_key)


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


@pytest.fixture()
def emitter() -> FakeEmitter:
    return FakeEmitter()


# ---------------------------------------------------------------------------
# TestClassificationLevel
# ---------------------------------------------------------------------------

class TestClassificationLevel:
    """ClassificationLevel enum ordering and values."""

    def test_public_is_zero(self) -> None:
        assert ClassificationLevel.PUBLIC == 0

    def test_internal_is_one(self) -> None:
        assert ClassificationLevel.INTERNAL == 1

    def test_restricted_is_two(self) -> None:
        assert ClassificationLevel.RESTRICTED == 2

    def test_restricted_gt_internal(self) -> None:
        assert ClassificationLevel.RESTRICTED > ClassificationLevel.INTERNAL

    def test_internal_gt_public(self) -> None:
        assert ClassificationLevel.INTERNAL > ClassificationLevel.PUBLIC


# ---------------------------------------------------------------------------
# TestClassifyMessagesNoPatterns
# ---------------------------------------------------------------------------

class TestClassifyMessagesBasics:
    """classify_messages with no sensitive data returns PUBLIC."""

    def test_empty_messages(self) -> None:
        result = classify_messages([])
        assert result.level == ClassificationLevel.PUBLIC
        assert result.pattern_types == []

    def test_safe_content(self) -> None:
        msgs = [{"role": "user", "content": "What is CVE-2024-1234?"}]
        result = classify_messages(msgs)
        # CVE-2024-1234 matches cve_id pattern but at PUBLIC level
        assert result.level == ClassificationLevel.PUBLIC

    def test_no_content_key(self) -> None:
        msgs = [{"role": "system"}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.PUBLIC

    def test_none_content(self) -> None:
        msgs = [{"role": "user", "content": None}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.PUBLIC

    def test_list_content(self) -> None:
        """Non-string content (multimodal) is skipped gracefully."""
        msgs = [{"role": "user", "content": [{"type": "text", "text": "10.0.0.1"}]}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.PUBLIC


# ---------------------------------------------------------------------------
# TestRFC1918Detection
# ---------------------------------------------------------------------------

class TestRFC1918Detection:
    """RFC1918 private IPs are classified as RESTRICTED."""

    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.255",
        "192.168.1.1",
        "192.168.0.100",
        "172.16.0.1",
        "172.31.255.255",
    ])
    def test_rfc1918_ips_are_restricted(self, ip: str) -> None:
        msgs = [{"role": "user", "content": f"Check host {ip}"}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.RESTRICTED
        assert "rfc1918_ip" in result.pattern_types


# ---------------------------------------------------------------------------
# TestPublicIPDetection
# ---------------------------------------------------------------------------

class TestPublicIPDetection:
    """Public IPv4 addresses are classified as INTERNAL."""

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "203.0.113.1",
        "44.235.100.50",
    ])
    def test_public_ips_are_internal(self, ip: str) -> None:
        msgs = [{"role": "user", "content": f"Scan {ip} for vulns"}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.INTERNAL
        assert "public_ip" in result.pattern_types


# ---------------------------------------------------------------------------
# TestFQDNDetection
# ---------------------------------------------------------------------------

class TestFQDNDetection:
    """FQDNs (host.domain.tld) are classified as INTERNAL."""

    @pytest.mark.parametrize("fqdn", [
        "db.internal.corp",
        "web01.prod.example.com",
        "mail.company.org",
    ])
    def test_fqdns_are_internal(self, fqdn: str) -> None:
        msgs = [{"role": "user", "content": f"Connect to {fqdn}"}]
        result = classify_messages(msgs)
        assert result.level >= ClassificationLevel.INTERNAL
        assert "fqdn" in result.pattern_types

    @pytest.mark.parametrize("not_fqdn", [
        "file.tar.gz",
        "model.json",
        "v2.0.0",
        "config.yaml",
        "data.csv",
        "script.py",
        "readme.md",
        "archive.zip",
    ])
    def test_file_extensions_not_fqdn(self, not_fqdn: str) -> None:
        """File extensions and version patterns do NOT match as FQDNs."""
        msgs = [{"role": "user", "content": f"Open {not_fqdn}"}]
        result = classify_messages(msgs)
        assert "fqdn" not in result.pattern_types


# ---------------------------------------------------------------------------
# TestSSHKeyDetection
# ---------------------------------------------------------------------------

class TestSSHKeyDetection:
    """SSH key headers are classified as RESTRICTED."""

    @pytest.mark.parametrize("header", [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ED25519 PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ])
    def test_ssh_keys_are_restricted(self, header: str) -> None:
        msgs = [{"role": "user", "content": f"Here is my key:\n{header}\nMIIE..."}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.RESTRICTED
        assert "ssh_key" in result.pattern_types


# ---------------------------------------------------------------------------
# TestCredentialDetection
# ---------------------------------------------------------------------------

class TestCredentialDetection:
    """Credential patterns are classified as RESTRICTED."""

    @pytest.mark.parametrize("cred", [
        "password=secret123",
        "api_key=abc-def-ghi",
        "token=eyJhbGciOi...",
        "secret: mysecretvalue",
        "access_key=AKIAIOSFODNN7EXAMPLE",
        "PASSWORD=Admin123!",
    ])
    def test_credentials_are_restricted(self, cred: str) -> None:
        msgs = [{"role": "user", "content": f"Use {cred} for auth"}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.RESTRICTED
        assert "credential" in result.pattern_types


# ---------------------------------------------------------------------------
# TestCVEExclusion
# ---------------------------------------------------------------------------

class TestCVEExclusion:
    """CVE IDs alone do not escalate classification."""

    def test_cve_alone_is_public(self) -> None:
        msgs = [{"role": "user", "content": "Tell me about CVE-2024-1234"}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.PUBLIC
        assert "cve_id" in result.pattern_types

    def test_cve_with_ip_is_restricted(self) -> None:
        """CVE + RFC1918 IP -> RESTRICTED (IP drives classification)."""
        msgs = [{"role": "user", "content": "CVE-2024-1234 on 10.0.0.1"}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.RESTRICTED
        assert "cve_id" in result.pattern_types
        assert "rfc1918_ip" in result.pattern_types


# ---------------------------------------------------------------------------
# TestEPSSCVSSExclusion
# ---------------------------------------------------------------------------

class TestEPSSCVSSExclusion:
    """EPSS and CVSS scores alone do not escalate classification."""

    @pytest.mark.parametrize("content", [
        "EPSS score is 0.97",
        "EPSS: 0.001",
        "CVSS 9.8",
        "CVSS score: 7.5",
        "The EPSS is 0.45 and CVSS is 8.1",
    ])
    def test_scores_alone_are_public(self, content: str) -> None:
        msgs = [{"role": "user", "content": content}]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.PUBLIC


# ---------------------------------------------------------------------------
# TestFullMessageScan
# ---------------------------------------------------------------------------

class TestFullMessageScan:
    """classify_messages scans all messages (system + user + assistant)."""

    def test_scans_system_message(self) -> None:
        msgs = [
            {"role": "system", "content": "System config at 10.0.0.1"},
            {"role": "user", "content": "Hello"},
        ]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.RESTRICTED

    def test_scans_assistant_message(self) -> None:
        msgs = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "I found key: password=leaked"},
        ]
        result = classify_messages(msgs)
        assert result.level == ClassificationLevel.RESTRICTED

    def test_scans_all_messages_not_just_last(self) -> None:
        msgs = [
            {"role": "system", "content": "Connect to db.internal.corp"},
            {"role": "user", "content": "What is the time?"},
            {"role": "assistant", "content": "It is noon."},
        ]
        result = classify_messages(msgs)
        assert result.level >= ClassificationLevel.INTERNAL


# ---------------------------------------------------------------------------
# TestClassifyStep
# ---------------------------------------------------------------------------

class TestClassifyStep:
    """classify_step writes ctx and handles behaviors."""

    @pytest.mark.asyncio
    async def test_public_prompt_sets_ctx(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry()
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "What is CVE-2024-1234?"}]
        await step(ctx, msgs, routing)
        assert ctx["classification"] == "PUBLIC"

    @pytest.mark.asyncio
    async def test_restricted_prompt_sets_ctx(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry()
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}]
        # Default behavior is fail -> raises
        with pytest.raises(ClassificationBlockedError):
            await step(ctx, msgs, routing)
        assert ctx["classification"] == "RESTRICTED"


# ---------------------------------------------------------------------------
# TestRestrictedFailClosed
# ---------------------------------------------------------------------------

class TestRestrictedFailClosed:
    """RESTRICTED + fail-closed raises ClassificationBlockedError."""

    @pytest.mark.asyncio
    async def test_fail_closed_raises(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry()
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "password=secret123 on 10.0.0.1"}]
        with pytest.raises(ClassificationBlockedError) as exc_info:
            await step(ctx, msgs, routing)
        err = exc_info.value
        assert "RESTRICTED" in str(err)
        assert "credential" in str(err) or "rfc1918_ip" in str(err)
        assert "redact" in str(err)  # hint about config

    @pytest.mark.asyncio
    async def test_fail_closed_explicit_config(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry({
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "fail",
        })
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "10.0.0.1"}]
        with pytest.raises(ClassificationBlockedError):
            await step(ctx, msgs, routing)


# ---------------------------------------------------------------------------
# TestRedaction
# ---------------------------------------------------------------------------

class TestRedaction:
    """RESTRICTED + redact replaces tokens with [REDACTED-*] tags."""

    @pytest.mark.asyncio
    async def test_redact_ips(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry({
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "redact",
        })
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "Check 10.0.0.1 and 192.168.1.1"}]
        await step(ctx, msgs, routing)
        assert "[REDACTED-IP]" in msgs[0]["content"]
        assert "10.0.0.1" not in msgs[0]["content"]
        assert "192.168.1.1" not in msgs[0]["content"]

    @pytest.mark.asyncio
    async def test_redact_ssh_key(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry({
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "redact",
        })
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "Key: -----BEGIN RSA PRIVATE KEY-----"}]
        await step(ctx, msgs, routing)
        assert "[REDACTED-KEY]" in msgs[0]["content"]

    @pytest.mark.asyncio
    async def test_redact_credential(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry({
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "redact",
        })
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "Use password=secret123 to connect"}]
        await step(ctx, msgs, routing)
        assert "[REDACTED-CRED]" in msgs[0]["content"]
        assert "secret123" not in msgs[0]["content"]

    @pytest.mark.asyncio
    async def test_redact_sets_ctx(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        """Redaction sets ctx['redacted']=True and ctx['redacted_count']=N."""
        registry = FakeRegistry({
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "redact",
        })
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "10.0.0.1 and password=secret123"}]
        await step(ctx, msgs, routing)
        assert ctx["redacted"] is True
        assert ctx["redacted_count"] >= 2  # at least 2 replacements


# ---------------------------------------------------------------------------
# TestAuditEvent
# ---------------------------------------------------------------------------

class TestAuditEvent:
    """Classification audit event emission."""

    @pytest.mark.asyncio
    async def test_event_emitted(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry()
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "Hello world"}]
        await step(ctx, msgs, routing)
        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.stage == "llm_classification"
        assert event.action == "classify"
        assert "scoring" in event.key
        assert event.details["classification_level"] == "PUBLIC"
        assert event.details["task_type"] == "scoring"
        assert event.details["model_id"] == "test-model"
        assert event.details["provider"] == "http://test"
        assert event.details["pattern_types_triggered"] == []
        assert event.details["redacted"] is False

    @pytest.mark.asyncio
    async def test_event_with_patterns(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        registry = FakeRegistry({
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "redact",
        })
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "Check 10.0.0.1"}]
        await step(ctx, msgs, routing)
        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.details["classification_level"] == "RESTRICTED"
        assert "rfc1918_ip" in event.details["pattern_types_triggered"]
        assert event.details["redacted"] is True

    @pytest.mark.asyncio
    async def test_event_no_prompt_content(self, routing: LLMRouting, emitter: FakeEmitter) -> None:
        """Audit event details must NOT contain prompt content or matched values."""
        registry = FakeRegistry({
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "redact",
        })
        step = make_classify_step(registry=registry, emitter=emitter)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "password=supersecret123 on 10.0.0.1"}]
        await step(ctx, msgs, routing)
        event = emitter.events[0]
        details_str = str(event.details)
        assert "supersecret123" not in details_str
        assert "10.0.0.1" not in details_str
        assert "password" not in details_str or "pattern_types" in details_str

    @pytest.mark.asyncio
    async def test_no_emitter_no_crash(self, routing: LLMRouting) -> None:
        """If emitter is None, classify_step still works."""
        registry = FakeRegistry()
        step = make_classify_step(registry=registry, emitter=None)  # type: ignore[arg-type]
        ctx: dict[str, Any] = {"task_type": "scoring"}
        msgs = [{"role": "user", "content": "Hello world"}]
        await step(ctx, msgs, routing)
        assert ctx["classification"] == "PUBLIC"


# ---------------------------------------------------------------------------
# TestClassificationBlockedError
# ---------------------------------------------------------------------------

class TestClassificationBlockedError:
    """ClassificationBlockedError is an LLMError subclass."""

    def test_is_llm_error_subclass(self) -> None:
        err = ClassificationBlockedError("test")
        assert isinstance(err, LLMError)

    def test_not_retryable(self) -> None:
        err = ClassificationBlockedError("test")
        assert err.retryable is False

    def test_message_preserved(self) -> None:
        err = ClassificationBlockedError("blocked for reason X")
        assert err.message == "blocked for reason X"


# ---------------------------------------------------------------------------
# TestPipelineReRaise
# ---------------------------------------------------------------------------

class TestPipelineReRaise:
    """Pipeline _run_step always re-raises ClassificationBlockedError."""

    @pytest.mark.asyncio
    async def test_classification_blocked_always_propagates(self, routing: LLMRouting) -> None:
        """Even in fail-open mode, ClassificationBlockedError is re-raised."""
        provider = LLMConfigProvider(
            registry=FakeRegistry({"platform.llm_default_model": "test-model"}),  # type: ignore[arg-type]
            secret_store=FakeSecretStore({"openai_api_key": "sk-test"}),  # type: ignore[arg-type]
        )
        runner = PipelineRunner(config_provider=provider)

        async def blocking_step(
            ctx: dict[str, Any],
            messages: list[dict[str, Any]],
            r: LLMRouting,
        ) -> None:
            raise ClassificationBlockedError("RESTRICTED data detected")

        runner.register("classify", blocking_step)
        call_fn = AsyncMock(return_value=MagicMock(content="should-not-reach"))

        with pytest.raises(ClassificationBlockedError, match="RESTRICTED data detected"):
            await runner.run(
                task_type="scoring",
                messages=[],
                routing=routing,
                call_fn=call_fn,
                call_kwargs={},
            )

        call_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_classification_error_swallowed_in_fail_open(self, routing: LLMRouting) -> None:
        """Non-ClassificationBlockedError is swallowed when the step is fail-open.

        Per fix \u00a7156, ``classify`` is in ``_SECURITY_CRITICAL_STEPS`` and defaults
        to fail-closed. To exercise the fail-open behavior an operator would opt into,
        we set ``llm_pipeline_classify_fail_mode_scoring=open`` explicitly here.
        """
        provider = LLMConfigProvider(
            registry=FakeRegistry({
                "platform.llm_default_model": "test-model",
                "platform.llm_pipeline_classify_fail_mode_scoring": "open",
            }),  # type: ignore[arg-type]
            secret_store=FakeSecretStore({"openai_api_key": "sk-test"}),  # type: ignore[arg-type]
        )
        runner = PipelineRunner(config_provider=provider)

        async def buggy_step(
            ctx: dict[str, Any],
            messages: list[dict[str, Any]],
            r: LLMRouting,
        ) -> None:
            raise RuntimeError("unexpected bug")

        runner.register("classify", buggy_step)
        call_fn = AsyncMock(return_value=MagicMock(content="survived"))

        response, ctx = await runner.run(
            task_type="scoring",
            messages=[],
            routing=routing,
            call_fn=call_fn,
            call_kwargs={},
        )

        call_fn.assert_called_once()
        assert response.content == "survived"


# ---------------------------------------------------------------------------
# TestRegisterPattern
# ---------------------------------------------------------------------------

class TestRegisterPattern:
    """register_pattern adds new patterns that classify_messages detects."""

    def test_register_custom_pattern(self) -> None:
        initial_count = len(_PATTERNS)
        register_pattern(
            name="test_custom",
            regex=r"\bTEST-SECRET-\d+\b",
            level=ClassificationLevel.RESTRICTED,
            redact_tag="[REDACTED-TEST]",
        )
        try:
            assert len(_PATTERNS) == initial_count + 1
            msgs = [{"role": "user", "content": "Use TEST-SECRET-42 for auth"}]
            result = classify_messages(msgs)
            assert result.level == ClassificationLevel.RESTRICTED
            assert "test_custom" in result.pattern_types
        finally:
            # Clean up -- remove the test pattern to avoid polluting other tests
            _PATTERNS.pop()


# ---------------------------------------------------------------------------
# Mock helper (same pattern as test_pipeline.py)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# TestClassifyPipelineIntegration
# ---------------------------------------------------------------------------

class TestClassifyPipelineIntegration:
    """End-to-end: classify step registered on AilaLLMClient.

    These tests verify the classify step works through the real AilaLLMClient
    with a mocked AsyncOpenAI backend. Covers PUBLIC, INTERNAL, RESTRICTED
    paths including fail-closed block, redact-and-send, and disabled config.
    """

    @pytest.fixture()
    def client_with_classify(self) -> AilaLLMClient:
        """AilaLLMClient with classify step registered (default config)."""
        registry = FakeRegistry({
            "platform.llm_default_model": "test-model",
        })
        secret_store = FakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )
        step = make_classify_step(registry=registry, emitter=None)  # type: ignore[arg-type]
        client.pipeline.register("classify", step)
        return client

    @pytest.mark.asyncio
    async def test_public_prompt_classified(self, client_with_classify: AilaLLMClient) -> None:
        """Prompt with only CVE IDs -> classification=PUBLIC."""
        mock_completion = _make_completion(content="CVE analysis result")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

            response = await client_with_classify.chat(
                "scoring",
                [{"role": "user", "content": "Tell me about CVE-2024-1234"}],
            )

        assert response.classification == "PUBLIC"
        assert response.content == "CVE analysis result"

    @pytest.mark.asyncio
    async def test_internal_prompt_classified(self, client_with_classify: AilaLLMClient) -> None:
        """Prompt with public IP -> classification=INTERNAL."""
        mock_completion = _make_completion(content="IP scan result")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

            response = await client_with_classify.chat(
                "scoring",
                [{"role": "user", "content": "Check 8.8.8.8 for vulnerabilities"}],
            )

        assert response.classification == "INTERNAL"
        assert response.content == "IP scan result"

    @pytest.mark.asyncio
    async def test_restricted_prompt_fails_closed(self) -> None:
        """Prompt with RFC1918 IP + default fail behavior -> ClassificationBlockedError."""
        registry = FakeRegistry({
            "platform.llm_default_model": "test-model",
        })
        secret_store = FakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )
        step = make_classify_step(registry=registry, emitter=None)  # type: ignore[arg-type]
        client.pipeline.register("classify", step)

        with pytest.raises(ClassificationBlockedError, match="RESTRICTED"):
            await client.chat(
                "scoring",
                [{"role": "user", "content": "SSH to 10.0.0.1"}],
            )

    @pytest.mark.asyncio
    async def test_restricted_prompt_redacts(self) -> None:
        """Prompt with RFC1918 IP + redact behavior -> classification=RESTRICTED, content sent."""
        registry = FakeRegistry({
            "platform.llm_default_model": "test-model",
            "platform.llm_pipeline_classify_restricted_behavior_scoring": "redact",
        })
        secret_store = FakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )
        step = make_classify_step(registry=registry, emitter=None)  # type: ignore[arg-type]
        client.pipeline.register("classify", step)

        mock_completion = _make_completion(content="Redacted analysis")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "SSH to 10.0.0.1"}],
            )

        assert response.classification == "RESTRICTED"
        assert response.content == "Redacted analysis"

        # Verify the messages passed to AsyncOpenAI had the IP redacted
        create_call = mock_instance.chat.completions.create
        call_kwargs = create_call.call_args[1] if create_call.call_args[1] else {}
        # Messages are passed via call_kwargs from _single_call
        messages_sent = call_kwargs.get("messages", [])
        for msg in messages_sent:
            content = msg.get("content", "")
            if isinstance(content, str):
                assert "10.0.0.1" not in content, "RFC1918 IP should have been redacted"

    @pytest.mark.asyncio
    async def test_classify_disabled_skips(self) -> None:
        """Classify step disabled via config -> classification=None (not set)."""
        registry = FakeRegistry({
            "platform.llm_default_model": "test-model",
            "platform.llm_pipeline_classify_scoring": "false",
        })
        secret_store = FakeSecretStore({"openai_api_key": "sk-test"})
        client = AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )
        step = make_classify_step(registry=registry, emitter=None)  # type: ignore[arg-type]
        client.pipeline.register("classify", step)

        mock_completion = _make_completion(content="Unclassified response")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "SSH to 10.0.0.1"}],
            )

        assert response.classification is None
        assert response.content == "Unclassified response"

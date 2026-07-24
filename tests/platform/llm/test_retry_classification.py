"""Retry-classification tests for ``AilaLLMClient._call_with_retry`` (#44).

Two surfaces are exercised in isolation:

* ``_is_retryable(exc)`` -- the pure classification predicate. Called by
  the bare ``except Exception`` branch to decide whether a provider
  failure keeps the retry+backoff behaviour or aborts immediately.
* ``AilaLLMClient._call_with_retry`` -- the retry loop itself, driven by
  a fake pipeline. Non-retryable exceptions must abort on the first
  attempt; retryable exceptions must exhaust ``_MAX_RETRIES``.

No network, no provider, no ConfigRegistry, no SecretStore. The client
instance is constructed with ``__new__`` and required attributes are
stubbed in-place; ``asyncio.sleep`` is monkeypatched to a no-op so the
retryable-path test runs at CPU speed rather than backoff speed.
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest
from openai import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    UnprocessableEntityError,
)

from aila.platform.llm import client as client_mod
from aila.platform.llm.cancellation import (
    LLMCancelledError,
    cancel_for_investigation,
    clear_for_investigation,
    get_cancellation_token,
)
from aila.platform.llm.client import AilaLLMClient, _AsyncOpenAIPool, _is_retryable
from aila.platform.llm.errors import LLMError

# --------------------------------------------------------------------
# openai exception construction helpers
# --------------------------------------------------------------------
#
# The openai SDK exception constructors require a ``response`` object and
# a ``body`` argument. Build the minimum viable ``httpx.Response`` per
# call so the tests never rely on incidental defaults from the SDK.


def _make_openai_response(status_code: int) -> httpx.Response:
    request = httpx.Request("POST", "http://localhost/v1/chat/completions")
    return httpx.Response(status_code=status_code, request=request)


def _make_api_status_exc(exc_cls: type, status_code: int) -> Exception:
    return exc_cls(
        message=f"synthetic status {status_code}",
        response=_make_openai_response(status_code),
        body=None,
    )


def _make_api_connection_error() -> APIConnectionError:
    request = httpx.Request("POST", "http://localhost/v1/chat/completions")
    return APIConnectionError(request=request)


def _make_api_timeout_error() -> APITimeoutError:
    request = httpx.Request("POST", "http://localhost/v1/chat/completions")
    return APITimeoutError(request=request)


def _make_rate_limit_error() -> RateLimitError:
    return _make_api_status_exc(RateLimitError, 429)


def _make_internal_server_error() -> InternalServerError:
    return _make_api_status_exc(InternalServerError, 500)


class _AnyStatusError(Exception):
    """Provider-agnostic exception carrying an HTTP-shaped ``status_code``.

    Third-party provider SDKs (Anthropic, Vertex, self-hosted OpenAI
    proxies) may raise their own exception classes with a status_code
    attribute. The classifier MUST fall back to the attribute rather
    than only recognising the openai-specific subclasses.
    """

    def __init__(self, status_code: int, message: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code


# --------------------------------------------------------------------
# _is_retryable -- pure classification predicate
# --------------------------------------------------------------------


class TestIsRetryable:
    """Direct tests against the pure ``_is_retryable(exc)`` helper."""

    def test_llm_error_retryable_true(self) -> None:
        assert _is_retryable(LLMError("boom", retryable=True)) is True

    def test_llm_error_retryable_false(self) -> None:
        assert _is_retryable(LLMError("blocked", retryable=False)) is False

    @pytest.mark.parametrize(
        "exc_factory",
        [
            _make_api_connection_error,
            _make_api_timeout_error,
            _make_rate_limit_error,
            _make_internal_server_error,
        ],
        ids=["APIConnectionError", "APITimeoutError", "RateLimitError", "InternalServerError"],
    )
    def test_transient_provider_exceptions_are_retryable(
        self, exc_factory: Any,
    ) -> None:
        assert _is_retryable(exc_factory()) is True

    @pytest.mark.parametrize(
        ("exc_cls", "status_code"),
        [
            (AuthenticationError, 401),
            (PermissionDeniedError, 403),
            (BadRequestError, 400),
            (NotFoundError, 404),
            (UnprocessableEntityError, 422),
        ],
    )
    def test_openai_4xx_auth_and_malformed_are_not_retryable(
        self, exc_cls: type, status_code: int,
    ) -> None:
        exc = _make_api_status_exc(exc_cls, status_code)
        assert _is_retryable(exc) is False

    @pytest.mark.parametrize("status_code", [500, 502, 503, 504])
    def test_provider_agnostic_5xx_is_retryable(self, status_code: int) -> None:
        exc = _AnyStatusError(status_code)
        assert _is_retryable(exc) is True

    @pytest.mark.parametrize("status_code", [408, 425, 429])
    def test_provider_agnostic_retryable_4xx_is_retryable(
        self, status_code: int,
    ) -> None:
        exc = _AnyStatusError(status_code)
        assert _is_retryable(exc) is True

    @pytest.mark.parametrize("status_code", [400, 401, 403, 404, 405, 422])
    def test_provider_agnostic_4xx_is_not_retryable(
        self, status_code: int,
    ) -> None:
        exc = _AnyStatusError(status_code)
        assert _is_retryable(exc) is False

    def test_unknown_exception_defaults_to_retryable(self) -> None:
        # A vanilla RuntimeError with no status_code preserves the
        # historical "retry everything" behaviour so an unfamiliar
        # transient failure is not silently regressed.
        assert _is_retryable(RuntimeError("mystery")) is True

    def test_status_code_none_defaults_to_retryable(self) -> None:
        exc = _AnyStatusError(0)
        exc.status_code = None  # type: ignore[assignment]
        assert _is_retryable(exc) is True

    def test_status_code_non_int_ignored(self) -> None:
        # Some libraries put string status codes on their exceptions.
        # The classifier must not mis-classify by comparing str < int
        # (which would raise TypeError). It should just default.
        exc = _AnyStatusError(0)
        exc.status_code = "401"  # type: ignore[assignment]
        assert _is_retryable(exc) is True


# --------------------------------------------------------------------
# _call_with_retry -- loop-level driven by a counting fake pipeline
# --------------------------------------------------------------------


class _CountingPipeline:
    """Fake ``PipelineRunner`` whose ``run`` raises a preset exception.

    Records the number of times ``run`` is entered so the test can
    assert either "called exactly once" (non-retryable fail-fast) or
    "called exactly ``_MAX_RETRIES`` times" (retryable path).
    """

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc
        self.calls = 0

    async def run(self, **_kwargs: Any) -> Any:
        self.calls += 1
        raise self.exc


class _FakeRouting:
    """Minimum-shape routing object consumed by ``_call_with_retry``."""

    def __init__(self) -> None:
        self.task_type = "test"
        self.model_id = "test/model"
        self.api_key = "test-key"
        self.base_url = "http://localhost:1/v1"
        self.max_tokens = 100


def _make_stub_client(pipeline: _CountingPipeline) -> AilaLLMClient:
    """Build an ``AilaLLMClient`` without touching ConfigRegistry or SecretStore.

    ``AilaLLMClient.__init__`` requires a live registry + secret_store.
    The retry loop only touches ``self._pipeline`` and ``self.cost_tracker``
    once ``check_budget_async`` is skipped (cost_tracker=None). Bypassing
    ``__init__`` is the least-invasive way to test the loop in isolation.
    """
    client = AilaLLMClient.__new__(AilaLLMClient)
    client._pipeline = pipeline  # type: ignore[attr-defined]
    client.cost_tracker = None
    client.bus = None
    # __init__ is bypassed here, so the pool that _call_with_retry reads must
    # be stubbed in explicitly (added with the AsyncOpenAI pool in #44).
    client._client_pool = _AsyncOpenAIPool()  # type: ignore[attr-defined]
    return client


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip the backoff sleeps so retry-path tests run at CPU speed."""

    async def _instant_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(client_mod.asyncio, "sleep", _instant_sleep)


class TestCallWithRetryLoop:
    """Loop-level behaviour of ``AilaLLMClient._call_with_retry``.

    The fake pipeline drives the retry loop by raising a preset
    exception on every call; assertions check the call counter and the
    raised exception's ``retryable`` flag.
    """

    @pytest.mark.asyncio
    async def test_non_retryable_auth_error_fails_fast_after_one_call(
        self, no_sleep: None,
    ) -> None:
        """A 401 AuthenticationError must NOT enter the retry loop.

        Regression: prior behaviour caught auth failures in the bare
        ``except Exception`` branch and slept up to _MAX_RETRIES * base
        seconds before surfacing the wrapped LLMError. That burned the
        worker slot on a request the provider will never accept.
        """
        exc = _make_api_status_exc(AuthenticationError, 401)
        pipeline = _CountingPipeline(exc)
        client = _make_stub_client(pipeline)

        with pytest.raises(LLMError) as exc_info:
            await client._call_with_retry(
                routing=_FakeRouting(),
                messages=[{"role": "user", "content": "hello"}],
                response_format=None,
                tools=None,
                tool_executor=None,
                run_id=None,
                team_id=None,
            )

        assert pipeline.calls == 1, (
            f"non-retryable error must abort on first attempt, saw "
            f"{pipeline.calls} calls"
        )
        assert exc_info.value.retryable is False
        assert "AuthenticationError" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_non_retryable_bad_request_fails_fast(
        self, no_sleep: None,
    ) -> None:
        exc = _make_api_status_exc(BadRequestError, 400)
        pipeline = _CountingPipeline(exc)
        client = _make_stub_client(pipeline)

        with pytest.raises(LLMError) as exc_info:
            await client._call_with_retry(
                routing=_FakeRouting(),
                messages=[{"role": "user", "content": "hello"}],
                response_format=None,
                tools=None,
                tool_executor=None,
            )

        assert pipeline.calls == 1
        assert exc_info.value.retryable is False

    @pytest.mark.asyncio
    async def test_retryable_provider_agnostic_503_exhausts_max_retries(
        self, no_sleep: None,
    ) -> None:
        """A 503 status_code from an unfamiliar provider class keeps retrying.

        Exercises the ``_AnyStatusError`` branch that flows through the
        classifier's ``500 <= status_code < 600`` path -- the openai
        transport-level classes are covered by other tests.
        """
        pipeline = _CountingPipeline(_AnyStatusError(503, "upstream down"))
        client = _make_stub_client(pipeline)

        with pytest.raises(LLMError) as exc_info:
            await client._call_with_retry(
                routing=_FakeRouting(),
                messages=[{"role": "user", "content": "hello"}],
                response_format=None,
                tools=None,
                tool_executor=None,
            )

        assert pipeline.calls == client_mod._MAX_RETRIES, (
            f"retryable error must exhaust _MAX_RETRIES={client_mod._MAX_RETRIES}, "
            f"saw {pipeline.calls} calls"
        )
        # Final wrap is the retryable "API failed after N retries" LLMError,
        # not the non-retryable fail-fast wrap.
        assert exc_info.value.retryable is True
        assert "after" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_retryable_api_connection_error_exhausts_max_retries(
        self, no_sleep: None,
    ) -> None:
        # APIConnectionError is caught by its own dedicated branch, not
        # the bare Exception classifier. This test locks in that the
        # dedicated branch keeps retrying (regression coverage for the
        # branch ordering after the classifier was inserted).
        pipeline = _CountingPipeline(_make_api_connection_error())
        client = _make_stub_client(pipeline)

        with pytest.raises(LLMError):
            await client._call_with_retry(
                routing=_FakeRouting(),
                messages=[{"role": "user", "content": "hello"}],
                response_format=None,
                tools=None,
                tool_executor=None,
            )

        assert pipeline.calls == client_mod._MAX_RETRIES

    @pytest.mark.asyncio
    async def test_non_retryable_llm_error_bypasses_retry(
        self, no_sleep: None,
    ) -> None:
        """LLMError(retryable=False) is caught by the LLMError branch and re-raised.

        This behaviour predates issue #44 -- the test locks it in so a
        future refactor of the classifier does not accidentally start
        wrapping ClassificationBlockedError et al.
        """
        exc = LLMError("classification blocked", retryable=False)
        pipeline = _CountingPipeline(exc)
        client = _make_stub_client(pipeline)

        with pytest.raises(LLMError) as exc_info:
            await client._call_with_retry(
                routing=_FakeRouting(),
                messages=[{"role": "user", "content": "hi"}],
                response_format=None,
                tools=None,
                tool_executor=None,
            )

        assert pipeline.calls == 1
        assert exc_info.value.retryable is False
        # The original LLMError propagates unchanged -- no fail-fast wrap.
        assert exc_info.value is exc


class _CancelOnFirstCallPipeline:
    """Fake pipeline that cancels a run's token, then raises a retryable error.

    Simulates a pause landing WHILE the provider call on attempt 1 is in
    flight: attempt 1 raises a retryable error and flips the token; the
    retry loop's pre-attempt cancellation check on attempt 2 must then
    abort with ``LLMCancelledError`` before entering the pipeline again.
    """

    def __init__(self, run_id: str) -> None:
        self._run_id = run_id
        self.calls = 0

    async def run(self, **_kwargs: Any) -> Any:
        self.calls += 1
        cancel_for_investigation(self._run_id)
        raise _AnyStatusError(503, "upstream down")


class TestCallWithRetryCancellation:
    """#44: the retry loop aborts promptly when the run's token is cancelled.

    The cancellation token is process-local and keyed on ``run_id``
    (== investigation_id for investigation turns). The loop peeks it
    before every attempt via ``is_run_cancelled`` (a no-create peek), so a
    pause during a long provider backoff aborts within one attempt instead
    of waiting out the whole retry schedule.
    """

    @pytest.fixture(autouse=True)
    def _clean_registry(self) -> Any:
        # Each test owns a unique run_id, but clear defensively so a token
        # left by one test never leaks a cancelled state into another.
        yield
        clear_for_investigation("inv-cancel-preempt")
        clear_for_investigation("inv-cancel-midretry")
        clear_for_investigation("inv-no-token")

    @pytest.mark.asyncio
    async def test_already_cancelled_token_aborts_before_first_call(
        self, no_sleep: None,
    ) -> None:
        """A token cancelled before the call raises without touching the pipeline."""
        run_id = "inv-cancel-preempt"
        get_cancellation_token(run_id).cancel()
        pipeline = _CountingPipeline(_AnyStatusError(503, "unused"))
        client = _make_stub_client(pipeline)

        with pytest.raises(LLMCancelledError) as exc_info:
            await client._call_with_retry(
                routing=_FakeRouting(),
                messages=[{"role": "user", "content": "hello"}],
                response_format=None,
                tools=None,
                tool_executor=None,
                run_id=run_id,
                team_id=None,
            )

        assert pipeline.calls == 0, (
            "a cancelled token must abort before the pipeline is entered, "
            f"saw {pipeline.calls} calls"
        )
        assert run_id in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_cancel_mid_retry_aborts_on_next_attempt(
        self, no_sleep: None,
    ) -> None:
        """A pause during attempt 1's backoff aborts attempt 2, not the full schedule."""
        run_id = "inv-cancel-midretry"
        # Token exists (created at the turn-boundary check) but is not
        # cancelled yet -- the pipeline flips it on the first call.
        get_cancellation_token(run_id)
        pipeline = _CancelOnFirstCallPipeline(run_id)
        client = _make_stub_client(pipeline)

        with pytest.raises(LLMCancelledError):
            await client._call_with_retry(
                routing=_FakeRouting(),
                messages=[{"role": "user", "content": "hello"}],
                response_format=None,
                tools=None,
                tool_executor=None,
                run_id=run_id,
                team_id=None,
            )

        assert pipeline.calls == 1, (
            "the loop must enter the pipeline exactly once (attempt 1), then "
            f"abort on the cancelled token before attempt 2, saw {pipeline.calls}"
        )

    @pytest.mark.asyncio
    async def test_run_id_without_token_is_not_pre_aborted(
        self, no_sleep: None,
    ) -> None:
        """A run_id with no token in the registry never triggers a cancel abort.

        Non-investigation calls pass a run_id that has no token; the
        no-create peek must return False and let the loop run normally
        (here: enter the pipeline and surface the provider error).
        """
        run_id = "inv-no-token"
        exc = _make_api_status_exc(BadRequestError, 400)
        pipeline = _CountingPipeline(exc)
        client = _make_stub_client(pipeline)

        with pytest.raises(LLMError) as exc_info:
            await client._call_with_retry(
                routing=_FakeRouting(),
                messages=[{"role": "user", "content": "hello"}],
                response_format=None,
                tools=None,
                tool_executor=None,
                run_id=run_id,
                team_id=None,
            )

        assert pipeline.calls == 1, (
            "no token means no pre-abort -- the pipeline must be entered"
        )
        assert not isinstance(exc_info.value, LLMCancelledError)


# --------------------------------------------------------------------
# asyncio marker registration
# --------------------------------------------------------------------
#
# The repo's pytest-asyncio config is discovered via pyproject.toml.
# Marking every coroutine test with @pytest.mark.asyncio matches the
# other tests under tests/platform/llm/.

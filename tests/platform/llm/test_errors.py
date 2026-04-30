"""Unit tests for aila.platform.llm.errors."""

from __future__ import annotations

import pytest

from aila.platform.llm.errors import (
    BudgetExceededError,
    LLMDisabledError,
    LLMError,
    LLMTransientError,
)


class TestLLMError:
    """LLMError base exception."""

    def test_message_stored(self) -> None:
        err = LLMError("something broke")
        assert err.message == "something broke"
        assert str(err) == "something broke"

    def test_retryable_default_false(self) -> None:
        err = LLMError("fail")
        assert err.retryable is False

    def test_retryable_explicit_true(self) -> None:
        err = LLMError("timeout", retryable=True)
        assert err.retryable is True

    def test_is_exception(self) -> None:
        with pytest.raises(LLMError):
            raise LLMError("test")


class TestLLMDisabledError:
    """LLMDisabledError kill-switch error."""

    def test_inherits_llm_error(self) -> None:
        err = LLMDisabledError()
        assert isinstance(err, LLMError)

    def test_message(self) -> None:
        err = LLMDisabledError()
        assert err.message == "LLM disabled by operator"
        assert str(err) == "LLM disabled by operator"

    def test_not_retryable(self) -> None:
        err = LLMDisabledError()
        assert err.retryable is False

    def test_raises_as_llm_error(self) -> None:
        with pytest.raises(LLMError, match="disabled by operator"):
            raise LLMDisabledError()


class TestBudgetExceededError:
    """BudgetExceededError -- budget ceiling exceeded for a scan run."""

    def test_inherits_llm_error(self) -> None:
        err = BudgetExceededError("budget exceeded")
        assert isinstance(err, LLMError)

    def test_message(self) -> None:
        err = BudgetExceededError("budget exceeded for run r1")
        assert err.message == "budget exceeded for run r1"
        assert str(err) == "budget exceeded for run r1"

    def test_not_retryable(self) -> None:
        err = BudgetExceededError("budget exceeded")
        assert err.retryable is False

    def test_raises_as_llm_error(self) -> None:
        with pytest.raises(LLMError, match="budget"):
            raise BudgetExceededError("budget exceeded")


class TestLLMTransientError:
    """LLMTransientError -- retriable provider failures (rate limit, 503, 504)."""

    def test_inherits_llm_error(self) -> None:
        err = LLMTransientError("rate limit")
        assert isinstance(err, LLMError)

    def test_identity(self) -> None:
        err = LLMTransientError("rate limit")
        assert isinstance(err, LLMTransientError)

    def test_retryable_true(self) -> None:
        err = LLMTransientError("rate limit")
        assert err.retryable is True

    def test_default_retry_after_none(self) -> None:
        err = LLMTransientError("rate limit")
        assert err.retry_after_s is None

    def test_retry_after_stored(self) -> None:
        err = LLMTransientError("foo", retry_after_s=5.0)
        assert err.retry_after_s == 5.0

    def test_message_default_empty(self) -> None:
        err = LLMTransientError()
        assert err.message == ""
        assert str(err) == ""

    def test_raises_as_llm_error(self) -> None:
        with pytest.raises(LLMError, match="rate"):
            raise LLMTransientError("rate limited")

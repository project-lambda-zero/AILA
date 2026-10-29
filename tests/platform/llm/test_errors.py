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


class TestLLMDisabledError:
    """LLMDisabledError kill-switch error."""


    def test_not_retryable(self) -> None:
        err = LLMDisabledError()
        assert err.retryable is False

    def test_raises_as_llm_error(self) -> None:
        with pytest.raises(LLMError, match="disabled by operator"):
            raise LLMDisabledError()


class TestBudgetExceededError:
    """BudgetExceededError -- budget ceiling exceeded for a scan run."""


    def test_not_retryable(self) -> None:
        err = BudgetExceededError("budget exceeded")
        assert err.retryable is False

    def test_raises_as_llm_error(self) -> None:
        with pytest.raises(LLMError, match="budget"):
            raise BudgetExceededError("budget exceeded")


class TestLLMTransientError:
    """LLMTransientError -- retriable provider failures (rate limit, 503, 504)."""


    def test_retryable_true(self) -> None:
        err = LLMTransientError("rate limit")
        assert err.retryable is True


    def test_raises_as_llm_error(self) -> None:
        with pytest.raises(LLMError, match="rate"):
            raise LLMTransientError("rate limited")

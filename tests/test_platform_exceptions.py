"""Tests for platform/exceptions.py typed exception hierarchy."""
from __future__ import annotations

import pytest


def test_imports():
    from aila.platform.exceptions import (
        AILAError,
        AuthenticationError,
        NotFoundError,
        RateLimitError,
        ValidationError,
    )
    assert AILAError is not None


def test_aila_error_is_exception():
    from aila.platform.exceptions import AILAError
    assert issubclass(AILAError, Exception)


def test_authentication_error_is_aila_error():
    from aila.platform.exceptions import AILAError, AuthenticationError
    assert issubclass(AuthenticationError, AILAError)


def test_rate_limit_error_is_aila_error():
    from aila.platform.exceptions import AILAError, RateLimitError
    assert issubclass(RateLimitError, AILAError)


def test_not_found_error_is_aila_error():
    from aila.platform.exceptions import AILAError, NotFoundError
    assert issubclass(NotFoundError, AILAError)


def test_validation_error_is_aila_error():
    from aila.platform.exceptions import AILAError, ValidationError
    assert issubclass(ValidationError, AILAError)


def test_catching_aila_error_catches_authentication_error():
    from aila.platform.exceptions import AILAError, AuthenticationError
    with pytest.raises(AILAError):
        raise AuthenticationError("bad creds")


def test_catching_aila_error_catches_rate_limit_error():
    from aila.platform.exceptions import AILAError, RateLimitError
    with pytest.raises(AILAError):
        raise RateLimitError("too fast")


def test_authentication_error_does_not_catch_rate_limit_error():
    from aila.platform.exceptions import AuthenticationError, RateLimitError
    with pytest.raises(RateLimitError):
        try:
            raise RateLimitError("too fast")
        except AuthenticationError:
            pass


def test_rate_limit_error_does_not_catch_authentication_error():
    from aila.platform.exceptions import AuthenticationError, RateLimitError
    with pytest.raises(AuthenticationError):
        try:
            raise AuthenticationError("bad creds")
        except RateLimitError:
            pass


def test_isinstance_check():
    from aila.platform.exceptions import AILAError, AuthenticationError, RateLimitError
    auth_err = AuthenticationError("x")
    rate_err = RateLimitError("x")
    assert isinstance(auth_err, AILAError)
    assert isinstance(rate_err, AILAError)
    assert not isinstance(auth_err, RateLimitError)
    assert not isinstance(rate_err, AuthenticationError)

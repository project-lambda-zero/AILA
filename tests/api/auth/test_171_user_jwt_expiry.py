"""#171 -- user JWT expiry matches the documented design.

Regression coverage for the constants at ``src/aila/api/auth.py``:
``_USER_ACCESS_EXPIRY`` is a 1-hour access-token lifetime and
``_USER_REFRESH_EXPIRY`` is a 7-day refresh-token lifetime. Prior to the
fix both were 31_536_000s (1 year), directly contradicting the docstrings
on ``issue_user_jwt`` (60 minutes) and ``issue_user_refresh_token``
(7 days, per D-14).

This module intentionally covers ONLY the pure/sync issuance path plus
the constants that drive both the returned JWT ``exp`` and the DB-row
``expires_at`` inside ``issue_user_refresh_token``. Endpoint-level
coverage of the same expiry lives in ``tests/api/test_138_01_auth.py``.
"""
from __future__ import annotations

import jwt

from aila.api import auth as auth_module
from aila.api.auth import _USER_ACCESS_EXPIRY, _USER_REFRESH_EXPIRY, issue_user_jwt


def test_user_access_expiry_constant_is_one_hour() -> None:
    """The access-token constant matches the 60-minute documented design."""
    assert _USER_ACCESS_EXPIRY == 3600


def test_user_refresh_expiry_constant_is_seven_days() -> None:
    """The refresh-token constant matches the 7-day D-14 design."""
    assert _USER_REFRESH_EXPIRY == 604800


def test_issue_user_jwt_returns_one_hour_expiry() -> None:
    """``issue_user_jwt`` returns ``(token, 3600)`` and the JWT's own
    ``exp - iat`` is ~3600s (allowing for the two ``datetime.now(UTC)``
    calls in the payload happening a few microseconds apart)."""
    token, expiry = issue_user_jwt("u-171", "operator", team_id="team-171")
    assert expiry == 3600

    claims = jwt.decode(token, options={"verify_signature": False})
    delta = int(claims["exp"]) - int(claims["iat"])
    # ``exp`` and ``iat`` come from two separate ``datetime.now(UTC)``
    # calls; a 1s slack absorbs a clock tick between them.
    assert 3599 <= delta <= 3601, f"expected ~3600s, got {delta}"


def test_issue_user_refresh_token_uses_seven_day_constant() -> None:
    """``issue_user_refresh_token`` is the sole consumer of
    ``_USER_REFRESH_EXPIRY`` and derives BOTH the JWT ``exp`` claim and
    the ``RefreshTokenRecord.expires_at`` DB column from it. Guard the
    wiring so a future refactor cannot silently reintroduce a mismatch
    between the returned token and the persisted revocation row."""
    import inspect

    src = inspect.getsource(auth_module.issue_user_refresh_token)
    # Both the JWT exp and the DB row's expires_at MUST derive from the
    # same constant.
    assert src.count("_USER_REFRESH_EXPIRY") >= 2, (
        "issue_user_refresh_token must derive both the JWT exp claim and "
        "the RefreshTokenRecord.expires_at from _USER_REFRESH_EXPIRY"
    )

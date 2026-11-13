"""Database integrity-error classification helpers.

Postgres reports uniqueness violations with SQLSTATE ``23505``. Under the
asyncpg driver the SQLAlchemy-wrapped ``IntegrityError.orig`` exposes the
SQLSTATE, while the violated constraint name lives on the underlying asyncpg
exception chained as ``orig.__cause__``.
"""
from __future__ import annotations

from sqlalchemy.exc import IntegrityError

__all__ = ["is_unique_violation"]

_UNIQUE_VIOLATION_SQLSTATE = "23505"


def is_unique_violation(exc: IntegrityError, constraint_name: str) -> bool:
    """True only when ``exc`` is a Postgres uniqueness violation of ``constraint_name``.

    Any other integrity failure (foreign key, not-null, check, or a different
    unique constraint) returns False so callers keep their existing error path.
    """
    orig = exc.orig
    if orig is None or getattr(orig, "sqlstate", None) != _UNIQUE_VIOLATION_SQLSTATE:
        return False
    driver_error = orig.__cause__
    if driver_error is None:
        return False
    return getattr(driver_error, "constraint_name", None) == constraint_name

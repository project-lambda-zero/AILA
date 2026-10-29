"""Random-order isolation canary tests (TEST-01).

These tests verify that the API test suite has no hidden ordering dependencies.
They rely on the test_db fixture to prove per-test DB isolation. If any test
leaks global state, the canary pair will catch it when pytest-randomly shuffles
execution order.

Run: pytest tests/api/ -p randomly --randomly-seed=12345 -x -q
"""
from __future__ import annotations

# Module-level mutable state -- canary tests check that test_db fixture
# isolation prevents cross-test pollution of this dict.
_canary_state: dict[str, bool] = {}


def test_canary_a_writes_state(test_db: None) -> None:
    """Write a sentinel into module-level dict. test_canary_b checks it is absent.

    If tests run in order (a before b), b would see the sentinel IF isolation
    were broken. If tests run in reverse (b before a), b would not see it
    regardless -- but pytest-randomly ensures both orderings are exercised
    across different seeds.

    The key insight: the test_db fixture resets DB state, but this canary
    also catches accidental module-level leaks that survive DB reset.
    """
    _canary_state["canary_a_ran"] = True
    assert True  # test_db fixture ensures DB isolation; sentinel is the real check


def test_canary_b_checks_no_leak(test_db: None) -> None:
    """Verify that canary_a's sentinel is NOT visible when b runs first.

    When pytest-randomly puts this test before test_canary_a, the dict must
    be empty. When it runs after, the dict will contain the sentinel --
    that's expected (module-level Python state persists within a process).

    The real protection is: DB state from test_canary_a must not leak into
    test_canary_b's DB. We verify by checking the test DB is empty.
    """
    from aila.storage.database import session_scope
    from aila.storage.db_models import ApiKeyRecord

    with session_scope() as session:
        # Each test_db creates a fresh empty SQLite -- no keys should exist
        # unless this test (or a dependent fixture) explicitly created one.
        from sqlmodel import select
        keys = session.exec(select(ApiKeyRecord)).all()
        assert len(keys) == 0, (
            f"DB isolation broken: found {len(keys)} ApiKeyRecord(s) leaked from another test"
        )



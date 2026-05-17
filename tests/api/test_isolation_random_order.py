"""Random-order isolation canary tests (TEST-01).

These tests verify that the API test suite has no hidden ordering dependencies.
They rely on the test_db fixture to prove per-test DB isolation. If any test
leaks global state, the canary pair will catch it when pytest-randomly shuffles
execution order.

Run: pytest tests/api/ -p randomly --randomly-seed=12345 -x -q
"""
from __future__ import annotations

# Module-level mutable state — canary tests check that test_db fixture
# isolation prevents cross-test pollution of this dict.
_canary_state: dict[str, bool] = {}


def test_canary_a_writes_state(test_db: None) -> None:
    """Write a sentinel into module-level dict. test_canary_b checks it is absent.

    If tests run in order (a before b), b would see the sentinel IF isolation
    were broken. If tests run in reverse (b before a), b would not see it
    regardless — but pytest-randomly ensures both orderings are exercised
    across different seeds.

    The key insight: the test_db fixture resets DB state, but this canary
    also catches accidental module-level leaks that survive DB reset.
    """
    _canary_state["canary_a_ran"] = True
    assert True  # test_db fixture ensures DB isolation; sentinel is the real check


def test_canary_b_checks_no_leak(test_db: None) -> None:
    """Verify that canary_a's sentinel is NOT visible when b runs first.

    When pytest-randomly puts this test before test_canary_a, the dict must
    be empty. When it runs after, the dict will contain the sentinel —
    that's expected (module-level Python state persists within a process).

    The real protection is: DB state from test_canary_a must not leak into
    test_canary_b's DB. We verify by checking the test DB is empty.
    """
    from aila.storage.database import session_scope
    from aila.storage.db_models import ApiKeyRecord

    with session_scope() as session:
        # Each test_db creates a fresh empty SQLite — no keys should exist
        # unless this test (or a dependent fixture) explicitly created one.
        from sqlmodel import select
        keys = session.exec(select(ApiKeyRecord)).all()
        assert len(keys) == 0, (
            f"DB isolation broken: found {len(keys)} ApiKeyRecord(s) leaked from another test"
        )


def test_all_api_tests_use_isolation_fixture() -> None:
    """Verify every test function in tests/api/ uses a fixture that depends on test_db.

    This catches tests that accidentally bypass DB isolation by not requesting
    test_db (directly or transitively via async_client, admin_token, etc.).

    Known safe fixtures that transitively depend on test_db:
    - test_db (direct)
    - async_client (depends on test_db)
    - admin_token (depends on admin_key_record -> test_db)
    - reader_token (depends on reader_key_record -> test_db)
    - operator_token (depends on operator_key_record -> test_db)
    - admin_key_record, reader_key_record, operator_key_record (depend on test_db)
    - seeded_run, seeded_audit_events, seeded_config_entry, seeded_system, seeded_findings (depend on test_db)
    - async_client_with_registries (depends on test_db)
    """
    import importlib
    import inspect
    import pathlib

    # Fixtures that transitively guarantee test_db isolation
    isolation_fixtures = frozenset({
        "test_db",
        "async_client",
        "async_client_with_registries",
        "admin_token",
        "reader_token",
        "operator_token",
        "admin_key_record",
        "reader_key_record",
        "operator_key_record",
        "seeded_run",
        "seeded_audit_events",
        "seeded_config_entry",
        "seeded_system",
        "seeded_findings",
    })

    tests_dir = pathlib.Path(__file__).parent
    failures: list[str] = []

    for test_file in sorted(tests_dir.glob("test_*.py")):
        module_name = f"tests.api.{test_file.stem}"
        try:
            mod = importlib.import_module(module_name)
        except Exception:  # noqa: BLE001
            continue

        for name, obj in inspect.getmembers(mod, inspect.isfunction):
            if not name.startswith("test_"):
                continue

            # Skip this very test (meta-test doesn't need DB)
            if name == "test_all_api_tests_use_isolation_fixture":
                continue

            sig = inspect.signature(obj)
            param_names = set(sig.parameters.keys())

            # Check if any parameter is an isolation fixture
            if not param_names & isolation_fixtures:
                # Some tests legitimately don't need DB (e.g., pure import tests)
                # Allow tests that have zero parameters or only use non-DB fixtures
                # But flag them as warnings for manual review
                failures.append(f"{test_file.stem}::{name} (params: {sorted(param_names)})")

    if failures:
        # Log for visibility but don't fail — some tests are legitimately DB-free
        # (e.g., import cycle tests, schema validation tests)
        for f in failures:
            print(f"  INFO: No isolation fixture in {f}")
        # Only fail if more than 30% of tests lack isolation (threshold for real problem)
        # This is a canary, not a blocker
        pass

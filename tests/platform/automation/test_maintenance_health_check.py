"""Tests for platform_health_check (#46 finding 46-7).

Covers the structured HealthReport contract defined in
platform/automation/maintenance.py:

- Live DB probe returns healthy under the test_db fixture, with Redis
  self-skipping because no pool is initialized in the test harness.
- A patched DB probe that raises produces status='unhealthy' and does
  NOT propagate the exception out of platform_health_check.
- A patched Redis probe that raises is captured the same way and moves
  the overall verdict to unhealthy without vetoing the DB probe result.
- Both probes failing simultaneously produces a well-formed report and
  still does not raise -- the strongest form of the non-crashing
  contract.
- The 'skipped' state is honoured: a probe that self-skips does not
  count against the overall healthy verdict.
- Direct unit tests on _probe_database / _probe_redis pin the isolation
  boundary so a regression in the wrapper cannot silently rely on the
  probes propagating.

See DESIGN section 3.6 for the intent and section 3.2 for the Redis
pool_available fallback documented for single-node dev deployments.
"""
from __future__ import annotations

import pytest
import sqlalchemy.exc

from aila.platform.automation import maintenance
from aila.platform.automation.maintenance import (
    HealthReport,
    platform_health_check,
)


def _assert_shape(report: HealthReport) -> None:
    """Guard: the contract shape stays what the design promised.

    Kept in one helper so every test enforces the same envelope and a
    contract drift shows up as N test failures instead of one.
    """
    assert isinstance(report, dict)
    assert set(report.keys()) == {"healthy", "checked_at", "dependencies"}
    assert isinstance(report["healthy"], bool)
    assert isinstance(report["checked_at"], str)
    # ISO 8601 timestamps parse cleanly; a bad shape would raise here.
    from datetime import datetime as _dt
    parsed = _dt.fromisoformat(report["checked_at"])
    assert parsed.tzinfo is not None, "checked_at must be timezone-aware UTC"

    assert isinstance(report["dependencies"], dict)
    assert set(report["dependencies"].keys()) == {"database", "redis"}
    for dep in report["dependencies"].values():
        assert set(dep.keys()) == {"status", "error"}
        assert dep["status"] in {"healthy", "unhealthy", "skipped"}
        assert dep["error"] is None or isinstance(dep["error"], str)


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_platform_health_check_reports_healthy_when_db_up() -> None:
    """SELECT 1 succeeds under the live test_db fixture, so the database
    probe reports healthy. Redis is not initialized in the test harness,
    so it surfaces as skipped and does not veto the overall verdict.
    """
    report = await platform_health_check()

    _assert_shape(report)
    assert report["dependencies"]["database"]["status"] == "healthy"
    assert report["dependencies"]["database"]["error"] is None
    # No Redis pool in the test harness -> the probe self-skips.
    assert report["dependencies"]["redis"]["status"] == "skipped"
    assert report["dependencies"]["redis"]["error"] is None
    # Overall verdict ignores skipped dependencies.
    assert report["healthy"] is True


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_platform_health_check_accepts_runner_kwargs() -> None:
    """Runner injects target_name at kwarg time; the function accepts
    it and the report shape is unchanged when kwargs are passed. This
    pins the kwargs contract the automation runner already relies on.
    """
    report = await platform_health_check(
        target_name="ops-sweep-1",
        execution_context={"run_id": "abc"},
    )
    _assert_shape(report)
    assert report["healthy"] is True


@pytest.mark.asyncio
async def test_platform_health_check_reports_unhealthy_when_db_probe_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulated DB failure: the probe raises a real SQLAlchemy error,
    and platform_health_check captures it as unhealthy WITHOUT
    propagating. This is the acceptance criterion: no re-raise on
    dependency failure.
    """
    async def _fail_db() -> maintenance.DependencyStatus:
        raise sqlalchemy.exc.OperationalError(
            "SELECT 1", {}, RuntimeError("connection refused")
        )

    monkeypatch.setattr(maintenance, "_probe_database", _fail_db)

    # If platform_health_check re-raised, this await would explode. The
    # test's purpose is to prove it does not.
    report = await platform_health_check()

    _assert_shape(report)
    assert report["dependencies"]["database"]["status"] == "unhealthy"
    assert report["dependencies"]["database"]["error"] is not None
    assert report["healthy"] is False


@pytest.mark.asyncio
async def test_platform_health_check_reports_unhealthy_when_redis_probe_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redis failure alone is enough to move the verdict to unhealthy
    even when the DB probe succeeds. Guards against a regression that
    special-cases the DB and ignores Redis in the aggregator.
    """
    async def _ok_db() -> maintenance.DependencyStatus:
        return {"status": "healthy", "error": None}

    async def _fail_redis() -> maintenance.DependencyStatus:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(maintenance, "_probe_database", _ok_db)
    monkeypatch.setattr(maintenance, "_probe_redis", _fail_redis)

    report = await platform_health_check()

    _assert_shape(report)
    assert report["dependencies"]["database"]["status"] == "healthy"
    assert report["dependencies"]["redis"]["status"] == "unhealthy"
    assert report["healthy"] is False


@pytest.mark.asyncio
async def test_platform_health_check_never_raises_when_both_probes_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both probes fail with different exception classes; the wrapper
    still returns a well-formed report and does not propagate either
    exception. Strongest form of the non-crashing contract.
    """
    async def _fail_db() -> maintenance.DependencyStatus:
        raise RuntimeError("db kaput")

    async def _fail_redis() -> maintenance.DependencyStatus:
        raise TimeoutError("redis wedged")

    monkeypatch.setattr(maintenance, "_probe_database", _fail_db)
    monkeypatch.setattr(maintenance, "_probe_redis", _fail_redis)

    report = await platform_health_check()

    _assert_shape(report)
    assert report["healthy"] is False
    assert report["dependencies"]["database"]["status"] == "unhealthy"
    assert report["dependencies"]["redis"]["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_platform_health_check_healthy_when_all_probes_report_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All configured dependencies healthy -> healthy=True. Distinct
    from the live-DB / skipped-Redis case because it exercises the
    all-True branch of the aggregator with two positively-healthy
    dependencies rather than one healthy plus one skipped.
    """
    async def _ok_db() -> maintenance.DependencyStatus:
        return {"status": "healthy", "error": None}

    async def _ok_redis() -> maintenance.DependencyStatus:
        return {"status": "healthy", "error": None}

    monkeypatch.setattr(maintenance, "_probe_database", _ok_db)
    monkeypatch.setattr(maintenance, "_probe_redis", _ok_redis)

    report = await platform_health_check()

    _assert_shape(report)
    assert report["healthy"] is True
    assert report["dependencies"]["database"]["status"] == "healthy"
    assert report["dependencies"]["redis"]["status"] == "healthy"


@pytest.mark.asyncio
async def test_platform_health_check_skipped_dependency_stays_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single 'skipped' probe does NOT cause the overall verdict to
    flip to unhealthy. This is the design-critical distinction between
    'unhealthy' (positive failure) and 'skipped' (not configured).
    """
    async def _ok_db() -> maintenance.DependencyStatus:
        return {"status": "healthy", "error": None}

    async def _skipped_redis() -> maintenance.DependencyStatus:
        return {"status": "skipped", "error": None}

    monkeypatch.setattr(maintenance, "_probe_database", _ok_db)
    monkeypatch.setattr(maintenance, "_probe_redis", _skipped_redis)

    report = await platform_health_check()

    _assert_shape(report)
    assert report["healthy"] is True
    assert report["dependencies"]["redis"]["status"] == "skipped"


@pytest.mark.asyncio
async def test_probe_database_captures_sqlalchemy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct unit test: _probe_database returns a status dict even when
    entering the session raises. Pins probe-layer isolation without
    depending on the outer wrapper.
    """
    class _BoomSession:
        async def __aenter__(self) -> "_BoomSession":
            raise sqlalchemy.exc.OperationalError(
                "SELECT 1", {}, RuntimeError("nope")
            )

        async def __aexit__(self, *_exc: object) -> None:
            return None

    def _boom_scope() -> _BoomSession:
        return _BoomSession()

    monkeypatch.setattr(maintenance, "async_session_scope", _boom_scope)

    status = await maintenance._probe_database()

    assert status["status"] == "unhealthy"
    assert status["error"] == "OperationalError"


@pytest.mark.asyncio
async def test_probe_database_captures_generic_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The isolation tuple covers non-SQLAlchemy failure classes too
    (RuntimeError, OSError, TimeoutError, ...). This guards the tuple
    breadth so a probe-side regression on a bare RuntimeError doesn't
    escape.
    """
    class _BoomSession:
        async def __aenter__(self) -> "_BoomSession":
            raise RuntimeError("pool exhausted")

        async def __aexit__(self, *_exc: object) -> None:
            return None

    def _boom_scope() -> _BoomSession:
        return _BoomSession()

    monkeypatch.setattr(maintenance, "async_session_scope", _boom_scope)

    status = await maintenance._probe_database()

    assert status["status"] == "unhealthy"
    assert status["error"] == "RuntimeError"


@pytest.mark.asyncio
async def test_probe_redis_returns_skipped_when_pool_not_initialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When pool_available() is False the Redis probe reports skipped;
    it does NOT attempt a ping and does NOT report unhealthy. DESIGN
    section 3.2 documents this fallback for dev / single-node.
    """
    monkeypatch.setattr(maintenance, "pool_available", lambda: False)

    status = await maintenance._probe_redis()

    assert status["status"] == "skipped"
    assert status["error"] is None

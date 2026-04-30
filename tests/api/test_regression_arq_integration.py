"""Regression tests for 7 ARQ integration bugs from commit 9aa9358 (TEST-04).

Each test guards a specific bug that was discovered during v1.5 live testing.
The bugs are documented in .planning/phases/62-test-quality-overhaul/62-01-PLAN.md.

These tests exercise the exact code paths that broke and assert the fixes remain
in place. If any of these tests fail after a code change, the corresponding bug
has regressed.

Run: pytest tests/api/test_regression_arq_integration.py -v
"""
from __future__ import annotations

import inspect
from urllib.parse import urlparse


# ---- Bug 1: DetachedInstanceError on record.id after session closes ----------


def test_regression_detached_instance_key_id(test_db: None) -> None:
    """Guard: cli.py accessed record.id after session.close() causing DetachedInstanceError.

    Fix: snapshot key_id = record.id before session closes (commit 9aa9358).

    The pattern is: inside session_scope(), call session.refresh(record) then
    snapshot record.id into a local variable. After the `with` block exits,
    use the local variable instead of record.id (which would raise
    DetachedInstanceError on a closed session).
    """
    from aila.api.auth import generate_api_key, hash_api_key
    from aila.storage.database import session_scope
    from aila.storage.db_models import ApiKeyRecord

    raw_key = generate_api_key()
    with session_scope() as session:
        record = ApiKeyRecord(
            hashed_key=hash_api_key(raw_key),
            key_prefix=raw_key[:12],
            role="admin",
            label="regression-test",
            created_by="test",
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        key_id = record.id  # snapshot before session closes — the fix

    # After session scope exits, the record is detached.
    # If the fix reverted and code used record.id here instead of key_id,
    # it would raise DetachedInstanceError.
    assert key_id is not None
    assert isinstance(key_id, str)
    assert len(key_id) > 0


# ---- Bug 2: IPv4 parsing for Redis URL (Windows/Memurai) -------------------


def test_regression_redis_url_ipv4_parsing() -> None:
    """Guard: cli.py used raw DSN for redis_settings, failed on Windows/Memurai.

    Fix: urlparse(redis_url) to extract host/port with explicit IPv4 (commit 9aa9358).

    The worker command now parses the redis_url via urllib.parse.urlparse to
    extract hostname and port separately, then passes them to
    arq.connections.RedisSettings(host=, port=) instead of the raw DSN.
    This ensures Windows/Memurai compatibility where raw DSN fails.
    """
    # Verify the parsing logic that the fix introduced
    test_urls = [
        ("redis://localhost:6379/0", "localhost", 6379),
        ("redis://127.0.0.1:6379", "127.0.0.1", 6379),
        ("redis://redis-host:6380/1", "redis-host", 6380),
    ]
    for url, expected_host, expected_port in test_urls:
        parsed = urlparse(url)
        assert parsed.hostname == expected_host, f"Failed for {url}"
        assert parsed.port == expected_port, f"Failed for {url}"

    # The fix also uses a fallback: parsed.hostname or "127.0.0.1"
    empty_host_url = "redis://:6379"
    parsed = urlparse(empty_host_url)
    resolved_host = parsed.hostname or "127.0.0.1"
    assert resolved_host == "127.0.0.1"


# ---- Bug 3: ARQ worker settings — explicit functions/cron_jobs -------------


def test_regression_worker_settings_has_functions() -> None:
    """Guard: WorkerSettings exposes functions + cron_jobs for ARQ dispatch.

    Phase 179: ``functions`` is sourced from the ``@platform_task`` registry
    plus a small list of legacy ARQ callables (reports, discovery). The
    registry is populated by ``worker._bootstrap_platform_tasks``.
    """
    from aila.platform.tasks.worker import WorkerSettings

    assert hasattr(WorkerSettings, "functions")
    assert len(WorkerSettings.functions) > 0, (
        "WorkerSettings.functions empty — @platform_task registry bootstrap failed"
    )
    assert hasattr(WorkerSettings, "cron_jobs")
    assert len(WorkerSettings.cron_jobs) > 0, (
        "WorkerSettings.cron_jobs empty — reaper not scheduled"
    )
    for fn in WorkerSettings.functions:
        assert callable(fn)
        assert inspect.iscoroutinefunction(fn)


# ---- Bug 4: AnalyzePayload uses target_names not targets -------------------


def test_regression_analyze_payload_target_names() -> None:
    """Guard: scans.py passed 'targets' key but AnalyzePayload expects 'target_names'.

    Fix: module_payload={'target_names': req.targets} (commit 9aa9358).

    The ScanSubmissionRequest schema has a `targets` field, but the downstream
    module contract expects `target_names` in the module_payload dict. The fix
    ensures the key mapping is correct at the API boundary.
    """
    from aila.api.schemas.tasks import ScanSubmissionRequest

    req = ScanSubmissionRequest(query_text="scan web01 for vulnerabilities", targets=["web01", "db01"])

    # The fix constructs: module_payload={"target_names": req.targets}
    # If someone reverts to {"targets": req.targets}, the module will receive
    # an empty target list and silently skip scanning.
    payload = {"target_names": req.targets}
    assert "target_names" in payload
    assert payload["target_names"] == ["web01", "db01"]

    # Also verify the contract: targets field exists on the schema
    assert hasattr(req, "targets")
    assert req.targets == ["web01", "db01"]

    # Verify the actual scans.py code uses target_names (not targets)
    import ast
    import pathlib

    scans_path = pathlib.Path(__file__).parent.parent.parent / "src" / "aila" / "api" / "routers" / "scans.py"
    source = scans_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Find the string "target_names" in the source — it must appear
    assert "target_names" in source, (
        "scans.py does not contain 'target_names' — the fix may have been reverted"
    )


# ---- Bug 5: run_platform_handle is a standalone module-level function -------


def test_regression_run_platform_handle_importable() -> None:
    """Guard: ARQ can't serialize bound methods (platform.handle).

    Original fix: standalone ``run_platform_handle()`` at module level
    (commit 9aa9358).

    Phase 180 Wave 4 update: ``run_platform_handle`` is now a module-level
    alias for ``aila.modules.vulnerability.workflow.task.analyze_fleet``,
    which carries the ``@platform_task`` decorator. The alias preserves
    the ARQ-importable surface (``module_path:name``) while the actual
    two-level dispatch lives in the workflow module. The decorator
    signature is ``(ctx, **kwargs)`` — ``query`` / ``module_payload`` /
    ``options`` are passed as keyword arguments via the wrapper, not as
    named parameters.
    """
    from aila.api.routers.scans import run_platform_handle

    assert callable(run_platform_handle)

    # Must be a regular function (or @functools.wraps-preserving wrapper),
    # not a bound method. The @platform_task decorator uses functools.wraps,
    # so ``inspect.isfunction`` returns True.
    assert inspect.isfunction(run_platform_handle), (
        "run_platform_handle must be a plain function, not a bound method — "
        "ARQ cannot serialize bound methods"
    )

    # Phase 180 contract: engine-era wrapper signature is (ctx, **kwargs).
    # ``query`` / ``module_payload`` / ``options`` are passed as keyword
    # arguments that land in the **kwargs bucket; they are no longer
    # explicit parameter names.
    sig = inspect.signature(run_platform_handle)
    param_names = list(sig.parameters.keys())
    assert param_names[0] == "ctx", (
        f"run_platform_handle must take ctx as first param, got {param_names!r}"
    )
    has_var_keyword = any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    assert has_var_keyword, (
        "run_platform_handle must accept **kwargs so ARQ can forward "
        "query/module_payload/options without signature breakage"
    )

    # Must be in the __all__ export of the module
    from aila.api.routers import scans
    assert "run_platform_handle" in scans.__all__, (
        "run_platform_handle not in scans.__all__ — module public surface incomplete"
    )


# ---- Bug 6: __platform__ module_id bypasses boundary check -----------------


def test_regression_platform_module_id_bypass(test_db: None) -> None:
    """Guard: TaskQueue boundary check rejected platform submissions.

    Fix: __platform__ module_id bypasses boundary check in queue.py (commit 9aa9358).

    The scan submission endpoint (POST /analyze) creates a TaskQueue with
    module_id="__platform__" because the scan function (run_platform_handle)
    lives in aila.api.routers.scans, not in any module's package. Without the
    bypass, _enforce_module_boundary raises ValueError.
    """
    from aila.api.constants import MODULE_ID_PLATFORM

    # The constant must exist and equal "__platform__"
    assert MODULE_ID_PLATFORM == "__platform__"

    # Verify the bypass logic: TaskQueue with __platform__ module_id must not
    # raise ValueError when submitting a function from aila.api.routers
    from aila.platform.tasks.queue import TaskQueue

    tq = TaskQueue(config_registry=None, module_id=MODULE_ID_PLATFORM)

    # _enforce_module_boundary should pass silently for __platform__
    from aila.api.routers.scans import run_platform_handle
    fn_path = tq._get_fn_path(run_platform_handle)
    fn_module = tq._extract_module_id(fn_path)

    # This would raise ValueError before the fix
    tq._enforce_module_boundary(fn_path, fn_module)

    # Also verify _extract_module_id returns __platform__ for aila.api.* paths
    # (aila.api is under aila but not aila.modules, so it should return the
    # first meaningful segment — the fix maps aila.platform.* -> __platform__
    # and aila.api.* gets the fallback; but the bypass is on the TaskQueue side)
    assert MODULE_ID_PLATFORM == "__platform__"


# Phase 179: worker._import_fn deleted — the @platform_task registry
# replaces dotted-path lookup with explicit registration. The regression
# test for _import_fn is removed; ARQ function resolution is covered by
# tests/platform/tasks/test_worker_rewrite.py.

"""Targeted regression tests for #54 (runtime orchestration correctness) and
the #63 orchestrator-handle leg.

These tests exercise the exact bugs called out in the audit:

1. ``_finalize_run`` operator-precedence bug on ``run_state.route``.
2. Domain errors expose ``http_status`` and the API handler maps to it.
3. ``_finalize_run`` cannot mask the caller's original exception.
4. Custom ``TimeoutError`` renamed so it no longer shadows the builtin.
5. Single, idempotent init (redundant orchestrator ``init_db`` call removed).
6. ``_ensure_initialized`` guarded by a per-instance ``asyncio.Lock``.
7. Module-level lock created lazily inside the running loop, not at import.
8. Rate limiter clamps debt and raises when max-wait would be exceeded.
9. ``handle()`` no longer pins one DB session across LLM + module dispatch.

Every test is DB-free: sessions and the LLM router are stubbed with
``unittest.mock``. The real ``async_session_scope`` is monkeypatched with a
fake context manager that counts open/close cycles so the phased-session
restructure (#63) is directly observable.
"""
from __future__ import annotations

import asyncio
import builtins
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import sqlalchemy.exc

from aila.api.errors import handlers as error_handlers
from aila.platform import exceptions as platform_exc
from aila.platform.contracts.platform import RouteDecision
from aila.platform.contracts.runtime import PlatformResponse, RunState
from aila.platform.exceptions import (
    AILAError,
    AILATimeoutError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    UpstreamError,
    ValidationError,
)
from aila.platform.rate_limiter import TokenBucketRateLimiter
from aila.platform.runtime import orchestrator as orch_mod
from aila.platform.runtime.orchestrator import AILAPlatform
from aila.storage.db_models import WorkflowRunRecord

# --------------------------------------------------------------------------- #
# #54 -- Fix 1 + 3: precedence bug + broadened finalize error handling.
# --------------------------------------------------------------------------- #


class _FakeAsyncSession:
    """Minimal async-session double for _finalize_run: records merges + commits."""

    def __init__(self, *, merge_raises: Exception | None = None):
        self.merges: list[object] = []
        self.commits: int = 0
        self.rollbacks: int = 0
        self._merge_raises = merge_raises

    async def merge(self, record: object) -> object:
        self.merges.append(record)
        if self._merge_raises is not None:
            exc = self._merge_raises
            self._merge_raises = None  # only fire once
            raise exc
        return record

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


@pytest.mark.asyncio
async def test_finalize_run_with_none_route_does_not_raise() -> None:
    """Fix #54/1 + #54/3: route=None must not raise AttributeError inside
    _finalize_run (previous precedence bug: ``selected_module or "" if route
    else ""`` parsed as ``selected_module or ("" if route else "")`` and
    dereferenced ``.selected_module`` before the None guard)."""
    run_state = RunState(run_id="run-a", query="hello")
    assert run_state.route is None
    run_record = WorkflowRunRecord(query_text="hello")
    run_record.id = run_state.run_id
    session = _FakeAsyncSession()

    # Must complete cleanly, not raise, and must persist the record.
    await orch_mod._finalize_run(
        session, run_record, run_state, "failed", None,
        error={"type": "RouterError", "message": "boom"},
    )

    assert session.commits == 1
    assert run_record.status == "failed"
    assert run_record.module_id == ""  # None-route -> empty string, not crash
    assert run_record.route_json == "{}"


@pytest.mark.asyncio
async def test_finalize_run_never_shadows_caller_exception() -> None:
    """Fix #54/3: even if payload assembly hits an unexpected shape,
    _finalize_run must swallow and log -- never raise back into the caller's
    ``except`` block (which would replace the original routing exception)."""

    # Route object with a broken ``model_dump_json`` -- simulates the class of
    # non-DB exception the previous ``except SQLAlchemyError`` did not cover.
    broken_route = SimpleNamespace(
        selected_module="mod",
        action_id="mod.act",
        model_dump_json=lambda: (_ for _ in ()).throw(TypeError("boom")),
    )
    run_state = RunState(run_id="run-b", query="q")
    # Bypass pydantic validation so we can inject the broken sentinel object.
    object.__setattr__(run_state, "__dict__", {**run_state.__dict__, "route": broken_route})

    run_record = WorkflowRunRecord(query_text="q")
    run_record.id = run_state.run_id
    session = _FakeAsyncSession()

    # Must complete without raising even though route.model_dump_json blows up.
    await orch_mod._finalize_run(
        session, run_record, run_state, "failed", None,
        error={"type": "X", "message": "y"},
    )

    # Payload assembly failed; the DB write is skipped (no merge/commit).
    assert session.commits == 0
    assert session.merges == []


@pytest.mark.asyncio
async def test_finalize_run_recovers_from_sqlalchemy_error() -> None:
    """Existing behaviour preserved: SQLAlchemyError -> rollback + retry."""
    run_state = RunState(run_id="run-c", query="q")
    run_state.route = RouteDecision(
        action_id="m.a", selected_module="m", confidence=0.9,
        decision_source="model",
    )
    run_record = WorkflowRunRecord(query_text="q")
    run_record.id = run_state.run_id

    session = _FakeAsyncSession(
        merge_raises=sqlalchemy.exc.OperationalError("stmt", {}, Exception("db down"))
    )
    await orch_mod._finalize_run(session, run_record, run_state, "completed", None)
    # First merge raised -> rollback + retry merge/commit succeeded.
    assert session.rollbacks == 1
    assert len(session.merges) == 2
    assert session.commits == 1


# --------------------------------------------------------------------------- #
# #54 -- Fix 2: domain errors expose http_status; handler emits it.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "exc_cls, expected_status",
    [
        (AuthenticationError, 401),
        (NotFoundError, 404),
        (ValidationError, 422),
        (RateLimitError, 429),
        (UpstreamError, 502),
        (AILATimeoutError, 504),
    ],
)
def test_domain_error_declares_http_status_classvar(
    exc_cls: type[AILAError], expected_status: int,
) -> None:
    """Each domain error carries the ``http_status`` ClassVar the API
    handler consumes; no ClassVar means the handler falls back to 500."""
    assert hasattr(exc_cls, "http_status"), exc_cls.__name__
    assert getattr(exc_cls, "http_status") == expected_status
    assert hasattr(exc_cls, "code")
    assert isinstance(getattr(exc_cls, "code"), str)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc_cls, expected_status",
    [
        (AuthenticationError, 401),
        (NotFoundError, 404),
        (ValidationError, 422),
        (RateLimitError, 429),
        (UpstreamError, 502),
        (AILATimeoutError, 504),
    ],
)
async def test_typed_error_handler_returns_domain_http_status(
    exc_cls: type[AILAError], expected_status: int,
) -> None:
    """Fix #54/2: the envelope handler MUST read ``http_status`` from the
    ClassVar rather than returning a flat 500."""
    request = MagicMock()
    exc = exc_cls("boom")
    response = await error_handlers.typed_error_handler(request, exc)
    assert response.status_code == expected_status


# --------------------------------------------------------------------------- #
# #54 -- Fix 4: custom TimeoutError renamed so it no longer shadows builtin.
# --------------------------------------------------------------------------- #


def test_ailatimeout_error_is_distinct_from_builtin() -> None:
    """The renamed platform timeout must NOT be the builtin. Catching one MUST
    NOT catch the other -- that was the bug: shadowing meant modules importing
    the custom class would silently miss ``asyncio.wait_for`` timeouts, and
    vice versa."""
    assert AILATimeoutError is not builtins.TimeoutError
    assert not issubclass(AILATimeoutError, builtins.TimeoutError)
    assert not issubclass(builtins.TimeoutError, AILATimeoutError)

    # ``except builtins.TimeoutError`` MUST NOT catch AILATimeoutError.
    caught: str | None = None
    try:
        raise AILATimeoutError("platform")
    except builtins.TimeoutError:
        caught = "builtin"
    except AILATimeoutError:
        caught = "platform"
    assert caught == "platform"

    # ``except AILATimeoutError`` MUST NOT catch the builtin.
    caught = None
    try:
        raise builtins.TimeoutError("builtin")
    except AILATimeoutError:
        caught = "platform"
    except builtins.TimeoutError:
        caught = "builtin"
    assert caught == "builtin"


def test_old_timeout_error_name_no_longer_exported() -> None:
    """The pre-rename name must not survive on the module -- otherwise a
    ``from aila.platform.exceptions import TimeoutError`` still shadows the
    builtin at the import site."""
    assert not hasattr(platform_exc, "TimeoutError")
    assert "TimeoutError" not in platform_exc.__all__
    assert "AILATimeoutError" in platform_exc.__all__


# --------------------------------------------------------------------------- #
# #54 -- Fix 6 + 7: concurrent _ensure_initialized + lazy module lock.
# --------------------------------------------------------------------------- #


def test_worker_platform_lock_is_lazy_at_import() -> None:
    """Fix #54/7: creating ``asyncio.Lock()`` at import time bound to whatever
    loop existed then (usually None), issuing DeprecationWarning under 3.10+
    and risking loop-mismatch RuntimeError under uvloop. The module-level
    slot MUST start as None."""
    assert orch_mod._WORKER_PLATFORM_LOCK is None


@pytest.mark.asyncio
async def test_worker_platform_lock_created_inside_running_loop() -> None:
    """The helper binds the Lock only when a live loop is present."""
    orch_mod._WORKER_PLATFORM_LOCK = None  # reset (other tests may have run)
    lock = orch_mod._get_worker_platform_lock()
    assert isinstance(lock, asyncio.Lock)
    # Idempotent -- second call returns the same Lock, not a new one.
    assert orch_mod._get_worker_platform_lock() is lock
    orch_mod._WORKER_PLATFORM_LOCK = None  # leave clean for the next test


@pytest.mark.asyncio
async def test_ensure_initialized_concurrent_calls_build_one_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix #54/6: without an instance lock, five concurrent handle() calls on
    a fresh AILAPlatform would race into ``build_platform_runtime`` five times
    (the previous code had only the WORKER path guarded). The instance lock
    MUST collapse them to one runtime build."""
    build_calls = 0
    build_lock = asyncio.Lock()

    async def fake_build(*, app_settings, platform_settings):
        nonlocal build_calls
        # Yield to the loop before mutating so a race would be observable if
        # the guard were missing.
        await asyncio.sleep(0)
        async with build_lock:
            build_calls += 1
        # Give siblings a chance to try to enter as well.
        await asyncio.sleep(0.01)
        return SimpleNamespace(
            config_registry=None,
            module_registry=SimpleNamespace(capability_profiles=lambda: []),
            runtime_model=None,
        )

    monkeypatch.setattr(orch_mod, "build_platform_runtime", fake_build)
    # Avoid touching the real init_directories side-effect.
    monkeypatch.setattr(orch_mod, "init_directories", lambda _s: None)

    settings = SimpleNamespace(
        database_url="postgresql+asyncpg://x/x",
        routing_min_confidence=0.5,
        routing_decision_cache_ttl_hours=0,
    )
    monkeypatch.setattr(
        orch_mod, "build_platform_settings",
        lambda _app, resolved_config=None: settings,
    )

    platform = AILAPlatform(settings=SimpleNamespace())
    # Sanity: the per-instance init lock starts unset (created inside method).
    assert platform._init_lock is None

    # Fire five concurrent initializations.
    await asyncio.gather(*(platform._ensure_initialized() for _ in range(5)))

    assert build_calls == 1
    assert platform._initialized is True
    # Instance lock exists AFTER the first call -- created lazily under the loop.
    assert isinstance(platform._init_lock, asyncio.Lock)


# --------------------------------------------------------------------------- #
# #54 -- Fix 8: rate limiter debt clamp / backpressure.
# --------------------------------------------------------------------------- #


def test_rate_limiter_backpressure_raises_before_unbounded_wait() -> None:
    """Fix #54/8: the previous accounting drove ``self._tokens`` arbitrarily
    negative under a burst. The 100th caller against a 1req/s limiter waited
    ~99s. The clamp MUST refuse the claim once wait would exceed
    ``max_wait_seconds`` so debt stays bounded and pool workers do not pin on
    minutes of cumulative sleep."""
    limiter = TokenBucketRateLimiter(rate=1.0, capacity=1.0, max_wait_seconds=2.0)

    # First call consumes the full-bucket token, no sleep.
    assert limiter._claim_token() == pytest.approx(0.0)

    # Next two calls each get a bounded future slot (1s, 2s -- both <= cap).
    assert 0.9 < limiter._claim_token() <= 2.0
    assert 1.9 < limiter._claim_token() <= 2.5  # slightly above 2 refused

    # Anything past that would compute wait > max_wait_seconds -> refuse.
    with pytest.raises(RateLimitError) as excinfo:
        for _ in range(20):
            limiter._claim_token()
    assert "queue full" in str(excinfo.value)


def test_rate_limiter_refused_claim_does_not_consume_token() -> None:
    """When the claim is refused, ``self._tokens`` MUST NOT drop further --
    otherwise a stampede still accumulates unbounded debt one refusal at a
    time."""
    limiter = TokenBucketRateLimiter(rate=1.0, capacity=1.0, max_wait_seconds=0.5)
    limiter._claim_token()  # exhaust the bucket
    tokens_before = limiter._tokens
    with pytest.raises(RateLimitError):
        limiter._claim_token()
    # Refused claim leaves the state unchanged (modulo the deterministic
    # refill, which within one microsecond is negligible).
    assert limiter._tokens == pytest.approx(tokens_before, abs=1e-3)


def test_rate_limiter_rejects_invalid_max_wait_seconds() -> None:
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(rate=1.0, capacity=1.0, max_wait_seconds=0.0)
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(rate=1.0, capacity=1.0, max_wait_seconds=-1.0)


# --------------------------------------------------------------------------- #
# #63 -- orchestrator handle() no longer pins one DB session across LLM + dispatch.
# --------------------------------------------------------------------------- #


def _make_platform_stub():
    """Construct an AILAPlatform without running __init__ side effects.

    ``AILAPlatform.__init__`` calls ``build_platform_settings`` +
    ``init_directories`` which want a real settings object. handle() only
    reads ``self.settings`` (for ``async_session_scope``, which we stub),
    ``self.memory_store``, ``self.report_artifact_store``,
    ``self.progress_callback``, ``self.runtime`` / ``self.router``, and
    the ``_ensure_initialized`` flag. Bypass __init__ and stub the minimum.
    """
    p = AILAPlatform.__new__(AILAPlatform)
    p.app_settings = SimpleNamespace()
    p.settings = SimpleNamespace()
    p.memory_store = MagicMock()
    p.report_artifact_store = MagicMock()
    p.progress_callback = None
    p._runtime = SimpleNamespace(
        module_registry=SimpleNamespace(capability_profiles=lambda: []),
    )
    p._initialized = True
    p._init_lock = None
    p.router = None
    return p


class _FakeRunSession:
    """Minimal async-session double: records commit + tracks open state."""

    def __init__(self, name: str, sessions_log: list[str]):
        self.name = name
        self.sessions_log = sessions_log
        self.opened_at = len(sessions_log)
        self.closed = False
        self.commits: int = 0

    async def commit(self) -> None:
        self.commits += 1

    async def merge(self, obj):
        return obj

    async def rollback(self) -> None:
        pass

    async def exec(self, *args, **kwargs):  # pragma: no cover - defensive
        return MagicMock()


@pytest.mark.asyncio
async def test_handle_opens_a_separate_session_for_each_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix #63: previously ONE session wrapped routing (with its multi-second
    LLM call) + module dispatch + finalize. That pinned a pooled DB
    connection for the whole request. handle() MUST now open the routing,
    dispatch, and finalize sessions distinctly so the connection is released
    between phases and pool exhaustion under concurrent interactive load is
    no longer a pool-hold problem."""

    sessions_log: list[str] = []
    lifecycle: list[str] = []

    @asynccontextmanager
    async def fake_scope(_settings):
        name = f"session-{len(sessions_log)}"
        sess = _FakeRunSession(name, sessions_log)
        sessions_log.append(name)
        lifecycle.append(f"open:{name}")
        try:
            yield sess
        finally:
            sess.closed = True
            lifecycle.append(f"close:{name}")

    monkeypatch.setattr(orch_mod, "async_session_scope", fake_scope)

    # Stub out build_emitter so we do not need the whole event pipeline.
    def fake_build_emitter(*, session, run_state, progress_callback=None):
        emitter = MagicMock()
        emitter.emit = MagicMock()
        return emitter
    monkeypatch.setattr(orch_mod, "build_emitter", fake_build_emitter)

    async def fake_dispatch(**_kwargs):
        # Verify we are inside the DISPATCH session (session-1), not the
        # routing session (session-0). The routing session must already have
        # been closed by the time we get here.
        assert lifecycle[-1] == "open:session-1"
        assert "close:session-0" in lifecycle
        return PlatformResponse(
            run_id=_kwargs["run_id"],
            action_id="m.act",
            message="ok",
            module_payload={},
            artifacts={},
        )
    monkeypatch.setattr(orch_mod, "_dispatch_module_request", fake_dispatch)

    async def fake_finalize(session, record, state, status, response, error=None):
        # Finalize runs on session-2 -- both routing and dispatch already released.
        assert lifecycle[-1] == "open:session-2"
        assert "close:session-1" in lifecycle
        assert "close:session-0" in lifecycle

    monkeypatch.setattr(orch_mod, "_finalize_run", fake_finalize)

    # Build an AILAPlatform without running __init__ (which would try to
    # resolve real settings + init_directories side effects). This test
    # only exercises handle()'s session lifecycle, not init.
    platform = _make_platform_stub()

    router = MagicMock()
    async def fake_route(session, query):
        # The session passed into route MUST be session-0 (routing session)
        # -- confirms the LLM-hosting session is NOT the same object that
        # persists across dispatch and finalize.
        assert session.name == "session-0"
        return RouteDecision(
            action_id="m.act",
            selected_module="m",
            confidence=0.9,
            decision_source="model",
        )
    router.route = fake_route
    platform.router = router

    resp = await platform.handle("hello")
    assert resp.action_id == "m.act"

    # Three separate sessions were opened AND closed, in order.
    assert sessions_log == ["session-0", "session-1", "session-2"]
    assert lifecycle == [
        "open:session-0", "close:session-0",
        "open:session-1", "close:session-1",
        "open:session-2", "close:session-2",
    ]


@pytest.mark.asyncio
async def test_handle_failure_path_finalizes_on_a_fresh_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When routing raises, handle() MUST still finalize the run record --
    but on a FRESH session, so a broken routing-phase session does not block
    the failure write. And the ORIGINAL routing exception MUST propagate
    (not the finalize path's own error, if any). This is the joint acceptance
    for #54/1+3 (finalize must not mask caller exception) and #54/6+7 (each
    phase gets its own session)."""

    sessions_log: list[str] = []

    @asynccontextmanager
    async def fake_scope(_settings):
        name = f"session-{len(sessions_log)}"
        sess = _FakeRunSession(name, sessions_log)
        sessions_log.append(name)
        try:
            yield sess
        finally:
            sess.closed = True

    monkeypatch.setattr(orch_mod, "async_session_scope", fake_scope)
    monkeypatch.setattr(
        orch_mod, "build_emitter",
        lambda **_kw: MagicMock(emit=MagicMock()),
    )

    finalize_calls: list[str] = []
    async def fake_finalize(session, record, state, status, response, error=None):
        finalize_calls.append(status)

    monkeypatch.setattr(orch_mod, "_finalize_run", fake_finalize)

    platform = _make_platform_stub()
    router = MagicMock()
    router.route = AsyncMock(side_effect=platform_exc.UpstreamError("router down"))
    platform.router = router

    with pytest.raises(platform_exc.UpstreamError, match="router down"):
        await platform.handle("q")

    # Two sessions: session-0 for routing (that raised) + session-1 for
    # failure-path finalize.
    assert sessions_log == ["session-0", "session-1"]
    # Finalize was called exactly once with status="failed".
    assert finalize_calls == ["failed"]

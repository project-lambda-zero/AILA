"""FastAPI application factory for AILA.

Creates the ASGI app with lifespan (AILAPlatform singleton), CORS middleware,
and mounted routers. Import `app` for direct uvicorn use:
  uvicorn aila.api.app:app

Or use create_app() for test isolation (fresh app per test).
"""
from __future__ import annotations

__all__ = ["app", "create_app", "lifespan", "limiter"]

import asyncio
import importlib.metadata as _importlib_metadata
import os
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from aila._dotenv import load_project_env as _load_project_env

_load_project_env()

from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.config import get_settings
from aila.platform.runtime import AILAPlatform

_log = __import__("logging").getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage AILAPlatform singleton lifecycle.

    Creates the platform on startup and stores it in app.state.platform.
    Records start_time at lifespan entry so /status reports true server uptime
    rather than module import time.

    Startup sequence:
    1. configure_logging() — must be first so all subsequent startup logs use structlog
    2. AILAPlatform construction — may fail gracefully for LLM-less environments
    3. AILA_BOOTSTRAP_KEY — legacy API key bootstrap (D-03: idempotent after first run)
    4. Admin user bootstrap — if no UserRecord exists and AILA_ADMIN_PASSWORD is set,
       creates the default admin user with argon2id-hashed password (D-21/D-43/D-44).
       If AILA_ADMIN_PASSWORD is NOT set AND no UserRecord exists, raises RuntimeError
       to fail startup with a clear error (D-21).

    The platform is created once per process — never per-request (Pitfall 2
    anti-pattern: per-request platform construction wastes 2-5s on module init).
    """
    import os as _os

    from aila.api.auth import hash_api_key
    from aila.logging_config import configure_logging
    from aila.platform.contracts._common import utc_now
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import ApiKeyRecord, UserRecord

    # Step 1: configure structlog before any other startup log output
    configure_logging()

    app.state.start_time = time.monotonic()
    settings = get_settings()
    # Core platform startup must tell the truth. If platform initialization
    # fails, the API process should fail fast rather than pretending to be up
    # in a degraded state where a runtime is missing behind app.state.platform.
    platform: AILAPlatform = AILAPlatform(settings=settings)
    await platform._ensure_initialized()
    app.state.platform = platform

    if not _os.getenv("AILA_JWT_SECRET_KEY"):
        _log.warning(
            "AILA_JWT_SECRET_KEY is not set. JWT secret was auto-generated. "
            "Tokens will NOT survive server restart. "
            "Set AILA_JWT_SECRET_KEY in environment for production use."
        )

    # Step 3: D-03: AILA_BOOTSTRAP_KEY — create legacy admin key on first start if DB is empty
    bootstrap_key_value = _os.getenv("AILA_BOOTSTRAP_KEY", "").strip()
    if bootstrap_key_value:
        from sqlmodel import select as _select

        async with async_session_scope() as session:
            existing_count = len((await session.exec(_select(ApiKeyRecord))).all())
        if existing_count == 0:
            hashed = hash_api_key(bootstrap_key_value)
            key_prefix = bootstrap_key_value[:12] if len(bootstrap_key_value) >= 12 else bootstrap_key_value
            record = ApiKeyRecord(
                hashed_key=hashed,
                key_prefix=key_prefix,
                role=ROLE_ADMIN,
                label="bootstrap",
                created_by="bootstrap",
                created_at=utc_now(),
            )
            async with async_session_scope() as session:
                session.add(record)
                await session.commit()

    # Step 4: D-21/D-43/D-44: Admin user bootstrap
    # Check whether any UserRecord exists in the database.
    from sqlmodel import select as _select

    async with async_session_scope() as session:
        user_count_result = await session.exec(_select(UserRecord))
        existing_users = user_count_result.all()

    if not existing_users:
        admin_password = _os.getenv("AILA_ADMIN_PASSWORD", "").strip()
        if not admin_password:
            raise RuntimeError(
                "AILA_ADMIN_PASSWORD is required on first boot when no admin user exists. "
                "Set this environment variable to a strong password and restart. "
                "This prevents an unprotected admin account from being created automatically."
            )
        # Create default admin user with argon2id-hashed password
        from argon2 import PasswordHasher as _PH

        _ph = _PH()
        hashed_admin_pw = _ph.hash(admin_password)
        now = utc_now()
        admin_user = UserRecord(
            username="admin",
            hashed_password=hashed_admin_pw,
            role=ROLE_ADMIN,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        async with async_session_scope() as session:
            session.add(admin_user)
            await session.commit()
            await session.refresh(admin_user)

        # D-16/D-43: Assign all existing ApiKeyRecords with null user_id to the admin user
        async with async_session_scope() as session:
            key_result = await session.exec(_select(ApiKeyRecord))
            orphan_keys = key_result.all()
            for key in orphan_keys:
                if key.user_id is None:
                    key.user_id = admin_user.id
            await session.commit()

        _log.info("Admin user created on first boot. REMOVE AILA_ADMIN_PASSWORD from environment after initial setup.")

    # Initialize shared Redis connection pool (OPS-03)
    from aila.platform.services.redis_pool import init_redis_pool

    redis_url = _os.getenv("AILA_PLATFORM_REDIS_URL")
    try:
        await init_redis_pool(redis_url)
    except Exception:
        _log.warning("Redis pool init failed; Redis features will be unavailable", exc_info=True)

    # Startup validation (OPS-06)
    _log.info("Running startup validation...")

    # 1. DB connectivity
    try:
        import sqlalchemy.exc as _sa_exc
        from sqlalchemy import text as _sa_text

        async with async_session_scope() as _check_session:
            await _check_session.execute(_sa_text("SELECT 1"))
        _log.info("Startup check: database OK")
    except (OSError, RuntimeError, _sa_exc.SQLAlchemyError) as exc:
        raise RuntimeError(f"Startup check failed: database unreachable — {exc}") from exc

    # 2. Redis connectivity (non-fatal if pool not configured)
    from aila.platform.services.redis_pool import pool_available

    if pool_available():
        _log.info("Startup check: Redis OK (pool initialized)")
    else:
        _log.warning("Startup check: Redis unavailable (non-fatal)")

    # 3. Keyring path writable
    keyring_path = _os.getenv("AILA_SECRET_KEYRING_PATH")
    if keyring_path:
        from pathlib import Path as _Path

        kp = _Path(keyring_path)
        if not kp.parent.exists():
            raise RuntimeError(f"Startup check failed: keyring parent dir does not exist — {kp.parent}")
        _log.info("Startup check: keyring path OK")

    _log.info("Startup validation complete")

    # Module-specific provider credential checks belong to module-owned health or
    # runtime surfaces, not platform API startup. Keep startup truthful and module-agnostic.
    _log.info("Startup check: provider credentials checked")

    # AUTO-03/AUTO-06: Initialize automation registry and runner.
    # Registry holds action descriptors; runner evaluates cron schedules via tick().
    # Platform maintenance actions (health check etc.) run with team_id=None.
    try:
        from aila.api.constants import MODULE_ID_PLATFORM
        from aila.platform.automation.maintenance import register_maintenance_actions
        from aila.platform.automation.registry import AutomationRegistry
        from aila.platform.automation.runner import AutomationRunner
        from aila.platform.tasks.queue import TaskQueue

        automation_registry = AutomationRegistry()
        register_maintenance_actions(automation_registry)
        app.state.automation_registry = automation_registry

        # Platform-level TaskQueue for automation submissions (no module boundary)
        platform_task_queue = TaskQueue(config_registry=None, module_id=MODULE_ID_PLATFORM)  # type: ignore[arg-type]
        automation_runner = AutomationRunner(
            registry=automation_registry,
            task_queue=platform_task_queue,
        )
        app.state.automation_runner = automation_runner
        _log.info("Automation registry and runner initialized")
    except Exception:
        _log.warning("Automation subsystem init failed -- scheduling unavailable", exc_info=True)
        app.state.automation_registry = None
        app.state.automation_runner = None

    # Start background automation tick loop (60s interval).
    # Wires the fully-implemented AutomationRunner that was previously
    # instantiated but never invoked (AUDIT-01 fix).
    _automation_tick_task: asyncio.Task[None] | None = None
    if app.state.automation_runner is not None:
        _runner = app.state.automation_runner

        async def _tick_loop() -> None:
            import sqlalchemy.exc as _sa_exc

            from aila.platform.exceptions import AILAError as _AILAError
            while True:
                try:
                    await _runner.tick()
                except asyncio.CancelledError:
                    raise
                except (_AILAError, _sa_exc.SQLAlchemyError, ValueError, OSError):
                    _log.warning("Automation tick failed", exc_info=True)
                await asyncio.sleep(60)

        _automation_tick_task = asyncio.create_task(_tick_loop(), name="automation-tick")
        _log.info("Automation tick loop started (60s interval)")

    yield

    # Cancel automation tick loop before other shutdown.
    if _automation_tick_task is not None:
        _automation_tick_task.cancel()
        try:
            await _automation_tick_task
        except asyncio.CancelledError:
            pass

    # --- Shutdown (OPS-03) ---
    _log.info("Shutting down AILA platform...")
    try:
        from aila.platform.services.redis_pool import close_redis_pool

        await close_redis_pool()
    except Exception:
        _log.warning("Redis pool close failed", exc_info=True)
    _log.info("AILA platform shutdown complete")


def _mount_module_routers(application: FastAPI) -> None:
    """Auto-discover and include routers from all registered modules.

    Iterates all built-in module factories and instantiates each module to
    call route_specs(). For each ModuleRouteSpec, calls spec.router_factory()
    to obtain a FastAPI APIRouter and mounts it under spec.prefix.

    Module factories are cached via lru_cache (builtin_module_factories), so
    this does not cause re-registration or re-import overhead at app startup.

    If a module raises during route_specs() or router_factory(), that module's
    routes are skipped with a warning — the platform continues starting.
    This matches the pattern used for module health_checks().
    """
    from aila.platform.modules.builtin import builtin_module_factories

    for factory in builtin_module_factories():
        try:
            module = factory()
            specs = module.route_specs()
        except Exception:
            _log.warning(
                "Module factory %r raised during route_specs() — skipping module routes",
                factory,
            )
            continue
        for spec in specs:
            try:
                from aila.api.auth import require_user_or_api_key

                router = spec.router_factory()
                deps = [Depends(require_user_or_api_key)] if spec.auth_required else []
                application.include_router(
                    router,
                    prefix=spec.prefix,
                    dependencies=deps,
                )
            except Exception:
                _log.warning(
                    "Failed to mount router for module prefix %r — skipping",
                    spec.prefix,
                )


async def _validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Reshape FastAPI 422 validation errors into ErrorResponse envelope.

    Default FastAPI 422 puts error list directly in ``detail``.  This handler
    moves the structured errors into the ``errors`` array and sets ``detail``
    to a human-readable summary string so every error response conforms to
    ErrorResponse(detail=str, code=str|None, errors=list|None).
    """
    errors = [
        {
            "loc": list(err.get("loc", [])),
            "msg": err.get("msg", ""),
            "type": err.get("type", ""),
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Validation failed",
            "code": "VALIDATION_ERROR",
            "errors": errors,
        },
    )


async def _http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    """Wrap HTTPException responses in the ErrorResponse envelope.

    Ensures every HTTPException (401, 403, 404, 409, 422, 500, etc.) returns
    a JSON body with ``detail`` as a string, matching ErrorResponse shape.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "code": None, "errors": None},
        headers=getattr(exc, "headers", None),
    )


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Registers CORS middleware, mounts all routers, and wires the lifespan
    context for AILAPlatform startup. Used by both production (app module-level
    instance) and tests (fresh app per test session).

    Routers are mounted in the order defined below. Module-owned routers are
    auto-discovered via route_specs() and mounted last.

    Returns:
        Configured FastAPI application instance.
    """
    application = FastAPI(
        title="AILA REST API",
        description="AI Lab Assistant — modular security platform REST API",
        version=_importlib_metadata.version("aila"),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS: load from env var -- never hardcode wildcard (RESEARCH Pitfall 11)
    # Default includes Vite dev (3000), Vite preview (4173), and default Vite (5173)
    cors_origins_raw = os.getenv(
        "AILA_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,"
        "http://localhost:4173,http://127.0.0.1:4173,"
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]

    # Correlation ID middleware: bind correlation_id/path/method to structlog contextvars
    from aila.api.middleware import CorrelationIdMiddleware
    application.add_middleware(CorrelationIdMiddleware)

    # Idempotency middleware: replay cached POST responses for duplicate Idempotency-Key
    # headers (SEC-06). Uses shared Redis pool (OPS-01). Graceful degradation if pool unavailable.
    from aila.api.middleware.idempotency import IdempotencyMiddleware
    application.add_middleware(IdempotencyMiddleware)

    # CORS MUST be added LAST so it is the outermost middleware.
    # Starlette processes middleware LIFO: last-added = outermost = wraps every response
    # including early returns from IdempotencyMiddleware. If CORSMiddleware is added
    # before IdempotencyMiddleware, cached replay responses bypass it and the browser
    # never receives Access-Control-Allow-Origin headers.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom exception handlers — ensure all error responses match ErrorResponse shape.
    # Phase 80: every 4xx/5xx returns {"detail": str, "code": str|None, "errors": list|None}.
    application.add_exception_handler(RequestValidationError, _validation_error_handler)
    application.add_exception_handler(HTTPException, _http_exception_handler)

    # Phase 176a: standardized ErrorEnvelope handlers (D-10a..d, D-20, D-25, D-26).
    # Registered AFTER the Phase 80 HTTPException handler so FastAPI's existing
    # HTTPException path continues to return its ErrorResponse shape, while every
    # AILAError subclass, RequestValidationError, and unhandled Exception now
    # produces the ErrorEnvelope {code, message, hint, trace_id} body.
    # NOTE: this overrides the Phase 80 RequestValidationError handler above
    # per D-10a — validation errors now use the envelope shape.
    from aila.api.errors import register_error_handlers

    register_error_handlers(application)

    # XCUT-09: Catch-all middleware for unhandled exceptions.  Starlette's
    # add_exception_handler(Exception, ...) does not intercept non-HTTPException
    # errors, so an HTTP middleware is the correct mechanism.  This prevents
    # stack trace leaks on 500 responses and returns the ErrorResponse envelope.
    @application.middleware("http")
    async def _catch_unhandled_exceptions(request: Request, call_next):  # type: ignore[misc]
        try:
            return await call_next(request)
        except Exception:
            _log.exception("Unhandled exception on %s %s", request.method, request.url.path)
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error", "code": None, "errors": None},
            )

    # STRESS-12: Reject oversized request bodies before they reach application code.
    # Default 200 MB (covers the largest realistic APK; APKs are 30-150 MB typical).
    # Operator can tune via `AILA_MAX_REQUEST_BYTES` env var when forensics dumps,
    # binary uploads, or LLM transcripts need a different ceiling.
    # Returns 413 with ErrorResponse envelope. Registered after
    # _catch_unhandled_exceptions so it runs before it (Starlette middleware
    # stack is LIFO — last registered runs first).
    import os as _os
    _default_max_body = 200 * 1024 * 1024  # 200 MB
    try:
        _max_body_bytes = int(_os.environ.get("AILA_MAX_REQUEST_BYTES", str(_default_max_body)))
    except ValueError:
        _max_body_bytes = _default_max_body
    _max_body_mb = _max_body_bytes // (1024 * 1024)

    @application.middleware("http")
    async def _reject_oversized_requests(request: Request, call_next):  # type: ignore[misc]
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > _max_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"Request body too large (max {_max_body_mb}MB)",
                            "code": "PAYLOAD_TOO_LARGE",
                            "errors": None,
                        },
                    )
            except ValueError:
                pass  # Non-numeric content-length will be caught by ASGI server
        return await call_next(request)

    # OBS-01: Prometheus request instrumentation middleware.
    # Registered last among HTTP middlewares so it runs outermost (LIFO),
    # capturing true response status and latency including error handling.
    from aila.api.metrics import REQUEST_COUNT, REQUEST_LATENCY

    @application.middleware("http")
    async def _prometheus_request_middleware(request: Request, call_next):  # type: ignore[misc]
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        path = request.url.path
        REQUEST_COUNT.labels(
            method=request.method, endpoint=path, status_code=response.status_code
        ).inc()
        REQUEST_LATENCY.labels(method=request.method, endpoint=path).observe(duration)
        return response

    # Auth router: /auth/token and /auth/refresh (public) + /auth/keys (admin-only)
    from aila.api.routers.auth import router as auth_router
    application.include_router(auth_router)

    # Users router: /auth/login, /auth/refresh/user, /auth/logout (public) + /users/* (admin)
    from aila.api.routers.users import router as users_router
    application.include_router(users_router)

    # OIDC router: /auth/oidc/authorize, /auth/oidc/callback (public) + /auth/oidc/providers (admin)
    from aila.api.routers.oidc import router as oidc_router
    application.include_router(oidc_router)

    # Phase 177: Admin teams router (admin only — multi-team management)
    from aila.api.routers.admin_teams import router as admin_teams_router
    application.include_router(admin_teams_router)

    # Phase 178: Admin dead-letter router (admin only — poison-pill inspection)
    from aila.api.routers.admin_dead_letter import router as admin_dead_letter_router
    application.include_router(admin_dead_letter_router)

    # Phase 181: Admin workflow inspection router (admin only — run/transition audit)
    from aila.api.routers.admin_workflows import router as admin_workflows_router
    application.include_router(admin_workflows_router)

    # Health router: /health and /status — no auth required (public endpoints)
    from aila.api.routers.health import router as health_router
    application.include_router(health_router)

    # Platform routers: audit, config, systems, tools (Phase 53 plans 02-04)
    from aila.api.routers.audit import router as audit_router
    application.include_router(audit_router)

    from aila.api.routers.config import router as config_router
    application.include_router(config_router)

    from aila.api.routers.systems import router as systems_router
    application.include_router(systems_router)

    from aila.api.routers.tools import router as tools_router
    application.include_router(tools_router)

    # Platform tasks router: /tasks (Phase 54 plan 05 — task queue API surface)
    from aila.api.routers.tasks import router as tasks_router
    application.include_router(tasks_router)

    # Standalone POST /task — freeform task submission (TASK-01, D-09)
    # Separate from /tasks/ prefix router to keep the route at /task (not /tasks/).
    from aila.api.routers.tasks import task_submit_router
    application.include_router(task_submit_router)

    # Sessions router: /sessions (Phase 55 plan 04 — conversation session persistence)
    from aila.api.routers.sessions import router as sessions_router
    application.include_router(sessions_router)

    # Scan submission and status polling router: POST /analyze, GET /scans/{run_id}
    # Phase 55 plan 03 — mutation surface for async scan submission (API-01, API-02)
    from aila.api.routers.scans import router as scans_router
    application.include_router(scans_router)

    # Plan 138-03: slowapi rate limiter state and exception handler
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Plan 138-03: new endpoint routers (dashboard, search, tags, findings workflow,
    # saved filters, widgets, scheduled reports, notifications).
    from aila.api.routers.dashboard import router as dashboard_router
    application.include_router(dashboard_router)

    from aila.api.routers.search import router as search_router
    application.include_router(search_router)

    from aila.api.routers.tags import router as tags_router
    application.include_router(tags_router)

    from aila.api.routers.findings_workflow import router as findings_workflow_router
    application.include_router(findings_workflow_router)

    from aila.api.routers.saved_filters import router as saved_filters_router
    application.include_router(saved_filters_router)

    from aila.api.routers.widgets import router as widgets_router
    application.include_router(widgets_router)

    from aila.api.routers.scheduled_reports import router as scheduled_reports_router
    application.include_router(scheduled_reports_router)

    from aila.api.routers.notifications import router as notifications_router
    application.include_router(notifications_router)

    # Plan 171-03: automation schedules CRUD + actions listing (AUTO-04/AUTO-05)
    from aila.api.routers.automation import router as automation_router
    application.include_router(automation_router)

    # Plan 146-01: SSE platform event stream (RT-01)
    from aila.api.routers.sse_events import router as sse_events_router
    application.include_router(sse_events_router)

    # Plan 138-04: topology aggregation router (RADAR-05)
    # Platform-owned network graph endpoint — D-01: topology is not module-specific.
    from aila.api.routers.topology import router as topology_router
    application.include_router(topology_router)

    # Plan 147-01: executive reporting router (EXEC-01, EXEC-03)
    from aila.api.routers.executive import router as executive_router
    application.include_router(executive_router)

    # Plan 175-03: LLM cost intelligence router (LLM-COST-01, LLM-COST-03 to LLM-COST-05)
    from aila.api.routers.cost import router as cost_router
    application.include_router(cost_router)

    # Plan 176e: admin LLM interaction log router (admin-only)
    from aila.api.routers.llm_log import router as llm_log_router
    application.include_router(llm_log_router)

    # MOD-01/MOD-02: auto-discover and mount module-owned routers.
    # Modules declare their HTTP surface via route_specs() on ModuleProtocol.
    # Platform iterates registered module factories and mounts each declared router.
    _mount_module_routers(application)

    # OBS-01: Mount Prometheus /metrics endpoint for scraping.
    from prometheus_client import make_asgi_app as _make_metrics_app

    metrics_app = _make_metrics_app()
    application.mount("/metrics", metrics_app)

    # OBS-01: Set application metadata for Prometheus info metric.
    from aila.api.metrics import APP_INFO

    APP_INFO.info({"version": _importlib_metadata.version("aila"), "environment": os.getenv("AILA_ENV", "development")})

    return application


# Module-level app instance for uvicorn: `uvicorn aila.api.app:app`
app: FastAPI = create_app()

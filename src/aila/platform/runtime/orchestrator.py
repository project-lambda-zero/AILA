from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

import sqlalchemy.exc

from ...config import get_settings, init_directories
from ...storage.database import async_session_scope
from ...storage.db_models import WorkflowRunRecord
from ...storage.memory import PermanentMemoryStore, append_run_event
from ...storage.report_store import ReportArtifactStore
from ..config import (
    ApplicationSettings,
    PlatformSettings,
    build_platform_settings,
)
from ..contracts._common import JsonObject, utc_now
from ..contracts.platform import ProgressUpdate
from ..contracts.runtime import PlatformResponse, RunState
from ..events import PlatformEvent, build_emitter
from ..modules.protocol import UNROUTABLE_ACTION_ID, ModuleExecutionContext, ModuleRequest
from ..routing import ModuleRouter
from .builder import build_platform_runtime
from .platform import PlatformRuntime

_log = logging.getLogger(__name__)


_WORKER_PLATFORM: AILAPlatform | None = None
# #54 fix: create the asyncio.Lock lazily inside the running loop. Binding
# ``asyncio.Lock()`` at import time issued a DeprecationWarning on 3.10+ and
# risked a loop-mismatch RuntimeError under uvloop when the worker and web
# event loops differed.
_WORKER_PLATFORM_LOCK: asyncio.Lock | None = None


def _get_worker_platform_lock() -> asyncio.Lock:
    """Return the module-level init lock, creating it lazily on first use.

    Called from the running event loop so ``asyncio.Lock()`` binds to a live
    loop. Safe against the ``None -> Lock()`` race in async code because the
    creation is a synchronous assignment between two ``is None`` reads and
    the event loop only advances at ``await`` points.
    """
    global _WORKER_PLATFORM_LOCK
    if _WORKER_PLATFORM_LOCK is None:
        _WORKER_PLATFORM_LOCK = asyncio.Lock()
    return _WORKER_PLATFORM_LOCK


async def get_worker_platform(
    app_settings: ApplicationSettings | None = None,
) -> AILAPlatform:
    """Return the process-local worker platform, initializing it on first use."""
    global _WORKER_PLATFORM
    if _WORKER_PLATFORM is not None:
        return _WORKER_PLATFORM
    async with _get_worker_platform_lock():
        if _WORKER_PLATFORM is None:
            platform = AILAPlatform(settings=app_settings or get_settings())
            await platform._ensure_initialized()
            _WORKER_PLATFORM = platform
    if _WORKER_PLATFORM is None:
        raise RuntimeError("Worker platform initialization failed")
    return _WORKER_PLATFORM


class AILAPlatform:
    """The top-level entry point for all AILA operations.

    Owns the full lifecycle from query intake through routing, module dispatch,
    audit logging, run record persistence, and response construction. One
    AILAPlatform instance is created per process; each handle() call creates
    a fresh RunState, emitter, and session scope.

    The router checks DecisionCache first (if TTL > 0), then delegates to
    the LLM model. Module dispatch happens through PlatformRuntime.require_module()
    and ModuleRuntime.handle(). All workflow events are fanned out via the
    ThreadSafeEventEmitter to audit_db, run_history, and progress destinations.
    """

    def __init__(
        self,
        settings: ApplicationSettings | None = None,
        runtime: PlatformRuntime | None = None,
        progress_callback: Callable[[ProgressUpdate], None] | None = None,
    ):
        self.app_settings = settings or get_settings()
        self.settings: PlatformSettings = build_platform_settings(self.app_settings)
        init_directories(self.app_settings)   # per D-04: directories initialized once at startup
        self.memory_store = PermanentMemoryStore()
        self.report_artifact_store = ReportArtifactStore()
        self._runtime = runtime
        self._initialized = runtime is not None
        self.router: ModuleRouter | None = None
        self.progress_callback = progress_callback
        # #54 fix: per-instance init lock guards concurrent handle() calls on
        # a fresh platform. Created lazily inside the running loop (see
        # ``_ensure_initialized``) so the Lock binds to the correct loop and
        # never dangles at import time.
        self._init_lock: asyncio.Lock | None = None

    async def _ensure_initialized(self) -> None:
        """Lazily initialize the platform runtime and router on first use.

        Single-flight behind ``self._init_lock`` so concurrent ``handle()``
        callers on a fresh :class:`AILAPlatform` build one runtime, not one
        per caller (#54). ``build_platform_runtime`` already calls
        ``init_db`` internally with the correct ``ApplicationSettings`` and
        ``schema_registry``; the orchestrator no longer duplicates that
        call (which previously passed ``PlatformSettings`` where
        ``ApplicationSettings`` was expected and, thanks to the
        ``_INITIALIZED_URLS`` fast-path, would race the builder's
        schema-registry init to first-write on cold start).
        """
        if self._initialized:
            return
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        async with self._init_lock:
            # Second check inside the lock: a concurrent caller may have
            # completed initialization while we were waiting for the lock.
            if self._initialized:
                return
            self._runtime = await build_platform_runtime(
                app_settings=self.app_settings,
                platform_settings=self.settings,
            )
            # CFG-02: Re-resolve settings with operator-configured values now available
            if self._runtime.config_registry is not None:
                resolved_config = await self._runtime.config_registry.all_entries_by_namespace()
                self.settings = build_platform_settings(
                    self.app_settings, resolved_config=resolved_config
                )
            self.router = ModuleRouter(
                module_registry=self._runtime.module_registry,
                model=self._runtime.runtime_model,
                minimum_confidence=self.settings.routing_min_confidence,
                memory_store=self.memory_store,
                decision_cache_ttl_hours=self.settings.routing_decision_cache_ttl_hours,
            )
            self._initialized = True

    @property
    def runtime(self) -> PlatformRuntime:
        """Access the platform runtime. Raises if not yet initialized."""
        if self._runtime is None:
            raise RuntimeError("AILAPlatform not initialized. Call await _ensure_initialized() first.")
        return self._runtime

    async def handle(
        self,
        query: str,
        module_payload: JsonObject | None = None,
        module_options: JsonObject | None = None,
        progress_callback: Callable[[ProgressUpdate], None] | None = None,
        debug: bool = False,
        run_id: str | None = None,
        team_id: str | None = None,
    ) -> PlatformResponse:
        """Route and execute the query, returning a typed PlatformResponse.

        Creates a WorkflowRunRecord and RunState for this request, builds the
        emitter, routes via ModuleRouter, dispatches to the selected module,
        finalizes the run record, and strips state_history unless debug=True.
        Exceptions are emitted as 'failed' events, the run record is finalized
        with status='failed', and the exception is re-raised for the caller.
        """
        await self._ensure_initialized()
        request_payload = dict(module_payload or {})
        request_options = dict(module_options or {})

        run_record = WorkflowRunRecord(query_text=query)
        if run_id:
            run_record.id = run_id
        # Stamp the owning team so team-scoped readers (report list, module
        # health summaries) surface this run instead of hiding it. Queued
        # runs pass the team the task carries; direct API callers pass the
        # request team; god-tier and CLI leave it None (#36).
        run_record.team_id = team_id
        run_state = RunState(run_id=run_record.id, query=query)
        progress_cb = progress_callback or self.progress_callback

        # #63 fix: split the previous single ``async with async_session_scope``
        # spanning routing + module dispatch + finalize into three short
        # sessions. A pooled DB connection is no longer pinned across the
        # multi-second module-dispatch phase or across ``_finalize_run``; each
        # phase acquires a connection, commits, and releases it back to the
        # pool before the next phase starts. Routing still holds its own
        # session across the LLM round-trip inside ``router.route`` -- that
        # is local to the routing package and out of the orchestrator's
        # file domain -- but the connection is released the moment routing
        # returns instead of lingering for the whole request.
        try:
            # Phase 1: routing. The DecisionCache write inside
            # ``router.route`` uses ``commit=False``; commit here so the
            # cache row survives the scope exit.
            async with async_session_scope(self.settings) as routing_session:
                routing_emitter = build_emitter(
                    session=routing_session,
                    run_state=run_state,
                    progress_callback=progress_cb,
                )
                route = await self.router.route(routing_session, query)
                run_state.route = route
                run_record.action_id = route.action_id
                routing_emitter.emit(PlatformEvent(
                    stage="routing",
                    action="route",
                    key="routed",
                    message=(
                        f"Route selected: module={route.selected_module or 'none'}, action={route.action_id}, "
                        f"source={route.decision_source}, confidence={route.confidence if route.confidence is not None else 'n/a'}"
                        f"{f', rationale={route.rationale}' if route.rationale else ''}"
                    ),
                    run_id=run_record.id,
                ))
                await routing_session.commit()

            # Phase 2: module dispatch on a fresh, short-lived session so
            # the routing connection is already released while modules do
            # their (potentially slow) work. Modules manage their own
            # commits inside the session -- see hello_world/vulnerability/
            # forensics module.py for the canonical shape.
            async with async_session_scope(self.settings) as dispatch_session:
                dispatch_emitter = build_emitter(
                    session=dispatch_session,
                    run_state=run_state,
                    progress_callback=progress_cb,
                )
                execution_context = ModuleExecutionContext(
                    memory_store=self.memory_store,
                    report_artifact_store=self.report_artifact_store,
                    progress_callback=progress_cb,
                    emitter=dispatch_emitter,
                )
                response = await _dispatch_module_request(
                    runtime=self.runtime,
                    session=dispatch_session,
                    action_id=route.action_id,
                    run_id=run_record.id,
                    run_state=run_state,
                    execution_context=execution_context,
                    module_payload=request_payload,
                    module_options=request_options,
                )

            # Phase 3: persist the run record. Fresh session so a slow
            # finalize write cannot pin a connection during dispatch.
            async with async_session_scope(self.settings) as finalize_session:
                await _finalize_run(finalize_session, run_record, run_state, "completed", response)

            if not debug:
                response = response.model_copy(update={"state_history": []})
            return response
        except Exception as exc:
            error_payload = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            # Persist the failure record on a fresh session so the caller's
            # exception is preserved verbatim even if the previous phase's
            # session/connection is already broken. Any error here is logged
            # and swallowed so ``raise`` re-surfaces the original exception
            # (#54: _finalize_run must never mask the original error).
            try:
                async with async_session_scope(self.settings) as failure_session:
                    failure_emitter = build_emitter(
                        session=failure_session,
                        run_state=run_state,
                        progress_callback=progress_cb,
                    )
                    failure_emitter.emit(PlatformEvent(
                        stage="routing",
                        action="fail",
                        key="failed",
                        message=f"{error_payload['type']}: {error_payload['message']}",
                        run_id=run_record.id,
                    ))
                    await _finalize_run(
                        failure_session, run_record, run_state, "failed",
                        None, error=error_payload,
                    )
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
                _log.exception(
                    "Failed to persist failure record for run %s; "
                    "original exception %s will still propagate.",
                    run_record.id, type(exc).__name__,
                )
            raise


async def _dispatch_module_request(
    *,
    runtime: PlatformRuntime,
    session: Any,
    action_id: str,
    run_id: str,
    run_state: RunState,
    execution_context: ModuleExecutionContext,
    module_payload: JsonObject | None = None,
    module_options: JsonObject | None = None,
) -> PlatformResponse:
    """Look up the selected module runtime and invoke its handle() method.

    Returns an unroutable response when action_id is UNROUTABLE_ACTION_ID.
    Raises ValueError if the router assigned an action but no module was
    selected (should not happen in normal routing flow).
    """
    if action_id == UNROUTABLE_ACTION_ID:
        return _build_unknown_response(runtime, run_id, run_state)
    selected_module = run_state.route.selected_module if run_state.route else None
    if not selected_module:
        raise ValueError("Router returned no selected module for a routable action.")
    module_runtime = runtime.require_module(selected_module)
    return await module_runtime.handle(
        ModuleRequest(
            session=session,
            run_id=run_id,
            action_id=action_id,
            run_state=run_state,
            execution_context=execution_context,
            payload=dict(module_payload or {}),
            options=dict(module_options or {}),
        )
    )


def _build_unknown_response(
    runtime: PlatformRuntime,
    run_id: str,
    run_state: RunState,
) -> PlatformResponse:
    """Build a graceful response when the router could not confidently route the query.

    Lists all supported action IDs so the caller knows what the platform can handle.
    """
    supported_actions = sorted(
        {
            profile.action_id
            for profile in runtime.module_registry.capability_profiles()
        }
    )
    message = (
        "I could not confidently route that request. "
        f"Installed modules currently support: {', '.join(supported_actions)}."
    )
    append_run_event(run_state, "routing_uncertain", message)
    return PlatformResponse(
        run_id=run_id,
        action_id=UNROUTABLE_ACTION_ID,
        message=message,
        route=run_state.route,
        module_payload={"query_mode": "unroutable", "supported_actions": supported_actions},
        state_history=run_state.events,
    )


async def _finalize_run(
    session: Any,
    run_record: WorkflowRunRecord,
    run_state: RunState,
    status: str,
    response: PlatformResponse | None,
    error: JsonObject | None = None,
) -> None:
    """Persist the completed run record to the database.

    Writes run status, route JSON, run_state snapshot, summary JSON (action,
    module, payload, artifacts, error), and completed_at timestamp. Called for
    both successful and failed runs so every handle() call always produces a
    persisted WorkflowRunRecord.

    #54 fix: every ``run_state.route`` dereference now guards ``run_state.route
    is None`` BEFORE reading an attribute (previous code parsed as
    ``selected_module or ("" if route else "")``, dereferencing ``.selected_module``
    on the None branch and raising ``AttributeError`` inside the caller's
    ``except`` handler -- which shadowed the original routing exception).
    The whole persistence step is also wrapped in a broad guard: this helper
    must never raise back into the orchestrator's error-path ``except`` block
    because that path is running under an already-active caller exception and
    a second raise would replace it. All failures are logged and swallowed.
    """
    try:
        route = run_state.route
        # None guards precede attribute access on every branch (#54 finding).
        selected_module: str | None = route.selected_module if route is not None else None
        route_action_id: str = route.action_id if route is not None else ""
        route_json: str = route.model_dump_json() if route is not None else "{}"

        run_record.status = status
        run_record.route_json = route_json
        response_payload = dict(response.module_payload) if response else {}
        artifacts = dict(run_state.artifacts)
        if response:
            artifacts.update(response.artifacts)
        run_record.short_memory_json = json.dumps(
            {
                "run_state": run_state.model_dump(mode="json"),
                "error": error,
            }
        )
        run_record.summary_json = json.dumps(
            {
                "action_id": (response.action_id if response else route_action_id),
                "module_id": selected_module,
                "module_payload": response_payload,
                "artifacts": artifacts,
                "error": error,
            }
        )
        # None guard precedes attribute access; ``or ""`` coerces the empty
        # (or None) selected_module to a stable empty string so downstream
        # readers get a consistent value on unroutable / failed runs.
        run_record.module_id = (selected_module if route is not None else "") or ""
        run_record.report_path = _primary_report_path(artifacts)
        run_record.completed_at = utc_now()
    except (AttributeError, TypeError, ValueError) as exc:
        # Payload assembly failed (e.g. an unexpected route shape). Log and
        # bail -- the caller's original exception must remain the one that
        # propagates.
        _log.warning(
            "Failed to assemble run record payload for run %s: %s",
            run_record.id, exc, exc_info=True,
        )
        return

    try:
        await session.merge(run_record)
        await session.commit()
    except sqlalchemy.exc.SQLAlchemyError:
        try:
            await session.rollback()
        except sqlalchemy.exc.SQLAlchemyError:
            _log.warning(
                "Rollback failed for run record %s during finalize",
                run_record.id, exc_info=True,
            )
            return
        try:
            await session.merge(run_record)
            await session.commit()
        except sqlalchemy.exc.SQLAlchemyError:
            _log.warning(
                "Failed to finalize run record %s after rollback",
                run_record.id, exc_info=True,
            )


def _primary_report_path(artifacts: dict[str, str]) -> str | None:
    """Extract the primary report path from the artifacts dict.

    Prefers the 'primary_report' key; falls back to the first key ending
    with '_report' in sorted order. Returns None if no report artifact exists.
    """
    primary_report = artifacts.get("primary_report")
    if isinstance(primary_report, str):
        return primary_report
    for key in sorted(artifacts):
        value = artifacts[key]
        if key.endswith("_report") and isinstance(value, str):
            return value
    return None

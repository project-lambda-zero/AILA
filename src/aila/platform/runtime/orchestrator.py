from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

import sqlalchemy.exc

from ...config import get_settings, init_directories
from ...storage.database import async_session_scope, init_db
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
_WORKER_PLATFORM_LOCK: asyncio.Lock = asyncio.Lock()


async def get_worker_platform(
    app_settings: ApplicationSettings | None = None,
 ) -> AILAPlatform:
    """Return the process-local worker platform, initializing it on first use."""
    global _WORKER_PLATFORM
    if _WORKER_PLATFORM is not None:
        return _WORKER_PLATFORM
    async with _WORKER_PLATFORM_LOCK:
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

    async def _ensure_initialized(self) -> None:
        """Lazily initialize the platform runtime and router on first use."""
        if self._initialized:
            return
        await init_db(self.settings)
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

        async with async_session_scope(self.settings) as session:
            emitter = build_emitter(
                session=session,
                run_state=run_state,
                progress_callback=progress_callback or self.progress_callback,
            )
            execution_context = ModuleExecutionContext(
                memory_store=self.memory_store,
                report_artifact_store=self.report_artifact_store,
                progress_callback=progress_callback or self.progress_callback,
                emitter=emitter,
            )
            try:
                route = await self.router.route(session, query)
                run_state.route = route
                run_record.action_id = route.action_id
                emitter.emit(PlatformEvent(
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
                response = await _dispatch_module_request(
                    runtime=self.runtime,
                    session=session,
                    action_id=route.action_id,
                    run_id=run_record.id,
                    run_state=run_state,
                    execution_context=execution_context,
                    module_payload=request_payload,
                    module_options=request_options,
                )
                await _finalize_run(session, run_record, run_state, "completed", response)
                if not debug:
                    response = response.model_copy(update={"state_history": []})
                return response
            except Exception as exc:
                error_payload = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                emitter.emit(PlatformEvent(
                    stage="routing",
                    action="fail",
                    key="failed",
                    message=f"{error_payload['type']}: {error_payload['message']}",
                    run_id=run_record.id,
                ))
                await _finalize_run(session, run_record, run_state, "failed", None, error=error_payload)
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
        module_payload={"supported_actions": supported_actions},
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
    """
    run_record.status = status
    run_record.route_json = run_state.route.model_dump_json() if run_state.route else "{}"
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
            "action_id": (response.action_id if response else (run_state.route.action_id if run_state.route else "")),
            "module_id": run_state.route.selected_module if run_state.route else None,
            "module_payload": response_payload,
            "artifacts": artifacts,
            "error": error,
        }
    )
    run_record.module_id = run_state.route.selected_module or "" if run_state.route else ""
    run_record.report_path = _primary_report_path(artifacts)
    run_record.completed_at = utc_now()
    try:
        await session.merge(run_record)
        await session.commit()
    except sqlalchemy.exc.SQLAlchemyError:
        await session.rollback()
        try:
            await session.merge(run_record)
            await session.commit()
        except sqlalchemy.exc.SQLAlchemyError:
            _log.warning("Failed to finalize run record %s after rollback", run_record.id, exc_info=True)


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

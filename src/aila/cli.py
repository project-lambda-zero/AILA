from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pydantic
import typer

from ._dotenv import load_project_env as _load_project_env

_load_project_env()

__all__ = ["app", "main"]
import sqlalchemy.exc
from sqlmodel import delete as sqlmodel_delete
from sqlmodel import select as sqlmodel_select

from .config import get_settings
from .logging import configure_logging, get_logger
from .modules.vulnerability.config_schema import VulnerabilityConfigSchema
from .modules.vulnerability.contracts import (
    AdvisoryStrategyKey,
    DistributionProfileInput,
    LinuxDistribution,
    PackageParserKey,
)
from .modules.vulnerability.db_models import (
    CacheRecord,
    InventoryArtifactRecord,
)
from .modules.vulnerability.module import VulnerabilityModule
from .modules.vulnerability.runtime import VulnerabilityRuntime
from .modules.vulnerability.tools.baseline import baseline_compare as _baseline_compare
from .modules.vulnerability.tools.baseline import baseline_create as _baseline_create
from .modules.vulnerability.tools.blast_radius import blast_radius as _blast_radius
from .modules.vulnerability.tools.cve_arrivals import arrivals_departures as _arrivals_departures
from .modules.vulnerability.tools.digest import weekly_digest as _weekly_digest
from .modules.vulnerability.tools.heat_map import package_heat_map as _package_heat_map
from .modules.vulnerability.tools.inventory_drift import inventory_drift as _inventory_drift
from .modules.vulnerability.tools.kb_insights import kb_insights as _kb_insights
from .modules.vulnerability.tools.mttr import mttr as _mttr
from .modules.vulnerability.tools.patch_playbook import patch_playbook as _patch_playbook
from .modules.vulnerability.tools.peer_compare import peer_compare as _peer_compare
from .modules.vulnerability.tools.profiles import DistributionProfileTool
from .modules.vulnerability.tools.scheduled_scans import run_pending as _run_pending
from .modules.vulnerability.tools.scheduled_scans import schedule_status as _schedule_status
from .modules.vulnerability.tools.scoring_audit import scoring_audit as _scoring_audit
from .modules.vulnerability.tools.scoring_policy import DEFAULT_SCORING_POLICY_ID, ScoringPolicyTool
from .modules.vulnerability.tools.service_check import service_active_check as _service_active_check
from .modules.vulnerability.tools.sla_breach import sla_breach as _sla_breach
from .modules.vulnerability.tools.tag_risk import tag_risk as _tag_risk
from .modules.vulnerability.tools.verify_remediation import verify_remediation as _verify_remediation
from .modules.vulnerability.tools.what_if import what_if_patch as _what_if_patch
from .modules.vulnerability.workflow.planning import resolve_dry_run_targets
from .platform.config import PlatformConfigSchema, build_platform_settings
from .platform.contracts.platform import ProgressUpdate, SSHIntegrationInput
from .platform.exceptions import AILAError
from .platform.modules import load_builtin_modules
from .platform.routing import get_agent_stats, get_registered_schemas
from .platform.runtime import AILAPlatform
from .platform.runtime.tools import ToolRegistry
from .platform.services.audit import record_audit_event_sync
from .platform.services.ssh import SSHService
from .platform.tools import (
    ArtifactSearchTool,
    ArtifactStoreTool,
    AuditLogTool,
    DecisionCacheTool,
    HTTPFetchTool,
    KnowledgeRetrieveTool,
    KnowledgeStoreTool,
    PermanentMemoryTool,
    ReportsQueryTool,
    SecretsManageTool,
    SSHCommandTool,
    SystemRegistryTool,
)
from .storage.database import async_session_scope, backup_database, init_db
from .storage.provider_config import ProviderConfigStore
from .storage.secrets import SecretStore


def _run_async(coro):
    """Run an async coroutine from sync CLI context."""
    import asyncio
    return asyncio.run(coro)


class _SyncSessionProxy:
    """Wraps an AsyncSession for sync access from CLI commands.

    Each session method is executed via the proxy's dedicated event loop.
    Intentionally not optimized -- CLI commands are not latency-sensitive.
    """

    def __init__(self, async_session, loop):
        self._session = async_session
        self._loop = loop

    def exec(self, stmt):
        return self._loop.run_until_complete(self._session.exec(stmt))

    def execute(self, stmt):
        return self._loop.run_until_complete(self._session.execute(stmt))

    def commit(self):
        return self._loop.run_until_complete(self._session.commit())

    def refresh(self, obj):
        return self._loop.run_until_complete(self._session.refresh(obj))

    def add(self, obj):
        self._session.add(obj)

    def delete(self, obj):
        return self._loop.run_until_complete(self._session.delete(obj))

    def get(self, model, pk):
        return self._loop.run_until_complete(self._session.get(model, pk))


from contextlib import contextmanager as _contextmanager


@_contextmanager
def session_scope(settings=None):
    """Sync session scope for CLI commands, bridging to async_session_scope."""
    import asyncio as _aio

    loop = _aio.new_event_loop()
    ctx = async_session_scope(settings)
    session = loop.run_until_complete(ctx.__aenter__())
    proxy = _SyncSessionProxy(session, loop)
    try:
        yield proxy
    finally:
        loop.run_until_complete(ctx.__aexit__(None, None, None))
        loop.close()
from .storage.db_models import AuditEventRecord, ManagedSystemRecord, ReportArtifactRecord
from .storage.registry import ConfigRegistry
from .storage.report_repository import ReportRepository

app = typer.Typer(add_completion=False)


@app.callback()
def _app_callback(
    json_logs: bool = typer.Option(
        False,
        "--json-logs",
        envvar="AILA_JSON_LOGS",
        help="Emit logs as JSON lines to stderr.",
        is_eager=False,
    ),
) -> None:
    configure_logging(json_output=json_logs)


def emit_response(response) -> None:
    typer.echo(json.dumps(response.model_dump(mode="json"), indent=2))


def emit_progress(update: ProgressUpdate) -> None:
    timestamp = datetime.now().astimezone().strftime("%H:%M:%S")
    counter = ""
    if update.current is not None and update.total is not None:
        counter = f" [{update.current}/{update.total}]"
    typer.echo(f"[{timestamp}] {update.stage}{counter}: {update.message}", err=True)


def fail(exc: Exception) -> None:
    typer.echo(f"Error: {exc}", err=True)
    raise typer.Exit(code=1)


def parse_row_filters(entries: list[str] | None) -> dict[str, str]:
    filters: dict[str, str] = {}
    for entry in list(entries or []):
        if "=" not in entry:
            raise ValueError(f"Invalid --filter value {entry!r}. Expected key=value.")
        key, value = entry.split("=", 1)
        normalized_key = key.strip()
        normalized_value = value.strip()
        if not normalized_key or not normalized_value:
            raise ValueError(f"Invalid --filter value {entry!r}. Key and value must be non-empty.")
        filters[normalized_key] = normalized_value
    return filters


def _build_config_registry() -> ConfigRegistry:
    """Create a ConfigRegistry populated with all known schemas.
    Used by CLI config commands -- does not start the full platform.
    Runs async registration through _run_async since CLI is the sync boundary."""
    async def _init_registry() -> ConfigRegistry:
        registry = ConfigRegistry()
        await registry.register("platform", PlatformConfigSchema)
        await registry.register("vulnerability", VulnerabilityConfigSchema)
        return registry
    return _run_async(_init_registry())


def _build_tool_registry() -> ToolRegistry:
    """Create a ToolRegistry with all platform and module tools.
    Lightweight bootstrap: init_db + register tools -- no AILAPlatform, no LLM key required."""
    app_settings = get_settings()
    platform_settings = build_platform_settings(app_settings)
    _run_async(init_db(platform_settings))
    tool_registry = ToolRegistry()
    for key, tool in (
        ("registry.systems", SystemRegistryTool(platform_settings)),
        ("memory.permanent", PermanentMemoryTool(platform_settings)),
        ("ssh.command", SSHCommandTool(platform_settings)),
        ("reports.query", ReportsQueryTool(platform_settings)),
        ("artifacts.store", ArtifactStoreTool(platform_settings)),
        ("artifacts.search", ArtifactSearchTool(platform_settings)),
        ("secrets.manage", SecretsManageTool(platform_settings)),
        ("audit.log", AuditLogTool(platform_settings)),
        ("http.fetch", HTTPFetchTool(platform_settings)),
        ("cache.decision", DecisionCacheTool(platform_settings)),
        ("knowledge.store", KnowledgeStoreTool(namespace="platform", settings=platform_settings)),
        ("knowledge.retrieve", KnowledgeRetrieveTool(namespace="platform", settings=platform_settings)),
    ):
        tool_registry.register(key, tool)
    for module in load_builtin_modules():
        module.register_tools(tool_registry, app_settings)
    return tool_registry


config_app = typer.Typer(help="Read and write runtime config entries.")
app.add_typer(config_app, name="config")

tool_app = typer.Typer(help="Invoke registered platform tools directly.")
app.add_typer(tool_app, name="tool")

cache_app = typer.Typer(help="Manage platform caches.")
app.add_typer(cache_app, name="cache")

policy_app = typer.Typer(help="Manage scoring policies.")
app.add_typer(policy_app, name="policy")

feedback_app = typer.Typer(help="Store and retrieve operator knowledge entries.")
app.add_typer(feedback_app, name="feedback")

report_app = typer.Typer(help="Generate and query vulnerability reports.")
app.add_typer(report_app, name="report")

schedule_app = typer.Typer(help="Manage and execute scheduled scans.")
app.add_typer(schedule_app, name="schedule")

intel_app = typer.Typer(help="CVE and fleet intelligence queries.")
app.add_typer(intel_app, name="intel")

ops_app = typer.Typer(help="Operational intelligence: MTTR, SLA breach, tag risk, scoring audit, KB insights.")
app.add_typer(ops_app, name="ops")

auto_app = typer.Typer(help="Automation: patch playbooks, what-if simulator, verify, baselines, cost estimation.")
app.add_typer(auto_app, name="auto")

digest_app = typer.Typer(help="Executive reporting: CISO weekly digest and NL report queries.")
app.add_typer(digest_app, name="digest")


@app.command("worker")
def worker_start(
    queue: str = typer.Option(
        "default",
        "--queue",
        "-q",
        help="Task track/queue name to subscribe to.",
    ),
    redis_url: str = typer.Option(
        None,
        "--redis-url",
        help="Redis connection URL. Defaults to AILA_PLATFORM_REDIS_URL env var.",
    ),
) -> None:
    """Start an ARQ task worker for a specific queue track.

    Starts an ARQ worker subscribed to the given task track. The worker
    runs with max_jobs=1 (single-task concurrency per process).

    Example:
        aila worker --queue vulnerability_scan
    """
    # Resolve Redis URL: CLI arg > env var > safe IPv4 fallback
    import os
    from urllib.parse import urlparse

    import arq

    from aila.platform.tasks.worker import WorkerSettings, reaper
    _resolved_url = redis_url or os.environ.get("AILA_PLATFORM_REDIS_URL") or "redis://127.0.0.1:6379"
    parsed = urlparse(_resolved_url)
    redis_host = parsed.hostname or "127.0.0.1"
    redis_port = parsed.port or 6379

    from aila.platform.tasks import get_task_tuning
    from aila.platform.tasks.constants import (
        ARQ_JOB_TIMEOUT_S,
        ARQ_KEEP_RESULT_S,
        ARQ_MAX_TRIES,
    )

    # Phase 179: WorkerSettings.functions is sourced from _REGISTRY at
    # module import time. Phase 180's module ports add the @platform_task
    # decorators that populate it; Phase 179 leaves it [], with the
    # reaper cron satisfying ARQ's "at least one job" requirement.
    class _BoundWorkerSettings(WorkerSettings):
        queue_name = f"arq:queue:{queue}"
        redis_settings = arq.connections.RedisSettings(host=redis_host, port=redis_port)
        cron_jobs = [arq.cron(reaper, second=0)]
        job_timeout = get_task_tuning("arq_job_timeout_s", ARQ_JOB_TIMEOUT_S)
        keep_result = get_task_tuning("arq_keep_result_s", ARQ_KEEP_RESULT_S)
        max_tries = get_task_tuning("arq_max_tries", ARQ_MAX_TRIES)
        # arq.get_kwargs() reads __dict__, not the MRO -- inherited class attributes
        # are invisible to it. Without these lines WorkerSettings attributes never
        # reach arq.Worker. Explicitly shadowing them forces them into __dict__.
        functions = WorkerSettings.functions
        on_startup = WorkerSettings.on_startup
        on_job_start = WorkerSettings.on_job_start
        on_job_end = WorkerSettings.on_job_end

    # Validate required configuration before starting the worker.
    # Fail fast here rather than letting every job silently crash with
    # "AILA_DATABASE_URL must be set" after it's already been dequeued.
    try:
        from aila.config import get_settings
        _settings = get_settings()
        _ = _settings.database_url  # forces validation of DB URL
    except (ValueError, pydantic.ValidationError) as _cfg_err:
        typer.echo(
            f"ERROR: Worker cannot start -- configuration invalid: {_cfg_err}\n"
            "Set AILA_DATABASE_URL (and other required env vars) before starting the worker.",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(f"Starting ARQ worker for queue='{queue}', redis='{redis_host}:{redis_port}'")
    # On Windows, asyncio defaults to ProactorEventLoop (IOCP). asyncpg + SQLAlchemy
    # have known instability with ProactorEventLoop on Python 3.12+ -- connections
    # created inside the loop can end up with a None _proactor after any internal
    # loop-close path, breaking all subsequent I/O with AttributeError.
    # WindowsSelectorEventLoopPolicy uses the stable select()-based loop that
    # asyncpg was designed for. This is the recommended workaround until
    # asyncpg fully supports ProactorEventLoop on Windows.
    import asyncio
    import sys as _sys
    if _sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    arq.run_worker(_BoundWorkerSettings)


@feedback_app.command("store")
def feedback_store(
    content: str = typer.Option(..., "--content", help="Text to store as a knowledge entry."),
    tags: str = typer.Option("", "--tags", help="Comma-separated tags to attach (optional)."),
) -> None:
    """Store a knowledge entry in the platform knowledge base."""
    try:
        tags_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
        metadata = {"tags": tags_list} if tags_list else None
        tool_registry = _build_tool_registry()
        tool = tool_registry.require("knowledge.store", KnowledgeStoreTool)
        result = tool.forward(content=content, metadata=metadata)
        typer.echo(f"Stored entry {result['entry_id']}.")
    except AILAError as exc:
        fail(exc)


@feedback_app.command("retrieve")
def feedback_retrieve(
    query: str = typer.Option(..., "--query", help="Query text to search for relevant knowledge entries."),
    limit: int = typer.Option(10, "--limit", help="Maximum number of results to return (max 50)."),
) -> None:
    """Retrieve knowledge entries matching a query."""
    try:
        tool_registry = _build_tool_registry()
        tool = tool_registry.require("knowledge.retrieve", KnowledgeRetrieveTool)
        result = tool.forward(query=query, limit=limit)
        if result["count"] == 0:
            typer.echo("No results found.")
            return
        for r in result["results"]:
            typer.echo(f"[{r['score']:.3f}] {r['content']}")
    except AILAError as exc:
        fail(exc)


@report_app.command("pdf")
def report_pdf(
    run_id: str = typer.Option(..., "--run-id", help="Run ID to generate PDF for."),
    output_dir: str = typer.Option("reports", "--output-dir", help="Directory to write PDF into."),
) -> None:
    """Generate a PDF executive summary for a completed scan run."""
    from aila.modules.vulnerability.reporting.pdf import PDFReportRenderer
    repository = ReportRepository()
    app_settings = get_settings()
    _run_async(init_db(build_platform_settings(app_settings)))
    try:
        with session_scope(app_settings) as session:
            rows_result = repository.latest_report_rows(
                session=session,
                target=None,
                limit=10_000,
            )
            run_bundle = {
                "run_id": run_id,
                "summary": dict(rows_result.summary),
                "rows": list(rows_result.rows),
                "notes": list(rows_result.summary.get("notes", [])),
            }
    except sqlalchemy.exc.SQLAlchemyError as exc:
        fail(exc)
    try:
        pdf_path = PDFReportRenderer(run_bundle).render(Path(output_dir))
    except ImportError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)
    except (AILAError, OSError) as exc:
        fail(exc)
    typer.echo(str(pdf_path))


@report_app.command("findings")
def report_findings(
    run_id: str = typer.Option(..., "--run-id", help="Run ID to query findings for."),
    fmt: str = typer.Option("table", "--format", help="Output format: table or json."),
    limit: int = typer.Option(50, "--limit", help="Max findings to return."),
) -> None:
    """Query findings for a scan run with compliance tags."""
    from aila.modules.vulnerability.reporting.compliance import tag_finding
    repository = ReportRepository()
    app_settings = get_settings()
    _run_async(init_db(build_platform_settings(app_settings)))
    try:
        with session_scope(app_settings) as session:
            rows_result = repository.latest_report_rows(
                session=session,
                target=None,
                limit=limit,
            )
    except sqlalchemy.exc.SQLAlchemyError as exc:
        fail(exc)
    rows = list(rows_result.rows)[:limit]
    for row in rows:
        row["compliance_tags"] = tag_finding(row)
    if fmt == "json":
        typer.echo(json.dumps(rows, indent=2))
    else:
        for row in rows:
            tags = ", ".join(row.get("compliance_tags", []))
            typer.echo(f"{row.get('criticality', ''):<12} {row.get('cve_id', ''):<20} {row.get('system_name', ''):<20} tags=[{tags}]")


@policy_app.command("show")
def policy_show(
    policy_id: str = typer.Option(DEFAULT_SCORING_POLICY_ID, "--policy-id", help="Policy identifier to display."),
) -> None:
    """Display the current scoring policy as formatted JSON."""
    try:
        result = ScoringPolicyTool().forward(action="get", policy_id=policy_id)
    except AILAError as exc:
        fail(exc)
    if result.get("payload") is None:
        typer.echo(f"No scoring policy found for '{policy_id}'.")
        raise typer.Exit(code=1)
    typer.echo(json.dumps(result["payload"], indent=2))


@policy_app.command("reset")
def policy_reset(
    policy_id: str = typer.Option(DEFAULT_SCORING_POLICY_ID, "--policy-id", help="Policy identifier to reset."),
) -> None:
    """Restore the scoring policy to its factory defaults."""
    data_dir = Path(__file__).parent / "modules" / "vulnerability" / "data"
    default_payload = json.loads((data_dir / "scoring_policy.default.json").read_text(encoding="utf-8"))
    try:
        result = ScoringPolicyTool().forward(action="upsert", policy_id=policy_id, payload=default_payload)
    except AILAError as exc:
        fail(exc)
    typer.echo(f"Scoring policy '{result['policy_id']}' restored to defaults.")


@app.command("health")
def health() -> None:
    """Check SSH reachability, API status, DB, LLM config, and tool registration."""
    logger = get_logger("aila.health")
    failures: list[str] = []
    app_settings = get_settings()
    platform_settings = build_platform_settings(app_settings)
    _run_async(init_db(platform_settings))

    # 1. DB connectivity
    try:
        with session_scope() as _s:
            _s.exec(sqlmodel_select(ManagedSystemRecord).limit(1))
        typer.echo("  DB             OK")
    except sqlalchemy.exc.SQLAlchemyError as exc:
        typer.echo(f"  DB             FAIL  ({exc})")
        failures.append("db")

    # 2. SSH reachability per registered system
    try:
        with session_scope() as _s:
            systems = list(_s.exec(sqlmodel_select(ManagedSystemRecord)))
    except sqlalchemy.exc.SQLAlchemyError:
        logger.debug("Failed to query ManagedSystemRecord for health check", exc_info=True)
        systems = []
    ssh_service = SSHService(platform_settings)
    for system in systems:
        try:
            ssh_service.run_command(system, "true")
            typer.echo(f"  SSH {system.name:<20} OK")
        except AILAError as exc:
            typer.echo(f"  SSH {system.name:<20} FAIL  ({exc})")
            failures.append(f"ssh:{system.name}")

    # 3. API health -- HEAD requests with 5s timeout (URLs from config schema, R10/R53)
    from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema
    _cfg = VulnerabilityConfigSchema()
    api_endpoints = {
        "NVD":  _cfg.nvd_cve_url,
        "OSV":  _cfg.osv_batch_url,
        "EPSS": _cfg.epss_url,
        "KEV":  _cfg.kev_url,
    }
    for name, url in api_endpoints.items():
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.head(url)
                resp.raise_for_status()
            typer.echo(f"  API {name:<8}     OK  ({resp.status_code})")
        except httpx.HTTPError as exc:
            typer.echo(f"  API {name:<8}     FAIL  ({exc})")
            failures.append(f"api:{name.lower()}")

    # 4. LLM provider config
    try:
        _pcs = ProviderConfigStore(app_settings)
        _model_id = _pcs.get_config("openai_model_id") or ""
        _api_key = os.environ.get("OPENAI_API_KEY")
        if _model_id and _api_key:
            typer.echo(f"  LLM            OK  (model={_model_id})")
        else:
            typer.echo("  LLM            WARN  (not configured -- scoring will fail)")
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:
        typer.echo(f"  LLM            FAIL  ({exc})")
        failures.append("llm")

    # 5. Tool registration count
    try:
        tool_registry = _build_tool_registry()
        count = len(tool_registry._tools)
        typer.echo(f"  Tools          OK  ({count} registered)")
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:
        typer.echo(f"  Tools          FAIL  ({exc})")
        failures.append("tools")

    if failures:
        typer.echo(f"\nFailed checks: {', '.join(failures)}", err=True)
        logger.warning("health check failed: %s", ", ".join(failures))
        raise typer.Exit(code=1)
    typer.echo("\nAll checks passed.")


@app.command("audit-log")
def audit_log(
    since: str | None = typer.Option(None, "--since", help="ISO date lower bound, e.g. 2026-01-01"),
    until: str | None = typer.Option(None, "--until", help="ISO date upper bound, e.g. 2026-12-31"),
    stage: str | None = typer.Option(None, "--stage", help="Filter by stage name"),
    run_id_filter: str | None = typer.Option(None, "--run-id", help="Filter by exact run_id"),
    status: str | None = typer.Option(None, "--status", help="Filter by status"),
    user_id: str | None = typer.Option(None, "--user", help="Filter by user_id"),
    limit: int = typer.Option(200, "--limit", help="Max rows to return"),
) -> None:
    """Query the platform audit log."""
    stmt = sqlmodel_select(AuditEventRecord).order_by(AuditEventRecord.created_at.desc()).limit(limit)
    if since:
        since_dt = datetime.fromisoformat(since).replace(tzinfo=None)
        stmt = stmt.where(AuditEventRecord.created_at >= since_dt)
    if until:
        until_dt = datetime.fromisoformat(until).replace(tzinfo=None)
        stmt = stmt.where(AuditEventRecord.created_at <= until_dt)
    if stage:
        stmt = stmt.where(AuditEventRecord.stage == stage)
    if run_id_filter:
        stmt = stmt.where(AuditEventRecord.run_id == run_id_filter)
    if status:
        stmt = stmt.where(AuditEventRecord.status == status)
    if user_id:
        stmt = stmt.where(AuditEventRecord.user_id == user_id)
    app_settings = get_settings()
    platform_settings = build_platform_settings(app_settings)
    _run_async(init_db(platform_settings))
    try:
        with session_scope() as _s:
            records = list(_s.exec(stmt))
    except sqlalchemy.exc.SQLAlchemyError as exc:
        fail(exc)
    if not records:
        typer.echo("No audit events match the given filters.")
        return
    typer.echo(f"{'ID':<6} {'RUN_ID':<38} {'USER':<10} {'STAGE':<20} {'ACTION':<30} {'STATUS':<12} CREATED_AT")
    typer.echo("-" * 130)
    for r in records:
        typer.echo(f"{r.id!s:<6} {r.run_id:<38} {r.user_id:<10} {r.stage:<20} {r.action:<30} {r.status:<12} {r.created_at.isoformat()}")


@cache_app.command("clear")
def cache_clear(
    cve: str | None = typer.Option(None, "--cve", help="Clear cache entries for a specific CVE ID."),
    target: str | None = typer.Option(None, "--target", help="Clear inventory cache entries for a target host name."),
    all_caches: bool = typer.Option(False, "--all", help="Clear all cache tables."),
    retention: str | None = typer.Option(
        None,
        "--retention",
        help="Delete report artifacts older than this period (e.g. '30d'). Files are removed from disk and DB records are deleted.",
    ),
) -> None:
    """Selectively clear cache entries."""
    if not any([cve, target, all_caches, retention]):
        fail(ValueError("Provide --cve, --target, --all, or --retention."))
    app_settings = get_settings()
    platform_settings = build_platform_settings(app_settings)
    _run_async(init_db(platform_settings))
    deleted: dict[str, int] = {}
    try:
        with session_scope() as _s:
            if all_caches or cve:
                if cve:
                    entry = _s.get(CacheRecord, ("cve_intel", cve))
                    count = 1 if entry else 0
                    if entry:
                        _s.delete(entry)
                    scoring_stmt = sqlmodel_delete(CacheRecord).where(
                        CacheRecord.namespace == "scoring_review",
                        CacheRecord.cache_key.startswith(cve),
                    )
                    result = _s.exec(scoring_stmt)
                    deleted["cve_intel"] = count
                    deleted["scoring_review"] = result.rowcount
                else:
                    # --all: wipe all cache namespaces and inventory artifacts
                    r1 = _s.exec(sqlmodel_delete(CacheRecord).where(CacheRecord.namespace == "cve_intel"))
                    r2 = _s.exec(sqlmodel_delete(CacheRecord).where(CacheRecord.namespace == "scoring_review"))
                    r3 = _s.exec(sqlmodel_delete(InventoryArtifactRecord))
                    deleted["cve_intel"] = r1.rowcount
                    deleted["scoring_review"] = r2.rowcount
                    deleted["inventory"] = r3.rowcount
            if target and not all_caches:
                inv_stmt = sqlmodel_delete(InventoryArtifactRecord).where(
                    InventoryArtifactRecord.host == target
                )
                result = _s.exec(inv_stmt)
                deleted["inventory"] = result.rowcount
            if retention:
                cutoff = _parse_retention_cutoff(retention)
                stale_records = list(
                    _s.exec(
                        sqlmodel_select(ReportArtifactRecord).where(
                            ReportArtifactRecord.created_at < cutoff
                        )
                    )
                )
                files_deleted = 0
                for record in stale_records:
                    artifact_path = Path(record.path)
                    if artifact_path.exists():
                        try:
                            artifact_path.unlink()
                            files_deleted += 1
                        except OSError:
                            pass
                    _s.delete(record)
                deleted["report_artifacts"] = len(stale_records)
                deleted["report_files"] = files_deleted
            _s.commit()
    except sqlalchemy.exc.SQLAlchemyError as exc:
        fail(exc)
    typer.echo(json.dumps({"cleared": deleted}, indent=2))


def _parse_retention_cutoff(retention: str) -> datetime:
    """Parse a retention period string like '30d' and return the cutoff datetime.

    Supported suffixes: d (days), h (hours).
    Raises ValueError for unrecognised formats.
    """
    normalized = retention.strip().lower()
    if normalized.endswith("d"):
        days = int(normalized[:-1])
        return datetime.now(UTC) - timedelta(days=days)
    if normalized.endswith("h"):
        hours = int(normalized[:-1])
        return datetime.now(UTC) - timedelta(hours=hours)
    raise ValueError(
        f"Unrecognised retention format {retention!r}. Use a number followed by 'd' (days) or 'h' (hours), e.g. '30d'."
    )


@config_app.command("list")
def config_list() -> None:
    """List all registered config entries grouped by namespace."""
    try:
        registry = _build_config_registry()
        entries = _run_async(registry.all_entries())
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover
        fail(exc)
    if not entries:
        typer.echo("No config entries registered.")
        return
    current_ns = None
    for entry in entries:
        if entry["namespace"] != current_ns:
            current_ns = entry["namespace"]
            typer.echo(f"\n[{current_ns}]")
        source_tag = f" ({entry['source']})" if entry["source"] == "env" else ""
        typer.echo(f"  {entry['key']} = {entry['value']}  [{entry['value_type']}]{source_tag}")


@config_app.command("set")
def config_set(entry: str = typer.Argument(..., help="namespace.key"), value: str = typer.Argument(...)) -> None:
    """Set a config value. Format: namespace.key value"""
    if "." not in entry:
        fail(ValueError(f"Invalid key format {entry!r}. Expected namespace.key (e.g. vulnerability.nvd_min_interval_seconds)."))
    namespace, key = entry.split(".", 1)
    try:
        registry = _build_config_registry()
        _run_async(registry.set(namespace, key, value))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover
        fail(exc)
    typer.echo(json.dumps({"namespace": namespace, "key": key, "value": value, "status": "ok"}, indent=2))


@config_app.command("get")
def config_get(entry: str = typer.Argument(..., help="namespace.key")) -> None:
    """Get a resolved config value (env > DB > default). Format: namespace.key"""
    if "." not in entry:
        fail(ValueError(f"Invalid key format {entry!r}. Expected namespace.key (e.g. vulnerability.nvd_min_interval_seconds)."))
    namespace, key = entry.split(".", 1)
    try:
        registry = _build_config_registry()
        resolved = _run_async(registry.get(namespace, key))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover
        fail(exc)
    if resolved is None:
        fail(ValueError(f"Key '{namespace}.{key}' not found in any registered schema."))
    typer.echo(json.dumps({"namespace": namespace, "key": key, "value": resolved}, indent=2))


@tool_app.command("invoke")
def tool_invoke(
    key: str = typer.Argument(..., help="Tool key, e.g. nvd.lookup"),
    arg: list[str] = typer.Option(None, "--arg", help="Argument as name=value (repeatable)."),
) -> None:
    """Invoke a registered platform tool directly. Bypasses agent reasoning."""
    kwargs: dict[str, str] = {}
    for entry in list(arg or []):
        if "=" not in entry:
            fail(ValueError(f"Invalid --arg value {entry!r}. Expected name=value."))
        name, value = entry.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            fail(ValueError(f"Invalid --arg value {entry!r}. Name and value must be non-empty."))
        kwargs[name] = value
    try:
        tool_registry = _build_tool_registry()
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover
        fail(exc)
    try:
        tool = tool_registry.require(key)
    except KeyError as exc:
        fail(exc)
    run_id = str(uuid.uuid4())
    with session_scope() as session:
        try:
            result = tool.forward(**kwargs)
            record_audit_event_sync(
                session,
                run_id=run_id,
                stage="direct_tool",
                action=key,
                status="completed",
                user_id="cli",
                details={"args": kwargs},
            )
            session.commit()
        except AILAError as exc:
            record_audit_event_sync(
                session,
                run_id=run_id,
                stage="direct_tool",
                action=key,
                status="error",
                user_id="cli",
                details={"args": kwargs, "error": str(exc)},
            )
            session.commit()
            fail(exc)
    typer.echo(json.dumps(result if isinstance(result, (dict, list)) else {"result": result}, indent=2))


@tool_app.command("list")
def tool_list() -> None:
    """List all registered tool keys."""
    try:
        tool_registry = _build_tool_registry()
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover
        fail(exc)
    typer.echo("\n".join(sorted(tool_registry._tools)))


@app.command("task")
def task(query: str, target: list[str] = typer.Option(None, "--target")) -> None:
    try:
        response = asyncio.run(
            AILAPlatform(progress_callback=emit_progress).handle(
                query=query,
                module_payload={"target_names": list(target or [])},
            )
        )
    except AILAError as exc:  # pragma: no cover - typer surface
        fail(exc)
    emit_response(response)


@app.command("add-ssh")
def add_ssh(
    name: str,
    host: str,
    username: str,
    port: int = 22,
    distro: str = LinuxDistribution.UNKNOWN.value,
    description: str = "",
    private_key_path: str | None = None,
    prompt_password: bool = typer.Option(False, "--prompt-password"),
    password_file: Path | None = None,
    known_hosts_path: str | None = None,
    host_key_fingerprint: str | None = None,
) -> None:
    if prompt_password and password_file is not None:
        fail(ValueError("Use either --prompt-password or --password-file, not both."))
    password: str | None = None
    if prompt_password:
        password = typer.prompt("SSH password", hide_input=True, confirmation_prompt=True)
    elif password_file is not None:
        password = password_file.read_text(encoding="utf-8").strip()

    payload = SSHIntegrationInput(
        name=name,
        host=host,
        username=username,
        port=port,
        distro=distro,
        description=description,
        private_key_path=private_key_path,
        password=password,
        known_hosts_path=known_hosts_path,
        host_key_fingerprint=host_key_fingerprint,
    )
    try:
        response = asyncio.run(AILAPlatform().handle(query="add ssh integration", module_payload={"integration": payload}))
    except AILAError as exc:  # pragma: no cover - typer surface
        fail(exc)
    emit_response(response)


@app.command("list-integrations")
def list_integrations() -> None:
    try:
        response = asyncio.run(AILAPlatform().handle(query="how many SSH integrations are configured"))
    except AILAError as exc:  # pragma: no cover - typer surface
        fail(exc)
    emit_response(response)


@app.command("delete-integration")
def delete_integration(name: list[str] = typer.Argument(...)) -> None:
    try:
        response = asyncio.run(AILAPlatform().handle(
            query="delete ssh integration",
            module_payload={"target_names": list(name)},
        ))
    except AILAError as exc:  # pragma: no cover - typer surface
        fail(exc)
    emit_response(response)


@app.command("list-distro-profiles")
def list_distro_profiles() -> None:
    try:
        payload = DistributionProfileTool().forward(action="list")
    except AILAError as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(payload, indent=2))


@app.command("upsert-distro-profile")
def upsert_distro_profile(
    distro_key: str,
    inventory_command: str,
    package_parser: PackageParserKey,
    advisory_strategy: AdvisoryStrategyKey,
    display_name: str = "",
    os_release_id: list[str] = typer.Option(None, "--os-release-id"),
    advisory_ecosystem: str | None = None,
    advisory_batch_size: int | None = None,
    enabled: bool = True,
) -> None:
    payload = DistributionProfileInput(
        distro_key=distro_key,
        display_name=display_name,
        os_release_ids=list(os_release_id or []),
        inventory_command=inventory_command,
        package_parser=package_parser,
        advisory_strategy=advisory_strategy,
        advisory_ecosystem=advisory_ecosystem,
        advisory_batch_size=advisory_batch_size,
        enabled=enabled,
    )
    try:
        result = DistributionProfileTool().forward(action="upsert", profile=payload.model_dump(mode="json"))
    except AILAError as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@app.command("delete-distro-profile")
def delete_distro_profile(distro_key: list[str] = typer.Argument(...)) -> None:
    try:
        payload = DistributionProfileTool().forward(action="delete", distro_keys=list(distro_key))
    except AILAError as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(payload, indent=2))


@app.command("set-provider-secret")
def set_provider_secret(
    secret_name: str,
    prompt_value: bool = typer.Option(True, "--prompt/--no-prompt"),
    value_file: Path | None = None,
) -> None:
    if prompt_value and value_file is not None:
        fail(ValueError("Use either the hidden prompt or --value-file, not both."))
    if not prompt_value and value_file is None:
        fail(ValueError("Provide --value-file when --no-prompt is used."))
    if prompt_value:
        secret_value = typer.prompt(f"Secret value for {secret_name}", hide_input=True, confirmation_prompt=True)
    else:
        secret_value = value_file.read_text(encoding="utf-8").strip()
    metadata = _run_async(SecretStore().upsert_provider_secret(secret_name, secret_value))
    typer.echo(
        json.dumps(
            {
                "message": f"Stored provider secret '{secret_name}'.",
                "secret_name": metadata["secret_key"],
                "backend": metadata["backend"],
                "algorithm": metadata["algorithm"],
                "key_version": metadata["key_version"],
                "hint": metadata["hint"],
                "updated_at": metadata["updated_at"].isoformat(),
            },
            indent=2,
        )
    )


@app.command("delete-provider-secret")
def delete_provider_secret(secret_name: str) -> None:
    deleted = SecretStore().delete_provider_secret(secret_name)
    typer.echo(
        json.dumps(
            {
                "message": f"Deleted provider secret '{secret_name}'." if deleted else f"No provider secret '{secret_name}' was stored.",
                "secret_name": secret_name,
                "deleted": deleted,
            },
            indent=2,
        )
    )


@app.command("list-provider-secrets")
def list_provider_secrets() -> None:
    metadata = _run_async(SecretStore().list_provider_secrets())
    typer.echo(
        json.dumps(
            {
                "message": f"Loaded {len(metadata)} provider secrets.",
                "count": len(metadata),
                "secrets": [
                    {
                        "id": item["id"],
                        "scope": item["scope"],
                        "secret_key": item["secret_key"],
                        "backend": item["backend"],
                        "algorithm": item["algorithm"],
                        "key_version": item["key_version"],
                        "hint": item["hint"],
                        "updated_at": item["updated_at"].isoformat(),
                    }
                    for item in metadata
                ],
            },
            indent=2,
        )
    )


@app.command("set-provider-config")
def set_provider_config(config_name: str, value: str) -> None:
    metadata = ProviderConfigStore().upsert_config(config_name, value)
    typer.echo(
        json.dumps(
            {
                "message": f"Stored provider config '{config_name}'.",
                "config_name": metadata["config_key"],
                "value": metadata["value"],
                "updated_at": metadata["updated_at"].isoformat(),
            },
            indent=2,
        )
    )


@app.command("delete-provider-config")
def delete_provider_config(config_name: str) -> None:
    deleted = ProviderConfigStore().delete_config(config_name)
    typer.echo(
        json.dumps(
            {
                "message": f"Deleted provider config '{config_name}'." if deleted else f"No provider config '{config_name}' was stored.",
                "config_name": config_name,
                "deleted": deleted,
            },
            indent=2,
        )
    )


@app.command("list-provider-configs")
def list_provider_configs() -> None:
    metadata = ProviderConfigStore().list_configs()
    typer.echo(
        json.dumps(
            {
                "message": f"Loaded {len(metadata)} provider configs.",
                "count": len(metadata),
                "configs": [
                    {
                        "id": item["id"],
                        "config_key": item["config_key"],
                        "value": item["value"],
                        "updated_at": item["updated_at"].isoformat(),
                    }
                    for item in metadata
                ],
            },
            indent=2,
        )
    )


@app.command("analyze")
def analyze(
    target: list[str] = typer.Option(None, "--target"),
    refresh_intel: bool = typer.Option(False, "--refresh-intel", help="Bypass cached CVE intelligence and fetch fresh NVD/EPSS/KEV data for this run."),
    refresh_advisories: bool = typer.Option(False, "--refresh-advisories", help="Bypass cached OSV advisory responses and fetch fresh package advisory data for this run."),
    refresh_scoring: bool = typer.Option(False, "--refresh-scoring", help="Bypass cached model-backed scoring reviews and regenerate them for this run."),
    execution_mode: str = typer.Option("auto", "--execution-mode", help="Force a specific operation mode (e.g. full_analysis). Defaults to auto."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate SSH connections and target resolution only. No packages collected, no scoring."),
) -> None:
    if dry_run:
        app_settings = get_settings()
        platform_settings = build_platform_settings(app_settings)
        _run_async(init_db(platform_settings))
        results = resolve_dry_run_targets(platform_settings, list(target or []))
        failures = [r for r in results if r["status"] == "fail"]
        typer.echo(f"Dry-run: {len(results)} target(s) checked.")
        for r in results:
            status_str = "OK" if r["status"] == "ok" else f"FAIL ({r['error']})"
            typer.echo(f"  {r['name']:<20} {r['host']:<30} distro={r['distro']}  {status_str}")
        if failures:
            typer.echo(f"\n{len(failures)} connection(s) failed.", err=True)
            raise typer.Exit(code=1)
        typer.echo("\nAll connections succeeded. No packages collected.")
        return
    try:
        response = asyncio.run(AILAPlatform(progress_callback=emit_progress).handle(
            query="analyze the registered fleet for package cves",
            module_payload={"target_names": list(target or [])},
            module_options={
                "execution_mode": execution_mode,
                "refresh_intel": refresh_intel,
                "refresh_advisories": refresh_advisories,
                "refresh_scoring": refresh_scoring,
            },
        ))
    except AILAError as exc:  # pragma: no cover - typer surface
        fail(exc)
    emit_response(response)


@app.command("latest-report")
def latest_report(
    target: str | None = typer.Option(None, "--target", help="Return the latest stored target report for a system name or host."),
    include_content: bool = typer.Option(False, "--include-content", help="Include stored report content from the database when available."),
) -> None:
    async def _run():
        repository = ReportRepository()
        async with async_session_scope(get_settings()) as session:
            return (await repository.latest_report(
                session=session,
                target=target,
                include_content=include_content,
            )).to_payload()
    try:
        payload = _run_async(_run())
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(payload, indent=2))


@app.command("latest-report-rows")
def latest_report_rows(
    target: str | None = typer.Option(None, "--target", help="Return the latest stored target report rows for a system name or host."),
    offset: int = typer.Option(0, "--offset", help="Zero-based starting row offset."),
    limit: int = typer.Option(100, "--limit", help="Maximum number of rows to return."),
    row_filter: list[str] = typer.Option(None, "--filter", help="Filter rows with key=value (repeatable)."),
) -> None:
    async def _run():
        parsed_filters = parse_row_filters(row_filter)
        repository = ReportRepository()
        row_filters = {
            module.module_id: module.filter_report_rows
            for module in load_builtin_modules()
        }
        async with async_session_scope(get_settings()) as session:
            latest = await repository.latest_report(
                session=session,
                target=target,
                include_content=False,
            )
            return (await repository.latest_report_rows(
                session=session,
                target=target,
                offset=offset,
                limit=limit,
                filters=parsed_filters,
                row_filter=row_filters.get(latest.module_id or ""),
                module_id=latest.module_id,
            )).to_payload()
    try:
        payload = _run_async(_run())
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(payload, indent=2))


@app.command("prewarm-intel")
def prewarm_intel(
    cve_id: list[str] = typer.Argument(...),
    refresh_intel: bool = typer.Option(False, "--refresh-intel", help="Bypass cached CVE intelligence and fetch fresh data while prewarming."),
) -> None:
    try:
        platform = AILAPlatform(progress_callback=emit_progress)
        runtime = platform.runtime.require_module(VulnerabilityModule.module_id)
        if not isinstance(runtime, VulnerabilityRuntime):
            raise TypeError("Vulnerability runtime is not active.")
        result = runtime.intel.prewarm(
            cve_ids=list(cve_id),
            force_refresh=refresh_intel,
        )
    except (AILAError, TypeError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    output = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
    typer.echo(json.dumps(output, indent=2))


@app.command("diff")
def diff(
    run_id_a: str = typer.Option(..., "--run-id-a", help="Base run ID (older scan)."),
    run_id_b: str = typer.Option(..., "--run-id-b", help="Comparison run ID (newer scan)."),
) -> None:
    """Compare two scan runs and show new, resolved, and criticality-changed findings."""
    from aila.storage.report_store import ReportArtifactStore

    app_settings = get_settings()
    platform_settings = build_platform_settings(app_settings)
    _run_async(init_db(platform_settings))

    artifact_store = ReportArtifactStore()

    def _load_run_rows(run_id: str) -> list[dict]:
        with session_scope(app_settings) as session:
            bundle = artifact_store.load_run_bundle(session, run_id)
        if bundle is None:
            raise ValueError(f"No report artifacts found for run {run_id!r}.")
        if not isinstance(bundle.rows_document, list):
            raise ValueError(f"Structured rows unavailable for run {run_id!r}.")
        return [dict(row) for row in bundle.rows_document if isinstance(row, dict)]

    try:
        rows_a = _load_run_rows(run_id_a)
        rows_b = _load_run_rows(run_id_b)
    except (AILAError, sqlalchemy.exc.SQLAlchemyError, ValueError) as exc:
        fail(exc)

    def _key(row: dict) -> tuple[str, str, str]:
        return (
            str(row.get("host", "")),
            str(row.get("package_name", "")),
            str(row.get("cve_id", "")),
        )

    index_a: dict[tuple[str, str, str], dict] = {_key(r): r for r in rows_a}
    index_b: dict[tuple[str, str, str], dict] = {_key(r): r for r in rows_b}

    new_findings: list[dict] = []
    resolved_findings: list[dict] = []
    changed_criticality: list[dict] = []

    for key, row in index_b.items():
        if key not in index_a:
            new_findings.append(row)
        elif row.get("criticality") != index_a[key].get("criticality"):
            changed_criticality.append({
                "host": key[0],
                "package_name": key[1],
                "cve_id": key[2],
                "criticality_before": index_a[key].get("criticality", ""),
                "criticality_after": row.get("criticality", ""),
            })

    for key, row in index_a.items():
        if key not in index_b:
            resolved_findings.append(row)

    typer.echo(f"Diff: {run_id_a} -> {run_id_b}")
    typer.echo(f"  New findings:           {len(new_findings)}")
    typer.echo(f"  Resolved findings:      {len(resolved_findings)}")
    typer.echo(f"  Criticality changes:    {len(changed_criticality)}")

    if new_findings:
        typer.echo("\nNew findings:")
        typer.echo(f"  {'HOST':<20} {'PACKAGE':<25} {'CVE':<22} CRITICALITY")
        typer.echo("  " + "-" * 90)
        for row in new_findings:
            typer.echo(f"  {str(row.get('host', '')):<20} {str(row.get('package_name', '')):<25} {str(row.get('cve_id', '')):<22} {row.get('criticality', '')}")

    if resolved_findings:
        typer.echo("\nResolved findings:")
        typer.echo(f"  {'HOST':<20} {'PACKAGE':<25} {'CVE':<22} CRITICALITY")
        typer.echo("  " + "-" * 90)
        for row in resolved_findings:
            typer.echo(f"  {str(row.get('host', '')):<20} {str(row.get('package_name', '')):<25} {str(row.get('cve_id', '')):<22} {row.get('criticality', '')}")

    if changed_criticality:
        typer.echo("\nCriticality changes:")
        typer.echo(f"  {'HOST':<20} {'PACKAGE':<25} {'CVE':<22} {'BEFORE':<12} AFTER")
        typer.echo("  " + "-" * 102)
        for row in changed_criticality:
            typer.echo(f"  {str(row['host']):<20} {str(row['package_name']):<25} {str(row['cve_id']):<22} {str(row['criticality_before']):<12} {row['criticality_after']}")


@app.command("backup-db")
def backup_db(destination: Path | None = None) -> None:
    try:
        backup_path = _run_async(backup_database(destination=destination))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError, OSError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps({"message": f"Database backup created at {backup_path}.", "backup_path": str(backup_path)}, indent=2))


@app.command("restore-db")
def restore_db(source: Path) -> None:
    typer.echo("Database restore from pg_dump is not yet implemented for PostgreSQL.", err=True)
    raise typer.Exit(1)


@schedule_app.command("create")
def schedule_create(
    target_name: str = typer.Option(..., "--target", help="Target system name to scan."),
    cron_expression: str = typer.Option(..., "--cron", help="Cron expression (e.g. '0 3 * * *')."),
) -> None:
    """Register a scheduled scan.

    NOTE: AILA does not manage cron execution. External cron is required.
    Use 'aila schedule run-pending' in your crontab to trigger due scans.
    """
    from .modules.vulnerability.tools.scheduled_scans import ScheduledScansTool
    try:
        tool = ScheduledScansTool()
        result = tool.forward(action="create", target_name=target_name, cron_expression=cron_expression)
    except AILAError as exc:
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@schedule_app.command("run-pending")
def schedule_run_pending() -> None:
    """Execute all enabled schedules whose cron expression is due."""
    try:
        result = _run_pending()
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@schedule_app.command("status")
def schedule_status_cmd() -> None:
    """Show last/next run info for all schedules."""
    try:
        result = _schedule_status()
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    for sched in result.get("schedules", []):
        if sched.get("last_run_at") is None:
            sched["last_run_at"] = "never executed"
    typer.echo(json.dumps(result, indent=2))


@intel_app.command("arrivals")
def intel_arrivals(
    since: str | None = typer.Option(
        None,
        "--since",
        help="ISO date or datetime cutoff (e.g. 2025-01-01). Defaults to 24h ago.",
    ),
) -> None:
    """Show CVE arrivals and departures since a reference timestamp."""
    try:
        result = _run_async(_arrivals_departures(since=since))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@intel_app.command("blast-radius")
def intel_blast_radius(
    cve: str = typer.Option(..., "--cve", help="CVE identifier to look up (e.g. CVE-2024-1234)."),
) -> None:
    """Show all hosts affected by a given CVE from materialized findings."""
    try:
        result = _run_async(_blast_radius(cve_id=cve))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@intel_app.command("heat-map")
def intel_heat_map() -> None:
    """Show package risk heat map across the fleet, sorted by max score."""
    try:
        result = _run_async(_package_heat_map())
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@intel_app.command("drift")
def intel_drift(
    target: str = typer.Option(..., "--target", help="Hostname to inspect for inventory drift."),
) -> None:
    """Show package additions, removals, and version changes between the two most recent scans."""
    try:
        result = _run_async(_inventory_drift(target=target))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@intel_app.command("compare")
def intel_compare(
    host_a: str = typer.Option(..., "--host-a", help="First hostname to compare."),
    host_b: str = typer.Option(..., "--host-b", help="Second hostname to compare."),
) -> None:
    """Diff packages and findings between two hosts."""
    try:
        result = _run_async(_peer_compare(host_a=host_a, host_b=host_b))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@intel_app.command("service-check")
def intel_service_check(
    target: str = typer.Option(..., "--target", help="System name in the AILA registry."),
    service: str = typer.Option(..., "--service", help="Service name to check (e.g. nginx, sshd)."),
) -> None:
    """Check whether a service is active on a target host via SSH systemctl is-active."""
    try:
        result = _run_async(_service_active_check(target=target, service=service))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@ops_app.command("mttr")
def ops_mttr() -> None:
    """Show mean time to remediate grouped by criticality (p50/p90/p99)."""
    try:
        result = _run_async(_mttr())
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@ops_app.command("sla-breach")
def ops_sla_breach() -> None:
    """List open findings that have exceeded or are approaching their SLA threshold."""
    try:
        result = _run_async(_sla_breach())
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@ops_app.command("tag-risk")
def ops_tag_risk() -> None:
    """Show risk posture score per asset tag segment (e.g. per environment)."""
    try:
        result = _run_async(_tag_risk())
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@ops_app.command("scoring-audit")
def ops_scoring_audit() -> None:
    """Flag CVEs scored with different criticality across hosts."""
    try:
        result = _run_async(_scoring_audit())
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@ops_app.command("kb-insights")
def ops_kb_insights() -> None:
    """Show knowledge base entry counts by namespace and top CVEs mentioned."""
    try:
        result = _kb_insights()
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@ops_app.command("agent-stats")
def ops_agent_stats() -> None:
    """Show cumulative run_structured() call stats per agent (in-process, resets on restart)."""
    typer.echo(json.dumps(get_agent_stats(), indent=2))


@ops_app.command("list-schemas")
def ops_list_schemas() -> None:
    """List all registered agent input/output schemas with name and schema hash."""
    typer.echo(json.dumps(get_registered_schemas(), indent=2))


@auto_app.command("playbook")
def auto_playbook(
    target: str | None = typer.Option(None, "--target", help="Filter to a single host by name."),
) -> None:
    """Generate per-host ordered patch playbook from materialized findings."""
    try:
        result = _run_async(_patch_playbook(target=target))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@auto_app.command("what-if")
def auto_what_if(
    package: str = typer.Option(..., "--package", help="Package name to simulate patching."),
    version: str | None = typer.Option(None, "--version", help="Target fixed version. Omit to remove all findings for package."),
) -> None:
    """Simulate fleet risk posture change if a package is patched to a given version."""
    try:
        result = _run_async(_what_if_patch(package_name=package, version=version))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@auto_app.command("verify")
def auto_verify(
    target: str = typer.Option(..., "--target", help="System name in the AILA registry."),
    cve: str = typer.Option(..., "--cve", help="CVE identifier to verify (e.g. CVE-2024-1234)."),
) -> None:
    """Verify a CVE remediation on a target host via SSH version check."""
    try:
        result = _run_async(_verify_remediation(target=target, cve_id=cve))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))


@auto_app.command("baseline")
def auto_baseline(
    action: str = typer.Argument(help="Action: create or compare."),
    name: str = typer.Option(..., "--name", help="Snapshot name (e.g. q1-2026)."),
) -> None:
    """Create or compare a named fleet baseline snapshot."""
    try:
        if action == "create":
            result = _run_async(_baseline_create(name=name))
        elif action == "compare":
            result = _run_async(_baseline_compare(name=name))
        else:
            typer.echo(f"Unknown baseline action '{action}'. Use: create, compare.", err=True)
            raise typer.Exit(code=1)
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))



@digest_app.command("weekly")
def digest_weekly(
    period_days: int = typer.Option(7, "--period-days", help="Number of days for CVE arrival window."),
) -> None:
    """Generate a CISO-facing weekly digest combining all fleet intelligence."""
    try:
        result = _run_async(_weekly_digest(period_days=period_days))
    except (AILAError, sqlalchemy.exc.SQLAlchemyError) as exc:  # pragma: no cover - typer surface
        fail(exc)
    typer.echo(json.dumps(result, indent=2))



@app.command()
def serve(
    host: str | None = typer.Option(None, "--host", help="Bind host (default: AILA_API_HOST or 127.0.0.1)"),
    port: int | None = typer.Option(None, "--port", help="Bind port (default: AILA_API_PORT or 8000)"),
    reload: bool = typer.Option(False, "--reload", help="Enable hot reload for development"),
) -> None:
    """Start the AILA REST API server via uvicorn.

    Launches the FastAPI application at the configured host and port.
    For production, set AILA_JWT_SECRET_KEY, AILA_API_HOST, AILA_API_PORT,
    and AILA_CORS_ORIGINS environment variables.

    Examples:
        aila serve
        aila serve --host 0.0.0.0 --port 8080
        aila serve --reload  # development hot-reload
    """
    import uvicorn

    settings = get_settings()
    effective_host = host or settings.api_host
    effective_port = port or settings.api_port

    uvicorn.run(
        "aila.api.app:app",
        host=effective_host,
        port=effective_port,
        reload=reload,
        workers=1,  # Single-process; scale by running multiple instances
    )


@app.command("create-api-key")
def create_api_key(
    label: str = typer.Option("", "--label", "-l", help="Optional human-readable label for this key"),
) -> None:
    """Create an admin-role API key and print it to stdout.

    D-01: CLI path for interactive admin key creation.
    D-02: Only admin role is supported via CLI; use POST /auth/keys for other roles.
    The raw key is shown ONCE. Store it securely -- it cannot be recovered.

    Examples:
        aila create-api-key
        aila create-api-key --label production-admin
    """
    from aila.api.auth import generate_api_key, hash_api_key
    from aila.platform.contracts import utc_now
    from aila.storage.db_models import ApiKeyRecord

    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)
    key_prefix = raw_key[:12]
    now = utc_now()

    record = ApiKeyRecord(
        hashed_key=hashed,
        key_prefix=key_prefix,
        role="admin",
        label=label,
        created_by="cli",
        created_at=now,
    )

    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
        key_id = record.id  # snapshot before session closes
        record_audit_event_sync(
            session,
            run_id=key_id,
            stage="auth",
            action="create_api_key",
            status="completed",
            target=key_prefix,
            user_id="cli",
            details={"role": "admin", "label": label},
        )
        session.commit()

    typer.echo("API key created:")
    typer.echo(f"  Key ID:  {key_id}")
    typer.echo(f"  Key:     {raw_key}")
    typer.echo("  Role:    admin")
    typer.echo(f"  Label:   {label or '(none)'}")
    typer.echo("")
    typer.echo("Store this key securely. It cannot be recovered.")


def main() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except OSError:
                pass
    app()


if __name__ == "__main__":
    main()



"""RFC-11 -- generic MCP client, resolver, and capability instance pool.

One :class:`McpClient` replaces the three bridges' hand-rolled HTTP
transport, ``GET /tools`` fetch, ``POST /tools/<action>`` dispatch,
JSON parsing, and per-call audit-log recording. The bridge classes are
kept as thin adapters that layer server-specific request/response
shaping (JADX path rewriter, IDA auto-name coercion, android-mcp
pipeline-only guard) on top of this generic transport -- see the audit
report on RFC-11 step 5 for which bridges could not collapse fully.

Three cooperating pieces:

* :class:`ResolvedInstance` -- resolver output; carries the URL, the
  source tier that produced it (``env`` > ``config`` > ``catalog`` >
  ``default``), the catalog row id when known, and the catalog's
  capability tags. ``instance_id`` is threaded into the per-call
  audit log so a finding's provenance records which physical server
  instance produced each reading (RFC-11 §7 provenance).
* :func:`resolve_instance` -- the shared 4-tier resolver used by the
  :class:`~aila.platform.mcp.registry.McpRegistryServiceBase` and by
  every :class:`~aila.platform.tools.Tool` bridge. Byte-identical to
  the pre-catalog behaviour when the catalog is empty for a scope so
  the operator's live dispatch is unchanged.
* :class:`InstancePool` -- round-robin selector for two or more
  enabled catalog rows advertising the same capability. Callers ask
  for one instance per invocation via :meth:`InstancePool.next`; the
  pool rotates a monotonic counter under an async lock so concurrent
  callers on the same event loop see interleaved picks. Empty pools
  raise :class:`EmptyPoolError` so the caller decides whether to fall
  back to the static default or surface the outage.

Every :meth:`McpClient.call_tool` invocation records the resolved
``instance_id`` (or ``None`` when no catalog row applied) via the
module's ``record_call`` async context manager. The call-log column
``instance_id`` on :class:`~aila.platform.contracts.mcp_call_log_base
.McpCallLogRecordBase` receives the value; the operator UI joins
audit rows to the catalog row on this key.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.llm.sanitize import sanitize_input
from aila.platform.mcp.instance_catalog import (
    McpInstanceCatalog,
    McpServerInstance,
    decode_capability_tags,
)
from aila.platform.observability.otel import (
    GEN_AI_OPERATION_EXECUTE_TOOL,
    gen_ai_span,
    inject_trace_context,
)
from aila.storage.registry import ConfigRegistry

__all__ = [
    "EmptyPoolError",
    "InstancePool",
    "McpClient",
    "ResolvedInstance",
    "build_recorder_context",
    "compact_tool_spec",
    "resolve_instance",
]

_log = logging.getLogger(__name__)


# Resolver source tiers -- match ``McpRegistryServiceBase._resolved_url``.
_SOURCE_ENV = "env"
_SOURCE_CONFIG = "config"
_SOURCE_CATALOG = "catalog"
_SOURCE_DEFAULT = "default"


@dataclass(frozen=True)
class ResolvedInstance:
    """The URL the caller should hit, plus provenance for the audit log.

    Immutable so the caller can safely pass the same instance into a
    fan-out of coroutines without racing. ``instance_id`` is ``None``
    when the URL came from ``env`` / ``config`` / ``default`` -- the
    catalog was not consulted or held no matching row, so there is no
    row id to stamp on the call log. ``capability_tags`` is empty for
    the same three tiers; only ``catalog``-sourced rows carry tags.
    """

    url: str
    source: str
    instance_id: str | None = None
    capability_tags: tuple[str, ...] = field(default_factory=tuple)
    name: str | None = None
    module_scope: str | None = None


class EmptyPoolError(RuntimeError):
    """Raised by :meth:`InstancePool.next` when the pool has no members.

    The caller decides whether to fall back to the code-embedded default
    URL or surface the outage. Bridges catch this and continue with the
    ``env`` / ``config`` / ``default`` resolution path so the empty
    catalog remains byte-identical to today.
    """


class InstancePool:
    """Round-robin selector across two or more enabled instances.

    ``pool.next()`` returns the next :class:`ResolvedInstance` in the
    rotation and advances the counter under an :class:`asyncio.Lock` so
    concurrent callers on the same event loop see interleaved picks.
    ``pool.snapshot()`` returns the underlying members without mutating
    the counter -- used by the operator dashboard.

    A pool is not a health checker: RFC-07 already drops unhealthy
    instances from the enabled set via the catalog's ``enabled`` bit
    and the healer's ``set_enabled`` flip. The pool trusts the caller
    to have filtered on ``enabled`` before constructing it.
    """

    def __init__(self, members: list[ResolvedInstance]) -> None:
        # Snapshot the caller's list so later mutations do not shift
        # the pool's rotation under our feet.
        self._members: tuple[ResolvedInstance, ...] = tuple(members)
        self._cursor: int = 0
        self._lock: asyncio.Lock = asyncio.Lock()

    def __len__(self) -> int:
        return len(self._members)

    def snapshot(self) -> tuple[ResolvedInstance, ...]:
        """Return the pool's members without advancing the cursor."""
        return self._members

    async def next(self) -> ResolvedInstance:
        """Return the next member in round-robin order.

        Raises :class:`EmptyPoolError` when the pool is empty so the
        caller knows to fall through to the code-embedded default
        rather than dispatching to nowhere.
        """
        if not self._members:
            raise EmptyPoolError("instance pool is empty")
        async with self._lock:
            picked = self._members[self._cursor % len(self._members)]
            self._cursor += 1
            return picked


def compact_tool_spec(raw: dict[str, Any]) -> dict[str, Any]:
    """Project one MCP ``tools/list`` entry into the prompt-builder shape.

    The three bridges each shipped a private copy of this helper (byte
    identical). It moves here so both the generic dispatcher and every
    bridge subclass consume one definition -- an operator adds a
    description length cap or a param-truncation rule here and every
    server picks it up.

    Input shape (MCP's ``tools/list``): ``{name, description,
    parameters: {properties, required}}``. Output shape (prompt
    builder's contract): ``{name, description, params: [{name, type,
    required, default, description}], required: [...]}``.
    """
    name = str(raw.get("name") or "")
    description = str(raw.get("description") or "").strip()
    schema = raw.get("parameters") or raw.get("inputSchema") or {}
    properties = schema.get("properties") or {}
    required = list(schema.get("required") or [])
    params: list[dict[str, Any]] = []
    for pname in sorted(properties.keys()):
        pspec = properties[pname] or {}
        entry: dict[str, Any] = {
            "name": pname,
            "type": pspec.get("type") or "any",
            "required": pname in required,
        }
        if "default" in pspec:
            entry["default"] = pspec["default"]
        pdesc = pspec.get("description")
        if pdesc:
            # RFC-11 zero-trust: an MCP server controls its own tool
            # descriptions, so strip prompt-injection patterns from the
            # free-text before it lands in an agent prompt (tool-poisoning
            # defense). Structural fields (name/type/required/default)
            # stay verbatim -- they drive dispatch and the approval hash.
            entry["description"] = sanitize_input(str(pdesc))[:240]
        params.append(entry)
    return {
        "name": name,
        "description": sanitize_input(description)[:400],
        "params": params,
        "required": required,
    }


async def resolve_instance(
    *,
    module_scope: str | None,
    server_name: str,
    env_var: str,
    config_key: str,
    default_url: str,
    catalog: McpInstanceCatalog | None = None,
    registry: ConfigRegistry | None = None,
) -> ResolvedInstance:
    """Resolve the base URL a caller should hit for ``server_name``.

    Priority (highest first): ``env`` > ``config`` > ``catalog`` >
    ``default``. Byte-identical to
    :meth:`McpRegistryServiceBase._resolved_url` so the two callers
    (registry probe path + bridge dispatch path) never disagree on
    where the operator PATCH landed.

    Only the ``catalog`` tier carries an ``instance_id`` and
    ``capability_tags`` -- the other three tiers pre-date the catalog
    and have no row to bind. A disabled catalog row is treated as
    absent so the operator's temporary disable acts as "revert to
    the code-embedded default" rather than "dispatch to nowhere".

    On a ``ConfigRegistry`` outage the resolver logs and falls
    through to the catalog / default tiers so a broken DB never
    silently rewrites the target URL to something a bridge can't
    reach.
    """
    env_value = os.environ.get(env_var)
    if env_value:
        return ResolvedInstance(
            url=env_value.rstrip("/"),
            source=_SOURCE_ENV,
            instance_id=None,
            capability_tags=(),
            name=server_name,
            module_scope=module_scope,
        )
    reg = registry or ConfigRegistry()
    module_ns = module_scope or ""
    try:
        cfg_value = await reg.get(module_ns, config_key) if module_ns else None
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
        # ConfigRegistry outages fall through to the catalog + default
        # tiers rather than crashing every bridge call. Same policy
        # the pre-RFC-11 bridges used; logged so the operator sees
        # the config path is stale.
        _log.info(
            "mcp resolve_instance: ConfigRegistry lookup failed for %s/%s (%s: %s) "
            "-- falling back to catalog + default",
            module_scope, config_key, type(exc).__name__, exc,
        )
        cfg_value = None
    if isinstance(cfg_value, str) and cfg_value.strip():
        return ResolvedInstance(
            url=cfg_value.rstrip("/"),
            source=_SOURCE_CONFIG,
            instance_id=None,
            capability_tags=(),
            name=server_name,
            module_scope=module_scope,
        )
    row = await _catalog_row(catalog or McpInstanceCatalog(), module_scope, server_name)
    if row is not None:
        endpoint = (row.endpoint or "").strip().rstrip("/")
        if endpoint:
            return ResolvedInstance(
                url=endpoint,
                source=_SOURCE_CATALOG,
                instance_id=row.id,
                capability_tags=tuple(decode_capability_tags(row.capability_tags)),
                name=row.name,
                module_scope=row.module_scope,
            )
    return ResolvedInstance(
        url=default_url.rstrip("/"),
        source=_SOURCE_DEFAULT,
        instance_id=None,
        capability_tags=(),
        name=server_name,
        module_scope=module_scope,
    )


async def _catalog_row(
    catalog: McpInstanceCatalog,
    module_scope: str | None,
    server_name: str,
) -> McpServerInstance | None:
    """Return the enabled catalog row for ``(module_scope, server_name)``.

    Catalog outages are swallowed so a bridge call never fails because
    the DB is down -- the caller falls through to the code-embedded
    default. A disabled row is treated as absent so ``enabled=False``
    on the row acts as an operator temporary revert to the default.
    """
    try:
        # RFC-11 zero-trust: live dispatch resolves only APPROVED catalog
        # rows. A pending / revoked row is treated as absent so the
        # resolver falls through to env / config / default -- an
        # unapproved server can never silently serve a live call.
        row = await catalog.get_by_scope_and_name(
            module_scope, server_name, approved_only=True,
        )
    except (SQLAlchemyError, OSError, RuntimeError) as exc:
        _log.info(
            "mcp resolve_instance: catalog lookup failed for %s/%s (%s) "
            "-- falling back to default",
            module_scope, server_name, exc,
        )
        return None
    if row is None or not row.enabled:
        return None
    return row


@asynccontextmanager
async def build_recorder_context(
    recorder: Callable[..., AbstractAsyncContextManager[dict[str, Any]]] | None,
    *,
    server_id: str,
    base_url: str,
    action: str,
    instance_id: str | None,
):
    """Wrap the caller's ``record_call`` factory in a uniform envelope.

    Callers pass their module-specific ``record_call`` (a functools
    partial pre-bound to their audit-log record model). When absent
    -- tests, ad-hoc scripts -- the context manager yields an empty
    dict so the dispatch path stays untouched. Threading
    ``instance_id`` here means every subclass of :class:`McpClient`
    records the catalog row on the same code path; no bridge can
    forget to stamp it.
    """
    if recorder is None:
        # tests and ad-hoc scripts pass no recorder; yield an inert
        # ctx dict so ``ctx["status"] = ...`` from the caller still
        # works without a NoneType raise.
        yield {}
        return
    async with recorder(
        server_id=server_id,
        base_url=base_url,
        action=action,
        instance_id=instance_id,
    ) as ctx:
        yield ctx


class McpClient:
    """Generic HTTP MCP client -- the transport half of every bridge.

    Owns the URL resolver, the ``GET /tools`` catalog fetch and cache,
    the ``POST /tools/<action>`` dispatch, the JSON parse, and the
    per-call recorder. Server-specific tricks (kwarg alias maps, JADX
    rewrites, IDA auto-name coercion, android-mcp pipeline blocks,
    dedup caches, dead-worker detection, prewarm fan-out) stay on the
    bridge subclasses -- see the RFC-11 step-5 audit for which bridges
    could not collapse fully.

    Two construction shapes:

    * ``McpClient(server_id=..., base_url="http://...")`` -- fixed
      URL. Used by tests and DI paths that inject a mock transport.
    * ``McpClient(server_id=..., resolver=lambda: resolve_instance(...))``
      -- deferred resolution. The client re-runs ``resolver`` on
      first use, caches the result for the client lifetime, and
      re-resolves after :meth:`invalidate_base_url`. Bridges use
      this shape so an operator PATCH against the catalog or the
      module's ConfigRegistry key takes effect on the next call
      without a worker restart.
    """

    def __init__(
        self,
        *,
        server_id: str,
        base_url: str | None = None,
        resolver: Callable[[], Any] | None = None,
        timeout: float = 60.0,
        recorder: (
            Callable[..., AbstractAsyncContextManager[dict[str, Any]]] | None
        ) = None,
        persistent_pool: bool = False,
    ) -> None:
        self.server_id = server_id
        self._fixed_base_url: str | None = (
            base_url.rstrip("/") if base_url else None
        )
        self._resolver = resolver
        self._timeout = timeout
        self._recorder = recorder
        self._resolved: ResolvedInstance | None = None
        self._spec_cache: list[dict[str, Any]] | None = None
        # ``persistent_pool`` reuses one httpx client across calls
        # (android-mcp's module-level connection pool); the default
        # opens and closes a fresh client per call, byte-identical to
        # the pre-Tier-C ida/audit bridges.
        self._persistent_pool = persistent_pool
        self._http: httpx.AsyncClient | None = None

    def invalidate_base_url(self) -> None:
        """Drop the cached resolution so the next call re-runs ``resolver``.

        Optional escape hatch for operators who PATCH the catalog row
        or the ConfigRegistry key mid-run -- the bridge instance still
        picks up the new value without a worker restart.
        """
        self._resolved = None

    def invalidate_spec_cache(self) -> None:
        """Drop the cached tool catalogue so the next list re-fetches.

        Mirrors :meth:`invalidate_base_url`. A middleware that governs
        its own catalogue freshness (audit-mcp's class-level TTL) calls
        this to force the client's per-client spec cache to refetch on
        the next :meth:`list_tool_specs`.
        """
        self._spec_cache = None

    async def resolve(self) -> ResolvedInstance:
        """Return the cached :class:`ResolvedInstance` or resolve fresh.

        ``base_url`` supplied at construction wins forever (tests + DI)
        and yields a synthetic ``ResolvedInstance(source='default',
        instance_id=None)`` so the dispatch path shape stays uniform.
        """
        if self._fixed_base_url is not None:
            return ResolvedInstance(
                url=self._fixed_base_url,
                source=_SOURCE_DEFAULT,
                instance_id=None,
                capability_tags=(),
                name=self.server_id,
            )
        if self._resolved is not None:
            return self._resolved
        if self._resolver is None:
            raise RuntimeError(
                f"McpClient({self.server_id}): no base_url and no resolver",
            )
        resolved = self._resolver()
        if asyncio.iscoroutine(resolved):
            resolved = await resolved
        if not isinstance(resolved, ResolvedInstance):
            raise TypeError(
                f"McpClient({self.server_id}): resolver returned "
                f"{type(resolved).__name__}, expected ResolvedInstance",
            )
        self._resolved = resolved
        return resolved

    async def base_url(self) -> str:
        """Return the URL, resolving via ``resolver`` on first call."""
        return (await self.resolve()).url

    async def instance_id(self) -> str | None:
        """Return the catalog row id, or ``None`` for env/config/default tiers."""
        return (await self.resolve()).instance_id

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Fetch ``GET /tools`` once per client and cache the parsed catalog.

        Returns a list of :func:`compact_tool_spec` outputs. Fetch
        failures (connect / timeout / non-JSON) cache an empty list
        so the caller sees a name-only listing rather than repeated
        stalls; the bridge subclass MAY override this method to add
        per-server schema-fetch hops (android-mcp fans schema URLs
        per tool because ``/tools`` returns only names).
        """
        if self._spec_cache is not None:
            return self._spec_cache
        resolved = await self.resolve()
        url = f"{resolved.url}/tools"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
            raw = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            _log.warning(
                "mcp_client %s: catalog fetch failed (%s) -- caching empty",
                self.server_id, exc,
            )
            self._spec_cache = []
            return []
        # Accept two on-wire shapes: bare list at top level (audit-mcp,
        # ida-headless) or ``{"tools": [...]}`` envelope (android-mcp).
        # A dict without a ``tools`` key is treated as an empty catalog
        # so downstream validators do not compare against a None
        # catalog (see the android-mcp §216 diagnosis).
        if isinstance(raw, dict):
            inner = raw.get("tools")
            raw = inner if isinstance(inner, list) else []
        if not isinstance(raw, list):
            self._spec_cache = []
            return []
        self._spec_cache = [compact_tool_spec(t) for t in raw if isinstance(t, dict)]
        return self._spec_cache

    @asynccontextmanager
    async def recorder_context(self, action: str):
        """Open the single audit-log envelope for one ``forward`` call.

        Resolves the instance (for ``base_url`` + ``instance_id``) then
        delegates to :func:`build_recorder_context`. A middleware wraps
        its whole ``forward`` in one ``recorder_context`` and threads the
        yielded ``ctx`` into the primary :meth:`post` so exactly one row
        is written per call with the final outcome -- pending-poll
        retries and fan-out calls run through :meth:`post` WITHOUT a
        ``ctx`` and add no rows, byte-identical to the pre-Tier-C
        bridges.
        """
        resolved = await self.resolve()
        async with build_recorder_context(
            self._recorder,
            server_id=self.server_id,
            base_url=resolved.url,
            action=action,
            instance_id=resolved.instance_id,
        ) as ctx:
            yield ctx

    async def _pooled_client(self) -> httpx.AsyncClient:
        """Return the reused pool client, creating it on first use.

        Only reached when ``persistent_pool`` is set. The client carries
        a connection pool sized to match android-mcp's module-level pool
        (100 connections, 20 keep-alive); the per-call timeout is passed
        on each request rather than baked into the client so a slow tool
        does not inherit a fast client's deadline.
        """
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                limits=httpx.Limits(
                    max_connections=100, max_keepalive_connections=20,
                ),
            )
        return self._http

    async def _http_post(
        self, url: str, payload: dict[str, Any], timeout: float,
    ) -> httpx.Response:
        """POST ``payload`` to ``url`` via the pool or a fresh client.

        The ``headers`` dict is populated by the otel propagator when
        ``platform.otel_enabled`` is on -- injecting the active span's
        W3C ``traceparent`` / ``tracestate`` so the downstream MCP
        server (audit-mcp / ida-headless / semble / ...) can stitch its
        own spans onto the caller's trace. When otel is absent or the
        flag is off, :func:`inject_trace_context` is a no-op and the
        headers dict stays empty -- httpx sends the same bytes as the
        pre-otel path (RFC #160).
        """
        headers: dict[str, str] = {}
        inject_trace_context(headers)
        if self._persistent_pool:
            client = await self._pooled_client()
            return await client.post(
                url, json=payload, headers=headers, timeout=timeout,
            )
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await client.post(url, json=payload, headers=headers)

    async def aclose(self) -> None:
        """Close the pool client if one was opened. No-op otherwise."""
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()
        self._http = None

    async def post(
        self,
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        ctx: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST ``/tools/<action>`` and return the normalised JSON body.

        The raw transport primitive: no audit-log row is written here.
        Pass ``ctx`` (from :meth:`recorder_context`) for the one call
        that should be recorded; omit it for secondary calls (poll
        retries, prewarm, fallbacks). Network failures and non-JSON
        responses collapse into the uniform ``{"status": "error",
        "error": "..."}`` envelope so the caller never branches on the
        transport layer. Status classification is byte-identical to the
        pre-Tier-C bridge dispatch.

        Wrapped in a GenAI ``execute_tool`` span (RFC #160) so the
        outbound httpx call carries this span's W3C ``traceparent`` --
        the downstream MCP server attaches its own spans as children.
        The wrapper is a no-op when otel is unavailable or the flag is
        off, so this dispatch stays byte-identical to the base install.
        """
        span_attrs: dict[str, Any] = {
            "gen_ai.tool.name": action,
            "aila.mcp.server_id": self.server_id,
        }
        with gen_ai_span(
            GEN_AI_OPERATION_EXECUTE_TOOL,
            attributes=span_attrs,
        ) as _span:
            started = time.perf_counter()
            try:
                return await self._post_impl(
                    action, payload, timeout=timeout, ctx=ctx, span=_span,
                )
            finally:
                _span.set_attribute(
                    "aila.mcp.latency_ms",
                    (time.perf_counter() - started) * 1000.0,
                )

    async def _post_impl(
        self,
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None,
        ctx: dict[str, Any] | None,
        span: Any,
    ) -> dict[str, Any]:
        """Inner body of :meth:`post` -- kept separate so the outer span
        wrapper reads cleanly. Semantics are byte-identical to the
        pre-#160 dispatch.
        """
        resolved = await self.resolve()
        base = resolved.url
        url = f"{base}/tools/{action}"
        span.set_attribute("aila.mcp.instance_source", resolved.source)
        if resolved.instance_id is not None:
            span.set_attribute("aila.mcp.instance_id", resolved.instance_id)
        effective_timeout = timeout if timeout is not None else self._timeout
        try:
            resp = await self._http_post(url, payload, effective_timeout)
        except httpx.ConnectError as exc:
            if ctx is not None:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
            return {
                "status": "error",
                "error": f"Cannot reach {self.server_id} at {base}: {exc}",
            }
        except httpx.TimeoutException as exc:
            if ctx is not None:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
            return {
                "status": "error",
                "error": (
                    f"Timeout ({effective_timeout}s) calling "
                    f"{self.server_id}.{action}: {exc}"
                ),
            }
        if ctx is not None:
            ctx["http_status"] = resp.status_code
        try:
            body = resp.json()
        except ValueError as exc:
            if ctx is not None:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
            return {
                "status": "error",
                "error": (
                    f"Non-JSON response from {self.server_id}.{action}: "
                    f"{resp.text[:200]}"
                ),
            }
        if not isinstance(body, dict):
            # A bare list / scalar body wraps into the uniform
            # envelope so the caller can index status uniformly.
            body = {"status": "ready", "result": body}
        status = body.get("status")
        if status in ("ready", "completed", "ok"):
            if ctx is not None:
                ctx["status"] = "ready"
        elif status in ("pending", "queued", "running"):
            if ctx is not None:
                ctx["status"] = "pending"
        elif status == "error":
            if ctx is not None:
                ctx["status"] = "error"
                err = body.get("error")
                if isinstance(err, str):
                    ctx["error_excerpt"] = err[:400]
        elif status is None:
            # HTTP 2xx + no status field is the documented MCP
            # success shape for tools that return a bare result
            # dict (list_functions, binary_metadata, etc.). Inject
            # ready so downstream success-whitelists never see a
            # missing key that reads as failure.
            if resp.status_code < 400:
                if ctx is not None:
                    ctx["status"] = "ready"
                body = {**body, "status": "ready"}
            elif ctx is not None:
                ctx["status"] = "error"
        else:
            # Unknown non-standard status -- log once and treat as
            # error rather than silently masking a partial-failure.
            _log.warning(
                "mcp_client %s: unknown payload status %r "
                "(HTTP %d) on action %s -- coercing to error",
                self.server_id, status, resp.status_code, action,
            )
            if ctx is not None:
                ctx["status"] = "error"
        return body

    async def call_tool(
        self,
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """POST ``/tools/<action>`` and record one audit row.

        The single-call convenience path: :meth:`recorder_context` +
        :meth:`post`. Middleware plugins that need retry / fallback /
        fan-out loops call :meth:`post` directly so only the primary
        call is recorded. Byte-identical to the pre-Tier-C dispatch.
        """
        async with self.recorder_context(action) as ctx:
            return await self.post(action, payload, timeout=timeout, ctx=ctx)

    async def health(self) -> dict[str, Any]:
        """Best-effort ``GET /health`` for the operator's readiness UI."""
        resolved = await self.resolve()
        url = f"{resolved.url}/health"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
            data = resp.json()
        except (httpx.HTTPError, ValueError):
            return {"status": "error", "error": f"Unreachable: {url}"}
        if not isinstance(data, dict):
            return {"status": "ready", "result": data}
        return data

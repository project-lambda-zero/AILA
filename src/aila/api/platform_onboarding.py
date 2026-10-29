"""Platform onboarding catalog behind ``GET /config/platform/schema`` (#246).

One declarative table names every platform key the first-run onboarding
wizard surfaces: its category, prerequisite checker, and whether the wizard
may write it. Descriptions and defaults come from ``PlatformConfigSchema``
field metadata and live values from ``ConfigRegistry.describe_resolution``,
so the wizard never re-authors copy that already lives in
``aila.platform.config``.

The same table backs the write gate on ``PUT /config/platform/<key>``:
enabling a boolean key whose prerequisite fails is rejected with the
checker's actionable detail, and enumerated string keys are restricted to
their declared choices.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib.util import find_spec
from typing import Literal

from sqlmodel import col, select

from aila.api.routers.platform_sandbox import SandboxStatus, build_sandbox_status
from aila.api.schemas.config import PlatformSchemaEntry, PlatformSchemaPrerequisite, PlatformSchemaResponse
from aila.config import get_settings
from aila.platform.config import PlatformConfigSchema, build_platform_settings
from aila.platform.observability.otel import is_otel_available
from aila.platform.services.sandbox.service import SandboxService
from aila.storage.database import async_session_scope
from aila.storage.db_models import ConfigEntryRecord
from aila.storage.registry import ConfigRegistry, ConfigResolution

__all__ = [
    "ONBOARDING_COMPLETED_KEY",
    "PLATFORM_NAMESPACE",
    "SANDBOX_BACKEND_CHOICES",
    "build_platform_schema",
    "validate_platform_write",
]

PLATFORM_NAMESPACE = "platform"
ONBOARDING_COMPLETED_KEY = "onboarding_completed"
SANDBOX_BACKEND_CHOICES: tuple[str, ...] = ("none", "nsjail", "firecracker")

_TRUE_TOKENS = frozenset({"true", "1", "yes"})

OnboardingCategory = Literal["capability", "infra", "operational"]
ValueType = Literal["str", "int", "float", "bool"]


@dataclass(frozen=True, slots=True)
class _PrereqContext:
    """Live state every checker reads; built once per request."""

    sandbox: SandboxStatus
    resolutions: Mapping[str, ConfigResolution]


Checker = Callable[[str, _PrereqContext], PlatformSchemaPrerequisite]


def _check_sandbox_provisioned(key: str, ctx: _PrereqContext) -> PlatformSchemaPrerequisite:
    del key
    status = ctx.sandbox
    if status.provisioned:
        return PlatformSchemaPrerequisite(
            name="sandbox backend provisioned",
            ok=True,
            detail=(
                f"sandbox_backend={status.backend} on {status.ssh_host} is configured. "
                "Run the live probe to confirm the host is reachable over SSH."
            ),
        )
    failing = "; ".join(check.detail for check in status.checks if not check.ok)
    return PlatformSchemaPrerequisite(
        name="sandbox backend provisioned",
        ok=False,
        detail=f"{failing}. Configure the sandbox host on the Sandbox page, then probe it.",
    )


def _check_miasm(key: str, ctx: _PrereqContext) -> PlatformSchemaPrerequisite:
    del key, ctx
    if find_spec("miasm") is not None:
        return PlatformSchemaPrerequisite(name="miasm installed", ok=True, detail="miasm is importable.")
    return PlatformSchemaPrerequisite(
        name="miasm installed",
        ok=False,
        detail="miasm is not importable. Run `pip install .[symbolic]` on the API and worker hosts, then restart them.",
    )


def _check_otel(key: str, ctx: _PrereqContext) -> PlatformSchemaPrerequisite:
    del key, ctx
    if is_otel_available():
        return PlatformSchemaPrerequisite(
            name="opentelemetry installed", ok=True, detail="opentelemetry is importable.",
        )
    return PlatformSchemaPrerequisite(
        name="opentelemetry installed",
        ok=False,
        detail=(
            "opentelemetry is not importable. Run `pip install .[otel]` on the API and worker hosts, "
            "wire an OTLP exporter through opentelemetry-instrument, then restart them."
        ),
    )


def _check_key_set(key: str, ctx: _PrereqContext) -> PlatformSchemaPrerequisite:
    res = ctx.resolutions[key]
    if res.effective_value.strip():
        return PlatformSchemaPrerequisite(
            name="API key configured", ok=True, detail=f"Key supplied via {res.source}.",
        )
    return PlatformSchemaPrerequisite(
        name="API key configured",
        ok=False,
        detail=f"No key configured. Enter one here or set {res.env_key}.",
    )


@dataclass(frozen=True, slots=True)
class _EntrySpec:
    key: str
    category: OnboardingCategory
    checker: Checker | None = None
    read_only: bool = False
    secret: bool = False
    choices: tuple[str, ...] | None = None


_ENTRIES: tuple[_EntrySpec, ...] = (
    _EntrySpec("vr_lateral_llm_enabled", "capability"),
    _EntrySpec("vr_explorer_enabled", "capability"),
    _EntrySpec("speculative_enabled", "capability"),
    _EntrySpec("prompt_layout_enabled", "capability"),
    _EntrySpec("context_retrieved_enabled", "capability"),
    _EntrySpec("context_shared_pool_enabled", "capability"),
    _EntrySpec("routing_negative_feedback_enabled", "capability"),
    _EntrySpec("lsp_enabled", "capability"),
    _EntrySpec("otel_enabled", "capability", checker=_check_otel),
    _EntrySpec("autopatch_enabled", "capability"),
    _EntrySpec("sandbox_backend", "infra", checker=_check_sandbox_provisioned, choices=SANDBOX_BACKEND_CHOICES),
    _EntrySpec("dynamic_execution_enabled", "infra", checker=_check_sandbox_provisioned),
    _EntrySpec("symbolic_enabled", "infra", checker=_check_miasm),
    _EntrySpec("retrieval_backend_voyage_api_key", "infra", checker=_check_key_set, secret=True),
    _EntrySpec("retrieval_backend_jina_api_key", "infra", checker=_check_key_set, secret=True),
    _EntrySpec("retrieval_backend_qwen_reranker_api_key", "infra", checker=_check_key_set, secret=True),
    _EntrySpec("llm_kill_switch", "operational", read_only=True),
    _EntrySpec("llm_pipeline_verify_default", "operational", read_only=True),
    _EntrySpec("mcp_tool_hash_strict", "operational", read_only=True),
    _EntrySpec("smtp_use_implicit_tls", "operational", read_only=True),
    _EntrySpec("index_readiness_gate_enabled", "operational", read_only=True),
    _EntrySpec("investigation_reconciler_periodic_enabled", "operational", read_only=True),
)

_SPECS_BY_KEY: dict[str, _EntrySpec] = {spec.key: spec for spec in _ENTRIES}

_VALUE_TYPES: dict[type, ValueType] = {bool: "bool", int: "int", float: "float", str: "str"}


def _value_type(key: str) -> ValueType:
    return _VALUE_TYPES[type(PlatformConfigSchema.model_fields[key].default)]


def _is_truthy(raw: str) -> bool:
    return raw.strip().lower() in _TRUE_TOKENS


async def _resolve_all(registry: ConfigRegistry, keys: tuple[str, ...]) -> dict[str, ConfigResolution]:
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == PLATFORM_NAMESPACE,
                col(ConfigEntryRecord.key).in_(keys),
            )
        )).all()
    db_values = {row.key: row.value for row in rows}
    return {
        key: registry.describe_resolution(PLATFORM_NAMESPACE, key, db_value=db_values.get(key))
        for key in keys
    }


async def _build_context(registry: ConfigRegistry) -> _PrereqContext:
    keys = (*(spec.key for spec in _ENTRIES), ONBOARDING_COMPLETED_KEY)
    resolutions = await _resolve_all(registry, keys)
    service = SandboxService(build_platform_settings(get_settings()), config_registry=registry)
    sandbox = build_sandbox_status(await service.describe())
    return _PrereqContext(sandbox=sandbox, resolutions=resolutions)


def _entry(spec: _EntrySpec, ctx: _PrereqContext) -> PlatformSchemaEntry:
    res = ctx.resolutions[spec.key]
    return PlatformSchemaEntry(
        key=spec.key,
        category=spec.category,
        value_type=_value_type(spec.key),
        default_value=None if spec.secret else res.default_value,
        effective_value=None if spec.secret else res.effective_value,
        effective_source=res.source,
        overridden_by_env=res.env_value is not None,
        env_key=res.env_key,
        description=PlatformConfigSchema.model_fields[spec.key].description or "",
        prerequisite=spec.checker(spec.key, ctx) if spec.checker is not None else None,
        read_only=spec.read_only,
        secret=spec.secret,
        is_set=bool(res.effective_value.strip()),
        choices=list(spec.choices) if spec.choices is not None else None,
    )


async def build_platform_schema(registry: ConfigRegistry) -> PlatformSchemaResponse:
    """Resolve every onboarding entry plus the completion marker."""
    ctx = await _build_context(registry)
    return PlatformSchemaResponse(
        onboarding_completed=_is_truthy(ctx.resolutions[ONBOARDING_COMPLETED_KEY].effective_value),
        entries=[_entry(spec, ctx) for spec in _ENTRIES],
    )


async def validate_platform_write(registry: ConfigRegistry, key: str, value: str) -> str | None:
    """Return an actionable rejection message for a platform write, or None.

    Enumerated keys accept only their declared choices. A boolean key with a
    prerequisite checker cannot be switched on while that prerequisite fails,
    so enabling it never lands as a silent no-op.
    """
    spec = _SPECS_BY_KEY.get(key)
    if spec is None:
        return None
    if spec.choices is not None and value not in spec.choices:
        allowed = ", ".join(spec.choices)
        return f"{key} must be one of: {allowed}; got {value!r}."
    if spec.checker is None or _value_type(key) != "bool" or not _is_truthy(value):
        return None
    prerequisite = spec.checker(key, await _build_context(registry))
    if prerequisite.ok:
        return None
    return f"Cannot enable {key}: {prerequisite.name} is not satisfied. {prerequisite.detail}"

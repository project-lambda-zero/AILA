"""RFC-11 step 1 -- DB-backed MCP server instance catalog.

An operator-editable catalog of MCP server instances (audit-mcp,
ida-headless, android-mcp, and future servers) persisted in
``mcp_server_instances`` and administered through the
``/platform/mcp/instances`` REST surface. Live dispatch stays untouched:
:class:`aila.platform.mcp.registry.McpRegistryServiceBase` MAY consult
the catalog as an operator-editable default that beats the code-embedded
``default_url`` but stays below ``env`` and ``config`` overrides. When
no catalog row exists for a given ``(module_scope, name)``, resolution
is byte-identical to the pre-catalog behaviour.

Each row carries:

* ``id`` -- stable primary key (uuid by default; the migration seeds
  descriptive ids so operators can address rows without a lookup).
* ``name`` -- the stable server token that matches ``spec['id']`` in
  the module's static :class:`MCP_SERVERS` tuple (``"audit_mcp"``,
  ``"ida_headless"`` ...). The registry looks up catalog rows by
  ``(module_scope, name)``, so this field is the join key.
* ``transport`` -- ``"http"`` or ``"stdio"``. The current bridges are
  HTTP-only; ``"stdio"`` reserves the row for the future stdio subprocess
  transport without a schema migration.
* ``endpoint`` -- HTTP base URL for ``http`` rows, command line for
  ``stdio`` rows. Bridges keep resolving via
  :meth:`McpRegistryServiceBase._resolved_url`; this field replaces the
  static ``default_url`` when catalog resolution kicks in.
* ``capability_tags`` -- JSON-encoded ``list[str]`` describing the
  capability groups the instance advertises (``["source_audit",
  "graph"]``). Serialisation lives on the service; the column stores
  raw JSON text.
* ``enabled`` -- disables the row without deleting it (kept in the
  catalog for audit history and quick re-enable).
* ``module_scope`` -- module id namespace (``"vr"``, ``"malware"``,
  ``None`` for platform-wide). Combined with ``name`` for the natural
  unique key so ``audit_mcp`` can appear under multiple modules.
* ``created_at`` / ``updated_at`` -- lifecycle timestamps written by
  the service, not by SQLAlchemy defaults, so ``updated_at`` remains
  ``None`` until the first mutation and moves atomically on ``set_``
  / ``update_`` calls.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text, UniqueConstraint, func
from sqlmodel import Field, SQLModel, select

from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope

__all__ = [
    "McpInstanceCatalog",
    "McpServerInstance",
    "TRANSPORT_HTTP",
    "TRANSPORT_STDIO",
    "decode_capability_tags",
    "encode_capability_tags",
]

_log = logging.getLogger(__name__)

TRANSPORT_HTTP: str = "http"
TRANSPORT_STDIO: str = "stdio"
_ALLOWED_TRANSPORTS: frozenset[str] = frozenset({TRANSPORT_HTTP, TRANSPORT_STDIO})


class McpServerInstance(SQLModel, table=True):
    """One MCP server registration row in the operator-editable catalog.

    The natural key is ``(module_scope, name)`` -- the same ``name`` can
    appear under multiple scopes (``audit_mcp`` under ``vr`` and under
    ``malware`` are distinct rows with independent endpoints). ``id`` is
    the technical PK so PATCH / DELETE routes stay stable across renames.
    """

    __tablename__ = "mcp_server_instances"
    __table_args__ = (
        UniqueConstraint(
            "module_scope", "name",
            name="uq_mcp_server_instances_scope_name",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(sa_column=Column(Text, nullable=False, index=True))
    transport: str = Field(
        default=TRANSPORT_HTTP,
        sa_column=Column(Text, nullable=False, server_default=TRANSPORT_HTTP),
    )
    endpoint: str = Field(sa_column=Column(Text, nullable=False))
    capability_tags: str = Field(
        default="[]",
        sa_column=Column(Text, nullable=False, server_default="[]"),
    )
    enabled: bool = Field(default=True, nullable=False, index=True)
    module_scope: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True, index=True),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
        ),
    )
    updated_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


def decode_capability_tags(raw: str) -> list[str]:
    """Parse the ``capability_tags`` text column into a Python list.

    A malformed or non-list JSON payload logs a warning and yields an empty
    list rather than crashing the caller (the row is still returned to the
    operator so the bad value is visible and editable via PATCH).
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        _log.warning("mcp_instance capability_tags parse failed: %s", exc)
        return []
    if not isinstance(parsed, list):
        _log.warning(
            "mcp_instance capability_tags is not a JSON list: %r",
            type(parsed).__name__,
        )
        return []
    return [str(item) for item in parsed]


def encode_capability_tags(tags: list[str] | tuple[str, ...] | None) -> str:
    """Serialise a tag sequence to the JSON array text stored in the column."""
    if tags is None:
        return "[]"
    normalised = [str(tag) for tag in tags]
    return json.dumps(normalised)


class McpInstanceCatalog:
    """Async CRUD over :class:`McpServerInstance` rows.

    Every method opens its own :func:`async_session_scope` and commits
    before returning so callers do not need to manage a session. Reads
    that miss return ``None`` (never raise) so the API layer maps them
    to a 404. Mutations return the refreshed row (or ``None`` when the
    id is unknown) so PATCH handlers can serialise the new state without
    a second lookup.
    """

    async def list_instances(
        self, module_scope: str | None = None, *, include_disabled: bool = True,
    ) -> list[McpServerInstance]:
        """Return catalog rows, optionally filtered to a single ``module_scope``.

        ``module_scope=None`` returns every row across all scopes (used by
        the platform-level admin UI). Pass an explicit scope string to
        constrain to that namespace. Disabled rows are included by
        default so the operator can flip ``enabled`` from the same list.
        """
        async with async_session_scope() as session:
            statement = select(McpServerInstance)
            if module_scope is not None:
                statement = statement.where(
                    McpServerInstance.module_scope == module_scope,
                )
            if not include_disabled:
                statement = statement.where(McpServerInstance.enabled.is_(True))
            statement = statement.order_by(
                McpServerInstance.module_scope, McpServerInstance.name,
            )
            rows = (await session.exec(statement)).all()
            return list(rows)

    async def get_instance(self, instance_id: str) -> McpServerInstance | None:
        """Return the row by PK, or ``None`` if not present."""
        async with async_session_scope() as session:
            return await session.get(McpServerInstance, instance_id)

    async def get_by_scope_and_name(
        self, module_scope: str | None, name: str,
    ) -> McpServerInstance | None:
        """Look up by the natural key.

        The registry uses this to translate ``(module_id, spec['id'])``
        into an endpoint override. A missing row returns ``None`` so the
        caller can fall back to env / config / default without an
        exception path.
        """
        async with async_session_scope() as session:
            statement = select(McpServerInstance).where(
                McpServerInstance.name == name,
            )
            if module_scope is None:
                statement = statement.where(
                    McpServerInstance.module_scope.is_(None),
                )
            else:
                statement = statement.where(
                    McpServerInstance.module_scope == module_scope,
                )
            return (await session.exec(statement)).first()

    async def add_instance(
        self,
        *,
        name: str,
        transport: str,
        endpoint: str,
        capability_tags: list[str] | tuple[str, ...] | None = None,
        enabled: bool = True,
        module_scope: str | None = None,
        instance_id: str | None = None,
    ) -> McpServerInstance:
        """Insert a new catalog row and return it after refresh.

        The unique constraint on ``(module_scope, name)`` is enforced by
        Postgres; a duplicate raises :class:`sqlalchemy.exc.IntegrityError`
        so the API layer can map it to a 409. ``instance_id`` is
        caller-supplied when the migration seeds a stable id, otherwise
        a uuid4 is generated.
        """
        if transport not in _ALLOWED_TRANSPORTS:
            raise ValueError(
                f"unknown transport {transport!r}; "
                f"expected one of {sorted(_ALLOWED_TRANSPORTS)}",
            )
        row = McpServerInstance(
            id=instance_id if instance_id else str(uuid4()),
            name=name,
            transport=transport,
            endpoint=endpoint,
            capability_tags=encode_capability_tags(capability_tags),
            enabled=enabled,
            module_scope=module_scope,
            created_at=utc_now(),
            updated_at=None,
        )
        async with async_session_scope() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row

    async def set_enabled(
        self, instance_id: str, enabled: bool,
    ) -> McpServerInstance | None:
        """Flip the ``enabled`` bit and stamp ``updated_at``.

        Returns the refreshed row, or ``None`` when the id is unknown.
        A no-op (same value in, same value out) still stamps
        ``updated_at`` so the audit trail records the intent.
        """
        async with async_session_scope() as session:
            row = await session.get(McpServerInstance, instance_id)
            if row is None:
                return None
            row.enabled = enabled
            row.updated_at = utc_now()
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row

    async def update_endpoint(
        self, instance_id: str, endpoint: str,
    ) -> McpServerInstance | None:
        """Retarget the row's ``endpoint`` and stamp ``updated_at``.

        Trailing slashes are preserved verbatim (the registry strips
        them at resolve time so operators can copy-paste a URL without
        thinking about the trailing slash).
        """
        async with async_session_scope() as session:
            row = await session.get(McpServerInstance, instance_id)
            if row is None:
                return None
            row.endpoint = endpoint
            row.updated_at = utc_now()
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row

    async def update_capability_tags(
        self,
        instance_id: str,
        capability_tags: list[str] | tuple[str, ...],
    ) -> McpServerInstance | None:
        """Overwrite the JSON-encoded ``capability_tags`` column."""
        encoded = encode_capability_tags(capability_tags)
        async with async_session_scope() as session:
            row = await session.get(McpServerInstance, instance_id)
            if row is None:
                return None
            row.capability_tags = encoded
            row.updated_at = utc_now()
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row

    async def remove_instance(self, instance_id: str) -> bool:
        """Delete the row by PK. Returns ``True`` when a row was removed."""
        async with async_session_scope() as session:
            row = await session.get(McpServerInstance, instance_id)
            if row is None:
                return False
            await session.delete(row)
            await session.commit()
            return True

    def instance_to_dict(self, row: McpServerInstance) -> dict[str, Any]:
        """Project a row to an operator-facing dict.

        The API router uses this projection so the ``capability_tags``
        field is a JSON list in the response envelope instead of a raw
        JSON string. Timestamps are emitted as ISO-8601 with timezone.
        The instance parameter keeps the projection callable off a
        specific catalog binding, letting subclasses override formatting
        without touching the API layer.
        """
        del self
        return {
            "id": row.id,
            "name": row.name,
            "transport": row.transport,
            "endpoint": row.endpoint,
            "capability_tags": decode_capability_tags(row.capability_tags),
            "enabled": row.enabled,
            "module_scope": row.module_scope,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }

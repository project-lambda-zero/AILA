"""User-extensible specialist-agent registry (platform).

The investigation panel is a fixed 3-role spine (researcher, critic,
implementer) plus optional *specialist* agents that a core branch can
request from the oracle when a case needs a different expert perspective
(reverse engineering, crypto, exploit development, and any specialist a
user defines). A specialist is data, not code: a row here carries a
``capability`` (which matches the dispatch-phase ``capability`` so the hub
routes the specialist to the right phases), an optional ``strategy_family``
(its prompt family, threaded via the per-phase override), and a
description. Users add their own specialists through the CRUD API without a
code change; every module inherits the mechanism.

A spawned specialist branch carries the specialist ``name`` as its
``persona_voice``; the setup state resolves that name back to a capability
through this registry and threads ``_branch_capability`` into the dispatch
hub input, so the (already-tested) capability filter finally routes.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PField
from sqlalchemy import DateTime, Text
from sqlmodel import Field, SQLModel, select

from aila.platform.contracts import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "CrossTeamSpecialistError",
    "SpecialistAgentCreate",
    "SpecialistAgentRecord",
    "SpecialistAgentRegistry",
    "SpecialistAgentSummary",
]


class SpecialistAgentRecord(SQLModel, table=True):
    """One optional specialist agent a module can spawn on request."""

    __tablename__ = "specialist_agent"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    module_id: str = Field(index=True, max_length=64)
    # ``name`` doubles as the spawned branch's persona_voice.
    name: str = Field(max_length=64)
    # ``capability`` matches a dispatch PhaseSpec.capability so the hub
    # routes this specialist to the phases it owns.
    capability: str = Field(max_length=64, index=True)
    # Optional per-specialist prompt family (threaded via the per-phase
    # strategy_family override); None keeps the investigation family.
    strategy_family: str | None = Field(default=None, max_length=128)
    description: str = Field(default="", sa_type=Text, sa_column_kwargs={"nullable": True})
    enabled: bool = Field(default=True)
    team_id: str | None = Field(default=None, index=True, max_length=64)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
    updated_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class SpecialistAgentSummary(BaseModel):
    """Read-only projection of a specialist agent.

    ``team_id`` is NULL for platform-global built-ins and the caller's
    team_id for team-scoped rows; API callers see it so a team-scoped
    operator can tell an owned row from a global default.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    module_id: str
    name: str
    capability: str
    strategy_family: str | None = None
    description: str = ""
    enabled: bool = True
    team_id: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class SpecialistAgentCreate(BaseModel):
    """Create/update payload for a specialist agent."""

    model_config = ConfigDict(extra="forbid")

    module_id: str = PField(min_length=1, max_length=64)
    name: str = PField(min_length=1, max_length=64)
    capability: str = PField(min_length=1, max_length=64)
    strategy_family: str | None = PField(default=None, max_length=128)
    description: str = PField(default="", max_length=4096)
    enabled: bool = True


# Built-in defaults per module. Capabilities match the dispatch phases so a
# fresh install already routes; users extend or disable these via CRUD.
#
# Names are iconic PlayStation 1/2-era characters, chosen so a spawned
# specialist reads as a distinct named panelist alongside the core spine
# (halvar / maddie / renzo), not a bare capability slug. The ``name`` is
# display + persona_voice only; routing keys off ``capability``, so a name
# can change without touching the request or dispatch path.
_BUILTINS: dict[str, tuple[dict[str, str], ...]] = {
    "vr": (
        {"name": "snake", "capability": "binary-audit",
         "description": "Reverse-engineering specialist: disassembly, decompilation, binary internals."},
        {"name": "jak", "capability": "mobile-audit",
         "description": "Mobile specialist: Android/iOS app internals, platform APIs."},
        {"name": "kratos", "capability": "exploit-dev",
         "description": "Exploit-development specialist: turn a confirmed finding into a working PoC."},
        {"name": "lara", "capability": "variant-hunt",
         "description": "Variant-hunt specialist: find sibling instances of a confirmed bug pattern."},
    ),
    "malware": (
        {"name": "alucard", "capability": "re",
         "description": "Reverse-engineering specialist: unpacking, deobfuscation, image reconstruction."},
        {"name": "vincent", "capability": "crypto",
         "description": "Crypto/config specialist: config extraction, key/algorithm recovery."},
    ),
}



def _to_summary(rec: SpecialistAgentRecord) -> SpecialistAgentSummary:
    return SpecialistAgentSummary(
        id=rec.id, module_id=rec.module_id, name=rec.name,
        capability=rec.capability, strategy_family=rec.strategy_family,
        description=rec.description or "", enabled=rec.enabled,
        team_id=rec.team_id,
        created_at=rec.created_at, updated_at=rec.updated_at,
    )


class CrossTeamSpecialistError(Exception):
    """Raised by the registry when a caller addresses another team's row.

    The router translates this into a 404 (never 403) so a team-scoped
    caller cannot use the response code as an existence oracle for other
    teams' specialists.
    """


class SpecialistAgentRegistry:
    """CRUD + lookup over the specialist_agent table."""

    async def list_by_module(
        self,
        module_id: str,
        *,
        enabled_only: bool = False,
        team_id: str | None = None,
        is_admin: bool = True,
    ) -> list[SpecialistAgentSummary]:
        """Return specialists visible to the caller.

        * ``is_admin=True`` (god-tier admin, team_id=None): every row is
          visible regardless of its team stamp.
        * A team-scoped caller (``is_admin=False``, ``team_id="team-x"``)
          sees rows whose ``team_id`` equals its own PLUS rows whose
          ``team_id`` is NULL -- the platform-global built-in defaults are
          visible to every team.

        The ``team_id`` kwarg is ignored when ``is_admin`` is True; the
        two together model TeamContext without a hard dependency on the
        api layer.
        """
        async with UnitOfWork() as uow:
            stmt = select(SpecialistAgentRecord).where(
                SpecialistAgentRecord.module_id == module_id,
            )
            if enabled_only:
                stmt = stmt.where(SpecialistAgentRecord.enabled.is_(True))
            if not is_admin:
                stmt = stmt.where(
                    (SpecialistAgentRecord.team_id == team_id)
                    | (SpecialistAgentRecord.team_id.is_(None)),  # type: ignore[union-attr]
                )
            rows = list((await uow.session.exec(stmt)).all())
        return [_to_summary(r) for r in sorted(rows, key=lambda r: r.name)]

    async def get_by_name(
        self, module_id: str, name: str,
    ) -> SpecialistAgentSummary | None:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(SpecialistAgentRecord).where(
                    SpecialistAgentRecord.module_id == module_id,
                    SpecialistAgentRecord.name == name,
                ),
            )).first()
        return _to_summary(row) if row is not None else None

    async def resolve_capability(
        self, module_id: str, name: str,
    ) -> str | None:
        """Capability for a spawned specialist's persona_voice, or None.

        Core-role branches (researcher/critic/implementer) are not in the
        registry, so this returns None for them -- they walk every phase.
        """
        summary = await self.get_by_name(module_id, name)
        if summary is None or not summary.enabled:
            return None
        return summary.capability

    async def find_by_capability(
        self, module_id: str, capability: str,
    ) -> SpecialistAgentSummary | None:
        """The enabled specialist that owns *capability*, or None."""
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(SpecialistAgentRecord).where(
                    SpecialistAgentRecord.module_id == module_id,
                    SpecialistAgentRecord.capability == capability,
                    SpecialistAgentRecord.enabled.is_(True),
                ),
            )).first()
        return _to_summary(row) if row is not None else None

    async def upsert(
        self,
        spec: SpecialistAgentCreate,
        *,
        team_id: str | None = None,
        is_admin: bool = True,
    ) -> SpecialistAgentSummary:
        """Create or update a specialist, stamping the caller's team.

        * On INSERT the new row's ``team_id`` is the caller's team
          (``None`` for an admin, which yields a platform-global row).
        * On UPDATE a team-scoped caller may only touch a row whose
          ``team_id`` matches its own. Cross-team writes (including
          writes against a NULL-team global by a non-admin) raise
          :class:`CrossTeamSpecialistError`; the router converts that
          into a 404 so no existence oracle leaks.
        """
        async with UnitOfWork() as uow:
            existing = (await uow.session.exec(
                select(SpecialistAgentRecord).where(
                    SpecialistAgentRecord.module_id == spec.module_id,
                    SpecialistAgentRecord.name == spec.name,
                ),
            )).first()
            if existing is None:
                rec = SpecialistAgentRecord(
                    module_id=spec.module_id, name=spec.name,
                    capability=spec.capability,
                    strategy_family=spec.strategy_family,
                    description=spec.description, enabled=spec.enabled,
                    team_id=team_id,
                )
                uow.session.add(rec)
            else:
                if not is_admin and existing.team_id != team_id:
                    raise CrossTeamSpecialistError(
                        f"specialist {spec.module_id}/{spec.name} not owned by caller",
                    )
                existing.capability = spec.capability
                existing.strategy_family = spec.strategy_family
                existing.description = spec.description
                existing.enabled = spec.enabled
                existing.updated_at = utc_now()
                uow.session.add(existing)
                rec = existing
            await uow.session.commit()
            await uow.session.refresh(rec)
            return _to_summary(rec)

    async def delete(
        self,
        module_id: str,
        name: str,
        *,
        team_id: str | None = None,
        is_admin: bool = True,
    ) -> bool:
        """Delete a specialist owned by the caller.

        A team-scoped caller may only delete rows carrying its own
        ``team_id``. Missing rows AND rows owned by another team (or the
        NULL-team global built-ins, when the caller is not admin) both
        return ``False`` so the caller cannot distinguish "does not
        exist" from "not yours".
        """
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(SpecialistAgentRecord).where(
                    SpecialistAgentRecord.module_id == module_id,
                    SpecialistAgentRecord.name == name,
                ),
            )).first()
            if row is None:
                return False
            if not is_admin and row.team_id != team_id:
                return False
            await uow.session.delete(row)
            await uow.session.commit()
            return True

    async def seed_defaults(self, module_id: str) -> int:
        """Insert this module's built-in specialists that are not present.

        Built-in defaults are platform-global: every row is inserted
        with ``team_id=NULL`` regardless of caller so a team-scoped
        operator seeding on a fresh install produces the same globally
        visible defaults an admin would.

        Idempotent: existing names (whether NULL-team globals or a
        team-owned override) are left untouched. Returns the count
        inserted.
        """
        inserted = 0
        for tmpl in _BUILTINS.get(module_id, ()):
            if await self.get_by_name(module_id, tmpl["name"]) is not None:
                continue
            # Always write globals; upsert is called in admin mode with
            # team_id=None so the row gets team_id=NULL.
            await self.upsert(
                SpecialistAgentCreate(
                    module_id=module_id,
                    name=tmpl["name"],
                    capability=tmpl["capability"],
                    description=tmpl.get("description", ""),
                ),
                team_id=None,
                is_admin=True,
            )
            inserted += 1
        return inserted

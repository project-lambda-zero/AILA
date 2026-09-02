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
hub input, so the capability filter routes the specialist branch to its
capability-scoped phase. This routing is active for modules that set
``module_id`` in their setup bindings (such as "vr" and "malware").
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
    """One optional specialist agent or core persona in the registry."""

    __tablename__ = "specialist_agent"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    module_id: str = Field(index=True, max_length=64)
    # ``name`` doubles as the spawned branch's persona_voice.
    name: str = Field(max_length=64)
    # Classification: 'core' (spine persona), 'specialist' (on-demand expert), 'system' (arbitrator/verifier).
    agent_type: str = Field(default="specialist", max_length=32, index=True)
    # ``capability`` matches a dispatch PhaseSpec.capability so the hub
    # routes this specialist to the phases it owns.
    capability: str = Field(max_length=64, index=True)
    # Optional model role override (e.g. researcher, critic, implementer, reasoning, fast).
    model_role: str | None = Field(default=None, max_length=64)
    # Optional prompt store key (e.g. vr/vulnerability_research.discovery_research/halvar).
    prompt_key: str | None = Field(default=None, max_length=128)
    # Comma-delimited RAG domains this agent queries (e.g. cve_intel,patterns,knowledge,corpus).
    rag_scope: str | None = Field(default="cve_intel,patterns,knowledge,corpus", max_length=256)
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
    """Read-only projection of an agent registry row.

    ``team_id`` is NULL for platform-global built-ins and the caller's
    team_id for team-scoped rows; API callers see it so a team-scoped
    operator can tell an owned row from a global default.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    module_id: str
    name: str
    agent_type: str = "specialist"
    capability: str
    model_role: str | None = None
    prompt_key: str | None = None
    rag_scope: str | None = None
    strategy_family: str | None = None
    description: str = ""
    enabled: bool = True
    team_id: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class SpecialistAgentCreate(BaseModel):
    """Create/update payload for an agent registry row."""

    model_config = ConfigDict(extra="forbid")

    module_id: str = PField(min_length=1, max_length=64)
    name: str = PField(min_length=1, max_length=64)
    agent_type: str = PField(default="specialist", max_length=32)
    capability: str = PField(min_length=1, max_length=64)
    model_role: str | None = PField(default=None, max_length=64)
    prompt_key: str | None = PField(default=None, max_length=128)
    rag_scope: str | None = PField(default="cve_intel,patterns,knowledge,corpus", max_length=256)
    strategy_family: str | None = PField(default=None, max_length=128)
    description: str = PField(default="", max_length=4096)
    enabled: bool = True


# Built-in defaults per module (core personas + specialists).
_BUILTINS: dict[str, tuple[dict[str, str], ...]] = {
    "vr": (
        {"name": "halvar", "agent_type": "core", "capability": "lead-researcher", "model_role": "researcher",
         "prompt_key": "vr/vulnerability_research.discovery_research/halvar", "rag_scope": "cve_intel,patterns,knowledge,code_index",
         "strategy_family": "discovery_research",
         "description": "Lead vulnerability researcher: drives primary hypothesis generation and root cause analysis."},
        {"name": "maddie", "agent_type": "core", "capability": "adversarial-critic", "model_role": "critic",
         "prompt_key": "vr/vulnerability_research.discovery_research/maddie", "rag_scope": "cve_intel,patterns,knowledge,code_index",
         "strategy_family": "critic",
         "description": "Adversarial reviewer: challenges hypotheses, demands source citations, enforces falsification."},
        {"name": "renzo", "agent_type": "core", "capability": "exploit-verifier", "model_role": "implementer",
         "prompt_key": "vr/vulnerability_research.discovery_research/renzo", "rag_scope": "cve_intel,patterns,knowledge,code_index",
         "strategy_family": "verification",
         "description": "Verification specialist: validates reachable dataflow and constructs concrete proof of concept."},
        {"name": "snake", "agent_type": "specialist", "capability": "binary-audit", "model_role": "reasoning",
         "prompt_key": "vr/vulnerability_research.audit/base", "rag_scope": "cve_intel,patterns,knowledge,binary_disasm",
         "description": "Reverse-engineering specialist: disassembly, decompilation, binary internals."},
        {"name": "jak", "agent_type": "specialist", "capability": "mobile-audit", "model_role": "reasoning",
         "prompt_key": "vr/vulnerability_research.masvs_audit/base", "rag_scope": "cve_intel,patterns,knowledge,masvs_rules",
         "description": "Mobile specialist: Android/iOS app internals, platform APIs."},
        {"name": "kratos", "agent_type": "specialist", "capability": "exploit-dev", "model_role": "implementer",
         "prompt_key": "vr/vulnerability_research.audit/base", "rag_scope": "cve_intel,patterns,knowledge,poc_harness",
         "description": "Exploit-development specialist: turn a confirmed finding into a working PoC."},
        {"name": "lara", "agent_type": "specialist", "capability": "variant-hunt", "model_role": "researcher",
         "prompt_key": "vr/vulnerability_research.variant_hunt/base", "rag_scope": "cve_intel,patterns,knowledge,ast_search",
         "description": "Variant-hunt specialist: find sibling instances of a confirmed bug pattern."},
        {"name": "gordon", "agent_type": "specialist", "capability": "source-audit", "model_role": "reasoning",
         "prompt_key": "vr/vulnerability_research.audit/base", "rag_scope": "cve_intel,patterns,knowledge,source_tree",
         "description": "Source-audit specialist: read-only source review for injectable sinks, unsafe patterns, and untrusted-input flow into dangerous calls."},
        {"name": "garrett", "agent_type": "specialist", "capability": "crypto", "model_role": "reasoning",
         "prompt_key": "vr/vulnerability_research.audit/base", "rag_scope": "cve_intel,patterns,knowledge,crypto_primitives",
         "description": "Crypto specialist: review cryptographic construction, key handling, and algorithm misuse across source and binaries."},
        {"name": "ratchet", "agent_type": "specialist", "capability": "fuzz", "model_role": "implementer",
         "prompt_key": "vr/vulnerability_research.audit/base", "rag_scope": "cve_intel,patterns,knowledge,fuzz_harness",
         "description": "Fuzz-targeting specialist: identify and shape fuzzable entry points and harness candidates."},
    ),
    "platform": (
        {"name": "dante", "agent_type": "core", "capability": "console-assistant", "model_role": "fast",
         "prompt_key": "platform/dante/base", "rag_scope": "platform_corpus,investigations,system_health",
         "strategy_family": "routing",
         "description": "Console operator assistant: explains investigation state, proposes wizards, executes operator actions."},
        {"name": "oracle", "agent_type": "system", "capability": "arbitrator", "model_role": "reasoning",
         "prompt_key": "vr/synthesis/base", "rag_scope": "investigations,consensus_log",
         "strategy_family": "oracle",
         "description": "High-confidence finding verification and multi-branch consensus arbitration."},
        {"name": "claim_verifier", "agent_type": "system", "capability": "claim-verification", "model_role": "reasoning",
         "prompt_key": "platform/claim_verifier/verdict", "rag_scope": "code_index,corpus,findings",
         "strategy_family": "claim_verifier",
         "description": "Automated claim extraction and source-backed verification against codebase evidence."},
    ),
    "malware": (
        {"name": "analyst", "agent_type": "core", "capability": "triage-lead", "model_role": "researcher",
         "prompt_key": "malware/default/halvar", "rag_scope": "malware_yara,threat_intel,corpus",
         "strategy_family": "malware_triage",
         "description": "Lead malware triage analyst: coordinates static and dynamic execution analysis."},
        {"name": "alucard", "agent_type": "specialist", "capability": "re", "model_role": "reasoning",
         "prompt_key": "malware/default/base", "rag_scope": "ida_disasm,deobfuscation_rules",
         "description": "Reverse-engineering specialist: unpacking, deobfuscation, image reconstruction."},
        {"name": "vincent", "agent_type": "specialist", "capability": "crypto", "model_role": "reasoning",
         "prompt_key": "malware/default/base", "rag_scope": "crypto_keys,c2_signatures",
         "description": "Crypto/config specialist: config extraction, key/algorithm recovery."},
    ),
    "forensics": (
        {"name": "investigator", "agent_type": "core", "capability": "incident-investigation", "model_role": "researcher",
         "prompt_key": "forensics/freeflow/linux", "rag_scope": "system_logs,disk_artifacts,memory_dumps",
         "strategy_family": "forensics_investigation",
         "description": "DFIR lead investigator: analyzes host artifacts, system logs, and attacker lateral movement."},
        {"name": "timeline-analyst", "agent_type": "specialist", "capability": "timeline-analysis", "model_role": "reasoning",
         "prompt_key": "forensics/freeflow/linux", "rag_scope": "evtx_logs,mft_records,pcap_flow",
         "strategy_family": "timeline",
         "description": "Chronological timeline reconstruction and correlated event attribution across hosts."},
        {"name": "memory-analyst", "agent_type": "specialist", "capability": "memory-forensics", "model_role": "reasoning",
         "prompt_key": "forensics/freeflow/linux", "rag_scope": "volatility_dumps,process_trees,kernel_hooks",
         "description": "Memory forensics specialist: Volatility dump analysis, process injection, and rootkit detection."},
        {"name": "log-correlator", "agent_type": "specialist", "capability": "log-correlation", "model_role": "reasoning",
         "prompt_key": "forensics/freeflow/linux", "rag_scope": "evtx_logs,sysmon,auditd,siem_events",
         "description": "Log correlation specialist: EVTX, Sysmon, auditd, and SIEM event correlation and pivot analysis."},
        {"name": "disk-analyst", "agent_type": "specialist", "capability": "disk-forensics", "model_role": "reasoning",
         "prompt_key": "forensics/freeflow/linux", "rag_scope": "mft_records,usnjrnl,prefetch,shimcache",
         "description": "Disk & filesystem forensics: MFT parsing, unallocated space carving, prefetch, and shimcache analysis."},
        {"name": "network-tracer", "agent_type": "specialist", "capability": "network-forensics", "model_role": "reasoning",
         "prompt_key": "forensics/freeflow/linux", "rag_scope": "pcap_streams,zeek_logs,c2_beacons",
         "description": "Network forensics specialist: PCAP inspection, beaconing detection, TLS fingerprinting, and C2 extraction."},
    ),
}



def _to_summary(rec: SpecialistAgentRecord) -> SpecialistAgentSummary:
    return SpecialistAgentSummary(
        id=rec.id, module_id=rec.module_id, name=rec.name,
        agent_type=rec.agent_type or "specialist",
        capability=rec.capability,
        model_role=rec.model_role,
        prompt_key=rec.prompt_key,
        rag_scope=rec.rag_scope,
        strategy_family=rec.strategy_family,
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

    async def list_all(
        self,
        *,
        enabled_only: bool = False,
        team_id: str | None = None,
        is_admin: bool = True,
        agent_type: str | None = None,
    ) -> list[SpecialistAgentSummary]:
        """Return all agents across all modules visible to the caller."""
        async with UnitOfWork() as uow:
            stmt = select(SpecialistAgentRecord)
            if enabled_only:
                stmt = stmt.where(SpecialistAgentRecord.enabled.is_(True))
            if agent_type:
                stmt = stmt.where(SpecialistAgentRecord.agent_type == agent_type)
            if not is_admin:
                stmt = stmt.where(
                    (SpecialistAgentRecord.team_id == team_id)
                    | (SpecialistAgentRecord.team_id.is_(None)),  # type: ignore[union-attr]
                )
            rows = list((await uow.session.exec(stmt)).all())
        return [_to_summary(r) for r in sorted(rows, key=lambda r: (r.module_id, r.name))]

    async def list_by_module(
        self,
        module_id: str | None,
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
        * When ``module_id`` is None or "all", returns agents across all modules.
        """
        if not module_id or module_id == "all":
            return await self.list_all(
                enabled_only=enabled_only,
                team_id=team_id,
                is_admin=is_admin,
            )
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

        Core-role branches (researcher/critic/implementer) walk every phase,
        so this returns None for them. Only on-demand specialist agents
        resolve to a scoping capability.
        """
        summary = await self.get_by_name(module_id, name)
        if summary is None or not summary.enabled:
            return None
        if summary.agent_type != "specialist":
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
                    agent_type=spec.agent_type,
                    capability=spec.capability,
                    model_role=spec.model_role,
                    prompt_key=spec.prompt_key,
                    rag_scope=spec.rag_scope,
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
                existing.agent_type = spec.agent_type
                existing.capability = spec.capability
                existing.model_role = spec.model_role
                existing.prompt_key = spec.prompt_key
                existing.rag_scope = spec.rag_scope
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

    async def seed_defaults(self, module_id: str = "all") -> int:
        """Insert built-in specialists and core personas that are not present.

        Built-in defaults are platform-global: every row is inserted
        with ``team_id=NULL`` regardless of caller so a team-scoped
        operator seeding on a fresh install produces the same globally
        visible defaults an admin would.

        Idempotent: existing names (whether NULL-team globals or a
        team-owned override) are left untouched. Returns the count
        inserted.
        """
        inserted = 0
        modules_to_seed = (
            list(_BUILTINS.keys())
            if not module_id or module_id == "all"
            else [module_id]
        )
        for mod in modules_to_seed:
            for tmpl in _BUILTINS.get(mod, ()):
                if await self.get_by_name(mod, tmpl["name"]) is not None:
                    continue
                # Always write globals; upsert is called in admin mode with
                # team_id=None so the row gets team_id=NULL.
                await self.upsert(
                    SpecialistAgentCreate(
                        module_id=mod,
                        name=tmpl["name"],
                        agent_type=tmpl.get("agent_type", "specialist"),
                        capability=tmpl["capability"],
                        model_role=tmpl.get("model_role"),
                        prompt_key=tmpl.get("prompt_key"),
                        rag_scope=tmpl.get("rag_scope", "cve_intel,patterns,knowledge,corpus"),
                        strategy_family=tmpl.get("strategy_family"),
                        description=tmpl.get("description", ""),
                    ),
                    team_id=None,
                    is_admin=True,
                )
                inserted += 1
        return inserted

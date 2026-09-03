"""Resolve the SSH integration for an investigation's analysis workstation.

The PoC sandbox (compile / run / verify via ``poc_runner``) and the
agent-facing ``poc_runner`` tool both need the SSH config of the analyzer
workstation bound to an investigation. That binding lives on the
investigation's project: ``VRProjectRecord.poc_system_id`` names a dedicated
PoC machine and falls back to the shared ``analysis_system_id``, each
pointing at a registered ``ManagedSystemRecord``. This helper walks
investigation -> project -> system and returns the integration dict
``SSHService`` consumes, or ``None`` when no workstation is registered so
callers fail open (PoC verification is skipped, never crashed).
"""
from __future__ import annotations

from typing import Any

from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRProjectRecord,
)
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import ManagedSystemRecord

__all__ = ["integration_from_system", "resolve_investigation_integration"]


def integration_from_system(row: ManagedSystemRecord) -> dict[str, Any]:
    """Shape a ``ManagedSystemRecord`` into the SSH integration dict.

    Mirrors the field set ``FuzzProposalPreparer._load_system`` produces so
    both the fuzz launch path and the PoC sandbox feed ``SSHService`` an
    identical integration contract.
    """
    return {
        "name": row.name,
        "host": row.host,
        "username": row.username,
        "port": row.port,
        "private_key_path": row.private_key_path,
        "password_secret_id": row.password_secret_id,
        "known_hosts_path": row.known_hosts_path,
        "host_key_fingerprint": row.host_key_fingerprint,
    }


async def resolve_investigation_integration(
    investigation_id: str,
) -> dict[str, Any] | None:
    """Return the SSH integration dict for the investigation's PoC / analysis
    workstation, or ``None`` when none is resolvable (fail-open).

    Resolution order for the workstation id: the project's dedicated
    ``poc_system_id`` when set, else its shared ``analysis_system_id``. The
    project is resolved by the investigation's ``project_id`` when present,
    else by the investigation target's project row (mirrors
    ``FuzzProposalPreparer._default_system_for``).
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            ),
        )).first()
        if inv is None:
            return None
        project = None
        if inv.project_id:
            project = (await uow.session.exec(
                select(VRProjectRecord).where(
                    VRProjectRecord.id == inv.project_id,
                ),
            )).first()
        if project is None and inv.target_id:
            project = (await uow.session.exec(
                select(VRProjectRecord).where(
                    VRProjectRecord.target_id == inv.target_id,
                ),
            )).first()
        if project is None:
            return None
        system_id = project.poc_system_id or project.analysis_system_id
        if system_id is None:
            return None
        system = (await uow.session.exec(
            select(ManagedSystemRecord).where(
                ManagedSystemRecord.id == system_id,
            ),
        )).first()
        if system is None:
            return None
        return integration_from_system(system)

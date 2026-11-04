"""req 8 -- VR findings triage/classification fields are populated.

Covers ``PATCH /vr/findings/{finding_id}`` (project-agnostic, team-scoped),
which enriches an existing finding in place, matching the shape the frontend
editor writes.
"""
from __future__ import annotations

import json

import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.modules.vr.db_models import VRFindingRecord
from aila.platform.uow import UnitOfWork

pytestmark = pytest.mark.asyncio


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.usefixtures("test_db")
async def test_patch_finding_enriches_null_fields(
    async_client: AsyncClient, admin_token: str,
) -> None:
    """AC2: PATCH /vr/findings/{id} fills fields a writer left NULL."""
    async with UnitOfWork() as uow:
        bare = VRFindingRecord(team_id="team-a", root_cause="")
        uow.session.add(bare)
        await uow.session.commit()
        await uow.session.refresh(bare)
        finding_id = bare.id

    body = {
        "crash_type": "uaf",
        "vulnerable_function": "do_free",
        "cvss_score": 9.1,
        "cvss_vector": "AV:N",
        "cwe_id": "CWE-416",
        "assigned_cve_id": "CVE-2025-1",
        "evidence_refs": ["a", "b"],
    }
    resp = await async_client.patch(
        f"/vr/findings/{finding_id}",
        json=body,
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    envelope = resp.json()
    data = envelope["data"]
    assert data["crash_type"] == "uaf"
    assert data["vulnerable_function"] == "do_free"
    assert data["cvss_score"] == 9.1
    assert data["cvss_vector"] == "AV:N"
    assert data["cwe_id"] == "CWE-416"
    assert data["evidence_count"] == 2

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRFindingRecord).where(VRFindingRecord.id == finding_id),
        )).first()

    assert row is not None
    assert row.crash_type == "uaf"
    assert row.vulnerable_function == "do_free"
    assert row.cvss_score == 9.1
    assert row.cvss_vector == "AV:N"
    assert row.cwe_id == "CWE-416"
    assert row.assigned_cve_id == "CVE-2025-1"
    refs = json.loads(row.evidence_refs_json)
    assert isinstance(refs, list)
    assert len(refs) == 2

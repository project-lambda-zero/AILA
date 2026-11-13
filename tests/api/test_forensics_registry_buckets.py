"""Registry analysis buckets match what the disk collector emits (#421).

The bucket map must name only artifact types the disk collector produces,
and every bucket the endpoint returns must be fed by one of them. The route
test seeds one dissect row per mapped type on the test database and reads
them back through the real handler.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest
from fastapi.routing import APIRoute

from aila.api.auth import AuthContext
from aila.modules.forensics.api_router import (
    _REGISTRY_BUCKET_BY_TYPE,
    RegistryAnalysis,
    create_forensics_router,
)
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.db_models import ArtifactRecord, ForensicsProjectRecord
from aila.modules.forensics.workflow.states.collectors.disk import (
    _COMMON_QUERIES,
    _LINUX_QUERIES,
    _MACOS_QUERIES,
    _WINDOWS_QUERIES,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord

# Artifact type -> family exactly as the disk collector writes them.
_EMITTED_FAMILY_BY_TYPE = {
    query.replace(".", "_"): family
    for query, family in (*_COMMON_QUERIES, *_WINDOWS_QUERIES, *_LINUX_QUERIES, *_MACOS_QUERIES)
}


def test_every_mapped_type_is_emitted_by_the_disk_collector() -> None:
    assert set(_REGISTRY_BUCKET_BY_TYPE) - set(_EMITTED_FAMILY_BY_TYPE) == set()


def test_every_bucket_is_fed_by_a_mapped_type() -> None:
    assert set(RegistryAnalysis.model_fields) == set(_REGISTRY_BUCKET_BY_TYPE.values())


@pytest.fixture
def _no_limiter():
    prev = _forensics_limiter.enabled
    _forensics_limiter.enabled = False
    yield
    _forensics_limiter.enabled = prev


class _Req:
    """Request stand-in; the route does not read it with the limiter disabled."""


@pytest.mark.usefixtures("test_db", "_no_limiter")
async def test_each_emitted_row_lands_in_its_bucket() -> None:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        system = ManagedSystemRecord(name=f"sys-{suffix}", host="10.0.0.1", username="u")
        session.add(system)
        await session.flush()
        assert system.id is not None
        project = ForensicsProjectRecord(
            name=f"proj-{suffix}", system_id=system.id, evidence_directory=f"/evidence/{suffix}",
        )
        session.add(project)
        await session.flush()
        project_id = project.id
        for artifact_type in sorted(_REGISTRY_BUCKET_BY_TYPE):
            session.add(ArtifactRecord(
                project_id=project_id, artifact_family=_EMITTED_FAMILY_BY_TYPE[artifact_type],
                artifact_type=artifact_type, source_tool="dissect",
                data_json=json.dumps({"records": [{"marker": artifact_type}]}),
            ))
        await session.commit()

    endpoint = next(
        route.endpoint for route in create_forensics_router().routes
        if isinstance(route, APIRoute) and route.path == "/projects/{project_id}/registry-analysis"
    )
    auth = AuthContext(user_id="admin", role="admin", auth_type="user", team_id=None)
    analysis = (await endpoint(_Req(), project_id, auth=auth)).data.model_dump()

    placed = {
        row["_artifact_type"]: bucket for bucket, rows in analysis.items() for row in rows
    }
    assert placed == _REGISTRY_BUCKET_BY_TYPE
    assert placed["startupinfo"] == "autoruns"
    assert placed["users"] == "user_accounts"

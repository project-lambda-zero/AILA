"""Confirmed-finding promotion to the retrieval pool (issue #06).

RFC #252/#256/#268 -- knowledge reuse. Engine-confirmed findings must
become retrievable without operator action: the historical writer
stamped them ``scope=local, status=draft, trust_tier=unreviewed`` -- the
exact tuple ``retrieve_routed`` filters out -- so engine-generated
retrievals stayed at zero and every next hunt on the same target
restarted cold. :meth:`KnowledgeService.promote_confirmed_finding_to_pool`
is the automatic promotion path: it writes into
``<module_id>.pattern.workspace.<workspace_id>`` and stamps
``metadata['confirmed'] = True`` so
:func:`trust_tier_from_namespace` tiers the row as verified.
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import select as sm_select

from aila.platform.services.knowledge import (
    PATTERN_NAMESPACE_KIND,
    TRUST_TIER_VERIFIED,
    KnowledgeService,
    make_pattern_namespace,
    trust_tier_from_namespace,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

pytestmark = pytest.mark.asyncio


_STUB_EMBEDDING: list[float] = [1.0] * 1024


class _StubProvider:
    """Deterministic 1024-dim provider so the pgvector column accepts it."""

    @property
    def dimension(self) -> int:
        return 1024

    @property
    def model_name(self) -> str:
        return "stub-provider"

    def encode(self, _text: str) -> list[float]:
        return list(_STUB_EMBEDDING)

    async def encode_async(self, _text: str) -> list[float]:
        return list(_STUB_EMBEDDING)


def test_make_pattern_namespace_shape() -> None:
    ns = make_pattern_namespace("vr", "ws-1")
    assert ns == "vr.pattern.workspace.ws-1"
    assert f".{PATTERN_NAMESPACE_KIND}." in ns


def test_confirmed_pattern_namespace_is_verified() -> None:
    ns = make_pattern_namespace("vr", "ws-1")
    assert trust_tier_from_namespace(ns, {"confirmed": True}) == TRUST_TIER_VERIFIED


async def test_promote_confirmed_finding_writes_to_pool_namespace(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    result = await svc.promote_confirmed_finding_to_pool(
        module_id="vr",
        workspace_id="ws-99",
        content="confirmed finding: heap overflow in parse_playlist()",
        dedup_key="outcome:out-42",
        metadata={"outcome_id": "out-42", "hypothesis_id": "h1"},
    )
    assert result["status"] == "ok" or "operation" in result
    entry_id = int(result["entry_id"])
    async with async_session_scope() as session:
        row = (
            await session.exec(
                sm_select(KnowledgeEntryRecord).where(
                    KnowledgeEntryRecord.id == entry_id,
                )
            )
        ).first()
    assert row is not None
    assert row.namespace == "vr.pattern.workspace.ws-99"
    meta = json.loads(row.entry_metadata or "{}")
    assert meta["confirmed"] is True
    assert meta["outcome_id"] == "out-42"
    assert meta["module_id"] == "vr"
    assert meta.get("source") == "confirmed_finding_promotion"
    assert (
        trust_tier_from_namespace(row.namespace, meta) == TRUST_TIER_VERIFIED
    )


async def test_promote_confirmed_finding_is_idempotent_per_dedup_key(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    first = await svc.promote_confirmed_finding_to_pool(
        module_id="malware",
        workspace_id="ws-7",
        content="v1",
        dedup_key="outcome:out-77",
    )
    second = await svc.promote_confirmed_finding_to_pool(
        module_id="malware",
        workspace_id="ws-7",
        content="v2 -- revised summary",
        dedup_key="outcome:out-77",
    )
    assert int(first["entry_id"]) == int(second["entry_id"])
    async with async_session_scope() as session:
        rows = list(
            (
                await session.exec(
                    sm_select(KnowledgeEntryRecord).where(
                        KnowledgeEntryRecord.namespace
                        == "malware.pattern.workspace.ws-7",
                        KnowledgeEntryRecord.dedup_key == "outcome:out-77",
                    )
                )
            ).all()
        )
    assert len(rows) == 1
    assert rows[0].content == "v2 -- revised summary"

"""AC3 -- inline ``reproducer_head_hex`` on crash registration.

``VRFuzzCrashCreate`` now carries an optional inline hex preview so a
fuzz worker can post the minimised reproducer's first bytes directly
without needing the backend to configure a local staging root. When
the field is present, ``register_crash`` stores it verbatim (subject
to the ``_REPRODUCER_HEAD_LIMIT`` byte ceiling). When it is absent,
the historical config-gated ``_read_reproducer_head`` path runs, which
returns ``(None, None)`` while ``vr.fuzz_reproducer_local_root`` is
unset.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

from aila.modules.vr.contracts.fuzz import (
    CrashSeverity,
    FuzzEngineId,
    FuzzStrategyId,
    VRFuzzCampaignCreate,
    VRFuzzCrashCreate,
)
from aila.modules.vr.db_models import VRTargetRecord, VRWorkspaceRecord
from aila.modules.vr.services.fuzz_service import (
    _REPRODUCER_HEAD_LIMIT,
    FuzzCampaignService,
)
from aila.platform.uow import UnitOfWork


async def _seed_workspace_target(*, slug: str) -> tuple[str, str]:
    workspace_id = f"ws-{slug}-{uuid4().hex[:8]}"
    target_id = f"tgt-{slug}-{uuid4().hex[:8]}"
    async with UnitOfWork() as uow:
        uow.session.add(VRWorkspaceRecord(
            id=workspace_id,
            slug=slug,
            name=f"ws {slug}",
        ))
        await uow.session.commit()
    async with UnitOfWork() as uow:
        uow.session.add(VRTargetRecord(
            id=target_id,
            workspace_id=workspace_id,
            display_name=f"target {slug}",
            kind="native_binary",
            primary_language="c",
        ))
        await uow.session.commit()
    return workspace_id, target_id


async def _make_campaign(*, workspace_id: str, target_id: str) -> str:
    svc = FuzzCampaignService()
    summary = await svc.create_campaign(
        VRFuzzCampaignCreate(
            target_id=target_id,
            workspace_id=workspace_id,
            name=f"inline-{uuid4().hex[:6]}",
            engine_id=FuzzEngineId.LIBFUZZER,
            strategy_id=FuzzStrategyId.COVERAGE_GUIDED,
            source_investigation_id=None,
        ),
        team_id=None,
    )
    return summary.id


@pytest.mark.asyncio
async def test_inline_reproducer_head_stored_without_local_root(
    test_db,
) -> None:
    """Inline hex is persisted verbatim even when the local-root
    config knob is unset (the reason the on-disk path returns None)."""
    workspace_id, target_id = await _seed_workspace_target(slug="rh-inline")
    campaign_id = await _make_campaign(
        workspace_id=workspace_id, target_id=target_id,
    )
    inline_hex = "deadbeefcafeb0ba1122334455667788"
    svc = FuzzCampaignService()
    result = await svc.register_crash(
        VRFuzzCrashCreate(
            campaign_id=campaign_id,
            stack_hash="a" * 16,
            crash_type="heap-buffer-overflow",
            severity=CrashSeverity.HIGH,
            reproducer_path="/tmp/does-not-exist/repro.bin",
            reproducer_head_hex=inline_hex,
        ),
        team_id=None,
    )
    assert result.reproducer_head_hex == inline_hex
    assert result.reproducer_head_truncated_size == len(inline_hex) // 2


@pytest.mark.asyncio
async def test_inline_reproducer_head_truncated_to_limit(test_db) -> None:
    """Oversize inline hex is truncated to the same byte budget the
    on-disk path uses; the reported truncated-size is the ORIGINAL
    byte count so the UI can show the "read N of M" tail."""
    workspace_id, target_id = await _seed_workspace_target(slug="rh-trunc")
    campaign_id = await _make_campaign(
        workspace_id=workspace_id, target_id=target_id,
    )
    max_hex_chars = _REPRODUCER_HEAD_LIMIT * 2
    oversize_hex = "ab" * (_REPRODUCER_HEAD_LIMIT + 512)
    svc = FuzzCampaignService()
    result = await svc.register_crash(
        VRFuzzCrashCreate(
            campaign_id=campaign_id,
            stack_hash="b" * 16,
            crash_type="heap-buffer-overflow",
            reproducer_head_hex=oversize_hex,
        ),
        team_id=None,
    )
    assert result.reproducer_head_hex is not None
    assert len(result.reproducer_head_hex) == max_hex_chars
    assert result.reproducer_head_hex == oversize_hex[:max_hex_chars]
    assert result.reproducer_head_truncated_size == len(oversize_hex) // 2


@pytest.mark.asyncio
async def test_missing_inline_head_falls_back_to_config_gated_read(
    test_db,
) -> None:
    """Without inline hex the service defers to _read_reproducer_head;
    with ``vr.fuzz_reproducer_local_root`` unset that helper fails
    closed and returns None, so the crash record persists with no
    preview -- unchanged from the prior behavior."""
    workspace_id, target_id = await _seed_workspace_target(slug="rh-none")
    campaign_id = await _make_campaign(
        workspace_id=workspace_id, target_id=target_id,
    )
    svc = FuzzCampaignService()
    result = await svc.register_crash(
        VRFuzzCrashCreate(
            campaign_id=campaign_id,
            stack_hash="c" * 16,
            crash_type="heap-buffer-overflow",
            reproducer_path="/tmp/does-not-exist/repro.bin",
        ),
        team_id=None,
    )
    assert result.reproducer_head_hex is None
    assert result.reproducer_head_truncated_size is None

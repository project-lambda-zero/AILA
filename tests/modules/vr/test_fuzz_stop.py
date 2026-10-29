"""FuzzCampaignService.stop_campaign: remote fuzzer signalling + status write.

SSHService is patched at the fuzz_service import site; the DB is real
(test_db fixture). Status must change only when the fuzzer is confirmed
gone, reused, or stopped.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.fuzz import (
    CampaignStatus,
    FuzzEngineId,
    FuzzStrategyId,
    VRFuzzCampaignCreate,
)
from aila.modules.vr.db_models import (
    VRFuzzCampaignRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.fuzz_service import FuzzCampaignService, FuzzServiceError
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import ManagedSystemRecord

SSH_PATH = "aila.modules.vr.services.fuzz_service.SSHService"
REMOTE_PID = 4321


async def _seed_system() -> int:
    async with UnitOfWork() as uow:
        row = ManagedSystemRecord(
            name=f"fuzz-ws-{uuid4().hex[:8]}",
            host="10.0.0.5",
            username="analyst",
            port=22,
        )
        uow.session.add(row)
        await uow.session.commit()
        await uow.session.refresh(row)
        return row.id


async def _make_campaign(*, engine_id: FuzzEngineId = FuzzEngineId.LIBFUZZER) -> tuple[str, str]:
    slug = uuid4().hex[:8]
    workspace_id = f"ws-stop-{slug}"
    target_id = f"tgt-stop-{slug}"
    async with UnitOfWork() as uow:
        uow.session.add(VRWorkspaceRecord(id=workspace_id, slug=f"stop-{slug}", name=f"ws {slug}"))
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
    summary = await FuzzCampaignService().create_campaign(
        VRFuzzCampaignCreate(
            target_id=target_id,
            workspace_id=workspace_id,
            name=f"stop-{slug}",
            engine_id=engine_id,
            strategy_id=FuzzStrategyId.COVERAGE_GUIDED,
        ),
        team_id=None,
    )
    return summary.id, workspace_id


async def _set_remote_state(
    campaign_id: str,
    *,
    status: str,
    system_id: int | None,
    remote_pid: int | None,
    corpus_dir: str | None,
) -> None:
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRFuzzCampaignRecord).where(VRFuzzCampaignRecord.id == campaign_id),
        )).first()
        assert row is not None
        row.status = status
        row.analysis_system_id = system_id
        row.remote_pid = remote_pid
        row.remote_corpus_dir = corpus_dir
        await uow.session.commit()


async def _read_campaign(campaign_id: str) -> VRFuzzCampaignRecord:
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRFuzzCampaignRecord).where(VRFuzzCampaignRecord.id == campaign_id),
        )).first()
    assert row is not None
    return row


def _ssh_returning(output: str | None = None, error: Exception | None = None) -> MagicMock:
    ssh = MagicMock()
    ssh.run_command = AsyncMock(return_value=output, side_effect=error)
    return ssh


async def _running_campaign(sentinel_output: str | None = None, error: Exception | None = None):
    """Return (campaign_id, ssh_mock) for a RUNNING campaign on a live PID."""
    system_id = await _seed_system()
    campaign_id, _ = await _make_campaign()
    corpus = f"~/.aila/fuzz/{campaign_id}/corpus"
    await _set_remote_state(
        campaign_id,
        status=CampaignStatus.RUNNING.value,
        system_id=system_id,
        remote_pid=REMOTE_PID,
        corpus_dir=corpus,
    )
    return campaign_id, _ssh_returning(sentinel_output, error)


@pytest.mark.asyncio
async def test_stop_rejects_non_running_campaign_without_ssh(test_db) -> None:
    campaign_id, _ = await _make_campaign()
    ssh = _ssh_returning("stopped")
    with patch(SSH_PATH, return_value=ssh):
        with pytest.raises(FuzzServiceError, match="is not running"):
            await FuzzCampaignService().stop_campaign(campaign_id)
    ssh.run_command.assert_not_called()
    row = await _read_campaign(campaign_id)
    assert row.status == CampaignStatus.CREATED.value


@pytest.mark.asyncio
async def test_stop_without_remote_pid_aborts_without_ssh(test_db) -> None:
    campaign_id, _ = await _make_campaign()
    await _set_remote_state(
        campaign_id,
        status=CampaignStatus.RUNNING.value,
        system_id=None,
        remote_pid=None,
        corpus_dir=None,
    )
    ssh = _ssh_returning("stopped")
    with patch(SSH_PATH, return_value=ssh):
        summary = await FuzzCampaignService().stop_campaign(campaign_id)
    ssh.run_command.assert_not_called()
    assert summary.status == CampaignStatus.ABORTED.value
    row = await _read_campaign(campaign_id)
    assert row.status == CampaignStatus.ABORTED.value
    assert row.stopped_at is not None


@pytest.mark.asyncio
async def test_stop_live_pid_signals_term_and_aborts(test_db) -> None:
    campaign_id, ssh = await _running_campaign(sentinel_output="stopped\n")
    with patch(SSH_PATH, return_value=ssh):
        summary = await FuzzCampaignService().stop_campaign(campaign_id)
    command = ssh.run_command.call_args.args[1]
    assert f"kill -TERM {REMOTE_PID}" in command
    assert f"~/.aila/fuzz/{campaign_id}" in command
    assert summary.status == CampaignStatus.ABORTED.value
    row = await _read_campaign(campaign_id)
    assert row.status == CampaignStatus.ABORTED.value
    assert row.stopped_at is not None
    assert row.remote_pid == REMOTE_PID


@pytest.mark.asyncio
async def test_stop_ssh_oserror_leaves_status_running(test_db) -> None:
    campaign_id, ssh = await _running_campaign(error=OSError("connection refused"))
    with patch(SSH_PATH, return_value=ssh):
        with pytest.raises(FuzzServiceError, match="could not signal fuzzer"):
            await FuzzCampaignService().stop_campaign(campaign_id)
    row = await _read_campaign(campaign_id)
    assert row.status == CampaignStatus.RUNNING.value
    assert row.stopped_at is None


@pytest.mark.asyncio
async def test_stop_alive_sentinel_leaves_status_running(test_db) -> None:
    campaign_id, ssh = await _running_campaign(sentinel_output="alive")
    with patch(SSH_PATH, return_value=ssh):
        with pytest.raises(FuzzServiceError, match="still running"):
            await FuzzCampaignService().stop_campaign(campaign_id)
    row = await _read_campaign(campaign_id)
    assert row.status == CampaignStatus.RUNNING.value


@pytest.mark.asyncio
@pytest.mark.parametrize("sentinel", ["reused", "gone"])
async def test_stop_reused_or_gone_aborts_without_signalling(test_db, sentinel: str) -> None:
    campaign_id, ssh = await _running_campaign(sentinel_output=sentinel)
    with patch(SSH_PATH, return_value=ssh):
        summary = await FuzzCampaignService().stop_campaign(campaign_id)
    command = ssh.run_command.call_args.args[1]
    # The remote script must exit before any signal is sent in the
    # reused/gone branches: the early-exit echo precedes kill -TERM.
    early_exit = command.index("echo gone" if sentinel == "gone" else "echo reused")
    assert early_exit < command.index(f"kill -TERM {REMOTE_PID}")
    assert summary.status == CampaignStatus.ABORTED.value
    row = await _read_campaign(campaign_id)
    assert row.status == CampaignStatus.ABORTED.value


@pytest.mark.asyncio
async def test_stop_unverifiable_d8_leaves_status_running(test_db) -> None:
    system_id = await _seed_system()
    campaign_id, _ = await _make_campaign(engine_id=FuzzEngineId.V8_D8_SBX)
    await _set_remote_state(
        campaign_id,
        status=CampaignStatus.RUNNING.value,
        system_id=system_id,
        remote_pid=REMOTE_PID,
        corpus_dir=f"~/.aila/fuzz/{campaign_id}/corpus",
    )
    ssh = _ssh_returning("unverifiable")
    with patch(SSH_PATH, return_value=ssh):
        with pytest.raises(FuzzServiceError, match="cannot be verified"):
            await FuzzCampaignService().stop_campaign(campaign_id)
    command = ssh.run_command.call_args.args[1]
    # With no argv marker the script must exit before any signal is sent.
    assert command.index("echo unverifiable") < command.index(f"kill -TERM {REMOTE_PID}")
    row = await _read_campaign(campaign_id)
    assert row.status == CampaignStatus.RUNNING.value


@pytest.mark.asyncio
async def test_stop_unexpected_output_leaves_status_running(test_db) -> None:
    campaign_id, ssh = await _running_campaign(sentinel_output="garbage")
    with patch(SSH_PATH, return_value=ssh):
        with pytest.raises(FuzzServiceError, match="unexpected output"):
            await FuzzCampaignService().stop_campaign(campaign_id)
    row = await _read_campaign(campaign_id)
    assert row.status == CampaignStatus.RUNNING.value

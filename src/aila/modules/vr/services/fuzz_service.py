"""FuzzCampaignService — campaign + crash CRUD with dedup triage.

v1 ships campaign metadata storage + crash ingestion with stack-hash
deduplication. The actual fuzz worker processes (FUZZILLI / AFL++ /
libfuzzer) run on dedicated workstations per D-33; this service is the
landing zone for their telemetry.

Auto-triage on crash registration (CrashTriage):
  1. If a crash with same (campaign_id, stack_hash) already exists →
     DUPLICATE, duplicate_of_crash_id linked, no new row inserted.
  2. Else if crash_type matches security-relevant patterns
     (heap-buffer-overflow, use-after-free, SEGV, …) → SECURITY_RELEVANT.
  3. Else NEEDS_MANUAL_REVIEW.

Operator promotes SECURITY_RELEVANT crashes to vr_findings via the
finding-create endpoint with a back-reference to the crash.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any
from uuid import uuid4

from sqlalchemy import func as sa_func
from sqlmodel import select as _select

from aila.config import get_settings
from aila.modules.vr.contracts.fuzz import (
    CampaignStatus,
    CrashSeverity,
    CrashTriageVerdict,
    FuzzEngineId,
    FuzzStrategyId,
    VRFuzzCampaignCreate,
    VRFuzzCampaignPatch,
    VRFuzzCampaignSummary,
    VRFuzzCrashCreate,
    VRFuzzCrashSummary,
)
from aila.modules.vr.db_models import (
    VRFuzzCampaignRecord,
    VRFuzzCrashRecord,
    VRFuzzTelemetryRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.fuzz_launcher import (
    FuzzLauncherError,
    build_launch_command,
    serialize_for_log,
)
from aila.platform.config import build_platform_settings
from aila.platform.contracts._common import utc_now
from aila.platform.services.ssh import SSHService
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import ManagedSystemRecord

__all__ = [
    "FuzzServiceError",
    "FuzzCampaignService",
    "classify_crash_severity_default",
    "triage_crash",
]

_log = logging.getLogger(__name__)


# Patterns in crash_type that the auto-triage flags as security-relevant.
# Conservative — false positives are cheap (operator review); false
# negatives hide bugs.
_SECURITY_RELEVANT_CRASH_TYPES: frozenset[str] = frozenset({
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "use-after-free",
    "uaf",
    "double-free",
    "type-confusion",
    "wild-pointer",
    "wild-write",
    "integer-overflow",
    "stack-overflow",
    "negative-size-param",
    "container-overflow",
    "alloc-dealloc-mismatch",
    "new-delete-type-mismatch",
    "memory-leak",
    "race-condition",
    "data-race",
    "format-string",
    "command-injection",
    "ssrf",
    "deserialization",
    "sigsegv",
    "sigfpe",
    "sigbus",
    "sigill",
    "abort",
    "v8 sandbox violation detected!",
})


# Patterns that suggest the crash is likely harmless / out-of-scope.
_LIKELY_HARMLESS_CRASH_TYPES: frozenset[str] = frozenset({
    "out-of-memory",
    "timeout",
    "stack-exhaustion-recursion",
    "operator-induced-assert",
})


def classify_crash_severity_default(
    crash_type: str | None,
    explicit_severity: CrashSeverity,
) -> CrashSeverity:
    """Pick a default severity when the engine didn't supply one.

    Heap/UAF/type-confusion → HIGH. Stack/SIGSEGV → MEDIUM. Everything
    else stays at whatever the engine reported (default UNKNOWN).
    """
    if explicit_severity != CrashSeverity.UNKNOWN:
        return explicit_severity
    if not crash_type:
        return CrashSeverity.UNKNOWN
    normalized = crash_type.lower().strip()
    if any(
        p in normalized
        for p in ("heap-buffer-overflow", "use-after-free", "uaf", "type-confusion")
    ):
        return CrashSeverity.HIGH
    if any(
        p in normalized
        for p in ("stack-buffer-overflow", "stack-overflow", "sigsegv")
    ):
        return CrashSeverity.MEDIUM
    return CrashSeverity.UNKNOWN


def triage_crash(
    crash_type: str | None,
    *,
    has_duplicate_in_campaign: bool,
) -> tuple[CrashTriageVerdict, str]:
    """Pure triage classifier — returns (verdict, reason).

    Caller is responsible for the duplicate check; this function just
    interprets crash_type when has_duplicate_in_campaign is False.
    """
    if has_duplicate_in_campaign:
        return (
            CrashTriageVerdict.DUPLICATE,
            "stack_hash already seen in this campaign",
        )
    if not crash_type:
        return (
            CrashTriageVerdict.NEEDS_MANUAL_REVIEW,
            "no crash_type provided",
        )
    normalized = crash_type.lower().strip()
    for needle in _SECURITY_RELEVANT_CRASH_TYPES:
        if needle in normalized:
            return (
                CrashTriageVerdict.SECURITY_RELEVANT,
                f"crash_type matches security-relevant pattern: {needle!r}",
            )
    for needle in _LIKELY_HARMLESS_CRASH_TYPES:
        if needle in normalized:
            return (
                CrashTriageVerdict.LIKELY_HARMLESS,
                f"crash_type matches likely-harmless pattern: {needle!r}",
            )
    return (
        CrashTriageVerdict.NEEDS_MANUAL_REVIEW,
        f"crash_type {crash_type!r} not in classifier rules",
    )


class FuzzServiceError(Exception):
    """User-facing errors (unknown campaign, FK violations)."""


def _campaign_record_to_summary(
    record: VRFuzzCampaignRecord,
) -> VRFuzzCampaignSummary:
    return VRFuzzCampaignSummary(
        id=record.id,
        target_id=record.target_id,
        workspace_id=record.workspace_id,
        name=record.name,
        engine_id=FuzzEngineId(record.engine_id),
        strategy_id=FuzzStrategyId(record.strategy_id),
        engine_config=json.loads(record.engine_config_json or "{}"),
        strategy_config=json.loads(record.strategy_config_json or "{}"),
        status=CampaignStatus(record.status),
        duration_hours=record.duration_hours,
        analysis_system_id=record.analysis_system_id,
        remote_pid=record.remote_pid,
        remote_corpus_dir=record.remote_corpus_dir,
        remote_crashes_dir=record.remote_crashes_dir,
        launched_at=record.launched_at,
        launch_log=record.launch_log,
        execs_per_sec=record.execs_per_sec,
        total_execs=record.total_execs,
        corpus_size=record.corpus_size,
        coverage_pct=record.coverage_pct,
        crashes_found=record.crashes_found,
        started_at=record.started_at,
        stopped_at=record.stopped_at,
        last_progress_at=record.last_progress_at,
        notes=record.notes or "",
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _crash_record_to_summary(record: VRFuzzCrashRecord) -> VRFuzzCrashSummary:
    triage_chain: list[dict[str, Any]] = []
    try:
        triage_chain = json.loads(record.triage_chain_json or "[]") or []
    except (ValueError, TypeError):
        triage_chain = []
    return VRFuzzCrashSummary(
        id=record.id,
        campaign_id=record.campaign_id,
        stack_hash=record.stack_hash,
        crash_type=record.crash_type,
        crash_signature=record.crash_signature,
        severity=CrashSeverity(record.severity),
        triage_verdict=CrashTriageVerdict(record.triage_verdict),
        triage_reason=record.triage_reason,
        duplicate_of_crash_id=record.duplicate_of_crash_id,
        promoted_to_finding_id=record.promoted_to_finding_id,
        reproducer_path=record.reproducer_path,
        reproducer_size_bytes=record.reproducer_size_bytes,
        stack_trace=record.stack_trace,
        extra=json.loads(record.extra_json or "{}"),
        discovered_at=record.discovered_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
        reproducer_head_hex=record.reproducer_head_hex,
        reproducer_head_truncated_size=record.reproducer_head_truncated_size,
        llm_summary=record.llm_summary,
        triage_chain=triage_chain,
    )


# §1.6 — keep the head bytes preview tight. 4 KB at 16 bytes/row =
# 256 rows in the HexView, which fills the panel without burning RAM.
_REPRODUCER_HEAD_LIMIT = 4096


def _read_reproducer_head(
    path: str | None,
) -> tuple[str | None, int | None]:
    """Read up to ``_REPRODUCER_HEAD_LIMIT`` bytes from ``path``.

    Returns ``(hex_string, bytes_read)``. When the path is missing,
    unreadable, or empty, returns ``(None, None)``. Workers running
    on remote workstations write to local AILA storage via the same
    file-transfer flow that already places ``reproducer_path``; if
    the file isn't reachable we surface that as missing — the operator
    will see "no minimised input bytes available" on the UI.
    """
    if not path:
        return None, None
    try:
        with open(path, "rb") as fh:
            data = fh.read(_REPRODUCER_HEAD_LIMIT)
    except (OSError, PermissionError):
        return None, None
    if not data:
        return None, None
    truncated = os.path.getsize(path) if os.path.exists(path) else len(data)
    return data.hex(), int(truncated)


def _compose_crash_summary(
    crash_type: str | None,
    stack_trace: str | None,
) -> str:
    """Produce a one-line crash summary for the §1.6 LLM summary slot.

    Today this composes a deterministic string from the crash_type +
    the topmost stack frame. When a real LLM dispatcher is wired into
    the fuzz worker it should replace this with a model-generated
    sentence; the column type + projection don't change.
    """
    top = ""
    if stack_trace:
        for raw in stack_trace.splitlines():
            line = raw.strip()
            if line:
                top = line
                break
    if crash_type and top:
        return f"{crash_type} at {top}"
    if crash_type:
        return crash_type
    if top:
        return top
    return ""


def _record_telemetry_snapshot(
    uow: UnitOfWork,
    campaign: VRFuzzCampaignRecord,
    moment: Any,
) -> None:
    """Append one telemetry row from the campaign's scalar columns.

    Called from ``patch_campaign`` (whenever a scalar metric moves)
    and ``register_crash`` (each unique crash). The sparkline + stuck
    detection on the campaign detail page read these rows
    (08_FRONTEND_UX.md §1.5).
    """
    uow.session.add(VRFuzzTelemetryRecord(
        id=str(uuid4()),
        campaign_id=campaign.id,
        measured_at=moment,
        execs_per_sec=campaign.execs_per_sec,
        total_execs=campaign.total_execs,
        corpus_size=campaign.corpus_size,
        coverage_pct=campaign.coverage_pct,
        crashes_found=campaign.crashes_found,
    ))


class FuzzCampaignService:
    """CRUD + crash ingestion for VR fuzzing campaigns."""

    async def create_campaign(
        self,
        body: VRFuzzCampaignCreate,
        team_id: str | None,
    ) -> VRFuzzCampaignSummary:
        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _select(VRTargetRecord).where(
                    VRTargetRecord.id == body.target_id,
                ),
            )).first()
            if target is None:
                raise FuzzServiceError(
                    f"target {body.target_id} not found",
                )
            workspace = (await uow.session.exec(
                _select(VRWorkspaceRecord).where(
                    VRWorkspaceRecord.id == body.workspace_id,
                ),
            )).first()
            if workspace is None:
                raise FuzzServiceError(
                    f"workspace {body.workspace_id} not found",
                )

            # Validate the analysis_system_id FK if supplied — the
            # operator-supplied id must resolve to a registered
            # ManagedSystemRecord, and (when the team is set) belong
            # to the same team. None is allowed for metadata-only
            # campaigns that the operator drives by hand.
            if body.analysis_system_id is not None:
                sys_stmt = _select(ManagedSystemRecord).where(
                    ManagedSystemRecord.id == body.analysis_system_id,
                )
                if team_id is not None:
                    sys_stmt = sys_stmt.where(
                        ManagedSystemRecord.team_id == team_id,
                    )
                system_row = (await uow.session.exec(sys_stmt)).first()
                if system_row is None:
                    raise FuzzServiceError(
                        f"system {body.analysis_system_id} not found "
                        f"or not accessible to your team",
                    )

            record = VRFuzzCampaignRecord(
                team_id=team_id,
                target_id=body.target_id,
                workspace_id=body.workspace_id,
                name=body.name,
                engine_id=body.engine_id.value,
                strategy_id=body.strategy_id.value,
                engine_config_json=json.dumps(body.engine_config),
                strategy_config_json=json.dumps(body.strategy_config),
                duration_hours=body.duration_hours,
                analysis_system_id=body.analysis_system_id,
                notes=body.notes or "",
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)
            return _campaign_record_to_summary(record)

    async def get_campaign(
        self, campaign_id: str,
    ) -> VRFuzzCampaignSummary | None:
        async with UnitOfWork() as uow:
            record = (await uow.session.exec(
                _select(VRFuzzCampaignRecord).where(
                    VRFuzzCampaignRecord.id == campaign_id,
                ),
            )).first()
            if record is None:
                return None
            return _campaign_record_to_summary(record)

    async def list_campaigns(
        self,
        *,
        target_id: str | None = None,
        workspace_id: str | None = None,
        status: CampaignStatus | None = None,
        team_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[VRFuzzCampaignSummary], int]:
        async with UnitOfWork() as uow:
            stmt = _select(VRFuzzCampaignRecord)
            count_stmt = _select(sa_func.count()).select_from(
                VRFuzzCampaignRecord,
            )
            if team_id is not None:
                stmt = stmt.where(VRFuzzCampaignRecord.team_id == team_id)
                count_stmt = count_stmt.where(
                    VRFuzzCampaignRecord.team_id == team_id,
                )
            if target_id:
                stmt = stmt.where(VRFuzzCampaignRecord.target_id == target_id)
                count_stmt = count_stmt.where(
                    VRFuzzCampaignRecord.target_id == target_id,
                )
            if workspace_id:
                stmt = stmt.where(
                    VRFuzzCampaignRecord.workspace_id == workspace_id,
                )
                count_stmt = count_stmt.where(
                    VRFuzzCampaignRecord.workspace_id == workspace_id,
                )
            if status:
                stmt = stmt.where(VRFuzzCampaignRecord.status == status.value)
                count_stmt = count_stmt.where(
                    VRFuzzCampaignRecord.status == status.value,
                )

            total = (await uow.session.exec(count_stmt)).one()
            stmt = (
                stmt.order_by(VRFuzzCampaignRecord.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = (await uow.session.exec(stmt)).all()
            return [_campaign_record_to_summary(r) for r in rows], int(total)

    async def launch_campaign(
        self, campaign_id: str,
    ) -> dict[str, Any]:
        """SSH to the campaign's analysis_system_id workstation, start
        the fuzzer per its engine_id, record the remote PID + corpus/
        crashes dirs back onto the campaign row.

        Idempotent on remote_pid: if the campaign already has a
        remote_pid set + the campaign status is RUNNING, returns the
        existing state without spawning a duplicate. Otherwise
        composes the engine command via fuzz_launcher.build_launch_command,
        runs the setup commands then the nohup-wrapped fuzzer command,
        and captures stdout (which is the PID echoed by the nohup wrapper).
        """
        # ManagedSystemRecord, SSHService, build_platform_settings,
        # get_settings, fuzz_launcher helpers are imported at module
        # top — see imports near the top of this file.

        async with UnitOfWork() as uow:
            record = (await uow.session.exec(
                _select(VRFuzzCampaignRecord).where(
                    VRFuzzCampaignRecord.id == campaign_id,
                ),
            )).first()
            if record is None:
                raise FuzzServiceError(f"campaign {campaign_id} not found")
            if record.analysis_system_id is None:
                raise FuzzServiceError(
                    f"campaign {campaign_id} has no analysis_system_id — "
                    f"set one via campaign create before launch",
                )
            if record.remote_pid and record.status == CampaignStatus.RUNNING.value:
                _log.info(
                    "fuzz_campaign LAUNCH idempotent campaign_id=%s pid=%d",
                    campaign_id, record.remote_pid,
                )
                return {
                    "campaign_id": campaign_id,
                    "status": "already-running",
                    "remote_pid": record.remote_pid,
                }
            system_row = (await uow.session.exec(
                _select(ManagedSystemRecord).where(
                    ManagedSystemRecord.id == record.analysis_system_id,
                ),
            )).first()
            if system_row is None:
                raise FuzzServiceError(
                    f"campaign {campaign_id} references system "
                    f"#{record.analysis_system_id} which is not registered",
                )
            integration = {
                "name": system_row.name,
                "host": system_row.host,
                "username": system_row.username,
                "port": system_row.port,
                "private_key_path": system_row.private_key_path,
                "password_secret_id": system_row.password_secret_id,
                "known_hosts_path": system_row.known_hosts_path,
                "host_key_fingerprint": system_row.host_key_fingerprint,
            }
            engine_id = FuzzEngineId(record.engine_id)
            engine_config = json.loads(record.engine_config_json or "{}")
            strategy_config = json.loads(record.strategy_config_json or "{}")

        try:
            launch = build_launch_command(
                campaign_id=campaign_id,
                engine_id=engine_id,
                engine_config=engine_config,
                strategy_config=strategy_config,
            )
        except FuzzLauncherError as exc:
            raise FuzzServiceError(
                f"launch command construction failed: {exc}",
            ) from exc

        ssh = SSHService(build_platform_settings(get_settings()))
        # Setup commands first (mkdir, copy seeds). Each is a separate
        # round-trip so failures pinpoint which step blew up.
        for cmd in launch.setup_commands:
            try:
                await ssh.run_command(
                    integration, cmd,
                    timeout_seconds=30.0, connect_timeout=10.0,
                )
            except (OSError, TimeoutError) as exc:
                raise FuzzServiceError(
                    f"setup command failed on workstation: {cmd!r} → {exc}",
                ) from exc
        # Now run the nohup-wrapped fuzzer command; the wrapper echoes
        # the PID, which lands in stdout (which run_command returns).
        try:
            stdout = await ssh.run_command(
                integration, launch.run_in_background,
                timeout_seconds=20.0, connect_timeout=10.0,
            )
        except (OSError, TimeoutError) as exc:
            raise FuzzServiceError(
                f"fuzzer launch failed on workstation: {exc}",
            ) from exc

        remote_pid: int | None = None
        for token in (stdout or "").split():
            try:
                remote_pid = int(token.strip())
                break
            except ValueError:
                continue

        async with UnitOfWork() as uow:
            record = (await uow.session.exec(
                _select(VRFuzzCampaignRecord).where(
                    VRFuzzCampaignRecord.id == campaign_id,
                ),
            )).first()
            if record is None:
                raise FuzzServiceError(
                    f"campaign {campaign_id} disappeared during launch",
                )
            now = utc_now()
            record.remote_pid = remote_pid
            record.remote_corpus_dir = launch.corpus_dir
            record.remote_crashes_dir = launch.crashes_dir
            record.launched_at = now
            record.launch_log = serialize_for_log(launch)
            record.status = CampaignStatus.RUNNING.value
            if record.started_at is None:
                record.started_at = now
            record.last_progress_at = now
            record.updated_at = now
            await uow.session.commit()
            await uow.session.refresh(record)

        _log.info(
            "fuzz_campaign LAUNCH ok campaign_id=%s engine=%s pid=%s",
            campaign_id, engine_id.value, remote_pid,
        )
        return {
            "campaign_id": campaign_id,
            "status": "launched",
            "remote_pid": remote_pid,
            "remote_corpus_dir": launch.corpus_dir,
            "remote_crashes_dir": launch.crashes_dir,
            "description": launch.description,
        }

    async def patch_campaign(
        self, campaign_id: str, body: VRFuzzCampaignPatch,
    ) -> VRFuzzCampaignSummary:
        async with UnitOfWork() as uow:
            record = (await uow.session.exec(
                _select(VRFuzzCampaignRecord).where(
                    VRFuzzCampaignRecord.id == campaign_id,
                ),
            )).first()
            if record is None:
                raise FuzzServiceError(
                    f"campaign {campaign_id} not found",
                )

            mutated = False
            telemetry_changed = False
            now = utc_now()
            if body.status is not None and body.status.value != record.status:
                old = record.status
                record.status = body.status.value
                if (
                    body.status == CampaignStatus.RUNNING
                    and record.started_at is None
                ):
                    record.started_at = now
                if body.status in {
                    CampaignStatus.COMPLETED,
                    CampaignStatus.FAILED,
                    CampaignStatus.ABORTED,
                } and record.stopped_at is None:
                    record.stopped_at = now
                _log.info(
                    "fuzz_campaign STATUS campaign_id=%s old=%s new=%s",
                    campaign_id, old, body.status.value,
                )
                mutated = True
            if body.notes is not None and body.notes != record.notes:
                record.notes = body.notes
                mutated = True
            if body.duration_hours is not None and body.duration_hours != record.duration_hours:
                record.duration_hours = body.duration_hours
                mutated = True
            if body.execs_per_sec is not None:
                record.execs_per_sec = body.execs_per_sec
                record.last_progress_at = now
                mutated = True
                telemetry_changed = True
            if body.total_execs is not None:
                record.total_execs = body.total_execs
                record.last_progress_at = now
                mutated = True
                telemetry_changed = True
            if body.corpus_size is not None:
                record.corpus_size = body.corpus_size
                mutated = True
                telemetry_changed = True
            if body.coverage_pct is not None:
                record.coverage_pct = body.coverage_pct
                mutated = True
                telemetry_changed = True
            if body.crashes_found is not None:
                record.crashes_found = body.crashes_found
                mutated = True
                telemetry_changed = True

            if mutated:
                record.updated_at = now
                uow.session.add(record)
                # Take a telemetry snapshot whenever any scalar metric
                # moved. Each PATCH that brings new numbers from the
                # workstation becomes one time-series point — operator
                # gets a sparkline without a separate POST loop.
                if telemetry_changed:
                    _record_telemetry_snapshot(uow, record, now)
                await uow.session.commit()
                await uow.session.refresh(record)
            return _campaign_record_to_summary(record)

    async def register_crash(
        self,
        body: VRFuzzCrashCreate,
        team_id: str | None,
    ) -> VRFuzzCrashSummary:
        """Register a new crash; auto-dedup + auto-triage."""
        async with UnitOfWork() as uow:
            campaign = (await uow.session.exec(
                _select(VRFuzzCampaignRecord).where(
                    VRFuzzCampaignRecord.id == body.campaign_id,
                ),
            )).first()
            if campaign is None:
                raise FuzzServiceError(
                    f"campaign {body.campaign_id} not found",
                )

            existing = (await uow.session.exec(
                _select(VRFuzzCrashRecord).where(
                    VRFuzzCrashRecord.campaign_id == body.campaign_id,
                    VRFuzzCrashRecord.stack_hash == body.stack_hash,
                ),
            )).first()
            has_dup = existing is not None

            verdict, reason = triage_crash(
                body.crash_type, has_duplicate_in_campaign=has_dup,
            )
            severity = classify_crash_severity_default(
                body.crash_type, body.severity,
            )

            if has_dup and existing is not None:
                # Don't create a second row — return the existing one with
                # the triage verdict surfaced (the operator already saw it).
                return _crash_record_to_summary(existing)

            head_hex, head_size = _read_reproducer_head(body.reproducer_path)
            llm_summary = _compose_crash_summary(
                body.crash_type, body.stack_trace,
            )
            initial_chain: list[dict[str, Any]] = [
                {
                    "at": utc_now().isoformat(),
                    "actor": "fuzz_worker",
                    "verdict": verdict.value,
                    "reason": reason,
                    "notes": "auto-triage on crash registration",
                },
            ]
            record = VRFuzzCrashRecord(
                team_id=team_id,
                campaign_id=body.campaign_id,
                stack_hash=body.stack_hash,
                crash_type=body.crash_type,
                crash_signature=body.crash_signature,
                severity=severity.value,
                triage_verdict=verdict.value,
                triage_reason=reason,
                reproducer_path=body.reproducer_path,
                reproducer_size_bytes=body.reproducer_size_bytes,
                stack_trace=body.stack_trace,
                extra_json=json.dumps(body.extra),
                reproducer_head_hex=head_hex,
                reproducer_head_truncated_size=head_size,
                llm_summary=llm_summary,
                triage_chain_json=json.dumps(initial_chain),
            )
            uow.session.add(record)

            # Increment campaign crashes_found counter (one per unique).
            campaign.crashes_found = (campaign.crashes_found or 0) + 1
            campaign.last_progress_at = utc_now()
            uow.session.add(campaign)

            # Snapshot telemetry on every new crash so the sparkline
            # picks up the moment without a separate PATCH.
            _record_telemetry_snapshot(uow, campaign, utc_now())

            await uow.session.commit()
            await uow.session.refresh(record)
            return _crash_record_to_summary(record)

    async def get_crash(
        self, crash_id: str,
    ) -> VRFuzzCrashSummary | None:
        async with UnitOfWork() as uow:
            record = (await uow.session.exec(
                _select(VRFuzzCrashRecord).where(
                    VRFuzzCrashRecord.id == crash_id,
                ),
            )).first()
            if record is None:
                return None
            return _crash_record_to_summary(record)

    async def list_crashes(
        self,
        *,
        campaign_id: str | None = None,
        verdict: CrashTriageVerdict | None = None,
        severity: CrashSeverity | None = None,
        team_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[VRFuzzCrashSummary], int]:
        async with UnitOfWork() as uow:
            stmt = _select(VRFuzzCrashRecord)
            count_stmt = _select(sa_func.count()).select_from(VRFuzzCrashRecord)
            if team_id is not None:
                stmt = stmt.where(VRFuzzCrashRecord.team_id == team_id)
                count_stmt = count_stmt.where(
                    VRFuzzCrashRecord.team_id == team_id,
                )
            if campaign_id:
                stmt = stmt.where(VRFuzzCrashRecord.campaign_id == campaign_id)
                count_stmt = count_stmt.where(
                    VRFuzzCrashRecord.campaign_id == campaign_id,
                )
            if verdict:
                stmt = stmt.where(
                    VRFuzzCrashRecord.triage_verdict == verdict.value,
                )
                count_stmt = count_stmt.where(
                    VRFuzzCrashRecord.triage_verdict == verdict.value,
                )
            if severity:
                stmt = stmt.where(VRFuzzCrashRecord.severity == severity.value)
                count_stmt = count_stmt.where(
                    VRFuzzCrashRecord.severity == severity.value,
                )

            total = (await uow.session.exec(count_stmt)).one()
            stmt = (
                stmt.order_by(VRFuzzCrashRecord.discovered_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = (await uow.session.exec(stmt)).all()
            return [_crash_record_to_summary(r) for r in rows], int(total)

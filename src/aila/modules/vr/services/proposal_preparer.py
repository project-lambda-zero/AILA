"""ProposalPreparer -- materialize a fuzz campaign proposal into a
ready-to-run setup on the workstation.

Called by ``POST /vr/fuzz/proposals/{id}/accept``. The preparer:

  1. Loads the proposal + resolves the campaign config defaults from
     the target's capability_profile + project's analysis_system_id.
  2. (optional, skip via accept body) SSHes the workstation and:
       a. ``mkdir -p`` the per-campaign workdir
       b. writes ``harness_source`` to a file named after
          ``harness_language`` (e.g. ``harness.c``)
       c. runs ``harness_build_command`` from inside the workdir
       d. writes each seed corpus entry to ``corpus/<filename>``
       e. writes ``dictionary_content`` (if any) to ``dict.txt``
  3. Synthesizes a ``VRFuzzCampaignCreate`` from the resolved config
     + the harness target path and calls ``FuzzCampaignService.create_campaign``.
  4. (optional, default true) Enqueues ``run_fuzz_campaign_launch``
     so the operator sees the campaign go from CREATED → RUNNING
     without a second click.
  5. Marks the proposal ``status='accepted'`` + records
     ``accepted_campaign_id`` + ``prepare_log`` (the SSH transcript).

The preparer never raises into the route handler -- every failure
maps to a ``ProposalPrepareError`` with an operator-readable message.
"""
from __future__ import annotations

import base64
import json
import logging
import shlex
from dataclasses import dataclass
from typing import Any

from sqlmodel import select as _select

from aila.config import get_settings
from aila.modules.vr.contracts import (
    FuzzEngineId,
    FuzzProposalDecideAccept,
    FuzzStrategyId,
    VRFuzzCampaignCreate,
)
from aila.modules.vr.db_models import (
    VRFuzzCampaignProposalRecord,
    VRProjectRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.fuzz_service import (
    FuzzCampaignService,
    FuzzServiceError,
)
from aila.platform.config import build_platform_settings
from aila.platform.contracts import utc_now
from aila.platform.services.ssh import SSHService
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import ManagedSystemRecord

__all__ = [
    "PrepareResult",
    "ProposalPrepareError",
    "ProposalPreparer",
]

_log = logging.getLogger(__name__)


class ProposalPrepareError(Exception):
    """Operator-readable error from the preparer pipeline."""


@dataclass
class PrepareResult:
    """Outcome of a successful proposal acceptance."""

    proposal_id: str
    campaign_id: str
    workdir: str
    harness_path: str | None
    seeds_written: int
    dictionary_written: bool
    build_log: str
    auto_launched: bool


class ProposalPreparer:
    """Owns the accept-flow for fuzz campaign proposals."""

    async def accept(
        self,
        proposal_id: str,
        body: FuzzProposalDecideAccept,
        *,
        team_id: str | None,
        user_id: str | None,
    ) -> PrepareResult:
        proposal = await self._load_pending(proposal_id, team_id)

        # Resolve campaign config (operator overrides win).
        engine_id_raw = (
            body.engine_id
            or proposal.suggested_engine_id
            or await self._default_engine_for(proposal.target_id)
        )
        if not engine_id_raw:
            raise ProposalPrepareError(
                "No engine_id available -- neither the proposal nor the "
                "target's capability_profile.applicable_fuzzing_engines "
                "yielded a default; pass engine_id in the accept body.",
            )
        try:
            engine_id = FuzzEngineId(engine_id_raw)
        except ValueError as exc:
            raise ProposalPrepareError(
                f"Unsupported engine_id={engine_id_raw!r}",
            ) from exc

        strategy_id_raw = (
            body.strategy_id
            or proposal.suggested_strategy_id
            or "mutational"
        )
        try:
            strategy_id = FuzzStrategyId(strategy_id_raw)
        except ValueError as exc:
            raise ProposalPrepareError(
                f"Unsupported strategy_id={strategy_id_raw!r}",
            ) from exc

        # Workstation: accept override > project default.
        analysis_system_id = (
            body.analysis_system_id
            or await self._default_system_for(proposal.target_id)
        )
        if analysis_system_id is None:
            raise ProposalPrepareError(
                "No workstation available -- neither the accept body "
                "nor the project carried analysis_system_id; register "
                "a system and set it before accepting.",
            )

        # Workdir + harness path resolution.
        workdir = f"~/.aila/fuzz/proposals/{proposal_id}"
        harness_path = proposal.harness_target_path or self._infer_harness_path(
            workdir, proposal,
        )
        engine_config: dict[str, Any] = dict(
            json.loads(proposal.suggested_engine_config_json or "{}"),
        )
        if body.engine_config:
            engine_config.update(body.engine_config)
        # When the harness was built by the preparer, point the engine
        # at it -- operator overrides win.
        if harness_path and "target_binary" not in engine_config:
            engine_config["target_binary"] = harness_path
        if harness_path and engine_id == FuzzEngineId.LIBFUZZER:
            # libFuzzer is its own harness binary.
            engine_config.setdefault("target_binary", harness_path)
        if engine_id in (
            FuzzEngineId.AFL_PLUSPLUS,
            FuzzEngineId.AFL_PLUSPLUS_QEMU,
        ):
            engine_config.setdefault(
                "seed_dir",
                f"{workdir}/corpus",
            )

        # SSH + write harness + build + seeds + dict.
        build_log = ""
        seeds_written = 0
        dictionary_written = False
        if not body.skip_prepare:
            (
                build_log,
                seeds_written,
                dictionary_written,
            ) = await self._do_prepare(
                workdir, proposal, analysis_system_id,
            )

        # Materialize the campaign row.
        name = body.name or self._synthesize_name(proposal)
        create_body = VRFuzzCampaignCreate(
            target_id=proposal.target_id,
            workspace_id=proposal.workspace_id,
            name=name,
            engine_id=engine_id,
            strategy_id=strategy_id,
            engine_config=engine_config,
            strategy_config=body.strategy_config or {},
            duration_hours=body.duration_hours or proposal.suggested_duration_hours,
            analysis_system_id=analysis_system_id,
            notes=(
                f"Auto-created from fuzz proposal {proposal_id}. "
                f"Rationale: {proposal.rationale[:512]}"
            ),
        )
        try:
            summary = await FuzzCampaignService().create_campaign(
                create_body, team_id=team_id,
            )
        except FuzzServiceError as exc:
            raise ProposalPrepareError(
                f"Failed to create campaign row: {exc}",
            ) from exc
        campaign_id = summary.id

        # Optional auto-launch.
        auto_launched = False
        if body.auto_launch:
            try:
                await FuzzCampaignService().launch_campaign(campaign_id)
                auto_launched = True
            except FuzzServiceError as exc:
                # Don't unwind the campaign -- operator can retry Launch.
                build_log += f"\n[auto-launch failed: {exc}]"

        # Update the proposal row with the decision + transcript.
        await self._mark_accepted(
            proposal_id,
            campaign_id=campaign_id,
            decided_by=user_id,
            decision_reason=body.decision_reason or "operator accepted",
            prepare_log=build_log,
        )

        return PrepareResult(
            proposal_id=proposal_id,
            campaign_id=campaign_id,
            workdir=workdir,
            harness_path=harness_path,
            seeds_written=seeds_written,
            dictionary_written=dictionary_written,
            build_log=build_log,
            auto_launched=auto_launched,
        )

    async def reject(
        self,
        proposal_id: str,
        decision_reason: str,
        *,
        team_id: str | None,
        user_id: str | None,
    ) -> VRFuzzCampaignProposalRecord:
        async with UnitOfWork() as uow:
            row = await self._load_for_decision(uow, proposal_id, team_id)
            row.status = "rejected"
            row.decided_at = utc_now()
            row.decided_by = user_id
            row.decision_reason = decision_reason
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.session.commit()
            await uow.session.refresh(row)
            return row

    # ── Internals ────────────────────────────────────────────────────

    async def _load_pending(
        self, proposal_id: str, team_id: str | None,
    ) -> VRFuzzCampaignProposalRecord:
        async with UnitOfWork() as uow:
            row = await self._load_for_decision(uow, proposal_id, team_id)
            if row.status != "pending":
                raise ProposalPrepareError(
                    f"Proposal {proposal_id} is in status {row.status!r}; "
                    f"only pending proposals can be accepted.",
                )
            return row

    @staticmethod
    async def _load_for_decision(
        uow: UnitOfWork, proposal_id: str, team_id: str | None,
    ) -> VRFuzzCampaignProposalRecord:
        stmt = _select(VRFuzzCampaignProposalRecord).where(
            VRFuzzCampaignProposalRecord.id == proposal_id,
        )
        if team_id is not None:
            stmt = stmt.where(
                VRFuzzCampaignProposalRecord.team_id == team_id,
            )
        row = (await uow.session.exec(stmt)).first()
        if row is None:
            raise ProposalPrepareError(
                f"Proposal {proposal_id} not found or not in your team.",
            )
        return row

    @staticmethod
    async def _default_engine_for(target_id: str) -> str | None:
        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _select(VRTargetRecord).where(
                    VRTargetRecord.id == target_id,
                ),
            )).first()
            if target is None:
                return None
            try:
                profile = json.loads(target.capability_profile_json or "{}")
            except (ValueError, TypeError) as exc:
                _log.warning("FAILED reason=%s", exc)
                return None
            engines = profile.get("applicable_fuzzing_engines") or []
            return engines[0] if engines else None

    @staticmethod
    async def _default_system_for(target_id: str) -> int | None:
        """Pull analysis_system_id off any project rooted on this target."""
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRProjectRecord).where(
                    VRProjectRecord.target_id == target_id,
                ),
            )).first()
            return row.analysis_system_id if row else None

    async def _do_prepare(
        self,
        workdir: str,
        proposal: VRFuzzCampaignProposalRecord,
        analysis_system_id: int,
    ) -> tuple[str, int, bool]:
        """Push harness + build + seeds onto the workstation via SSH.

        Returns ``(transcript, seeds_written, dictionary_written)``.
        """
        integration = await self._load_system(analysis_system_id)
        ssh = SSHService(build_platform_settings(get_settings()))
        transcript: list[str] = []

        async def _run(cmd: str, *, timeout: float = 30.0) -> str:
            try:
                out = await ssh.run_command(
                    integration, cmd,
                    timeout_seconds=timeout,
                    connect_timeout=10.0,
                )
            except (OSError, TimeoutError) as exc:
                raise ProposalPrepareError(
                    f"SSH command failed: {cmd!r} → {exc}",
                ) from exc
            transcript.append(f"$ {cmd}\n{out}")
            return out

        await _run(f"mkdir -p {workdir} {workdir}/corpus")

        # 1) Write the harness source.
        if proposal.harness_source:
            ext = self._harness_extension(proposal.harness_language)
            harness_filename = f"harness.{ext}"
            await self._write_remote_file(
                ssh, integration,
                path=f"{workdir}/{harness_filename}",
                content=proposal.harness_source,
                transcript=transcript,
            )
            # 2) Build the harness.
            if proposal.harness_build_command:
                await _run(
                    f"cd {workdir} && {proposal.harness_build_command}",
                    timeout=600.0,
                )

        # 3) Seed corpus.
        seeds_written = 0
        try:
            seeds = json.loads(proposal.seed_corpus_json or "[]")
        except (ValueError, TypeError):
            seeds = []
        for entry in seeds:
            filename = str(entry.get("filename") or "").strip()
            b64 = entry.get("content_base64") or ""
            if not filename or not b64:
                continue
            try:
                payload = base64.b64decode(b64, validate=True)
            except (ValueError, base64.binascii.Error):
                transcript.append(
                    f"[skip seed {filename}: invalid base64]",
                )
                continue
            # The shell roundtrip can't carry binary bytes; pipe via
            # base64 -d on the remote side.
            safe_b64 = base64.b64encode(payload).decode("ascii")
            await _run(
                f"echo {shlex.quote(safe_b64)} | "
                f"base64 -d > {workdir}/corpus/{shlex.quote(filename)}",
                timeout=60.0,
            )
            seeds_written += 1

        # 4) Dictionary.
        dictionary_written = False
        if proposal.dictionary_content:
            await self._write_remote_file(
                ssh, integration,
                path=f"{workdir}/dict.txt",
                content=proposal.dictionary_content,
                transcript=transcript,
            )
            dictionary_written = True

        return "\n".join(transcript), seeds_written, dictionary_written

    @staticmethod
    async def _write_remote_file(
        ssh: SSHService,
        integration: dict[str, Any],
        *,
        path: str,
        content: str,
        transcript: list[str],
    ) -> None:
        """Write a UTF-8 text file via base64 pipe to avoid shell quoting hell."""
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        cmd = (
            f"echo {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}"
        )
        try:
            await ssh.run_command(
                integration, cmd,
                timeout_seconds=60.0, connect_timeout=10.0,
            )
        except (OSError, TimeoutError) as exc:
            raise ProposalPrepareError(
                f"SSH write of {path} failed: {exc}",
            ) from exc
        transcript.append(f"# wrote {path} ({len(content)} bytes)")

    @staticmethod
    async def _load_system(system_id: int) -> dict[str, Any]:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(ManagedSystemRecord).where(
                    ManagedSystemRecord.id == system_id,
                ),
            )).first()
            if row is None:
                raise ProposalPrepareError(
                    f"System {system_id} not registered.",
                )
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

    @staticmethod
    def _harness_extension(language: str | None) -> str:
        if not language:
            return "c"
        lang = language.lower()
        if lang in ("cpp", "c++"):
            return "cc"
        if lang == "rust":
            return "rs"
        if lang == "go":
            return "go"
        if lang in ("js", "javascript"):
            return "js"
        if lang in ("py", "python"):
            return "py"
        return "c"

    @staticmethod
    def _infer_harness_path(
        workdir: str, proposal: VRFuzzCampaignProposalRecord,
    ) -> str | None:
        if not proposal.harness_source:
            return None
        # When the agent didn't say WHERE the build will write, assume
        # the build emits a binary named "harness" in the workdir.
        return f"{workdir}/harness"

    @staticmethod
    def _synthesize_name(proposal: VRFuzzCampaignProposalRecord) -> str:
        try:
            descriptor = json.loads(proposal.target_descriptor_json or "{}")
        except (ValueError, TypeError):
            descriptor = {}
        target_key = (
            descriptor.get("harness")
            or descriptor.get("function")
            or descriptor.get("function_name")
            or proposal.profile
        )
        return f"{proposal.profile} · {target_key}"[:255]

    async def _mark_accepted(
        self,
        proposal_id: str,
        *,
        campaign_id: str,
        decided_by: str | None,
        decision_reason: str,
        prepare_log: str,
    ) -> None:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRFuzzCampaignProposalRecord).where(
                    VRFuzzCampaignProposalRecord.id == proposal_id,
                ),
            )).first()
            if row is None:
                return
            row.status = "accepted"
            row.accepted_campaign_id = campaign_id
            row.decided_at = utc_now()
            row.decided_by = decided_by
            row.decision_reason = decision_reason
            row.prepare_log = prepare_log
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.session.commit()

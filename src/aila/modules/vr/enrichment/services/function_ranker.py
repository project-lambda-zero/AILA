"""Function ranking dispatcher.

Routes by target kind to the appropriate MCP server and normalizes the
response into ``FunctionRanking``. No heuristics in Python -- the MCPs
already implement graph-aware ranking:

  source target  → audit-mcp ``fuzzing_targets`` (graph-aware ranked list,
                   already correlates entrypoints + blast radius + complexity
                   + taint reachability). Optional ``scan_and_correlate``
                   overlay when a SAST scanner is wired in.

  binary target  → IDA ``binary_survey`` hotspots (kuna-supported),
                   ranked by cyclomatic complexity with a log-scale
                   normalized score. Falls back to
                   ``list_functions(order_by=complexity_desc)`` when the
                   survey returns no hotspots.

The dispatcher persists the result into
``vr_targets.capability_profile_json.function_ranking`` and updates
``analysis_state``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math  # fix §232 -- log-scale normalization in _rank_binary
from typing import Any, Protocol

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.enrichment.contracts import (
    FunctionRanking,
    RankedFunction,
    RankingSource,
)
from aila.modules.vr.services.fuzz_proposal_producer import (
    produce_fuzz_proposals,
)
from aila.modules.vr.services.stage_tracker import (
    StageAlreadyDoneError,
    StageInFlightError,
    StageTracker,
    resolve_stage_timeout_s,
)
from aila.platform.contracts import utc_now
from aila.platform.contracts.target_stages import StageName
from aila.platform.uow import UnitOfWork

__all__ = [
    "FunctionRankerError",
    "FunctionRankingDispatcher",
    "McpCallable",
]

_log = logging.getLogger(__name__)


class McpCallable(Protocol):
    """Subset of bridge tool interface used by the dispatcher.

    Both ``IDABridgeTool`` and ``AuditMcpBridgeTool`` satisfy this
    protocol. The dispatcher takes the two callables as constructor
    arguments so it's unit-testable against fakes -- no live MCP server
    required for tests.
    """

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        ...


class FunctionRankerError(Exception):
    """Raised on fatal dispatch failures (no FunctionRanking producible)."""


class FunctionRankingDispatcher:
    """Per-target function-ranking dispatcher.

    Construction injects both MCP bridges so the dispatcher can route
    by target kind. Tests inject fakes; the ARQ worker
    (``ranking_worker.py``) injects the real bridge tools.
    """

    def __init__(
        self,
        ida: McpCallable,
        audit_mcp: McpCallable,
        *,
        top_k: int = 50,
    ) -> None:
        self._ida = ida
        self._audit_mcp = audit_mcp
        self._top_k = top_k

    async def _load(self, target_id):
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
            )).first()
            if row is None:
                raise FunctionRankerError(f"target {target_id} not found")
            return row

    async def rank(self, target_id: str) -> FunctionRanking | None:
        """Dispatch ranking for one target. Returns the produced report.

        Reads MCP handles from the target's private
        ``_mcp_handles_json`` column (populated by TargetAnalysisService).
        Uses StageTracker (stage = FUNCTION_RANKING) so:
          - Re-running a target that already has a ranking is a no-op.
          - Concurrent rank invocations on the same row refuse the
            second one (StageInFlightError).
          - On exception the stage flips FAILED with the message; the
            operator can resume via POST /vr/targets/:id/resume-analysis.
        Returns None when skipped (already DONE or in flight).
        """
        stage_timeout_s = await resolve_stage_timeout_s(StageName.FUNCTION_RANKING)
        try:
            async with StageTracker(
                target_id,
                StageName.FUNCTION_RANKING,
                stage_timeout_s=stage_timeout_s,
            ) as tracker:
                target_row = await self._load(target_id)
                handles = json.loads(target_row.mcp_handles_json or "{}")

                if target_row.kind == TargetKind.SOURCE_REPO.value:
                    ranking = await self._rank_source(target_id, handles, tracker)
                elif target_row.kind in {
                    TargetKind.NATIVE_BINARY.value,
                    TargetKind.ANDROID_APK.value,  # fix §228 -- canonical name (TargetKind.APK never existed)
                    TargetKind.IPA.value,
                    TargetKind.JAR.value,
                    TargetKind.DOTNET_ASSEMBLY.value,
                    TargetKind.KERNEL_IMAGE.value,
                    TargetKind.KERNEL_MODULE.value,
                    TargetKind.HYPERVISOR_IMAGE.value,
                }:
                    ranking = await self._rank_binary(target_id, handles)
                else:
                    _log.info(
                        "function_ranker: target_id=%s kind=%s is not rankable "
                        "(only SOURCE_REPO and binary kinds supported) -- skipping",
                        target_id, target_row.kind,
                    )
                    return None

                # Persist into capability_profile.function_ranking -- same
                # commit as the stage's DONE transition (no crash window
                # between persisting work + recording state).
                existing = json.loads(target_row.capability_profile_json or "{}")
                existing["function_ranking"] = ranking.model_dump(mode="json")
                tracker.record_output(capability_profile_json=json.dumps(existing))

                # req 9 / AC1 -- synthesize deterministic fuzz proposals
                # from the fresh ranking so the operator sees actionable
                # proposals populate WITHOUT an investigation outcome.
                # Producer failure MUST NOT fail the ranking commit; log
                # the specific exception and continue.
                try:
                    # Reflect the just-persisted ranking into the in-memory
                    # target row so the producer's capability lookup sees
                    # it (the DB write happens at stage-tracker exit).
                    target_row.capability_profile_json = json.dumps(existing)
                    async with UnitOfWork() as _producer_uow:
                        written = await produce_fuzz_proposals(
                            _producer_uow.session, target_row, ranking,
                        )
                        await _producer_uow.session.commit()
                    _log.info(
                        "fuzz_proposal_producer: wrote %d proposals for target_id=%s",
                        written, target_id,
                    )
                except (
                    SQLAlchemyError, OSError, RuntimeError,
                    ValueError, TypeError, KeyError,
                ) as prod_exc:
                    _log.warning(
                        "fuzz_proposal_producer failed for target_id=%s: %s",
                        target_id, prod_exc,
                    )

                _log.info(
                    "function_ranker COMPLETE target_id=%s source=%s top_k=%d total_candidates=%d",
                    target_id, ranking.source.value,
                    len(ranking.top_k), ranking.total_candidates,
                )
                return ranking
        except StageAlreadyDoneError:
            _log.info("function_ranker: target %s already ranked -- skip", target_id)
            return None
        except StageInFlightError:
            _log.info("function_ranker: target %s ranking in flight -- skip", target_id)
            return None

    async def _rank_source(
        self,
        target_id: str,
        handles: dict[str, Any],
        tracker: StageTracker,
    ) -> FunctionRanking:
        index_id = handles.get("audit_mcp_index_id")
        if not index_id:
            raise FunctionRankerError(
                f"target {target_id} not analyzed yet -- POST "
                "/vr/targets/{id}/analyze or wait for auto-ingestion",
            )

        resp = await self._audit_mcp.forward(
            action="fuzzing_targets", index_id=index_id, limit=self._top_k,
        )

        # Async pattern -- audit-mcp returns 'pending' + task_id for heavy
        # work (firefox-scale GPU CSR build + ranking). Poll until ready
        # or until we're inside the safety margin before the stage's
        # hard deadline.
        # fix §229 -- was hardcoded at 180 polls × 5 s = 15 min, half the
        # FUNCTION_RANKING stage's 30 min budget. Now poll up to 30 s
        # before the tracker's stage_timeout_s elapses, so audit-mcp
        # gets the full window the stage tracker advertises.
        poll_interval_s = 5.0
        deadline_safety_margin_s = 30.0
        _loop = asyncio.get_running_loop()
        _deadline_monotonic = _loop.time() + tracker.stage_timeout_s
        poll_attempts = 0
        while resp.get("status") == "pending":
            task_id = resp.get("task_id") or resp.get("id")
            if not task_id:
                # 'pending' without a task_id is a contract violation
                # we can't recover from -- fail loud rather than spin.
                raise FunctionRankerError(
                    f"audit-mcp fuzzing_targets returned pending with no task_id: {resp!r}",
                )
            remaining = _deadline_monotonic - _loop.time()
            if remaining <= deadline_safety_margin_s:
                raise FunctionRankerError(
                    f"audit-mcp fuzzing_targets still pending after {poll_attempts} polls "
                    f"for target {target_id}: <={deadline_safety_margin_s:.0f}s of the "
                    f"{tracker.stage_timeout_s:.0f}s FUNCTION_RANKING budget remaining",
                )
            poll_attempts += 1
            await asyncio.sleep(poll_interval_s)
            resp = await self._audit_mcp.forward(action="poll_task", task_id=task_id)

        if resp.get("status") not in {"ready", None}:
            err = resp.get("error") or f"audit-mcp returned status={resp.get('status')!r}"
            raise FunctionRankerError(f"audit-mcp fuzzing_targets failed: {err}")

        raw_entries: list[dict[str, Any]] = resp.get("targets") or resp.get("results") or []
        top_k = _normalize_audit_mcp_entries(raw_entries, self._top_k)

        return FunctionRanking(
            target_id=target_id,
            source=RankingSource.AUDIT_MCP_FUZZING_TARGETS,
            produced_at=utc_now(),
            total_candidates=int(resp.get("total_candidates") or len(raw_entries)),
            top_k=top_k,
            notes=resp.get("notes") or "",
        )

    async def _rank_binary(self, target_id: str, handles: dict[str, Any]) -> FunctionRanking:
        binary_id = handles.get("binary_id")
        if not binary_id:
            raise FunctionRankerError(
                f"target {target_id} not analyzed yet -- POST "
                "/vr/targets/{id}/analyze or wait for auto-ingestion",
            )

        # Rank binaries from kuna's ``binary_survey`` hotspots (complexity
        # sorted, pre-scored). ``find_api_call_sites`` + ``assess_exploitability``
        # were the prior path; kuna returns unsupported for assess and
        # emits call sites in a different shape, so the previous pipeline
        # always produced empty rankings. Falls back to ``list_functions``
        # ordered by cyclomatic complexity when the survey yields nothing.
        survey = await self._ida.forward(
            action="binary_survey",
            binary_id=binary_id,
            max_hotspots=max(self._top_k, 20),
        )
        hotspots = survey.get("hotspots") if isinstance(survey, dict) else None
        if not hotspots:
            lf = await self._ida.forward(
                action="list_functions",
                binary_id=binary_id,
                order_by="complexity_desc",
                exclude_thunks=True,
                exclude_libraries=True,
                limit=max(self._top_k, 20),
            )
            if isinstance(lf, dict):
                hotspots = [
                    {
                        "name": f.get("name"),
                        "address": f.get("address"),
                        "complexity": f.get("cyclomatic_complexity", 0),
                    }
                    for f in (lf.get("functions") or [])
                ]
            else:
                hotspots = []

        hotspots = [h for h in hotspots if h.get("address")]

        if not hotspots:
            return FunctionRanking(
                target_id=target_id,
                source=RankingSource.IDA_BINARY_SURVEY,
                produced_at=utc_now(),
                total_candidates=0,
                top_k=[],
                notes="binary_survey returned no hotspots",
            )

        hotspots.sort(key=lambda h: float(h.get("complexity") or 0), reverse=True)
        max_cx = float(hotspots[0].get("complexity") or 0) or 1.0

        top_k: list[RankedFunction] = []
        for pos, h in enumerate(hotspots[: self._top_k], start=1):
            c = float(h.get("complexity") or 0)
            score = min(1.0, math.log1p(c) / math.log1p(max_cx)) if max_cx > 0 else 0.0
            reasons = [f"cyclomatic_complexity={int(c)}"]
            if h.get("callees_count") is not None:
                reasons.append(f"callees={h['callees_count']}")
            if h.get("string_refs_count") is not None:
                reasons.append(f"string_refs={h['string_refs_count']}")
            top_k.append(RankedFunction(
                name=str(h.get("name") or "<unknown>")[:512],
                address=str(h.get("address") or "")[:64],
                score=score,
                rank=pos,
                reasons=reasons,
            ))

        return FunctionRanking(
            target_id=target_id,
            source=RankingSource.IDA_BINARY_SURVEY,
            produced_at=utc_now(),
            total_candidates=len(hotspots),
            top_k=top_k,
            notes=f"ranked {len(top_k)} hotspots from binary_survey by cyclomatic complexity",
        )


def _normalize_audit_mcp_entries(
    raw: list[dict[str, Any]],
    top_k: int,
) -> list[RankedFunction]:
    """Map audit-mcp fuzzing_targets entries into RankedFunction[].

    Real composite score (08_FRONTEND_UX.md feedback -- the prior
    implementation returned 1.0 for every entry when audit-mcp
    didn't ship a single dominant score field, making the rank
    useless for filtering or sorting).

    Signal weights (additive; each contribution is normalized to
    [0, 1] across the page so the operator can tell entries apart
    even when audit-mcp gives sparse data):

      - blast_radius           × 0.40  (downstream-reach count)
      - complexity (cyclomatic) × 0.25  (audit difficulty proxy)
      - tainted_from           × 0.20  (reachable from user input)
      - inverse entrypoint_distance × 0.10  (closer = better)
      - position fallback      × 0.05  (audit-mcp's own ordering)

    Entries missing all signals fall back to the position-only
    score so even a sparse response yields a differentiable ranking.
    """
    if not raw:
        return []

    def _f(entry: dict[str, Any], key: str) -> float:
        v = entry.get(key)
        if isinstance(v, bool):
            return 1.0 if v else 0.0
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, (list, tuple, set)):
            return float(len(v))
        return 0.0

    # Collect raw signal columns across the slice we're ranking.
    sliced = list(raw[:top_k])
    n = len(sliced)
    blast = [_f(e, "blast_radius") for e in sliced]
    cx = [
        max(_f(e, "complexity"), _f(e, "cyclomatic_complexity"))
        for e in sliced
    ]
    taint = [_f(e, "tainted_from") for e in sliced]
    # entrypoint_distance: lower is better. Convert to an "inverse"
    # signal so larger is better. Missing → 0 (no contribution).
    dist = [_f(e, "entrypoint_distance") for e in sliced]
    inv_dist = [
        0.0 if d <= 0 else 1.0 / d
        for d in dist
    ]
    # Position fallback: position 1 → 1.0, position n → 1/n.
    position = [1.0 / (i + 1) for i in range(n)]

    def _norm(col: list[float]) -> list[float]:
        peak = max(col) if col else 0.0
        if peak <= 0:
            return [0.0] * len(col)
        return [v / peak for v in col]

    nb, nc, nt, nd, np_ = (
        _norm(blast), _norm(cx), _norm(taint), _norm(inv_dist), _norm(position),
    )

    result: list[RankedFunction] = []
    for pos, entry in enumerate(sliced, start=1):
        i = pos - 1
        composite = (
            nb[i] * 0.40
            + nc[i] * 0.25
            + nt[i] * 0.20
            + nd[i] * 0.10
            + np_[i] * 0.05
        )
        # Clamp + nudge zero scores to a small floor so distinct rows
        # always sort below higher-signal rows but stay above absent
        # rows. Floor proportional to position for stable ordering.
        if composite <= 0:
            composite = max(0.01, np_[i] * 0.05)
        composite = max(0.0, min(1.0, composite))

        name = (
            entry.get("function_name")
            or entry.get("name")
            or entry.get("symbol")
            or "<unnamed>"
        )
        reasons: list[str] = []
        if entry.get("blast_radius") is not None:
            reasons.append(f"blast_radius={entry['blast_radius']}")
        if entry.get("complexity") is not None:
            reasons.append(f"complexity={entry['complexity']}")
        elif entry.get("cyclomatic_complexity") is not None:
            reasons.append(f"cyclomatic_complexity={entry['cyclomatic_complexity']}")
        if entry.get("tainted_from"):
            tval = entry["tainted_from"]
            if isinstance(tval, (list, tuple, set)):
                reasons.append(f"tainted_from={len(tval)} sources")
            else:
                reasons.append(f"tainted_from={tval}")
        if entry.get("entrypoint_distance") is not None:
            reasons.append(f"entrypoint_distance={entry['entrypoint_distance']}")
        if not reasons:
            reasons.append(f"audit-mcp position #{pos}")
        result.append(RankedFunction(
            name=str(name)[:512],
            file_path=str(entry.get("file_path") or entry.get("file") or "")[:1024],
            line=entry.get("line") if isinstance(entry.get("line"), int) else None,
            score=composite,
            rank=pos,
            reasons=reasons,
        ))
    # Re-sort by composite (descending). Stable on tie so audit-mcp
    # order is preserved, then re-assign rank positions.
    result.sort(key=lambda r: r.score, reverse=True)
    for new_rank, r in enumerate(result, start=1):
        r.rank = new_rank
    return result

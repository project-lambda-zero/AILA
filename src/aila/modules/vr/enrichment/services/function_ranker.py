"""Function ranking dispatcher.

Routes by target kind to the appropriate MCP server and normalizes the
response into ``FunctionRanking``. No heuristics in Python — the MCPs
already implement graph-aware ranking:

  source target  → audit-mcp ``fuzzing_targets`` (graph-aware ranked list,
                   already correlates entrypoints + blast radius + complexity
                   + taint reachability). Optional ``scan_and_correlate``
                   overlay when a SAST scanner is wired in.

  binary target  → IDA ``find_api_call_sites`` for parser sinks, aggregated
                   per function; top-K candidates get a deep
                   ``assess_exploitability`` verdict for the strongest sink.

The dispatcher persists the result into
``vr_targets.capability_profile_json.function_ranking`` and updates
``enrichment_status``.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Protocol

from sqlmodel import select as _select

from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.enrichment.contracts import (
    FunctionRanking,
    RankedFunction,
    RankingSource,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "FunctionRankerError",
    "FunctionRankingDispatcher",
    "McpCallable",
]

_log = logging.getLogger(__name__)


# Parser-sink API list used to bucket IDA find_api_call_sites results
# per function. Limited to the unambiguous high-signal APIs — the
# audit-mcp source path uses a richer taint analysis and doesn't need
# this list.
_PARSER_SINK_APIS: tuple[str, ...] = (
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "sscanf", "scanf", "fscanf", "memcpy", "memmove",
    "wcscpy", "wcscat", "wsprintfA", "wsprintfW",
    "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
)


class McpCallable(Protocol):
    """Subset of bridge tool interface used by the dispatcher.

    Both ``IDABridgeTool`` and ``AuditMcpBridgeTool`` satisfy this
    protocol. The dispatcher takes the two callables as constructor
    arguments so it's unit-testable against fakes — no live MCP server
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
        deep_assess_top_n: int = 10,
    ) -> None:
        self._ida = ida
        self._audit_mcp = audit_mcp
        self._top_k = top_k
        self._deep_assess_top_n = deep_assess_top_n

    async def rank(self, target_id: str) -> FunctionRanking:
        """Dispatch ranking for one target. Returns the produced report.

        Sets ``enrichment_status='running'`` at entry; transitions to
        ``complete`` on success or ``failed`` if the MCP call returned
        an error. Raises ``FunctionRankerError`` on fatal failure
        (target not found, descriptor missing required fields, MCP
        unreachable).
        """
        target_row = await self._load_and_mark_running(target_id)
        descriptor = json.loads(target_row.descriptor_json or "{}")

        try:
            if target_row.kind == TargetKind.SOURCE_REPO.value:
                ranking = await self._rank_source(target_id, descriptor)
            elif target_row.kind in {
                TargetKind.NATIVE_BINARY.value,
                TargetKind.APK.value,
                TargetKind.IPA.value,
                TargetKind.JAR.value,
                TargetKind.DOTNET_ASSEMBLY.value,
            }:
                ranking = await self._rank_binary(target_id, descriptor)
            else:
                await self._mark_failed(
                    target_id, f"unsupported target kind for ranking: {target_row.kind}",
                )
                raise FunctionRankerError(
                    f"target_id={target_id} kind={target_row.kind!r} "
                    "is not rankable (only SOURCE_REPO + NATIVE_BINARY + "
                    "APK + IPA + JAR + DOTNET_ASSEMBLY supported)",
                )
        except FunctionRankerError:
            raise
        except (OSError, TimeoutError, RuntimeError) as exc:
            await self._mark_failed(target_id, f"dispatcher raised: {exc}")
            raise FunctionRankerError(
                f"ranking dispatch failed for target_id={target_id}: {exc}",
            ) from exc

        await self._persist(target_id, ranking)
        _log.info(
            "function_ranker COMPLETE target_id=%s source=%s top_k=%d total_candidates=%d",
            target_id, ranking.source.value, len(ranking.top_k), ranking.total_candidates,
        )
        return ranking

    async def _rank_source(self, target_id: str, descriptor: dict[str, Any]) -> FunctionRanking:
        index_id = descriptor.get("audit_mcp_index_id")
        if not index_id:
            raise FunctionRankerError(
                f"source target {target_id} has no audit_mcp_index_id in descriptor — "
                "run audit-mcp index_codebase before ranking",
            )

        resp = await self._audit_mcp.forward(
            action="fuzzing_targets", index_id=index_id, limit=self._top_k,
        )
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

    async def _rank_binary(self, target_id: str, descriptor: dict[str, Any]) -> FunctionRanking:
        binary_id = descriptor.get("binary_id")
        if not binary_id:
            raise FunctionRankerError(
                f"binary target {target_id} has no binary_id in descriptor — "
                "upload + analyze in IDA MCP before ranking",
            )

        bucket: dict[str, dict[str, Any]] = {}
        for api in _PARSER_SINK_APIS:
            sites_resp = await self._ida.forward(
                action="find_api_call_sites", binary_id=binary_id, api_name=api,
            )
            if sites_resp.get("status") != "ready":
                continue
            for site in sites_resp.get("call_sites", []) or []:
                fn_addr = site.get("function_address") or site.get("caller_function_address")
                fn_name = site.get("function_name") or site.get("caller_function_name") or "<unknown>"
                if not fn_addr:
                    continue
                row = bucket.setdefault(fn_addr, {"name": fn_name, "hits": 0, "apis": set()})
                row["hits"] += 1
                row["apis"].add(api)

        if not bucket:
            return FunctionRanking(
                target_id=target_id,
                source=RankingSource.IDA_ASSESS_EXPLOITABILITY,
                produced_at=utc_now(),
                total_candidates=0,
                top_k=[],
                notes="no parser-sink callsites found in binary",
            )

        ordered = sorted(bucket.items(), key=lambda kv: kv[1]["hits"], reverse=True)
        max_hits = ordered[0][1]["hits"] if ordered else 1

        deep_addresses = [addr for addr, _ in ordered[: self._deep_assess_top_n]]
        deep_verdicts: dict[str, str] = {}
        for addr in deep_addresses:
            row = bucket[addr]
            sink = next(iter(row["apis"]), None)
            if not sink:
                continue
            verdict_resp = await self._ida.forward(
                action="assess_exploitability",
                binary_id=binary_id,
                address_or_name=addr,
                sink_function=sink,
                sink_argument_index=2 if sink in {"memcpy", "memmove"} else 0,
            )
            if verdict_resp.get("status") == "ready":
                verdict = verdict_resp.get("verdict") or verdict_resp.get("classification") or ""
                if verdict:
                    deep_verdicts[addr] = str(verdict)

        top_k: list[RankedFunction] = []
        for rank_pos, (addr, row) in enumerate(ordered[: self._top_k], start=1):
            normalized = row["hits"] / max_hits if max_hits else 0.0
            reasons = [f"{row['hits']} parser-sink callsite(s): {', '.join(sorted(row['apis']))}"]
            if addr in deep_verdicts:
                reasons.append(f"IDA assess_exploitability verdict: {deep_verdicts[addr]}")
            top_k.append(RankedFunction(
                name=row["name"],
                address=addr,
                score=min(1.0, normalized),
                rank=rank_pos,
                reasons=reasons,
            ))

        return FunctionRanking(
            target_id=target_id,
            source=RankingSource.IDA_ASSESS_EXPLOITABILITY,
            produced_at=utc_now(),
            total_candidates=len(bucket),
            top_k=top_k,
            notes=f"deep assess_exploitability ran on top {len(deep_verdicts)}/{len(deep_addresses)} candidates",
        )

    async def _load_and_mark_running(self, target_id: str) -> VRTargetRecord:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                raise FunctionRankerError(f"target {target_id} not found")
            row.enrichment_status = "running"
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()
            await uow.session.refresh(row)
            return row

    async def _mark_failed(self, target_id: str, message: str) -> None:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                return
            capability = json.loads(row.capability_profile_json or "{}")
            errors = capability.setdefault("enrichment_errors", [])
            errors.append({"step": "function_ranker", "message": message})
            row.capability_profile_json = json.dumps(capability)
            row.enrichment_status = "failed"
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()

    async def _persist(self, target_id: str, ranking: FunctionRanking) -> None:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                raise FunctionRankerError(
                    f"target {target_id} disappeared during ranking",
                )
            capability = json.loads(row.capability_profile_json or "{}")
            capability["function_ranking"] = ranking.model_dump(mode="json")
            row.capability_profile_json = json.dumps(capability)
            row.enrichment_status = "complete"
            row.last_enriched_at = utc_now()
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()


def _normalize_audit_mcp_entries(
    raw: list[dict[str, Any]],
    top_k: int,
) -> list[RankedFunction]:
    """Map audit-mcp fuzzing_targets entries into RankedFunction[].

    audit-mcp returns entries with at minimum ``function_name`` and a
    score-like field. The exact shape varies by audit-mcp version so we
    accept several common field names and ignore unknown fields.
    """
    if not raw:
        return []
    raw_scores = [_audit_mcp_score(entry) for entry in raw]
    max_score = max(raw_scores) if raw_scores else 1.0
    if max_score <= 0:
        max_score = 1.0

    result: list[RankedFunction] = []
    for pos, entry in enumerate(raw[:top_k], start=1):
        name = (
            entry.get("function_name")
            or entry.get("name")
            or entry.get("symbol")
            or "<unnamed>"
        )
        score = _audit_mcp_score(entry) / max_score
        reasons: list[str] = []
        if "blast_radius" in entry:
            reasons.append(f"blast_radius={entry['blast_radius']}")
        if "complexity" in entry:
            reasons.append(f"complexity={entry['complexity']}")
        if "tainted_from" in entry and entry["tainted_from"]:
            reasons.append(f"tainted_from={entry['tainted_from']}")
        if "entrypoint_distance" in entry:
            reasons.append(f"entrypoint_distance={entry['entrypoint_distance']}")
        result.append(RankedFunction(
            name=str(name)[:512],
            file_path=str(entry.get("file_path") or entry.get("file") or "")[:1024],
            line=entry.get("line") if isinstance(entry.get("line"), int) else None,
            score=min(1.0, max(0.0, score)),
            rank=pos,
            reasons=reasons,
        ))
    return result


def _audit_mcp_score(entry: dict[str, Any]) -> float:
    """Extract a numeric score from an audit-mcp fuzzing_targets entry."""
    for key in ("risk_score", "score", "priority", "blast_radius"):
        value = entry.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return float(value)
    return 1.0

"""Eval runner: score a candidate prompt version and gate promotion (RFC-08).

Scope of THIS increment
-----------------------
The runner scores a candidate against a benchmark of ``CaseOutcome`` rows
that are ALREADY resolved (predicted_verdict / verified_verdict /
confidence per case, per outcome_kind, per version). It does NOT replay
the agent loop against fresh inputs; recorded-replay is a later
increment (see the metrics module docstring).

Benchmark schema (``cases_json``)
--------------------------------
A JSON list of scored case dicts. Each case has:

    {
      "outcome_kind": str,
      "predicted_verdict": "accept" | "reject",
      "verified_verdict":  "accept" | "reject",
      "confidence": float in [0, 1],
      "version": str | null       # optional; see below
    }

The optional ``version`` field attributes a case to the predictor that
produced it. The runner partitions cases into two bundles:

- candidate bundle: cases whose ``version`` equals ``candidate_version``
  OR whose ``version`` is None (shared / common ground truth).
- baseline bundle:  cases whose ``version`` equals ``baseline_version``
  OR whose ``version`` is None.

Both bundles include the unversioned cases so a benchmark can carry a
shared floor of ground truth alongside per-version predictions. A run
against a candidate with no versioned cases (and no unversioned ones)
raises: an empty bundle is a misconfiguration, not a passing eval.

Runner flow
-----------
1. Load the benchmark row -- raise ``BenchmarkNotFoundError`` if absent.
2. Resolve the current 'production' alias for ``key`` via
   ``PromptVersionStore`` -- baseline is None on a first-ever eval.
3. Build an ``EvalReport`` for the candidate bundle. Build the baseline
   report from the baseline bundle when a baseline version exists.
4. Verdict = 'pass' when no baseline exists (first eval; a warning is
   logged so an operator sees the auto-pass) OR when
   ``candidate.beats(baseline)`` per the strict-beat gate. Otherwise
   'fail'.
5. When verdict == 'pass' AND ``auto_promote`` is True, call
   ``PromptVersionStore.set_alias`` to point the 'production' alias at
   ``candidate_version``. On 'fail' or when auto_promote is False, the
   alias is left untouched.
6. Persist and return an ``EvalRunRecord`` with the serialized report
   bundle.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict

from sqlmodel import select

from aila.platform.eval.metrics import (
    CaseOutcome,
    EvalReport,
    ece,
    faithfulness_score,
    precision_recall_per_kind,
)
from aila.platform.eval.models import EvalBenchmarkRecord, EvalRunRecord
from aila.platform.prompts.version_store import PromptVersionStore
from aila.storage.database import async_session_scope

__all__ = ["BenchmarkNotFoundError", "EmptyCaseBundleError", "EvalRunner", "PRODUCTION_ALIAS"]

_log = logging.getLogger(__name__)

PRODUCTION_ALIAS = "production"


class BenchmarkNotFoundError(LookupError):
    """Raised when a benchmark id resolves to no row."""


class EmptyCaseBundleError(ValueError):
    """Raised when a version's case bundle is empty (nothing to score)."""


def _score_cases(cases: list[CaseOutcome]) -> EvalReport:
    """Aggregate a list of scored cases into one ``EvalReport``.

    Determinism is 1.0 by definition on a pre-supplied case bundle: no
    replay happened, so there is no cross-replay divergence to score.
    Recorded-replay ingest is a later increment.
    """
    confidences = [c.confidence for c in cases]
    correct = [c.predicted_verdict == c.verified_verdict for c in cases]
    precision, recall = precision_recall_per_kind(cases)
    return EvalReport(
        ece=ece(confidences, correct),
        precision_by_kind=precision,
        recall_by_kind=recall,
        determinism_score=1.0,
        faithfulness_score=faithfulness_score(cases),
    )


def _parse_case_entries(cases_json: str) -> list[dict[str, object]]:
    """Deserialize cases_json into a validated list of raw case dicts."""
    parsed = json.loads(cases_json)
    if not isinstance(parsed, list):
        raise ValueError("cases_json must decode to a JSON list")
    out: list[dict[str, object]] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            raise ValueError("each case entry must be a JSON object")
        out.append(entry)
    return out


def _bundle_for_version(
    entries: list[dict[str, object]], version: str | None,
) -> list[CaseOutcome]:
    """Return the CaseOutcome bundle for ``version`` from raw entries.

    Includes entries whose ``version`` field matches ``version`` AND
    entries with no version field (shared ground truth). ``version=None``
    (no baseline resolved yet) returns only the unversioned entries.
    """
    bundle: list[CaseOutcome] = []
    for entry in entries:
        entry_version = entry.get("version")
        if entry_version is not None and entry_version != version:
            continue
        bundle.append(CaseOutcome(
            outcome_kind=str(entry["outcome_kind"]),
            predicted_verdict=str(entry["predicted_verdict"]),
            verified_verdict=str(entry["verified_verdict"]),
            confidence=float(entry.get("confidence", 0.0)),
        ))
    return bundle


def _report_to_dict(report: EvalReport) -> dict[str, object]:
    """Serialize an ``EvalReport`` to a JSON-safe dict."""
    return asdict(report)


class EvalRunner:
    """Score a candidate prompt version and (optionally) flip 'production'.

    Composed with a ``PromptVersionStore`` for baseline resolution and
    alias flips. Both collaborators open their own async sessions through
    ``async_session_scope``; there is no shared unit-of-work handle in
    this codebase.
    """

    def __init__(self, version_store: PromptVersionStore | None = None) -> None:
        self._store = version_store or PromptVersionStore()

    async def register_benchmark(
        self,
        *,
        key: str,
        name: str,
        cases: list[dict[str, object]],
        created_by: str = "",
    ) -> EvalBenchmarkRecord:
        """Persist a benchmark row from a list of case dicts.

        Each case is validated the same way ``run()`` will parse it, so a
        malformed case fails at register time rather than at scoring.
        """
        as_dicts: list[dict[str, object]] = []
        for entry in cases:
            if not isinstance(entry, dict):
                raise TypeError("cases must be dict entries")
            normalized: dict[str, object] = {
                "outcome_kind": str(entry["outcome_kind"]),
                "predicted_verdict": str(entry["predicted_verdict"]),
                "verified_verdict": str(entry["verified_verdict"]),
                "confidence": float(entry.get("confidence", 0.0)),
            }
            version = entry.get("version")
            if version is not None:
                normalized["version"] = str(version)
            as_dicts.append(normalized)
        record = EvalBenchmarkRecord(
            key=key, name=name,
            cases_json=json.dumps(as_dicts),
            created_by=created_by,
        )
        async with async_session_scope() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)
        return record

    async def run(
        self,
        *,
        key: str,
        candidate_version: str,
        benchmark_id: str,
        auto_promote: bool,
        actor: str = "",
    ) -> EvalRunRecord:
        """Score ``candidate_version`` against ``benchmark_id``.

        Raises ``BenchmarkNotFoundError`` when the benchmark row is absent.
        Raises ``EmptyCaseBundleError`` when the candidate has no scored
        cases in the benchmark. On verdict == 'pass' AND ``auto_promote``,
        flips the 'production' alias to ``candidate_version`` via
        ``PromptVersionStore.set_alias``. Returns the persisted
        ``EvalRunRecord``.
        """
        async with async_session_scope() as session:
            benchmark = (await session.exec(
                select(EvalBenchmarkRecord).where(
                    EvalBenchmarkRecord.id == benchmark_id,
                )
            )).first()
        if benchmark is None:
            raise BenchmarkNotFoundError(
                f"no benchmark registered with id {benchmark_id!r}",
            )

        entries = _parse_case_entries(benchmark.cases_json)
        candidate_cases = _bundle_for_version(entries, candidate_version)
        if not candidate_cases:
            raise EmptyCaseBundleError(
                f"benchmark {benchmark_id!r} has no cases for candidate "
                f"version {candidate_version!r}",
            )
        candidate_report = _score_cases(candidate_cases)

        baseline_row = await self._store.resolve(key, alias=PRODUCTION_ALIAS)
        baseline_version = baseline_row.version if baseline_row is not None else None
        baseline_report: EvalReport | None = None
        if baseline_version is not None:
            baseline_cases = _bundle_for_version(entries, baseline_version)
            if baseline_cases:
                baseline_report = _score_cases(baseline_cases)

        if baseline_report is None:
            _log.warning(
                "eval.run first-ever eval for key=%s: no production baseline, "
                "auto-passing candidate_version=%s",
                key, candidate_version,
            )
            verdict = "pass"
        elif candidate_report.beats(baseline_report):
            verdict = "pass"
        else:
            verdict = "fail"

        promoted = False
        if verdict == "pass" and auto_promote:
            await self._store.set_alias(
                key, PRODUCTION_ALIAS, candidate_version,
                actor=actor, reason=f"eval auto-promote benchmark_id={benchmark_id}",
            )
            promoted = True

        report_payload: dict[str, object] = {
            "candidate": _report_to_dict(candidate_report),
            "baseline": _report_to_dict(baseline_report) if baseline_report is not None else None,
            "promoted": promoted,
        }
        run_record = EvalRunRecord(
            key=key,
            candidate_version=candidate_version,
            baseline_version=baseline_version,
            benchmark_id=benchmark_id,
            report_json=json.dumps(report_payload),
            verdict=verdict,
            actor=actor,
        )
        async with async_session_scope() as session:
            session.add(run_record)
            await session.commit()
            await session.refresh(run_record)
        return run_record

    async def list_runs(
        self, key: str, *, limit: int = 100,
    ) -> list[EvalRunRecord]:
        """List eval runs for a key, newest first, bounded by ``limit``."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        async with async_session_scope() as session:
            rows = (await session.exec(
                select(EvalRunRecord)
                .where(EvalRunRecord.key == key)
                .order_by(EvalRunRecord.created_at.desc())
                .limit(limit)
            )).all()
        return list(rows)

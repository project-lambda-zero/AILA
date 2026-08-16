"""Semantic-tier memory consolidation (issue #150).

Purpose
-------
AILA already persists two forms of episodic trace on every investigation:

* the shared ``investigation_ledger`` (:class:`InvestigationLedgerRecord`)
  where every branch appends typed entries (``discovery`` / ``note`` /
  ``decision`` / ``objective``); and
* per-module ``<module>_investigation_messages`` tables holding the
  branch-by-branch dialogue.

Neither is ever distilled into de-contextualized, cross-investigation
factual statements that the retrieval path can surface on a fresh
question. This module implements the semantic tier of the three-tier
memory model (RFC issue #150): a periodic sweep reads recent
resolved-investigation ledger traces, runs a cheap LLM distillation to
extract a handful of reusable facts per investigation, and writes them
into the existing pgvector knowledge store under the module's live-read
``<module>.semantic.workspace.<workspace_id>`` namespace.

Live reader (no dead paths)
---------------------------
Each module scope helper (``modules/malware/services/knowledge_scope.py``,
``modules/vr/services/knowledge_scope.py``) declares the ``semantic``
namespace kind explicitly, so both

* the setup-time knowledge retriever
  (``modules/<module>/workflow/states/investigation_setup.py``), and
* the agentic ``knowledge_bridge`` (dispatched by the module tool
  executor's ``_pre_dispatch_correct_args`` which injects the
  workspace-scoped namespace list),

read from the same ``<module>.semantic.workspace.<id>`` bucket the
consolidator writes to. Adding the writer is therefore additive: the
retrieval surface is unchanged; entries land where the reader already
looks.

Storage reuse
-------------
No new table and no Alembic migration: consolidated facts live in the
existing :class:`KnowledgeEntryRecord` (pgvector, HNSW-indexed) and are
retrieved by the adaptive :meth:`KnowledgeService.retrieve_routed` path
with the same trust-tiering, sanitize gate, and journal that already
apply to every knowledge hit.

Idempotency
-----------
Every fact carries a stable ``consolidator:<investigation_id>:<i>`` dedup
key and re-runs are guarded by a per-investigation existence check that
short-circuits before the LLM call, so a repeat sweep for an
already-consolidated investigation is a cheap SELECT that never charges
the model again.

Failure posture
---------------
Best-effort: a distillation failure on one investigation is logged and
skipped (never aborts the batch), and the whole sweep degrades to a
guarded no-op when there is nothing new to consolidate.
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict

import sqlalchemy.exc
from sqlalchemy import select as sa_select

from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.contracts.investigation_base import InvestigationRecordBase
from aila.platform.contracts.target_base import TargetRecordBase
from aila.platform.llm.correlation import correlation_scope
from aila.platform.services.factory import ServiceFactory
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.ledger import LedgerService
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

__all__ = [
    "ConsolidationReport",
    "DEDUP_KEY_PREFIX",
    "SEMANTIC_NAMESPACE_KIND",
    "SemanticConsolidationError",
    "consolidate_recent_investigations",
    "run_semantic_consolidation_sweep",
]

_log = logging.getLogger(__name__)


# The namespace kind segment. Any module that opts into semantic memory
# advertises this same string in its scope helper (VR appends "semantic"
# to VR_KNOWLEDGE_KINDS; malware includes
# ``malware.semantic.workspace.<id>`` in its scope list) so the writer
# and the readers can never drift on the bucket name.
SEMANTIC_NAMESPACE_KIND: str = "semantic"

# Dedup key prefix, one per fact per investigation. The per-investigation
# existence check below matches the prefix, and each fact within an
# investigation carries a positional suffix so re-runs upsert in place
# instead of allocating new rows.
DEDUP_KEY_PREFIX: str = "consolidator"

# The LLM routing key. Operators pin a cheap model via ConfigRegistry
# (``llm_model_consolidation``); an unconfigured install falls through
# to the platform default (``llm_default_model``). That fallback is what
# keeps this sweep behavior-preserving on a fresh deploy -- adding the
# writer must not change model selection on any other call path.
DEFAULT_TASK_TYPE: str = "consolidation"

# Prompt version literal stamped on every LLM call this sweep issues
# (RFC-09). Bump when :func:`_distillation_messages` changes so the cost
# ledger and seal records name the exact prompt shape that produced the
# facts. Kept module-local -- the platform prompt registry does not
# version this internal maintenance template.
_PROMPT_VERSION: str = "semantic_consolidator@1"

# Terminal statuses an investigation must have reached before its trace
# is worth distilling. STALLED counts because the operator has been
# offered the branch and no further phase will run without their
# intervention, so its trace is effectively frozen.
_TERMINAL_STATUSES: frozenset[str] = frozenset({
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
    InvestigationStatus.ABANDONED.value,
    InvestigationStatus.STALLED.value,
})

# Ledger kinds worth feeding the distillation prompt. ``objective`` is
# stateful bookkeeping; ``decision`` is the quorum's approval envelope,
# not a first-class trace of what was learned.
_EPISODIC_KINDS: tuple[str, ...] = ("discovery", "note")

# Isolation tuple used at every reachable failure point below. Bare
# ``except Exception`` is banned by the honesty audit, and a per-
# investigation fault must never abort the sweep -- so the enumerated
# leak set is caught, logged, and the loop continues.
_STEP_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    LookupError,
    ConnectionError,
    TimeoutError,
    AttributeError,
)


class SemanticConsolidationError(RuntimeError):
    """Raised for domain-level consolidator faults the caller cares about.

    Never raised for per-investigation processing errors (those are caught
    and logged so the sweep continues); reserved for setup faults the
    caller has to see -- e.g. a caller passed a knowledge service without
    an embedder that could store into pgvector.
    """


class ConsolidationReport(TypedDict):
    """One-sweep summary the automation runner records as last_run_result."""

    scanned: int
    consolidated: int
    skipped_already: int
    skipped_no_workspace: int
    skipped_no_traces: int
    facts_written: int
    errors: int


class _Candidate(TypedDict):
    """One eligible resolved-investigation row picked up by the scan."""

    investigation_id: str
    module_id: str
    target_id: str
    team_id: str | None
    target_tablename: str


# JSON Schema for the distillation response. Kept minimal (no free-form
# dict fields) so strict-schema providers accept it without falling back
# to json_object mode, and small enough that a cheap model can hit it
# reliably.
_FACTS_SCHEMA: dict[str, Any] = {
    "title": "SemanticFacts",
    "type": "object",
    "additionalProperties": False,
    "required": ["facts"],
    "properties": {
        "facts": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 400},
            "maxItems": 20,
        },
    },
}


def _empty_report() -> ConsolidationReport:
    return ConsolidationReport(
        scanned=0,
        consolidated=0,
        skipped_already=0,
        skipped_no_workspace=0,
        skipped_no_traces=0,
        facts_written=0,
        errors=0,
    )


def _module_id_from_tablename(tablename: str) -> str:
    """Strip the ``_investigations`` suffix so ``vr_investigations`` -> ``vr``.

    Returns the raw tablename on any subclass that does not follow the
    RFC-01 convention; a mis-shaped tablename will simply produce a
    namespace nobody reads (the writer stays honest -- it never invents
    a module id) and the row will be visible only to a query that opts
    into that exact literal namespace.
    """
    suffix = "_investigations"
    if tablename.endswith(suffix):
        return tablename[: -len(suffix)]
    return tablename


def _iter_investigation_models() -> Iterable[type[InvestigationRecordBase]]:
    """Yield every concrete subclass with a ``__tablename__``.

    Mirrors :func:`aila.platform.services.investigation_cost.accrue_investigation_cost`
    -- the platform-general pattern for a job that must dispatch across
    every module's investigation table without importing the modules.
    """
    for model in InvestigationRecordBase.__subclasses__():
        if getattr(model, "__tablename__", None):
            yield model


def _target_model_for(tablename: str) -> type[TargetRecordBase] | None:
    """Look up a :class:`TargetRecordBase` subclass by ``__tablename__``.

    Returns ``None`` when no module has registered a target class with
    that name (a module removed since the row was written, or a
    scaffold under construction). The caller treats the miss as an
    unresolvable workspace and skips the investigation rather than
    guessing.
    """
    for model in TargetRecordBase.__subclasses__():
        if getattr(model, "__tablename__", None) == tablename:
            return model
    return None


async def _scan_candidates(
    session: Any,
    *,
    inactivity_hours: float,
    max_investigations: int,
) -> list[_Candidate]:
    """Return recent-terminal investigations across every module table.

    An eligible row is one whose ``status`` reached a terminal value and
    whose ``updated_at`` is at least ``inactivity_hours`` old (so a
    still-settling investigation is not distilled prematurely). Results
    are ordered newest-first and capped globally at ``max_investigations``
    so a large backlog is drained across successive sweeps without any
    single tick unbounded.
    """
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=max(0.0, float(inactivity_hours)))
    candidates: list[tuple[datetime, _Candidate]] = []
    for model in _iter_investigation_models():
        tablename = str(getattr(model, "__tablename__"))
        target_tablename = str(getattr(model, "__target_tablename__", "")) or ""
        module_id = _module_id_from_tablename(tablename)
        stmt = (
            sa_select(model.id, model.target_id, model.team_id, model.updated_at)
            .where(model.status.in_(list(_TERMINAL_STATUSES)))
            .where(model.updated_at <= cutoff)
            .order_by(model.updated_at.desc())
            .limit(max_investigations)
        )
        rows = (await session.exec(stmt)).all()
        for row in rows:
            inv_id, target_id, team_id, updated_at = (
                row[0], row[1], row[2], row[3],
            )
            candidates.append((
                updated_at,
                _Candidate(
                    investigation_id=str(inv_id),
                    module_id=module_id,
                    target_id=str(target_id),
                    team_id=str(team_id) if team_id is not None else None,
                    target_tablename=target_tablename,
                ),
            ))
    candidates.sort(key=lambda pair: pair[0] or now, reverse=True)
    return [cand for _stamp, cand in candidates[:max_investigations]]


async def _resolve_workspace_id(
    session: Any, candidate: _Candidate,
) -> str | None:
    """Return the target's ``workspace_id`` or ``None``.

    Skips silently when the module's target table is not registered
    (a module removed since the row was written) or when the row does
    not carry a ``workspace_id`` column (e.g. forensics uses
    ``project_id`` at the workspace layer; see the forensics scope
    helper for how that module wires its own retrieval and why the
    semantic tier lands under a workspace-keyed namespace only).
    """
    target_model = _target_model_for(candidate["target_tablename"])
    if target_model is None:
        return None
    workspace_attr = getattr(target_model, "workspace_id", None)
    if workspace_attr is None:
        return None
    stmt = sa_select(workspace_attr).where(
        target_model.id == candidate["target_id"],
    )
    row = (await session.exec(stmt)).first()
    if row is None:
        return None
    # SQLModel ``session.exec`` on a single-column select returns a Row
    # (an ORM-agnostic tuple-like) on some driver combinations and a
    # bare scalar on others; unwrap both consistently. A single-column
    # Row supports indexing via ``[0]`` even when it does not satisfy
    # ``isinstance(..., tuple)``.
    if hasattr(row, "__len__") and hasattr(row, "__getitem__") and not isinstance(row, (str, bytes)):
        try:
            workspace_id = row[0]
        except (IndexError, TypeError, KeyError):
            workspace_id = row
    else:
        workspace_id = row
    if not workspace_id:
        return None
    return str(workspace_id)


def _semantic_namespace(module_id: str, workspace_id: str) -> str:
    return f"{module_id}.{SEMANTIC_NAMESPACE_KIND}.workspace.{workspace_id}"


async def _has_prior_consolidation(
    session: Any, namespace: str, investigation_id: str,
) -> bool:
    """True when this investigation already has any consolidator entry.

    A prefix match on the dedup key is the cheapest existence check: an
    index-friendly ``LIKE 'consolidator:<inv_id>:%'`` filter that
    short-circuits before the LLM call, so a repeat sweep is a single
    SELECT and never re-charges the model for an already-consolidated
    investigation.
    """
    prefix = f"{DEDUP_KEY_PREFIX}:{investigation_id}:"
    stmt = (
        sa_select(KnowledgeEntryRecord.id)
        .where(KnowledgeEntryRecord.namespace == namespace)
        .where(KnowledgeEntryRecord.dedup_key.like(f"{prefix}%"))
        .limit(1)
    )
    row = (await session.exec(stmt)).first()
    return row is not None


def _render_traces(entries: list[dict[str, Any]], *, char_budget: int) -> str:
    """Fold ledger entries into a token-bounded prompt block.

    Each line is a ``[<kind>@<branch>] <payload preview>`` render of one
    entry; the preview is a JSON dump truncated to a per-line budget so
    a single verbose payload cannot dominate the prompt. The whole block
    is truncated to the caller's character budget so the distillation
    prompt stays within the cheap model's practical context window.
    """
    if char_budget <= 0:
        return ""
    lines: list[str] = []
    per_line_cap = max(120, char_budget // max(1, len(entries)))
    for entry in entries:
        kind = str(entry.get("kind") or "note")
        branch = str(entry.get("author_branch_id") or "?")[:32]
        payload = entry.get("payload") or {}
        try:
            payload_txt = json.dumps(payload, sort_keys=True)
        except (TypeError, ValueError):
            payload_txt = str(payload)
        if len(payload_txt) > per_line_cap:
            payload_txt = payload_txt[: per_line_cap - 3] + "..."
        lines.append(f"[{kind}@{branch}] {payload_txt}")
    rendered = "\n".join(lines)
    if len(rendered) > char_budget:
        rendered = rendered[: char_budget - 3] + "..."
    return rendered


def _distillation_messages(
    *, module_id: str, investigation_id: str, traces: str, facts_cap: int,
) -> list[dict[str, str]]:
    """Build the two-message prompt fed to the cheap distillation model."""
    system = (
        "You are a security-research memory distiller. You will receive raw "
        "ledger traces from a completed investigation and MUST extract "
        "de-contextualized, reusable factual statements that would help a "
        "future investigation on a different target. Each fact MUST be one "
        "or two sentences, MUST NOT name the specific investigation id or "
        "branch id, and MUST state a generalizable observation, hypothesis "
        "outcome, or tool-behavior insight. Return between 1 and "
        f"{max(1, int(facts_cap))} facts. If the traces contain nothing "
        "worth reusing, return an empty list."
    )
    user = (
        f"module={module_id}\ninvestigation_id={investigation_id}\n"
        f"traces:\n{traces}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _parse_facts(raw: str, cap: int) -> list[str]:
    """Extract the ``facts`` array from the LLM response.

    Tolerates both a bare JSON object (the strict json_schema path) and
    a fenced or padded response (the json_object fallback path). Returns
    at most ``cap`` non-empty, whitespace-collapsed strings; anything
    unparseable is logged and produces an empty list so the caller
    records the investigation as skipped and moves on. Refusing to
    tolerate a bad-JSON response would let one flaky model reply abort
    the whole batch, which is exactly the failure mode this sweep is
    documented to avoid.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        _log.warning(
            "semantic_consolidator._parse_facts: unparseable model "
            "response (%s); preview=%r",
            type(exc).__name__, raw[:120],
        )
        return []
    if not isinstance(parsed, dict):
        _log.warning(
            "semantic_consolidator._parse_facts: response is not an "
            "object (type=%s); dropping",
            type(parsed).__name__,
        )
        return []
    facts_raw = parsed.get("facts")
    if not isinstance(facts_raw, list):
        _log.warning(
            "semantic_consolidator._parse_facts: response missing "
            "'facts' list; keys=%s",
            sorted(parsed.keys())[:10],
        )
        return []
    out: list[str] = []
    for item in facts_raw:
        if not isinstance(item, str):
            continue
        cleaned = " ".join(item.split()).strip()
        if not cleaned:
            continue
        out.append(cleaned[:400])
        if len(out) >= cap:
            break
    return out


async def _distill_facts(
    llm_client: Any,
    *,
    task_type: str,
    messages: list[dict[str, str]],
    investigation_id: str,
    team_id: str | None,
) -> list[str]:
    """Call the LLM with the strict facts schema and return the parsed list.

    RFC-09: every LLM call is stamped with a stable
    ``prompt_content_hash`` + ``prompt_version`` so its cost + seal rows
    join back to the exact prompt template that produced them. The
    prompt is constructed here (fixed system + rendered traces) so the
    hash covers the concatenated messages and the version is a fixed
    literal for this action. ``investigation_id`` doubles as ``run_id``
    so the LLM cost record links to the source investigation the same
    way ``accrue_investigation_cost`` already does for reasoning turns.
    """
    prompt_hash = hashlib.sha256(
        json.dumps(messages, sort_keys=True).encode("utf-8"),
    ).hexdigest()
    with correlation_scope(
        investigation_id=investigation_id,
        prompt_content_hash=prompt_hash,
        prompt_version=_PROMPT_VERSION,
    ):
        response = await llm_client.chat_json(
            task_type,
            messages,
            _FACTS_SCHEMA,
            run_id=investigation_id,
            team_id=team_id,
        )
    return _parse_facts(getattr(response, "content", "") or "", cap=20)


async def _write_facts(
    knowledge: KnowledgeService,
    *,
    namespace: str,
    facts: list[str],
    investigation_id: str,
    module_id: str,
    team_id: str | None,
) -> int:
    """Store each fact under a stable dedup key. Returns the write count.

    Uses :meth:`KnowledgeService.store` in the non-chunked, non-enrich
    path so every fact takes exactly one embedding call and one INSERT
    or UPDATE (dedup-keyed upsert). The metadata carries provenance so
    an operator can trace a retrieved fact back to the investigation
    that produced it.
    """
    written = 0
    for index, fact in enumerate(facts):
        try:
            await knowledge.store(
                namespace=namespace,
                content=fact,
                metadata={
                    "source": "semantic_consolidator",
                    "module_id": module_id,
                    "investigation_id": investigation_id,
                    "team_id": team_id,
                    "fact_index": index,
                },
                dedup_key=f"{DEDUP_KEY_PREFIX}:{investigation_id}:{index}",
                team_id=team_id,
            )
            written += 1
        except _STEP_ERRORS as exc:
            _log.warning(
                "semantic_consolidator.write_facts inv=%s idx=%d failed: %s",
                investigation_id, index, exc,
                exc_info=exc,
            )
    return written


async def consolidate_recent_investigations(
    *,
    llm_client: Any | None = None,
    knowledge_service: KnowledgeService | None = None,
    ledger_service: LedgerService | None = None,
    inactivity_hours: float = 24.0,
    max_investigations: int = 25,
    facts_per_investigation: int = 5,
    max_trace_chars: int = 6000,
    max_ledger_entries: int = 200,
    task_type: str = DEFAULT_TASK_TYPE,
) -> ConsolidationReport:
    """Distill recent resolved investigations into semantic facts.

    The main entrypoint used both by the automation registry callable
    (:func:`run_semantic_consolidation_sweep`) and by tests. Every
    dependency is injectable so a caller can pass a stub LLM client
    without touching the platform LLM stack.

    Behavior-preserving guarantees:

    * When there is nothing to consolidate the function returns an empty
      report and issues zero writes and zero model calls.
    * A per-investigation processing error is logged with ``exc_info``,
      counted under ``errors``, and never aborts the batch.
    * A repeat sweep for an already-consolidated investigation is a
      single indexed SELECT and never re-charges the model.
    """
    report = _empty_report()

    # Optional dependencies: instantiate lazily so a bare guarded run
    # against an empty DB never pays the LLM client bootstrap.
    ledger = ledger_service or LedgerService()
    knowledge = knowledge_service or KnowledgeService()

    async with async_session_scope() as session:
        try:
            candidates = await _scan_candidates(
                session,
                inactivity_hours=inactivity_hours,
                max_investigations=max_investigations,
            )
        except _STEP_ERRORS as exc:
            _log.warning(
                "semantic_consolidator.scan failed; sweep is a no-op: %s",
                exc, exc_info=exc,
            )
            return report
        report["scanned"] = len(candidates)
        if not candidates:
            return report

        for candidate in candidates:
            try:
                workspace_id = await _resolve_workspace_id(session, candidate)
            except _STEP_ERRORS as exc:
                _log.warning(
                    "semantic_consolidator.resolve_workspace inv=%s failed: %s",
                    candidate["investigation_id"], exc, exc_info=exc,
                )
                report["errors"] += 1
                continue
            if not workspace_id:
                report["skipped_no_workspace"] += 1
                continue
            namespace = _semantic_namespace(
                candidate["module_id"], workspace_id,
            )
            try:
                if await _has_prior_consolidation(
                    session, namespace, candidate["investigation_id"],
                ):
                    report["skipped_already"] += 1
                    continue
            except _STEP_ERRORS as exc:
                _log.warning(
                    "semantic_consolidator.prior_check inv=%s failed: %s",
                    candidate["investigation_id"], exc, exc_info=exc,
                )
                report["errors"] += 1
                continue

            try:
                entries = await ledger.read_general(
                    candidate["investigation_id"],
                    kinds=list(_EPISODIC_KINDS),
                    limit=max_ledger_entries,
                    session=session,
                )
            except _STEP_ERRORS as exc:
                _log.warning(
                    "semantic_consolidator.read_ledger inv=%s failed: %s",
                    candidate["investigation_id"], exc, exc_info=exc,
                )
                report["errors"] += 1
                continue
            if not entries:
                report["skipped_no_traces"] += 1
                continue

            traces = _render_traces(entries, char_budget=max_trace_chars)
            if not traces:
                report["skipped_no_traces"] += 1
                continue

            if llm_client is None:
                # Lazy construction: an empty sweep or an all-already-done
                # sweep never reaches this branch, so an install without
                # LLM secrets configured pays no bootstrap cost until the
                # first actual distillation.
                llm_client = ServiceFactory().llm_client

            messages = _distillation_messages(
                module_id=candidate["module_id"],
                investigation_id=candidate["investigation_id"],
                traces=traces,
                facts_cap=facts_per_investigation,
            )
            try:
                facts = await _distill_facts(
                    llm_client,
                    task_type=task_type,
                    messages=messages,
                    investigation_id=candidate["investigation_id"],
                    team_id=candidate["team_id"],
                )
            except _STEP_ERRORS as exc:
                _log.warning(
                    "semantic_consolidator.distill inv=%s failed: %s",
                    candidate["investigation_id"], exc, exc_info=exc,
                )
                report["errors"] += 1
                continue
            if not facts:
                report["skipped_no_traces"] += 1
                continue
            facts = facts[: max(1, int(facts_per_investigation))]

            try:
                written = await _write_facts(
                    knowledge,
                    namespace=namespace,
                    facts=facts,
                    investigation_id=candidate["investigation_id"],
                    module_id=candidate["module_id"],
                    team_id=candidate["team_id"],
                )
            except _STEP_ERRORS as exc:
                _log.warning(
                    "semantic_consolidator.write inv=%s failed: %s",
                    candidate["investigation_id"], exc, exc_info=exc,
                )
                report["errors"] += 1
                continue

            if written > 0:
                report["consolidated"] += 1
                report["facts_written"] += written

    _log.info(
        "semantic_consolidator swept scanned=%d consolidated=%d "
        "skipped_already=%d skipped_no_workspace=%d "
        "skipped_no_traces=%d facts=%d errors=%d",
        report["scanned"], report["consolidated"],
        report["skipped_already"], report["skipped_no_workspace"],
        report["skipped_no_traces"], report["facts_written"],
        report["errors"],
    )
    return report


async def run_semantic_consolidation_sweep(**kwargs: object) -> dict[str, Any]:
    """Automation entrypoint (``platform.semantic_consolidation_sweep``).

    Registered in
    :func:`aila.platform.automation.maintenance.register_maintenance_actions`
    and seeded with a default cron by
    :func:`aila.platform.automation.seed_schedules.seed_default_automation_schedules`
    so an operator-free install still runs the sweep on a nightly
    cadence. Returns a plain dict so the automation runner can serialise
    it as ``last_run_result`` without a TypedDict friction point.

    Accepts and ignores arbitrary ``**kwargs`` so an operator can attach
    action-kwargs on the AutomationSchedule row without breaking the
    call signature; every knob is a keyword arg on
    :func:`consolidate_recent_investigations` and is applied here only
    when it appears in ``kwargs`` (the presence check lets an operator
    override ``inactivity_hours`` or ``max_investigations`` per schedule
    without forcing every knob into the row).
    """
    passthrough_keys = (
        "inactivity_hours",
        "max_investigations",
        "facts_per_investigation",
        "max_trace_chars",
        "max_ledger_entries",
        "task_type",
    )
    call_kwargs: dict[str, Any] = {}
    for key in passthrough_keys:
        if key in kwargs and kwargs[key] is not None:
            call_kwargs[key] = kwargs[key]
    report = await consolidate_recent_investigations(**call_kwargs)
    return dict(report)

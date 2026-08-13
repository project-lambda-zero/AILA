"""Procedural (skill-library) memory tier -- issue #150 second half.

Purpose
-------
The semantic tier (:mod:`.consolidator`) distills every resolved
investigation's ledger traces into de-contextualized factual statements.
This module builds the complementary skill tier: a resolved investigation
whose primary outcome is a confirmed finding contributes ONE reusable
``(problem_shape -> approach)`` pair so a later investigation that
matches the same problem shape can retrieve the winning approach and
compound on it (Voyager-style skill accumulation).

* ``problem_shape`` is a de-contextualized descriptor -- module id +
  target kind + outcome kind + strategy family -- and is the string we
  embed. Two investigations that share these four handles retrieve one
  another's skills at setup time regardless of workspace or team.
* ``approach`` is the winning strategy summary. When the outcome
  payload already carries a structured strategy blurb (malware ships
  ``summary`` on every payload; VR ships ``description`` /
  ``strategy_summary`` on the strategy-shaped kinds), the structured
  field is used verbatim so no LLM call is charged. When no structured
  strategy is present the sweep falls back to the same cheap distill
  route the semantic tier uses.

Team scope
----------
Skills live in a **team-scoped** namespace (``skill.team.<team_id>``
when the investigation carries a team, otherwise ``skill.global`` for
single-tenant installs). This bucket is intentionally *not*
workspace-scoped so a team's skill library compounds across every
investigation the team runs. Each module's scope helper appends the
matching team-scope namespace to its retrieval list, so both the
setup-time retriever (RFC-12 RETRIEVED tier) and the agentic knowledge
bridge already read from the same bucket the writer stores into -- the
namespace is not a dead path.

Success-stat scoping (honesty)
------------------------------
The only success signal recorded on each skill row is:
``outcome_kind`` + ``confidence`` (the polarity + strength of the
source outcome) + ``resolved_at`` (the source investigation's
``updated_at`` at extraction time). We do **not** build a use-tracking
feedback loop -- that would require the agent to report skill reuse
back into the ledger, which is out of scope for this slice. Operators
who need reuse counting can layer it on top of the journal_context
already emitted by :meth:`KnowledgeService.retrieve_routed`.

Storage reuse
-------------
No new table and no Alembic migration: skills live in
:class:`KnowledgeEntryRecord` under the ``skill.*`` namespace and are
retrieved by the adaptive :meth:`KnowledgeService.retrieve_routed`
simple path with the same gate + provenance stamping that already
applies to every knowledge hit.

Idempotency
-----------
Each skill row carries a stable ``skill:<investigation_id>`` dedup key.
A repeat sweep for an already-extracted investigation is a cheap
prefix-matched SELECT that short-circuits before the LLM call, so no
row is ever double-written and no model is re-charged.

Failure posture
---------------
Best-effort: a fault on any single outcome is logged with ``exc_info``
and skipped (never aborts the batch), and the whole sweep degrades to
a guarded no-op when there is nothing new to extract.
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

from aila.platform.contracts.enums import InvestigationStatus, OutcomeConfidence
from aila.platform.contracts.investigation_base import InvestigationRecordBase
from aila.platform.contracts.outcome_base import OutcomeRecordBase
from aila.platform.contracts.target_base import TargetRecordBase
from aila.platform.llm.correlation import correlation_scope
from aila.platform.services.factory import ServiceFactory
from aila.platform.services.knowledge import KnowledgeService
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

__all__ = [
    "SKILL_DEDUP_PREFIX",
    "SKILL_GLOBAL_NAMESPACE",
    "SKILL_NAMESPACE_KIND",
    "SkillLibraryError",
    "SkillLibraryReport",
    "extract_recent_skills",
    "run_skill_library_sweep",
    "skill_namespace",
]

_log = logging.getLogger(__name__)


# The namespace kind segment. Both module scope helpers
# (``modules/vr/services/knowledge_scope.py``,
# ``modules/malware/services/knowledge_scope.py``) advertise the exact
# ``skill.team.<team>`` / ``skill.global`` string returned by
# :func:`skill_namespace` so the writer and the two live readers can
# never drift on the bucket name.
SKILL_NAMESPACE_KIND: str = "skill"

# Fallback namespace for investigations with no team (single-tenant
# installs). The scope helpers append it unconditionally so a
# single-tenant setup still surfaces skills at retrieval time.
SKILL_GLOBAL_NAMESPACE: str = f"{SKILL_NAMESPACE_KIND}.global"

# Dedup key prefix. Exactly one skill row per investigation, so the
# per-investigation existence check that guards the LLM call is a
# tight equality lookup rather than a prefix scan.
SKILL_DEDUP_PREFIX: str = "skill"

# LLM routing key. Same knob the semantic tier uses so an operator that
# pins a cheap distillation model via ``llm_model_consolidation`` gets
# it for both tiers without pinning twice. Unconfigured install falls
# through to ``llm_default_model``.
DEFAULT_TASK_TYPE: str = "consolidation"

# Prompt version literal stamped on every LLM call this sweep issues
# (RFC-09). Bump when :func:`_approach_messages` changes so the cost
# ledger and seal records name the exact prompt shape.
_PROMPT_VERSION: str = "skill_library@1"

# Terminal statuses an investigation must have reached before its
# confirmed outcome is worth extracting. STALLED is excluded on
# purpose: the skill tier records winning approaches, and a STALLED
# investigation by definition did not conclude.
_TERMINAL_STATUSES: frozenset[str] = frozenset({
    InvestigationStatus.COMPLETED.value,
})

# The confidence tiers we treat as "confirmed" for skill extraction.
# CAVEATED / UNKNOWN outcomes do not merit compounding as a reusable
# approach -- they carry too much uncertainty. MEDIUM is included so
# the sweep is not starved on early-tenure teams whose panels rarely
# escalate to STRONG.
_POSITIVE_CONFIDENCES: frozenset[str] = frozenset({
    OutcomeConfidence.EXACT.value,
    OutcomeConfidence.STRONG.value,
    OutcomeConfidence.MEDIUM.value,
})

# Outcome kinds that describe a stalled / negative / summary-only
# terminal and therefore do NOT represent a winning approach. The set
# is deliberately conservative: we drop kinds every module explicitly
# uses as a failure / non-actionable terminal. Any other kind that
# reaches state=dispatched with a positive confidence is treated as a
# candidate winning approach and extracted.
_NEGATIVE_OUTCOME_KINDS: frozenset[str] = frozenset({
    "stalled_report",
    "no_finding",
    "no_primary_outcome",
})

# Structured-strategy field names to try, in order. First non-empty
# string wins and skips the LLM call. Covers the malware
# ``MalwareOutcomePayload.summary`` base field, VR strategy-shaped
# payloads that carry ``description`` (STRATEGY_DESCRIPTOR /
# PROFILE_SPEC_DRAFT / CONFIG_DELTA), and the malware ANALYSIS_REPORT
# ``report_body``.
_STRUCTURED_APPROACH_KEYS: tuple[str, ...] = (
    "strategy_summary",
    "description",
    "summary",
    "report_body",
)

# Isolation tuple used at every reachable failure point below. Bare
# ``except Exception`` is banned by the honesty audit, and a per-
# outcome fault must never abort the sweep -- so the enumerated leak
# set is caught, logged, and the loop continues.
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


class SkillLibraryError(RuntimeError):
    """Raised for domain-level skill-library faults the caller cares about.

    Never raised for per-outcome processing errors (those are caught
    and logged so the sweep continues); reserved for setup faults the
    caller has to see.
    """


class SkillLibraryReport(TypedDict):
    """One-sweep summary the automation runner records as last_run_result."""

    scanned: int
    skills_written: int
    skipped_already: int
    skipped_no_target: int
    skipped_no_approach: int
    errors: int


class _SkillCandidate(TypedDict):
    """One eligible confirmed-outcome row picked up by the scan."""

    outcome_id: str
    outcome_kind: str
    payload_json: str
    confidence: str
    outcome_created_at: datetime | None
    investigation_id: str
    module_id: str
    target_id: str
    target_tablename: str
    team_id: str | None
    strategy_family: str | None
    resolved_at: datetime | None


# JSON Schema for the approach distillation response. Single string
# field so strict-schema providers accept it without falling back to
# json_object mode.
_APPROACH_SCHEMA: dict[str, Any] = {
    "title": "SkillApproach",
    "type": "object",
    "additionalProperties": False,
    "required": ["approach"],
    "properties": {
        "approach": {"type": "string", "minLength": 1, "maxLength": 400},
    },
}


def _empty_report() -> SkillLibraryReport:
    return SkillLibraryReport(
        scanned=0,
        skills_written=0,
        skipped_already=0,
        skipped_no_target=0,
        skipped_no_approach=0,
        errors=0,
    )


def skill_namespace(team_id: str | None) -> str:
    """Return the skill bucket for ``team_id`` (or the global fallback).

    Both module scope helpers hard-code the same expressions so a
    change here MUST be mirrored on
    ``modules/vr/services/knowledge_scope.py`` and
    ``modules/malware/services/knowledge_scope.py``.
    """
    if team_id:
        return f"{SKILL_NAMESPACE_KIND}.team.{team_id}"
    return SKILL_GLOBAL_NAMESPACE


def _module_id_from_tablename(tablename: str) -> str:
    """Strip the ``_investigations`` suffix so ``vr_investigations`` -> ``vr``.

    Returns the raw tablename on any subclass that does not follow the
    RFC-01 convention; a mis-shaped tablename simply produces a
    provenance label nobody reads (the writer stays honest -- it never
    invents a module id).
    """
    suffix = "_investigations"
    if tablename.endswith(suffix):
        return tablename[: -len(suffix)]
    return tablename


def _iter_investigation_models() -> Iterable[type[InvestigationRecordBase]]:
    """Yield every concrete investigation subclass with a ``__tablename__``."""
    for model in InvestigationRecordBase.__subclasses__():
        if getattr(model, "__tablename__", None):
            yield model


def _iter_outcome_models() -> Iterable[type[OutcomeRecordBase]]:
    """Yield every concrete outcome subclass with a ``__tablename__``."""
    for model in OutcomeRecordBase.__subclasses__():
        if getattr(model, "__tablename__", None):
            yield model


def _target_model_for(tablename: str) -> type[TargetRecordBase] | None:
    """Look up a :class:`TargetRecordBase` subclass by ``__tablename__``."""
    for model in TargetRecordBase.__subclasses__():
        if getattr(model, "__tablename__", None) == tablename:
            return model
    return None


def _investigation_model_for(
    tablename: str,
) -> type[InvestigationRecordBase] | None:
    """Look up a :class:`InvestigationRecordBase` subclass by ``__tablename__``."""
    for model in _iter_investigation_models():
        if getattr(model, "__tablename__", None) == tablename:
            return model
    return None


async def _scan_candidates(
    session: Any,
    *,
    inactivity_hours: float,
    max_investigations: int,
) -> list[_SkillCandidate]:
    """Return recently-resolved investigations with a confirmed outcome.

    For each module's ``OutcomeRecordBase`` subclass we join to the
    matching investigation table and filter for:

    * investigation ``status`` in :data:`_TERMINAL_STATUSES`
    * investigation ``updated_at`` older than ``inactivity_hours``
    * outcome ``state`` == ``"dispatched"`` (approved + shipped)
    * outcome ``confidence`` in :data:`_POSITIVE_CONFIDENCES`
    * outcome ``outcome_kind`` not in :data:`_NEGATIVE_OUTCOME_KINDS`

    Results are globally sorted newest-first and capped at
    ``max_investigations`` distinct investigations so a large backlog
    is drained across successive sweeps without any single tick
    unbounded. When one investigation has multiple qualifying outcomes
    the earliest by ``created_at`` wins so re-runs stay deterministic.
    """
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=max(0.0, float(inactivity_hours)))
    module_cap = max(1, int(max_investigations))
    rows_by_inv: dict[str, tuple[datetime, _SkillCandidate]] = {}

    for outcome_model in _iter_outcome_models():
        inv_tablename = str(getattr(outcome_model, "__investigation_tablename__", "")) or ""
        if not inv_tablename:
            continue
        inv_model = _investigation_model_for(inv_tablename)
        if inv_model is None:
            continue
        module_id = _module_id_from_tablename(inv_tablename)
        target_tablename = str(getattr(inv_model, "__target_tablename__", "")) or ""

        stmt = (
            sa_select(
                outcome_model.id,
                outcome_model.outcome_kind,
                outcome_model.payload_json,
                outcome_model.confidence,
                outcome_model.created_at,
                inv_model.id,
                inv_model.target_id,
                inv_model.team_id,
                inv_model.strategy_family,
                inv_model.updated_at,
            )
            .join(inv_model, inv_model.id == outcome_model.investigation_id)
            .where(inv_model.status.in_(list(_TERMINAL_STATUSES)))
            .where(inv_model.updated_at <= cutoff)
            .where(outcome_model.state == "dispatched")
            .where(outcome_model.confidence.in_(list(_POSITIVE_CONFIDENCES)))
            .where(outcome_model.outcome_kind.notin_(list(_NEGATIVE_OUTCOME_KINDS)))
            .order_by(outcome_model.created_at.asc())
            .limit(module_cap * 4)
        )
        rows = (await session.exec(stmt)).all()
        for row in rows:
            outcome_id = str(row[0])
            outcome_kind = str(row[1])
            payload_json = str(row[2] or "{}")
            confidence = str(row[3])
            outcome_created_at = row[4]
            inv_id = str(row[5])
            target_id = str(row[6])
            team_id = str(row[7]) if row[7] is not None else None
            strategy_family = str(row[8]) if row[8] is not None else None
            inv_updated_at = row[9]

            if inv_id in rows_by_inv:
                # Earliest confirmed outcome per investigation wins;
                # ORDER BY created_at ASC on the SELECT keeps this a
                # single-pass first-seen preserve.
                continue
            rows_by_inv[inv_id] = (
                inv_updated_at or now,
                _SkillCandidate(
                    outcome_id=outcome_id,
                    outcome_kind=outcome_kind,
                    payload_json=payload_json,
                    confidence=confidence,
                    outcome_created_at=outcome_created_at,
                    investigation_id=inv_id,
                    module_id=module_id,
                    target_id=target_id,
                    target_tablename=target_tablename,
                    team_id=team_id,
                    strategy_family=strategy_family,
                    resolved_at=inv_updated_at,
                ),
            )

    ordered = sorted(rows_by_inv.values(), key=lambda pair: pair[0], reverse=True)
    return [cand for _stamp, cand in ordered[:module_cap]]


async def _resolve_target_kind(
    session: Any, candidate: _SkillCandidate,
) -> str | None:
    """Return the target row's ``kind`` field or ``None``.

    Skipping a candidate whose target row cannot be resolved keeps the
    problem_shape honest: without ``target.kind`` we cannot construct
    the shape's discriminator, so the skill would collapse to a
    module-only descriptor that retrieval on a similar problem shape
    would not surface reliably.
    """
    target_model = _target_model_for(candidate["target_tablename"])
    if target_model is None:
        return None
    kind_attr = getattr(target_model, "kind", None)
    if kind_attr is None:
        return None
    stmt = sa_select(kind_attr).where(
        target_model.id == candidate["target_id"],
    )
    row = (await session.exec(stmt)).first()
    if row is None:
        return None
    # Single-column select unwrap mirrors the consolidator's
    # ``_resolve_workspace_id`` helper.
    if (
        hasattr(row, "__len__")
        and hasattr(row, "__getitem__")
        and not isinstance(row, (str, bytes))
    ):
        try:
            value = row[0]
        except (IndexError, TypeError, KeyError):
            value = row
    else:
        value = row
    if not value:
        return None
    return str(value)


async def _has_prior_skill(
    session: Any, namespace: str, investigation_id: str,
) -> bool:
    """True when a skill row already exists for this investigation.

    Exactly one skill per investigation (dedup key is
    ``skill:<inv_id>``), so this is a tight equality lookup that
    short-circuits before the LLM call. Matches the consolidator's
    ``_has_prior_consolidation`` posture.
    """
    dedup_key = f"{SKILL_DEDUP_PREFIX}:{investigation_id}"
    stmt = (
        sa_select(KnowledgeEntryRecord.id)
        .where(KnowledgeEntryRecord.namespace == namespace)
        .where(KnowledgeEntryRecord.dedup_key == dedup_key)
        .limit(1)
    )
    row = (await session.exec(stmt)).first()
    return row is not None


def _problem_shape(
    *,
    module_id: str,
    target_kind: str,
    outcome_kind: str,
    strategy_family: str | None,
) -> str:
    """Assemble the de-contextualized ``problem_shape`` we embed.

    The four handles are intentionally short + human-readable so the
    embedded vector clusters shapes that share module + target family +
    outcome kind + strategy family. The prose format keeps the
    embedding meaningful under BGE-M3 sentence pooling; a raw JSON blob
    would embed the field names as noise.
    """
    strategy = strategy_family or "generic"
    return (
        f"{module_id} target_kind={target_kind} "
        f"outcome_kind={outcome_kind} strategy_family={strategy}"
    )


def _load_payload(payload_json: str) -> dict[str, Any]:
    """Decode the outcome ``payload_json`` column into a dict.

    Returns an empty dict when the column is malformed or non-object.
    A parse failure is logged so an operator can trace persistent bad
    payload columns; refusing to tolerate one bad row would let a
    single upstream write bug abort the whole sweep, which is exactly
    the failure mode this module is documented to avoid.
    """
    try:
        parsed = json.loads(payload_json)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _log.warning(
            "skill_library._load_payload: unparseable payload_json "
            "(%s); preview=%r",
            type(exc).__name__, payload_json[:120],
        )
        return {}
    if not isinstance(parsed, dict):
        _log.warning(
            "skill_library._load_payload: payload_json not an object "
            "(type=%s); dropping",
            type(parsed).__name__,
        )
        return {}
    return parsed


def _extract_structured_approach(payload: dict[str, Any]) -> str | None:
    """Return the first non-empty string among :data:`_STRUCTURED_APPROACH_KEYS`.

    Prefers structured strategy fields on the outcome payload so the
    sweep skips the LLM call for kinds that already carry a written
    strategy blurb (malware ships ``summary`` on every payload, VR ships
    ``description`` on strategy-shaped kinds).
    """
    for key in _STRUCTURED_APPROACH_KEYS:
        value = payload.get(key)
        if not isinstance(value, str):
            continue
        cleaned = " ".join(value.split()).strip()
        if cleaned:
            return cleaned[:400]
    return None


def _render_payload_excerpt(payload: dict[str, Any], *, char_budget: int) -> str:
    """Render the outcome payload into a bounded prompt excerpt.

    Used only when no structured strategy is available and we need to
    fall back to LLM distillation. Serialises the payload dict with
    sorted keys so the prompt hash is stable across repeat runs.
    """
    if char_budget <= 0:
        return ""
    try:
        rendered = json.dumps(payload, sort_keys=True)
    except (TypeError, ValueError):
        rendered = str(payload)
    if len(rendered) > char_budget:
        rendered = rendered[: char_budget - 3] + "..."
    return rendered


def _approach_messages(
    *,
    module_id: str,
    target_kind: str,
    outcome_kind: str,
    strategy_family: str | None,
    payload_excerpt: str,
) -> list[dict[str, str]]:
    """Build the two-message prompt for the approach distillation."""
    system = (
        "You are a security-research skill distiller. You will receive one "
        "resolved investigation's confirmed outcome payload and MUST return "
        "the WINNING APPROACH as a one- or two-sentence, de-contextualized "
        "strategy statement. Do NOT name the specific investigation, target, "
        "branch, or file paths. State the reusable tactic that a future "
        "investigation facing the same problem shape should try first. If "
        "the payload contains nothing worth reusing, return an empty string."
    )
    user = (
        f"module={module_id}\ntarget_kind={target_kind}\n"
        f"outcome_kind={outcome_kind}\n"
        f"strategy_family={strategy_family or 'generic'}\n"
        f"payload:\n{payload_excerpt}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _parse_approach(raw: str) -> str:
    """Extract the ``approach`` string from an LLM response.

    Tolerates both a bare JSON object (strict json_schema path) and a
    padded response (json_object fallback). Returns an empty string on
    any parse failure so the caller records the outcome as skipped and
    moves on -- refusing a bad reply would let one flaky model call
    abort the whole batch.
    """
    if not raw:
        return ""
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        _log.warning(
            "skill_library._parse_approach: unparseable model response "
            "(%s); preview=%r",
            type(exc).__name__, raw[:120],
        )
        return ""
    if not isinstance(parsed, dict):
        _log.warning(
            "skill_library._parse_approach: response is not an object "
            "(type=%s); dropping",
            type(parsed).__name__,
        )
        return ""
    value = parsed.get("approach")
    if not isinstance(value, str):
        _log.warning(
            "skill_library._parse_approach: response missing 'approach' "
            "string; keys=%s",
            sorted(parsed.keys())[:10],
        )
        return ""
    return " ".join(value.split()).strip()[:400]


async def _distill_approach(
    llm_client: Any,
    *,
    task_type: str,
    messages: list[dict[str, str]],
    investigation_id: str,
    team_id: str | None,
) -> str:
    """Call the LLM with the strict approach schema.

    RFC-09: every LLM call is stamped with a stable
    ``prompt_content_hash`` + ``prompt_version`` so its cost + seal rows
    join back to the exact prompt template that produced them.
    ``investigation_id`` doubles as ``run_id`` so the LLM cost record
    links to the source investigation the same way the consolidator
    already does.
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
            _APPROACH_SCHEMA,
            run_id=investigation_id,
            team_id=team_id,
        )
    return _parse_approach(getattr(response, "content", "") or "")


async def _write_skill(
    knowledge: KnowledgeService,
    *,
    namespace: str,
    problem_shape: str,
    approach: str,
    candidate: _SkillCandidate,
    target_kind: str,
) -> bool:
    """Persist one skill entry. Returns True on a successful store call.

    ``content`` is the ``problem_shape`` so retrieval scores by shape
    similarity. ``metadata`` carries the ``approach`` alongside the
    minimal provenance an operator needs to trace the row back to its
    source investigation. Uses the non-chunked, non-enriched store path
    -- exactly one embedding call and one INSERT-or-UPDATE per skill.
    """
    resolved_at = candidate.get("resolved_at")
    resolved_iso = (
        resolved_at.isoformat() if isinstance(resolved_at, datetime) else None
    )
    metadata: dict[str, Any] = {
        "source": "skill_library",
        "module_id": candidate["module_id"],
        "investigation_id": candidate["investigation_id"],
        "outcome_id": candidate["outcome_id"],
        "outcome_kind": candidate["outcome_kind"],
        "confidence": candidate["confidence"],
        "target_kind": target_kind,
        "strategy_family": candidate["strategy_family"] or "generic",
        "team_id": candidate["team_id"],
        "approach": approach,
        "resolved_at": resolved_iso,
    }
    await knowledge.store(
        namespace=namespace,
        content=problem_shape,
        metadata=metadata,
        dedup_key=f"{SKILL_DEDUP_PREFIX}:{candidate['investigation_id']}",
        team_id=candidate["team_id"],
    )
    return True


async def extract_recent_skills(
    *,
    llm_client: Any | None = None,
    knowledge_service: KnowledgeService | None = None,
    inactivity_hours: float = 24.0,
    max_investigations: int = 25,
    max_payload_chars: int = 4000,
    task_type: str = DEFAULT_TASK_TYPE,
) -> SkillLibraryReport:
    """Extract skills from recently-resolved investigations.

    The main entrypoint used both by the automation runner
    (:func:`run_skill_library_sweep`) and by tests. Every dependency is
    injectable so a caller can pass a stub LLM client without touching
    the platform LLM stack.

    Guarantees:

    * When there is nothing to extract the function returns an empty
      report and issues zero writes and zero model calls.
    * A per-outcome processing error is logged with ``exc_info``,
      counted under ``errors``, and never aborts the batch.
    * A repeat sweep for an already-extracted investigation is a
      single indexed SELECT and never re-charges the model.
    * The LLM client is only constructed lazily on the first candidate
      that lacks a structured strategy, so an install without LLM
      secrets configured pays no bootstrap cost on an empty sweep or a
      structured-only batch.
    """
    report = _empty_report()
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
                "skill_library.scan failed; sweep is a no-op: %s",
                exc, exc_info=exc,
            )
            return report
        report["scanned"] = len(candidates)
        if not candidates:
            return report

        for candidate in candidates:
            namespace = skill_namespace(candidate["team_id"])
            try:
                if await _has_prior_skill(
                    session, namespace, candidate["investigation_id"],
                ):
                    report["skipped_already"] += 1
                    continue
            except _STEP_ERRORS as exc:
                _log.warning(
                    "skill_library.prior_check inv=%s failed: %s",
                    candidate["investigation_id"], exc, exc_info=exc,
                )
                report["errors"] += 1
                continue

            try:
                target_kind = await _resolve_target_kind(session, candidate)
            except _STEP_ERRORS as exc:
                _log.warning(
                    "skill_library.resolve_target inv=%s failed: %s",
                    candidate["investigation_id"], exc, exc_info=exc,
                )
                report["errors"] += 1
                continue
            if not target_kind:
                report["skipped_no_target"] += 1
                continue

            payload = _load_payload(candidate["payload_json"])
            approach = _extract_structured_approach(payload)
            if not approach:
                if llm_client is None:
                    llm_client = ServiceFactory().llm_client
                excerpt = _render_payload_excerpt(
                    payload, char_budget=max_payload_chars,
                )
                messages = _approach_messages(
                    module_id=candidate["module_id"],
                    target_kind=target_kind,
                    outcome_kind=candidate["outcome_kind"],
                    strategy_family=candidate["strategy_family"],
                    payload_excerpt=excerpt,
                )
                try:
                    approach = await _distill_approach(
                        llm_client,
                        task_type=task_type,
                        messages=messages,
                        investigation_id=candidate["investigation_id"],
                        team_id=candidate["team_id"],
                    )
                except _STEP_ERRORS as exc:
                    _log.warning(
                        "skill_library.distill inv=%s failed: %s",
                        candidate["investigation_id"], exc, exc_info=exc,
                    )
                    report["errors"] += 1
                    continue
            if not approach:
                report["skipped_no_approach"] += 1
                continue

            problem_shape = _problem_shape(
                module_id=candidate["module_id"],
                target_kind=target_kind,
                outcome_kind=candidate["outcome_kind"],
                strategy_family=candidate["strategy_family"],
            )
            try:
                await _write_skill(
                    knowledge,
                    namespace=namespace,
                    problem_shape=problem_shape,
                    approach=approach,
                    candidate=candidate,
                    target_kind=target_kind,
                )
            except _STEP_ERRORS as exc:
                _log.warning(
                    "skill_library.write inv=%s failed: %s",
                    candidate["investigation_id"], exc, exc_info=exc,
                )
                report["errors"] += 1
                continue

            report["skills_written"] += 1

    _log.info(
        "skill_library swept scanned=%d skills=%d skipped_already=%d "
        "skipped_no_target=%d skipped_no_approach=%d errors=%d",
        report["scanned"], report["skills_written"],
        report["skipped_already"], report["skipped_no_target"],
        report["skipped_no_approach"], report["errors"],
    )
    return report


async def run_skill_library_sweep(**kwargs: object) -> dict[str, Any]:
    """Automation entrypoint (``platform.skill_library_sweep``).

    Registered in
    :func:`aila.platform.automation.maintenance.register_maintenance_actions`
    and seeded with a default cron by
    :func:`aila.platform.automation.seed_schedules.seed_default_automation_schedules`
    so an operator-free install still runs the sweep on a nightly
    cadence. Returns a plain dict so the automation runner can
    serialise it as ``last_run_result`` without a TypedDict friction
    point.

    Ships as its own action (rather than folded into
    ``platform.semantic_consolidation_sweep``) so the two tiers stay
    observably separate: an operator can pin a different cheap model,
    a different cadence, or a different max-per-tick per tier without
    dragging the other tier along. Both actions are best-effort and
    idempotent, so running them minutes apart is a bounded LLM-free
    no-op when there is nothing new. Accepts and ignores arbitrary
    ``**kwargs`` so an operator can attach action-kwargs on the
    :class:`AutomationScheduleRecord` row without breaking the call
    signature; every knob is a keyword arg on
    :func:`extract_recent_skills`.
    """
    passthrough_keys = (
        "inactivity_hours",
        "max_investigations",
        "max_payload_chars",
        "task_type",
    )
    call_kwargs: dict[str, Any] = {}
    for key in passthrough_keys:
        if key in kwargs and kwargs[key] is not None:
            call_kwargs[key] = kwargs[key]
    report = await extract_recent_skills(**call_kwargs)
    return dict(report)

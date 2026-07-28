"""Generic follow-up-discovery take-over -- platform primitive.

At the final verdict of an investigation, when the synthesised outcome
polarity is negative (``no_finding`` or ``inconclusive``) and the
deliberation panel recommended further discoveries, autonomously spawn
EXACTLY ONE child investigation that takes over those recommendations
as its own mandate. The child is self-terminating (its own synthesis
gate + finalizer chain still apply), depth-capped so a runaway "we
missed something" chain cannot recurse forever, budget-halved so the
$-envelope of the whole take-over chain converges, and idempotent so
the primitive can be re-invoked without spawning duplicates.

The primitive is generic over the caller module's ORM record models
(investigation / branch / outcome), the module's outcome-polarity
reducer, the module's recommendations extractor, and the module's task
enqueue closure. It hardcodes no module id, no record class, and no
ConfigRegistry namespace -- every module binding sits in its own
``services/followup_discovery.py``, exactly like the platform-generic
:mod:`aila.platform.services.investigation_finalizers` and its VR /
malware bindings.

Trigger polarities default to ``('no_finding', 'inconclusive')``. A
confirmed finding still takes the module's confirmed-finding path (VR:
``VARIANT_HUNT_ORDER`` under :mod:`aila.modules.vr.agents.outcome_dispatcher`)
which lives outside this primitive; the two mechanisms deliberately do
not overlap.

Guard defaults are the values RFC-05's variant-hunt fork guards
converged on:

* ``max_depth=5``           -- child stops recursing at depth 5.
* ``min_budget_usd=5.0``    -- child under $5 cannot pay for even one
  round of reasoning; skipping is honest.
* ``budget_fraction=0.5``   -- child inherits half the parent budget,
  so the take-over chain converges to zero even without a hard depth
  cap.

Idempotency: a follow-up already spawned for THIS investigation is
detected by a DB select for a child whose ``parent_investigation_id``
matches and whose ``initial_question`` carries the ``[followup-depth=N]``
marker. Any re-invocation (retry, operator-triggered re-synthesize,
worker restart mid-run) short-circuits with
``{'status': 'skipped', 'reason': 'already_spawned'}``.

Modules that don't yet bind:

* malware:   next-actions are operator-facing tactical steps
             (unpack these strings, extract this config, submit these
             IOCs) with no ``no_finding`` polarity path. The take-over
             shape does not fit; malware may bind a different
             next-actions consumer later.
* forensics: terminal lifecycle is operator-driven timeline sign-off,
             not agent-driven recommendation follow-through. Also
             deferred.

Both bindings are legitimate future work; nothing in this primitive
names either module.
"""
from __future__ import annotations

import json as _json
import logging
import re as _re
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from sqlmodel import select as _select

from aila.platform.contracts.enums import BranchStatus, InvestigationStatus
from aila.platform.uow import UnitOfWork

__all__ = [
    "DEFAULT_BUDGET_FRACTION",
    "DEFAULT_DEPTH_MARKER",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MIN_BUDGET_USD",
    "DEFAULT_TRIGGER_POLARITIES",
    "maybe_spawn_followup_discovery",
]

_log = logging.getLogger(__name__)

# Guard defaults -- match the variant-hunt fork guards in
# ``aila.modules.vr.agents.outcome_dispatcher`` (MAX_VARIANT_DEPTH=5,
# VARIANT_MIN_BUDGET_USD=5.0, half-budget child). Kept as module-level
# constants so a module binding can reference the platform default
# without repeating the number, and so a future policy revision moves
# every binding at once.
DEFAULT_MAX_DEPTH: int = 5
DEFAULT_MIN_BUDGET_USD: float = 5.0
DEFAULT_BUDGET_FRACTION: float = 0.5
DEFAULT_DEPTH_MARKER: str = "followup-depth"
DEFAULT_TRIGGER_POLARITIES: tuple[str, ...] = ("no_finding", "inconclusive")


class _UoWFactory(Protocol):
    """Callable returning an async-context UoW.

    Production callers pass :class:`aila.platform.uow.UnitOfWork` (the
    default). Tests pass a fake context manager wrapping a fake session
    so no live DB / ARQ is required.
    """

    def __call__(self) -> AbstractAsyncContextManager[Any]: ...


def _extract_current_depth(initial_question: str, marker: str) -> int:
    """Return the ``[<marker>=N]`` depth already stamped on ``initial_question``.

    Returns ``0`` when the marker is absent -- a parent investigation
    with no depth stamp is at depth 0, so its first follow-up child is
    at depth 1. The regex requires ``\\d+`` so any match yields a value
    ``int(...)`` accepts without raising; a hand-edited non-numeric
    stamp simply fails to match and falls through to the zero default.
    """
    if not initial_question:
        return 0
    pattern = _re.compile(rf"\[{_re.escape(marker)}=(\d+)\]")
    match = pattern.search(initial_question)
    if match is None:
        return 0
    return int(match.group(1))


def _build_child_initial_question(
    *,
    marker: str,
    child_depth: int,
    parent_investigation_id: str,
    polarity: str,
    recommendations: list[str],
) -> str:
    """Compose the child's initial_question with the depth stamp + mandate."""
    lines = [
        f"[{marker}={child_depth}] Continue the audit. The prior "
        f"investigation ({parent_investigation_id}) concluded {polarity} "
        "and recommended these further discoveries; pursue each and "
        "establish a finding or a defensible no-finding naming the "
        "boundary:",
    ]
    lines.extend(f"- {rec}" for rec in recommendations)
    return "\n".join(lines)


async def _load_investigation(session: Any, investigation_model: type, investigation_id: str) -> Any:
    """Load the parent investigation row by id, or ``None`` if missing."""
    result = await session.exec(
        _select(investigation_model).where(
            investigation_model.id == investigation_id,
        ),
    )
    return result.first()


async def _load_outcome(session: Any, outcome_model: type, outcome_id: str) -> Any:
    """Load the primary outcome row by id, or ``None`` if missing."""
    result = await session.exec(
        _select(outcome_model).where(outcome_model.id == outcome_id),
    )
    return result.first()


async def _existing_followup_child_id(
    session: Any,
    investigation_model: type,
    parent_investigation_id: str,
    marker: str,
) -> str | None:
    """Return an existing follow-up child's id when one is already recorded.

    Idempotency mechanism: the child's ``initial_question`` always
    carries the ``[<marker>=N]`` stamp, so a LIKE probe against the
    parent's children is enough to detect a prior spawn. Any re-invoke
    of the primitive on the same parent returns the same
    ``already_spawned`` skip result.
    """
    marker_fragment = f"%[{marker}=%"
    result = await session.exec(
        _select(investigation_model).where(
            investigation_model.parent_investigation_id == parent_investigation_id,
            investigation_model.initial_question.like(marker_fragment),
        ),
    )
    row = result.first()
    if row is None:
        return None
    return getattr(row, "id", None)


async def maybe_spawn_followup_discovery(
    investigation_id: str,
    *,
    investigation_model: type,
    branch_model: type,
    outcome_model: type,
    discovery_kind: str,
    strategy_family: str,
    derive_polarity: Callable[[str, dict[str, Any]], str | None],
    extract_recommendations: Callable[[dict[str, Any]], list[str]],
    enqueue_investigate: Callable[[str, str | None], Awaitable[Any]],
    max_depth: int = DEFAULT_MAX_DEPTH,
    min_budget_usd: float = DEFAULT_MIN_BUDGET_USD,
    budget_fraction: float = DEFAULT_BUDGET_FRACTION,
    depth_marker: str = DEFAULT_DEPTH_MARKER,
    trigger_polarities: tuple[str, ...] = DEFAULT_TRIGGER_POLARITIES,
    uow_factory: _UoWFactory = UnitOfWork,
) -> dict[str, Any]:
    """Autonomously spawn a follow-up-discovery child, at most once.

    Load ``investigation_id`` and its ``primary_outcome_id``. If the
    outcome polarity (via ``derive_polarity``) falls into
    ``trigger_polarities`` and the panel produced non-empty
    ``extract_recommendations``, and no prior follow-up child already
    exists, and the child depth would not exceed ``max_depth`` and the
    halved budget would not fall below ``min_budget_usd``, build a
    child ``investigation_model`` row (parent-linked, ``kind =
    discovery_kind``, halved budget, depth-stamped
    ``initial_question`` carrying the mandate + the panel's
    recommendations) plus its primary branch, commit both under one
    UoW, and enqueue the module's driver task via
    ``enqueue_investigate``.

    Every skip / failure path returns a ``{'status': 'skipped',
    'reason': ..., ...}`` dict; the sole success shape is
    ``{'status': 'spawned', 'child_id': ..., 'depth': ...,
    'budget': ..., 'recommendations': ...}``. Enqueue failure DOES NOT
    delete the child row -- the operator's re-enqueue path can drive
    the row from the ``CREATED`` state without a second spawn (the
    idempotency probe catches it).
    """
    async with uow_factory() as uow:
        session = uow.session
        inv = await _load_investigation(session, investigation_model, investigation_id)
        if inv is None:
            return {"status": "skipped", "reason": "investigation_not_found"}
        primary_outcome_id = getattr(inv, "primary_outcome_id", None)
        if not primary_outcome_id:
            return {"status": "skipped", "reason": "no_primary_outcome"}

        outcome = await _load_outcome(session, outcome_model, primary_outcome_id)
        if outcome is None:
            return {"status": "skipped", "reason": "primary_outcome_not_found"}

        try:
            payload = _json.loads(getattr(outcome, "payload_json", None) or "{}")
        except (ValueError, TypeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}

        polarity = derive_polarity(getattr(outcome, "outcome_kind", "") or "", payload)
        if polarity not in trigger_polarities:
            return {
                "status": "skipped",
                "reason": "polarity_not_terminal_negative",
                "polarity": polarity,
            }

        recommendations = list(extract_recommendations(payload) or [])
        recommendations = [r for r in (str(x).strip() for x in recommendations) if r]
        if not recommendations:
            return {"status": "skipped", "reason": "no_recommendations"}

        existing_child_id = await _existing_followup_child_id(
            session, investigation_model, investigation_id, depth_marker,
        )
        if existing_child_id is not None:
            return {
                "status": "skipped",
                "reason": "already_spawned",
                "child_id": existing_child_id,
            }

        current_depth = _extract_current_depth(
            getattr(inv, "initial_question", "") or "", depth_marker,
        )
        child_depth = current_depth + 1
        if child_depth > max_depth:
            return {
                "status": "skipped",
                "reason": "followup_depth_exceeded",
                "depth": current_depth,
                "max_depth": max_depth,
            }

        parent_budget = float(getattr(inv, "cost_budget_usd", None) or min_budget_usd)
        child_budget = parent_budget * budget_fraction
        if child_budget < min_budget_usd:
            return {
                "status": "skipped",
                "reason": "followup_budget_below_floor",
                "budget": child_budget,
                "min_budget_usd": min_budget_usd,
            }

        child_question = _build_child_initial_question(
            marker=depth_marker,
            child_depth=child_depth,
            parent_investigation_id=investigation_id,
            polarity=polarity or "inconclusive",
            recommendations=recommendations,
        )
        parent_title = getattr(inv, "title", "") or ""
        child_title = f"Follow-up discovery: {parent_title}"[:255]

        child = investigation_model(
            target_id=getattr(inv, "target_id"),
            team_id=getattr(inv, "team_id", None),
            parent_investigation_id=investigation_id,
            kind=discovery_kind,
            title=child_title,
            initial_question=child_question,
            status=InvestigationStatus.CREATED.value,
            auto_pilot=bool(getattr(inv, "auto_pilot", True)),
            strategy_family=strategy_family,
            cost_budget_usd=child_budget,
        )
        session.add(child)
        await session.flush()
        child_id = child.id
        child_team_id = getattr(child, "team_id", None)

        primary_branch = branch_model(
            investigation_id=child_id,
            status=BranchStatus.ACTIVE.value,
            fork_reason="primary",
        )
        session.add(primary_branch)
        await uow.commit()

    # Enqueue outside the UoW -- a queue transport blip must not roll
    # back the committed child. Same posture as the variant-hunt spawn
    # in the VR outcome dispatcher: log + swallow so the caller sees
    # the spawn as a success and an operator re-enqueue can pick the
    # row up.
    enqueue_error: str | None = None
    try:
        await enqueue_investigate(child_id, child_team_id)
    except (OSError, RuntimeError, TimeoutError, ImportError) as exc:
        enqueue_error = f"{type(exc).__name__}:{exc}"
        _log.warning(
            "maybe_spawn_followup_discovery: enqueue failed child=%s err=%s",
            child_id, exc,
        )

    return {
        "status": "spawned",
        "child_id": child_id,
        "depth": child_depth,
        "budget": child_budget,
        "recommendations": len(recommendations),
        "polarity": polarity,
        "enqueue_error": enqueue_error,
    }

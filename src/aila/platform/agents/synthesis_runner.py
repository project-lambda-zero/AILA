"""Shared synthesis runner (RFC-03 Phase 5).

``SynthesisRunnerBase.run`` is the single per-investigation synthesis
pipeline: load the canonical outcome, gate on already-synthesized,
build the panel from ``panel_contributions``, call the module's
schema-validated LLM, and commit ``panel_summary`` (plus any module-
specific payload promotions) under a row-lock on the investigation. It
was lifted verbatim from the byte-shared skeleton of the vr and malware
synthesis agents; the per-module differences are expressed as class
attributes and small override hooks that every subclass sets:

* class attributes -- ``_LOG_LABEL``, ``_TASK_TYPE``, ``_SYSTEM_PROMPT``
  (module-inline for now; RFC-09 moves prompts to the registry),
  ``_investigation_model``, ``_outcome_model``, ``_response_model``
  (the module's ``SynthesisResponse``), ``_branch_table`` (SQL table
  name for orphan-branch cleanup on the status flip).
* required hook -- ``_render_user_prompt(panel)`` builds the LLM
  user-side prompt; vr and malware render very different persona-panel
  shapes so this override is mandatory.
* optional hooks with sane defaults:
  - ``_should_force_resynthesize()`` -- default ``False``; malware
    overrides when ``options.force`` is set so a manual re-synthesize
    from the UI bypasses the already-synthesized + alive-status gates.
  - ``_should_flip_investigation_status(inv_row)`` -- default ``True``;
    malware overrides to skip the flip on force-runs against an
    already-completed investigation.
  - ``_build_panel_entry(contribution, canonical_payload)`` -- default
    returns the 7 core keys used by ``synthesis_confidence`` and the
    ``panel_summary.personas`` list; vr overrides to add
    ``affected_components`` + ``variant_hunt_orders`` derived from the
    canonical payload for its rendering.
  - ``_update_payload_extras(payload, parsed)`` -- default no-op (vr
    keeps every synthesised field inside the ``panel_summary``
    narrative); malware overrides to promote ``family_attribution`` /
    ``capabilities`` / ``iocs`` / ``detection_guidance`` / etc. onto
    the top-level canonical payload so the operator card renderer and
    downstream dispatch see the structured detail.

The two UoWs (read + row-locked write) preserve the fix §160 pattern
from both module copies: the LLM call runs outside any transaction so a
slow model does not hold the investigation row lock, and the write path
re-loads under ``SELECT FOR UPDATE`` so a concurrent operator pause
cannot lose to the payload write. The DB access is factored into
``_load_inv_and_canonical`` and ``_commit_synthesis`` so tests can
replace them with in-memory fakes without patching ``UnitOfWork``.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel
from sqlmodel import select as _select

from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import InvestigationStatus, OutcomeConfidence
from aila.platform.llm.errors import BudgetExceededError, LLMError
from aila.platform.services.branch_cleanup import close_orphan_branches_on_terminal
from aila.platform.services.factory import ServiceFactory
from aila.platform.services.investigation_lifecycle import mark_investigation_completed
from aila.platform.uow import UnitOfWork

__all__ = ["SynthesisRunnerBase", "synthesis_confidence"]

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------- #
#  verifier_report -> panel annotation (issue #105 wiring).              #
# ---------------------------------------------------------------------- #

# The claim verifier writes at most one ``verifier_report`` dict onto
# the canonical outcome payload (see
# :class:`aila.platform.agents.claim_verifier.ClaimVerifier`). Its
# ``verdict`` is one of ``"confirmed"`` / ``"refuted"`` /
# ``"inconclusive"``. Anything else -- missing dict, unknown verdict --
# collapses to ``"unverified"`` so the annotation always reads as a
# well-known token both for the synthesis prompt and for downstream
# consumers.
_KNOWN_VERIFIER_VERDICTS: frozenset[str] = frozenset(
    {"confirmed", "refuted", "inconclusive"},
)


def _verified_status_from_payload(canonical_payload: dict[str, Any]) -> str:
    """Map ``canonical_payload['verifier_report']['verdict']`` to a token.

    Returns one of ``"confirmed"``, ``"refuted"``, ``"inconclusive"``,
    or ``"unverified"``. Never raises; a malformed payload collapses to
    ``"unverified"``.
    """
    report = canonical_payload.get("verifier_report")
    if not isinstance(report, dict):
        return "unverified"
    verdict = report.get("verdict")
    if isinstance(verdict, str) and verdict in _KNOWN_VERIFIER_VERDICTS:
        return verdict
    return "unverified"


def _render_verifier_annotation(
    canonical_payload: dict[str, Any],
    panel: list[dict[str, Any]],
) -> str:
    """Render a per-persona verifier-status block appended to the prompt.

    Emitted alongside :meth:`SynthesisRunnerBase._render_user_prompt`
    output so the synthesis model sees which claims already carry an
    independent claim-verifier verdict (confirmed vs refuted vs
    inconclusive) and can weight the panel narrative accordingly
    instead of dropping refuted contributions silently.

    Returns an empty string when no panel entries exist so callers can
    unconditionally concatenate the block.
    """
    if not panel:
        return ""
    status_seen = {p.get("verified_status", "unverified") for p in panel}
    report = canonical_payload.get("verifier_report") or {}
    if not isinstance(report, dict):
        report = {}
    summary_raw = str(report.get("summary") or "").strip()
    summary = summary_raw[:400]
    lines: list[str] = [
        "",
        "# Claim verifier annotations",
        "",
        (
            "Each panel entry below carries a ``verified_status`` derived "
            "from the canonical outcome's ``verifier_report``. "
            "``confirmed`` means an independent probe reproduced the "
            "claim; ``refuted`` means the probe contradicted it; "
            "``inconclusive`` means the probe ran but could not decide; "
            "``unverified`` means the claim verifier has not run yet. "
            "Weight the synthesis toward confirmed claims and treat "
            "refuted claims as counter-evidence; do NOT drop refuted "
            "personas -- name the refutation explicitly."
        ),
        "",
    ]
    for entry in panel:
        persona = str(entry.get("persona_voice") or "(none)")
        branch = str(entry.get("branch_id") or "")
        status = str(entry.get("verified_status") or "unverified")
        lines.append(f"- {persona} (branch={branch}): verified_status={status}")
    if summary and status_seen - {"unverified"}:
        lines.append("")
        lines.append(f"Verifier summary: {summary}")
    return "\n".join(lines)

# Investigation statuses on which synthesis may write its consolidated
# outcome. CREATED / RUNNING are the live states; COMPLETED is included
# because the dispatch hub finalises the investigation through the emit
# state (hub_stalled / branch_already_terminal, outcome_id=None) BEFORE
# the async synthesis task runs, so a terminal-success investigation must
# still accept the panel consolidation -- otherwise synthesis never fires
# under the hub and the raw last-writer answer stays as the headline.
# PAUSED / FAILED / ABANDONED stay excluded: those mean the operator or
# another agent closed the investigation against synthesis's will while
# an LLM call was in flight, and UoW 2 aborts the write in that case
# (fix §160). Subclasses that need a different set override
# _should_force_resynthesize per-run instead of rebinding this constant.
_SYNTHESIZABLE_STATUSES: frozenset[str] = frozenset({
    InvestigationStatus.CREATED.value,
    InvestigationStatus.RUNNING.value,
    InvestigationStatus.COMPLETED.value,
})


class SynthesisRunnerBase(ABC):
    """Per-investigation synthesis pipeline shared by the module agents.

    Construction takes only ``investigation_id``; every module knob is a
    class attribute or an override hook so the two module subclasses
    (``vr.SynthesisAgent`` / ``malware.SynthesisAgent``) keep their
    pre-extraction constructor shape. Tests patch ``_load_inv_and_canonical``
    and ``_commit_synthesis`` with in-memory fakes and bypass the
    idempotency wrapper at the module boundary so no Postgres or
    ``ServiceFactory`` LLM initialisation is required.
    """

    _LOG_LABEL: ClassVar[str] = "synthesis"
    # Subclasses set the following (declared here for readers; the
    # methods below reach them off ``cls`` / ``self`` at call time).
    _TASK_TYPE: ClassVar[str]
    _SYSTEM_PROMPT: ClassVar[str]
    _investigation_model: ClassVar[type[Any]]
    _outcome_model: ClassVar[type[Any]]
    _response_model: ClassVar[type[BaseModel]]
    _branch_table: ClassVar[str]
    # Module's outcome-review record (vr / malware). Bound by the
    # subclass so synthesis can fold sibling review votes + comments +
    # suggested edits into the consolidated verdict (fix §170: the
    # request_edit vote's deferred consumer). None means the review pool
    # does not apply and _load_reviews returns an empty list.
    _review_model: ClassVar[type[Any] | None] = None

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id

    # ------------------------------------------------------------------ #
    #  Behavior hooks -- default vr behavior + malware override points.  #
    # ------------------------------------------------------------------ #

    def _should_force_resynthesize(self) -> bool:
        """Bypass ``already_synthesized`` + alive-status gates when True.

        Default (False) is the vr behavior: one synthesis per
        investigation, gated by canonical payload + investigation
        aliveness. Malware overrides this when ``options.force`` is set
        so an operator can re-run synthesis against a COMPLETED
        investigation from the UI. Both gates check this flag: the
        pre-lock check in :meth:`run` and the under-lock re-check in
        :meth:`_commit_synthesis`.
        """
        return False

    def _should_flip_investigation_status(self, inv_row: Any) -> bool:
        """Whether to mark the investigation COMPLETED + close orphan branches.

        Default (True) is the vr behavior: every successful synthesis
        transitions the investigation to COMPLETED and cleans up any
        stray active branches. Malware overrides to return False when
        ``options.force`` is set AND the investigation is already
        COMPLETED -- a manual re-synthesize from the UI must refresh
        the outcome payload without flapping the status column or
        re-firing orphan-branch cleanup on a settled investigation.
        """
        del inv_row  # default flips regardless of the current row state
        return True

    def _build_panel_entry(
        self,
        contribution: dict[str, Any],
        canonical_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Build one panel entry from a canonical ``panel_contributions`` dict.

        The default keys (used by :func:`synthesis_confidence`, the
        ``panel_summary.personas`` list, and every subclass renderer)
        are:

          - ``branch_id``
          - ``persona_voice``
          - ``turn_count``
          - ``outcome_kind``
          - ``confidence``
          - ``answer``
          - ``reasoning``
          - ``verified_status``

        ``verified_status`` is derived from the canonical payload's
        ``verifier_report`` (written by
        :class:`aila.platform.agents.claim_verifier.ClaimVerifier`
        post-synthesis, per issue #105 wiring). One verifier verdict
        applies to the whole canonical outcome so every panel entry
        carries the same status; the annotation lets the synthesiser
        know which claims already have an independent probe verdict
        instead of dropping refuted claims silently. Values:
        ``"confirmed"``, ``"refuted"``, ``"inconclusive"``, or
        ``"unverified"`` when no report has been written yet.

        Subclasses may add module-specific fields. vr overrides to
        include ``affected_components`` and ``variant_hunt_orders``
        derived from the canonical payload; those fields are only read
        by vr's ``_render_user_prompt``.
        """
        return {
            "branch_id": contribution.get("branch_id") or "",
            "persona_voice": contribution.get("persona") or "(none)",
            "turn_count": contribution.get("at_turn") or 0,
            "outcome_kind": contribution.get("outcome_kind") or "",
            "confidence": contribution.get("confidence") or "unknown",
            "answer": contribution.get("answer_brief") or "",
            "reasoning": "",
            "verified_status": _verified_status_from_payload(canonical_payload),
        }

    @abstractmethod
    def _render_user_prompt(
        self,
        panel: list[dict[str, Any]],
        reviews: list[dict[str, Any]],
    ) -> str:
        """Render the LLM user-side prompt from panel entries + reviews.

        No shared default: vr renders a plain persona panel with a
        Points-of-agreement / disagreement instruction; malware injects
        tone + length + optional operator-focus directives plus a
        different structured-schema instruction. Subclasses MUST
        implement this hook. ``reviews`` is the list produced by
        :meth:`_load_reviews` (one dict per sibling review carrying
        ``persona`` / ``vote`` / ``comment`` / ``suggested_edits``); the
        renderer surfaces the requested edits + dissent so the
        synthesiser folds them into the consolidated verdict rather than
        dropping them (fix §170).
        """

    def _update_payload_extras(
        self,
        payload: dict[str, Any],
        parsed: BaseModel,
    ) -> None:
        """Promote schema-specific fields onto the top-level payload dict.

        Default is a no-op (vr behavior: every synthesised field lives
        inside ``panel_summary.narrative`` markdown). Malware overrides
        to promote ``family_attribution`` / ``capabilities`` / ``iocs``
        / ``detection_guidance`` / ``next_actions`` / etc. onto the
        canonical outcome payload's top-level keys so the operator card
        renderer and downstream dispatch see the structured detail
        without having to parse the markdown blob.
        """
        del payload, parsed  # default: no field promotions

    # ------------------------------------------------------------------ #
    #  DB seams -- tests replace these to bypass Postgres.                #
    # ------------------------------------------------------------------ #

    async def _load_inv_and_canonical(
        self,
    ) -> tuple[Any, Any, dict[str, Any]] | dict[str, Any]:
        """UoW 1: read the investigation + canonical outcome + parsed payload.

        Returns the 3-tuple ``(inv, canonical, canonical_payload)`` on
        success or a ``{"status": "skipped", "reason": ...}`` dict when
        a required row is missing. The read is not row-locked -- the
        heavy LLM call runs outside any transaction and the write path
        (:meth:`_commit_synthesis`) re-loads under
        ``SELECT FOR UPDATE`` so a concurrent pause / close cannot race
        the payload write.
        """
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(self._investigation_model).where(
                    self._investigation_model.id == self.investigation_id,
                ),
            )).first()
            if inv is None:
                return {"status": "skipped", "reason": "investigation_not_found"}

            canonical = (await uow.session.exec(
                _select(self._outcome_model)
                .where(
                    self._outcome_model.investigation_id == self.investigation_id,
                )
                .order_by(self._outcome_model.created_at.asc())
                .limit(1),
            )).first()
            if canonical is None:
                return {"status": "skipped", "reason": "no_canonical_outcome"}

            try:
                canonical_payload = json.loads(canonical.payload_json or "{}")
            except (ValueError, TypeError):
                canonical_payload = {}
            return inv, canonical, canonical_payload

    async def _load_reviews(self, canonical_id: str) -> list[dict[str, Any]]:
        """UoW read: sibling reviews on the canonical outcome (fix §170).

        One dict per review row (``persona`` / ``vote`` / ``comment`` /
        parsed ``suggested_edits``) so :meth:`_render_user_prompt` can
        fold reviewer corrections + dissent into the consolidated
        verdict -- the deferred consumer the ``request_edit`` vote was
        waiting on. Returns an empty list when the subclass binds no
        ``_review_model`` so callers stay uniform. Overridable as a test
        seam alongside :meth:`_load_inv_and_canonical`.
        """
        model = self._review_model
        if model is None:
            return []
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(model).where(model.outcome_id == canonical_id),
            )).all()
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                edits = json.loads(getattr(r, "suggested_edits_json", None) or "{}")
            except (ValueError, TypeError):
                edits = {}
            out.append({
                "persona": getattr(r, "reviewer_persona", None) or "(none)",
                "vote": getattr(r, "vote", None) or "",
                "comment": getattr(r, "comment", None) or "",
                "suggested_edits": edits,
            })
        return out

    async def _commit_synthesis(
        self,
        canonical_id: str,
        panel: list[dict[str, Any]],
        parsed: BaseModel,
        synthesis_text: str,
    ) -> dict[str, Any]:
        """UoW 2: SELECT FOR UPDATE, alive re-check, write, optional flip.

        Re-loads the investigation + canonical outcome under a row lock
        so a concurrent pause / close cannot race the payload write.
        Applies the module's ``_should_force_resynthesize`` bypass for
        both the alive-status gate and the second already-synthesized
        gate, then writes the ``panel_summary`` + module-specific
        payload extras + confidence, and optionally flips the
        investigation status to COMPLETED + closes orphan branches via
        the shared helper.
        """
        async with UnitOfWork() as uow:
            # fix §160 -- SELECT FOR UPDATE on the investigation row so
            # a concurrent pause / close cannot race the payload write.
            inv_row = (await uow.session.exec(
                _select(self._investigation_model)
                .where(
                    self._investigation_model.id == self.investigation_id,
                )
                .with_for_update(),
            )).first()
            if inv_row is None:
                return {"status": "skipped", "reason": "investigation_disappeared"}
            # fix §160 -- re-check status under lock. options.force
            # bypass (malware) lets a UI-triggered re-synthesize touch a
            # COMPLETED investigation without aborting on the alive gate.
            if (
                not self._should_force_resynthesize()
                and inv_row.status not in _SYNTHESIZABLE_STATUSES
            ):
                _log.info(
                    "%s aborted inv=%s -- status=%s no longer alive "
                    "(paused or closed mid-synthesis)",
                    self._LOG_LABEL, self.investigation_id, inv_row.status,
                )
                return {
                    "status": "skipped",
                    "reason": f"investigation_not_alive:{inv_row.status}",
                }

            canonical_row = (await uow.session.exec(
                _select(self._outcome_model)
                .where(self._outcome_model.id == canonical_id)
                .with_for_update(),
            )).first()
            if canonical_row is None:
                return {"status": "skipped", "reason": "canonical_disappeared"}
            try:
                payload = json.loads(canonical_row.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            if (
                "panel_summary" in payload
                and not self._should_force_resynthesize()
            ):
                return {
                    "status": "skipped",
                    "reason": "already_synthesized_under_lock",
                    "canonical_outcome_id": canonical_row.id,
                }
            payload["panel_summary"] = {
                "narrative": synthesis_text,
                "personas": [
                    {
                        "persona": p["persona_voice"],
                        "branch_id": p["branch_id"],
                        "kind": p["outcome_kind"],
                        "confidence": p["confidence"],
                    }
                    for p in panel
                ],
                "synthesized_at": utc_now().isoformat(),
            }
            self._update_payload_extras(payload, parsed)
            canonical_row.payload_json = json.dumps(payload)
            canonical_row.confidence = synthesis_confidence(panel).value
            uow.session.add(canonical_row)

            if self._should_flip_investigation_status(inv_row):
                mark_investigation_completed(inv_row)
                uow.session.add(inv_row)
                # Phase C surgical (BLOCK fix): close orphan active
                # branches so the projection stays in lockstep with
                # the investigation status column. Rationale lives
                # alongside the branch_cleanup helper.
                await close_orphan_branches_on_terminal(
                    uow, self.investigation_id,
                    branch_table=self._branch_table,
                    reason="investigation_completed",
                    now=inv_row.updated_at,
                )
            await uow.commit()

        _log.info(
            "%s DONE inv=%s canonical_outcome_id=%s panel=%d",
            self._LOG_LABEL, self.investigation_id, canonical_id, len(panel),
        )
        return {
            "status": "ok",
            "canonical_outcome_id": canonical_id,
            "panel_size": len(panel),
        }

    # ------------------------------------------------------------------ #
    #  Orchestrator.                                                     #
    # ------------------------------------------------------------------ #

    async def run(self) -> dict[str, Any]:
        """Consolidate panel persona submissions into a synthesis verdict.

        D-101 architecture: ONE canonical outcome row per investigation
        holds every persona's submission inside
        ``payload.panel_contributions``. Synthesis reads that array
        (NOT per-branch outcome rows -- there is only one row),
        produces a consolidated narrative via LLM, writes
        ``panel_summary`` into the canonical row's payload, and (per
        the subclass ``_should_flip_investigation_status`` hook) flips
        ``inv.status`` to COMPLETED + records ``stopped_at``.

        Idempotency: skips when ``panel_summary`` already exists on the
        canonical payload UNLESS ``_should_force_resynthesize`` returns
        True. On force runs the previous synthesis is overwritten in
        place; ``_update_payload_extras`` re-fires and
        ``panel_summary.narrative`` is replaced.
        """
        load_result = await self._load_inv_and_canonical()
        if isinstance(load_result, dict):
            return load_result
        _inv_row, canonical, canonical_payload = load_result

        if (
            "panel_summary" in canonical_payload
            and not self._should_force_resynthesize()
        ):
            return {
                "status": "skipped",
                "reason": "already_synthesized",
                "canonical_outcome_id": canonical.id,
            }

        contributions = canonical_payload.get("panel_contributions") or []
        if not contributions:
            return {"status": "skipped", "reason": "no_panel_contributions"}

        # Build the per-persona panel from each contribution dict.
        # The upstream answer_brief field carries up to 4000 chars of
        # every persona submission which is enough for the synthesiser
        # without any extra DB round-trip.
        panel: list[dict[str, Any]] = []
        for c in contributions:
            if not isinstance(c, dict):
                continue
            panel.append(self._build_panel_entry(c, canonical_payload))
        if not panel:
            return {"status": "skipped", "reason": "no_valid_contributions"}

        # fix §170 -- load sibling reviews so the synthesiser folds
        # requested edits + dissent into the consolidated verdict
        # instead of silently dropping every request_edit suggestion.
        reviews = await self._load_reviews(canonical.id)

        # fix §159 -- chat_structured so the response is schema-validated;
        # the renderer never has to parse free-text markdown that might
        # drift. fix §158 -- broad LLM-failure catch so systemic errors
        # (TimeoutError, httpx errors, validation failures, etc.) surface
        # instead of crashing the worker. BudgetExceededError is re-raised
        # so the caller sees the budget halt for what it is.
        # #105 wiring -- append the claim-verifier per-persona status
        # block AFTER the subclass-rendered panel so the synthesis
        # model is told which claims already have an independent probe
        # verdict. When no verifier_report exists (initial synthesis
        # pass) every entry annotates as ``unverified`` and the model
        # sees an empty verdict roster; on re-synthesis the confirmed
        # vs refuted vs inconclusive tokens shape which claims the
        # narrative should lead with vs argue against.
        user_prompt = self._render_user_prompt(panel, reviews)
        verifier_block = _render_verifier_annotation(
            canonical_payload, panel,
        )
        if verifier_block:
            user_prompt = f"{user_prompt}\n{verifier_block}"

        services = ServiceFactory()
        try:
            response, _ = await idempotent_llm_call(
                services.llm_client,
                method="chat_structured",
                task_type=self._TASK_TYPE,
                messages=[
                    {"role": "system", "content": self._SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                model_class=self._response_model,
                investigation_id=self.investigation_id,
            )
        except BudgetExceededError:
            raise
        except (
            httpx.HTTPError, LLMError, OSError,
            RuntimeError, ValueError, TypeError,
        ) as exc:
            # Systemic LLM failure shapes: TimeoutError is a subclass of
            # OSError; httpx transport errors; LLM client errors; JSON
            # decode errors surface as ValueError; schema validation
            # failures also raise ValueError. fix §350 -- traceback now
            # reaches operator log so transient transport failures vs.
            # permanent schema/auth failures are distinguishable from
            # the warning alone.
            _log.warning(
                "%s LLM call failed for inv=%s err=%s",
                self._LOG_LABEL, self.investigation_id, exc,
                exc_info=True,
            )
            return {
                "status": "failed",
                "reason": f"llm_error:{type(exc).__name__}",
            }
        if response.disabled:
            return {"status": "skipped", "reason": "llm_kill_switch_active"}
        # chat_structured guarantees ``response.content`` is JSON matching
        # the schema. LLMResponse does NOT carry a ``.parsed`` field, so
        # validate explicitly here.
        try:
            parsed = self._response_model.model_validate_json(response.content)
        except ValueError as exc:
            _log.warning(
                "%s chat_structured content failed schema validation "
                "inv=%s err=%s",
                self._LOG_LABEL, self.investigation_id, exc,
            )
            return {"status": "failed", "reason": "structured_parse_failed"}
        synthesis_text = parsed.to_markdown().strip()
        if not synthesis_text:
            return {"status": "failed", "reason": "empty_llm_response"}

        return await self._commit_synthesis(
            canonical.id, panel, parsed, synthesis_text,
        )


def synthesis_confidence(panel: list[dict[str, Any]]) -> OutcomeConfidence:
    """Median panel confidence with a graduated disagreement penalty.

    Lifted verbatim from the byte-shared helper in both module copies.
    Take the median of the panel's confidences (ranked 0=exact to
    4=unknown), then downgrade one notch per distinct extra
    ``outcome_kind`` in the panel. Unanimous panels lose no notches;
    a 3-way outcome_kind split (finding / patch-present / audit-memo)
    caps the confidence two notches below the median because a panel
    that cannot even agree on what was found is fundamentally less
    confident than a panel arguing degree.
    """
    # fix §326 -- rank 0 ('exact' confidence) must round-trip to
    # OutcomeConfidence.EXACT, not STRONG. The reverse map was lossy.
    rank_to_conf = {
        0: OutcomeConfidence.EXACT,
        1: OutcomeConfidence.STRONG,
        2: OutcomeConfidence.MEDIUM,
        3: OutcomeConfidence.CAVEATED,
        4: OutcomeConfidence.UNKNOWN,
    }
    # fix §161 -- 'weak' is NOT in OutcomeConfidence; drop the alias.
    # Personas that emit 'weak' fall through to the .get(default=4)
    # ('unknown') rank, which is the same end-state CAVEATED would
    # have produced via the disagreement penalty.
    conf_rank = {
        "exact": 0, "strong": 1, "medium": 2, "caveated": 3, "unknown": 4,
    }
    ranks = sorted(
        conf_rank.get(p.get("confidence", "unknown"), 4) for p in panel
    )
    median = ranks[len(ranks) // 2]
    # fix §327 -- graduated disagreement penalty: the notch downgrade
    # scales with the number of distinct outcome_kinds in the panel.
    kinds = {p.get("outcome_kind") for p in panel}
    disagreement = max(len(kinds) - 1, 0)
    if disagreement:
        median = min(median + disagreement, 4)
    return rank_to_conf.get(median, OutcomeConfidence.MEDIUM)

"""Falsifier persona -- attempts to refute a promoted confirmed finding.

Docs `.run/vr_truth_aggregation_spine.md` \u00a71 and
`.run/vr_truth_agent_interaction_trace.md` \u00a71 both flag the
falsifier persona (``yuki`` in the VR/malware set) as defined-but-
unspawned: the prompt and role exist, but zero branches carry the
persona across the entire 1755-branch corpus, so the panel's designed
critic seat is empty and no adversarial pass ever runs before a finding
is dispatched.

This module supplies the missing verdict path. It is not a background
branch (branch spawning is owned by the module's setup base); it is a
per-outcome refutation attempt driven from
:func:`aila.platform.agents.outcome_dispatcher.finalize_investigation_aggregate`.
Given a promoted outcome, it:

1. Assembles a refutation packet (the outcome's payload + evidence
   refs + optional adjudication history of the same claim from the
   ledger).
2. Runs an LLM refutation-attempt prompt via ``completion(...)`` -- an
   independent, session-less call so the falsifier is not primed by
   the researcher's own reasoning history.
3. When the model returns a ``refuted`` verdict with a
   non-empty ``reason``, writes an ``adjudication`` entry
   (``verdict='refuted'``, ``target_outcome_id=<id>``) via
   :meth:`LedgerService.append_adjudication`.
4. Returns a :class:`FalsifierVerdict` so the caller can retract or
   downgrade the outcome (see
   :func:`outcome_dispatcher.handle_adjudication_refuted`).

Structured output is enforced by parsing the model reply as JSON; a
malformed reply is treated as ``inconclusive`` (fail safe -- a
refutation the model could not articulate is not evidence to retract a
finding).

The LLM entrypoint is passed in (``completion_fn``) so tests inject a
deterministic stub without the real client. In production wiring the
module's runtime passes a bound reference to the platform LLM client.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from aila.platform.services.ledger import LedgerService

__all__ = [
    "FALSIFIER_PERSONA",
    "FALSIFIER_SYSTEM_PROMPT",
    "FalsifierAgent",
    "FalsifierVerdict",
    "RefutationPacket",
]

_log = logging.getLogger(__name__)

FALSIFIER_PERSONA: str = "yuki"

FALSIFIER_SYSTEM_PROMPT: str = (
    "You are the falsifier persona (yuki). A sibling panel has approved "
    "a positive finding and is about to dispatch it downstream. Your "
    "job, before that dispatch fires, is to attempt an ADVERSARIAL "
    "refutation of the claim using ONLY the evidence packet supplied. "
    "You have three verdicts.\n"
    "\n"
    "  * refuted -- the packet itself contradicts the claim, OR a "
    "load-bearing precondition is unsupported by any cited evidence, "
    "OR the cited evidence does not reach the alleged sink. Provide a "
    "concrete reason grounded in the packet.\n"
    "  * inconclusive -- you cannot find a specific refutation from "
    "the packet. Default to this when uncertain; a refutation you "
    "cannot articulate is not a refutation.\n"
    "  * upheld -- the packet supports the claim end-to-end and you "
    "found no refutation surface.\n"
    "\n"
    "Reply with a single JSON object: {\"verdict\": <str>, \"reason\": "
    "<str>, \"cited_evidence\": [<str>...]}. cited_evidence MUST be a "
    "subset of the packet's evidence_refs. No prose outside the JSON."
)

_VERDICT_REFUTED: str = "refuted"
_VERDICT_INCONCLUSIVE: str = "inconclusive"
_VERDICT_UPHELD: str = "upheld"
_VALID_VERDICTS: frozenset[str] = frozenset({
    _VERDICT_REFUTED, _VERDICT_INCONCLUSIVE, _VERDICT_UPHELD,
})


@dataclass(slots=True)
class RefutationPacket:
    """Everything the falsifier is allowed to reason over.

    Kept deliberately narrow: the persona must NOT re-derive the case
    from scratch. It sees the finding, its evidence refs, and the
    prior adjudication history (so a refutation another sibling already
    filed is visible), and nothing else.
    """

    investigation_id: str
    outcome_id: str
    outcome_kind: str
    claim_text: str
    evidence_refs: list[str]
    payload: dict[str, Any] = field(default_factory=dict)
    prior_adjudications: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class FalsifierVerdict:
    """Structured result of one refutation attempt."""

    verdict: str
    reason: str
    cited_evidence: list[str]
    adjudication_id: int | None
    outcome_id: str

    @property
    def refuted(self) -> bool:
        return self.verdict == _VERDICT_REFUTED


class FalsifierAgent:
    """Persona wrapper around one refutation attempt.

    Instantiate with a ``completion_fn`` (see :meth:`try_refute`) and
    optionally a :class:`LedgerService`. The class holds no
    branch-scoped state -- every call is idempotent per outcome id via
    the ledger's adjudication idempotency key
    (``adjudication:out:<outcome_id>:<branch>``).
    """

    def __init__(
        self,
        completion_fn: Callable[..., Awaitable[str]],
        *,
        ledger: LedgerService | None = None,
        persona: str = FALSIFIER_PERSONA,
        system_prompt: str = FALSIFIER_SYSTEM_PROMPT,
    ) -> None:
        self._completion_fn = completion_fn
        self._ledger = ledger if ledger is not None else LedgerService()
        self._persona = persona
        self._system_prompt = system_prompt

    async def try_refute(
        self,
        packet: RefutationPacket,
        *,
        branch_id: str | None = None,
    ) -> FalsifierVerdict:
        """Ask the model to refute ``packet`` and write an adjudication on refuted.

        ``branch_id`` is the ledger author (defaults to the persona
        name so re-runs are idempotent per outcome). Any exception
        from ``completion_fn`` or from the ledger write is caught and
        surfaced as an ``inconclusive`` verdict -- the caller then
        dispatches on the prior verifier verdict rather than blocking
        on a broken adversarial pass.
        """
        author = branch_id or self._persona
        try:
            raw = await self._completion_fn(
                prompt=self._render_prompt(packet),
                system=self._system_prompt,
            )
        except (RuntimeError, ValueError, TypeError, OSError,
                LookupError, AttributeError) as exc:
            _log.warning(
                "falsifier completion failed inv=%s outcome=%s: %s",
                packet.investigation_id, packet.outcome_id, exc,
            )
            return FalsifierVerdict(
                verdict=_VERDICT_INCONCLUSIVE,
                reason=f"completion_error:{type(exc).__name__}",
                cited_evidence=[],
                adjudication_id=None,
                outcome_id=packet.outcome_id,
            )

        verdict, reason, cited = self._parse_reply(raw, packet)
        if verdict != _VERDICT_REFUTED:
            return FalsifierVerdict(
                verdict=verdict,
                reason=reason,
                cited_evidence=cited,
                adjudication_id=None,
                outcome_id=packet.outcome_id,
            )

        try:
            adjudication_id = await self._ledger.append_adjudication(
                packet.investigation_id,
                author,
                verdict=_VERDICT_REFUTED,
                reason=reason,
                cited_evidence=cited,
                target_outcome_id=packet.outcome_id,
            )
        except (RuntimeError, ValueError, TypeError) as exc:
            _log.warning(
                "falsifier adjudication write failed inv=%s outcome=%s: %s",
                packet.investigation_id, packet.outcome_id, exc,
            )
            return FalsifierVerdict(
                verdict=_VERDICT_INCONCLUSIVE,
                reason=f"ledger_error:{type(exc).__name__}",
                cited_evidence=cited,
                adjudication_id=None,
                outcome_id=packet.outcome_id,
            )
        _log.info(
            "falsifier REFUTED inv=%s outcome=%s adjudication=%s reason=%s",
            packet.investigation_id, packet.outcome_id,
            adjudication_id, reason,
        )
        return FalsifierVerdict(
            verdict=_VERDICT_REFUTED,
            reason=reason,
            cited_evidence=cited,
            adjudication_id=int(adjudication_id),
            outcome_id=packet.outcome_id,
        )

    def _render_prompt(self, packet: RefutationPacket) -> str:
        prior_block = ""
        if packet.prior_adjudications:
            lines = []
            for adj in packet.prior_adjudications[:10]:
                lines.append(
                    f"- verdict={adj.get('verdict')!r} "
                    f"reason={adj.get('reason', '')!r}"
                )
            prior_block = "PRIOR ADJUDICATIONS:\n" + "\n".join(lines) + "\n\n"
        evidence_block = "\n".join(f"- {r}" for r in packet.evidence_refs)
        if not evidence_block:
            evidence_block = "(no evidence refs cited)"
        payload_json = json.dumps(packet.payload, sort_keys=True)[:4000]
        return (
            f"OUTCOME_ID: {packet.outcome_id}\n"
            f"OUTCOME_KIND: {packet.outcome_kind}\n\n"
            f"CLAIM:\n{packet.claim_text}\n\n"
            f"EVIDENCE_REFS:\n{evidence_block}\n\n"
            f"{prior_block}"
            f"RAW_PAYLOAD (truncated):\n{payload_json}\n\n"
            "Refute if you can. JSON only."
        )

    def _parse_reply(
        self, raw: str, packet: RefutationPacket,
    ) -> tuple[str, str, list[str]]:
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            _log.debug(
                "falsifier reply not JSON inv=%s outcome=%s",
                packet.investigation_id, packet.outcome_id,
            )
            return _VERDICT_INCONCLUSIVE, "malformed_reply", []
        if not isinstance(data, dict):
            return _VERDICT_INCONCLUSIVE, "reply_not_object", []
        verdict = str(data.get("verdict") or "").strip().lower()
        if verdict not in _VALID_VERDICTS:
            return _VERDICT_INCONCLUSIVE, f"unknown_verdict:{verdict!r}", []
        reason = str(data.get("reason") or "").strip()
        if verdict == _VERDICT_REFUTED and not reason:
            # A refutation without a stated reason is not evidence.
            return _VERDICT_INCONCLUSIVE, "refuted_without_reason", []
        raw_cited = data.get("cited_evidence") or []
        if not isinstance(raw_cited, list):
            raw_cited = []
        allowed = {str(r) for r in packet.evidence_refs}
        cited = [str(r) for r in raw_cited if str(r) in allowed]
        return verdict, reason, cited

"""Decision-level replay harness (RFC-08 record-replay backbone).

Loads an :class:`EvalTranscriptRecord`, freezes every collaborator that
could non-deterministically drift a re-run (wall-clock, retrieval,
tool outputs), renders the decision prompt under a candidate prompt
version resolved through :class:`PromptVersionStore`, issues ONE LLM
call via the injected client, and returns a :class:`DecisionDiff`.

Scoring
-------
* **Determinism** -- run the candidate replay twice and score
  byte-match on the response JSONs via :func:`determinism_score`. The
  floor is :data:`DETERMINISM_FLOOR` = 0.98; a candidate that cannot
  reproduce its own output twice given frozen inputs is by design
  unshippable.
* **Faithfulness** -- run the recorded transcript's ORIGINAL prompt
  version once with the same frozen inputs and compare the replayed
  decision to the RECORDED decision as the fraction of matching
  decision fields over the union of keys. ``faithful == True`` means
  every recorded key survived the replay unchanged (fraction == 1.0).

Freezing
--------
The three ``Frozen*`` dataclasses are pure value objects: they carry
the recorded inputs from the transcript row and expose them via a
tiny read API the LLM-client bridge can consume. They intentionally
do NOT participate in a live retrieval/tool executor -- freezing
means "the recorded value is what the replay sees, not what a fresh
live call would return". A replay that leaked to the live substrates
would score noise, not the prompt-version change under audit.

Client bridge
-------------
:class:`ReplayLLMClient` is a Protocol so a caller can inject a
deterministic fake (tests) or a real bridge onto the platform LLM
client (production). The default bridge --
:class:`PlatformReplayLLMClient` -- wraps :class:`AilaLLMClient` via
:class:`ServiceFactory`, issues ``chat_json`` against the recorded
messages with ``prompt_body`` swapped into the system slot, and
parses the JSON response into a decision dict. It fails clearly when
the messages payload is unrecoverable rather than fabricating an
empty request.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.platform.eval.metrics import (
    DecisionDiff,
    decision_field_diffs,
    determinism_score,
)
from aila.platform.eval.transcript import EvalTranscriptRecord
from aila.platform.prompts.version_store import PromptVersionStore
from aila.storage.database import async_session_scope

if TYPE_CHECKING:
    pass

__all__ = [
    "DETERMINISM_FLOOR",
    "FrozenClock",
    "FrozenInputs",
    "FrozenRetrievalProvider",
    "FrozenToolExecutor",
    "PlatformReplayLLMClient",
    "ReplayError",
    "ReplayHarness",
    "ReplayLLMClient",
    "TranscriptNotFoundError",
    "replay",
]

_log = logging.getLogger(__name__)

# Minimum acceptable byte-match rate across two identical replays.
# A candidate that cannot reproduce its own output twice given frozen
# inputs is unshippable regardless of any faithfulness win -- that's
# the recorded-replay determinism floor named in RFC-08.
DETERMINISM_FLOOR: float = 0.98


class ReplayError(RuntimeError):
    """Base class for replay-time failures."""


class TranscriptNotFoundError(ReplayError):
    """Raised when the transcript id resolves to no row."""


class PromptResolutionError(ReplayError):
    """Raised when a prompt (key, version) fails to resolve to a body."""


@dataclass(frozen=True, slots=True)
class FrozenClock:
    """Immutable wrapper over the recorded wall-clock."""

    recorded_at: datetime

    def now(self) -> datetime:
        """Return the recorded wall-clock; the replay's ONLY time source."""
        return self.recorded_at


@dataclass(frozen=True, slots=True)
class FrozenRetrievalProvider:
    """Frozen retrieval provider: returns the RECORDED hits, always."""

    recorded_hits: tuple[dict[str, Any], ...] = ()

    def hits(self) -> tuple[dict[str, Any], ...]:
        """Return the recorded hits verbatim; never live-fetches."""
        return self.recorded_hits


@dataclass(frozen=True, slots=True)
class FrozenToolExecutor:
    """Frozen tool executor: returns the RECORDED tool outputs, always."""

    recorded_outputs: tuple[dict[str, Any], ...] = ()

    def outputs(self) -> tuple[dict[str, Any], ...]:
        """Return the recorded tool outputs verbatim; never live-invokes."""
        return self.recorded_outputs


@dataclass(frozen=True, slots=True)
class FrozenInputs:
    """Bundle of every frozen collaborator plus the recorded LLM request."""

    clock: FrozenClock
    retrieval: FrozenRetrievalProvider
    tools: FrozenToolExecutor
    llm_request: dict[str, Any] = field(default_factory=dict)


class ReplayLLMClient(Protocol):
    """Interface a replay-time LLM bridge implements.

    A single call produces the decision dict. The caller passes the
    resolved prompt body and the frozen inputs; the bridge is responsible
    for assembling the actual messages payload against the recorded
    request, issuing exactly ONE LLM call, and parsing the response.
    """

    async def replay_decide(
        self,
        *,
        prompt_key: str,
        prompt_version: str,
        prompt_body: str,
        frozen_inputs: FrozenInputs,
    ) -> dict[str, Any]:
        """Return the decision dict from ONE LLM call."""


class PlatformReplayLLMClient:
    """Default replay client bridge onto the platform LLM client.

    Instantiates :class:`AilaLLMClient` lazily via
    :class:`ServiceFactory` on the first call so a caller who never
    replays never pays the config/secret-store bootstrap tax. The
    messages list is taken from the recorded ``llm_request`` under the
    ``messages`` key; when it is a JSON string (the shape
    ``record_llm_call_bodies`` writes into ``platform_journal``) it is
    parsed transparently. The system prompt is REPLACED with
    ``prompt_body`` so only the prompt varies between recorded and
    replayed calls. When the recorded request has no system message a
    new one is prepended.
    """

    def __init__(
        self,
        *,
        service_factory: Any = None,
        task_type_default: str = "replay",
    ) -> None:
        self._factory_override = service_factory
        self._task_type_default = task_type_default
        self._factory_cache: Any = None

    def _factory(self) -> Any:
        if self._factory_override is not None:
            return self._factory_override
        if self._factory_cache is None:
            # Deferred import: ServiceFactory pulls the platform storage
            # graph which is unnecessary for callers that inject their
            # own client (tests, canary tools).
            from aila.platform.services.factory import ServiceFactory
            self._factory_cache = ServiceFactory()
        return self._factory_cache

    async def replay_decide(
        self,
        *,
        prompt_key: str,
        prompt_version: str,
        prompt_body: str,
        frozen_inputs: FrozenInputs,
    ) -> dict[str, Any]:
        """Issue one LLM call with the frozen request + swapped prompt."""
        del prompt_key, prompt_version  # threaded for observability; unused in default bridge
        recorded = frozen_inputs.llm_request
        messages = _extract_messages(recorded)
        task_type = str(recorded.get("task_type") or self._task_type_default)
        swapped = _swap_system_prompt(messages, prompt_body)
        client = self._factory().llm_client
        # A minimal open schema: the platform's chat_json only enforces
        # "JSON object"; the specific decision shape is module-defined
        # and the caller aggregates by field_diffs, not by strict
        # schema validation.
        schema = {"type": "object", "additionalProperties": True}
        response = await client.chat_json(task_type, swapped, schema)
        return _parse_replay_response(response.content)


def _extract_messages(recorded: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the recorded messages list, decoding the JSON-string form."""
    raw = recorded.get("messages", [])
    if isinstance(raw, list):
        return [dict(m) for m in raw if isinstance(m, dict)]
    if isinstance(raw, str):
        if not raw:
            return []
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ReplayError(
                f"recorded llm_request.messages is not decodable JSON: {exc}",
            ) from exc
        if not isinstance(decoded, list):
            raise ReplayError(
                "recorded llm_request.messages decoded to a non-list "
                f"({type(decoded).__name__})",
            )
        return [dict(m) for m in decoded if isinstance(m, dict)]
    raise ReplayError(
        "recorded llm_request has no usable messages list "
        f"(got {type(raw).__name__})",
    )


def _swap_system_prompt(
    messages: list[dict[str, Any]], prompt_body: str,
) -> list[dict[str, Any]]:
    """Return a copy of ``messages`` with the system prompt = ``prompt_body``."""
    swapped: list[dict[str, Any]] = []
    replaced = False
    for msg in messages:
        if not replaced and msg.get("role") == "system":
            new = dict(msg)
            new["content"] = prompt_body
            swapped.append(new)
            replaced = True
        else:
            swapped.append(dict(msg))
    if not replaced:
        swapped.insert(0, {"role": "system", "content": prompt_body})
    return swapped


def _parse_replay_response(content: str | None) -> dict[str, Any]:
    """Parse an LLM response body into a decision dict.

    Returns ``{"raw_text": content}`` when the body is not a JSON
    object so a replay never fabricates structured fields. Mirrors
    :func:`aila.platform.eval.transcript._parse_decision_from_response`.
    """
    if not content:
        return {"raw_text": ""}
    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _log.debug(
            "replay response not JSON-shaped (falling back to raw_text): %s",
            exc,
        )
        return {"raw_text": content}
    if isinstance(parsed, dict):
        return parsed
    return {"raw_text": content, "parsed_scalar": parsed}


class ReplayHarness:
    """Load a transcript, run frozen-input replays, produce a DecisionDiff."""

    def __init__(
        self, version_store: PromptVersionStore | None = None,
    ) -> None:
        self._store = version_store or PromptVersionStore()

    async def replay(
        self,
        *,
        transcript_id: str,
        candidate_version: str,
        llm_client: ReplayLLMClient | None = None,
    ) -> DecisionDiff:
        """See module docstring for scoring semantics."""
        transcript = await self._load_transcript(transcript_id)
        candidate_body = await self._resolve_body(
            transcript.prompt_key, candidate_version,
        )
        original_body = await self._resolve_body(
            transcript.prompt_key, transcript.prompt_version,
        )
        frozen = _freeze(transcript)
        recorded_decision = _decode_json_dict(transcript.recorded_decision_json)

        client = llm_client if llm_client is not None else PlatformReplayLLMClient()

        # Determinism: two candidate replays with byte-identical frozen
        # inputs. A serialized JSON body per replay makes the byte-match
        # comparison well-defined for the shared ``determinism_score``
        # metric (which was written for two lists of (turn, response_json)
        # pairs and reuses cleanly here with turn=0).
        replay_a = await client.replay_decide(
            prompt_key=transcript.prompt_key,
            prompt_version=candidate_version,
            prompt_body=candidate_body,
            frozen_inputs=frozen,
        )
        replay_b = await client.replay_decide(
            prompt_key=transcript.prompt_key,
            prompt_version=candidate_version,
            prompt_body=candidate_body,
            frozen_inputs=frozen,
        )
        determinism = determinism_score(
            [(0, _canonical_json(replay_a))],
            [(0, _canonical_json(replay_b))],
        )

        # Faithfulness: one replay under the ORIGINAL prompt version.
        # Compare to the recorded decision as the fraction of matching
        # keys (equal / (equal + changed + added + removed)).
        faithful_replay = await client.replay_decide(
            prompt_key=transcript.prompt_key,
            prompt_version=transcript.prompt_version,
            prompt_body=original_body,
            frozen_inputs=frozen,
        )
        diffs = decision_field_diffs(recorded_decision, faithful_replay)
        faithfulness = _match_fraction(diffs)

        return DecisionDiff(
            transcript_id=transcript.id,
            recorded_decision=recorded_decision,
            replayed_decision=faithful_replay,
            determinism_score=determinism,
            faithfulness=faithfulness,
            faithful=faithfulness == 1.0,
            field_diffs=diffs,
        )

    async def _load_transcript(self, transcript_id: str) -> EvalTranscriptRecord:
        async with async_session_scope() as session:
            try:
                row = (await session.exec(
                    select(EvalTranscriptRecord).where(
                        EvalTranscriptRecord.id == transcript_id,
                    )
                )).first()
            except SQLAlchemyError as exc:
                raise ReplayError(
                    f"transcript lookup failed for id={transcript_id!r}: {exc}",
                ) from exc
        if row is None:
            raise TranscriptNotFoundError(
                f"no eval_transcripts row with id={transcript_id!r}",
            )
        return row

    async def _resolve_body(self, key: str, version: str) -> str:
        row = await self._store.resolve(key, version=version)
        if row is None:
            raise PromptResolutionError(
                f"no registered prompt body for key={key!r} version={version!r}",
            )
        return row.body


def _freeze(transcript: EvalTranscriptRecord) -> FrozenInputs:
    """Build the FrozenInputs bundle from the transcript's stored JSON."""
    retrieval = _decode_json_list(transcript.retrieval_hits_json)
    tools = _decode_json_list(transcript.tool_outputs_json)
    request = _decode_json_dict(transcript.llm_request_json)
    return FrozenInputs(
        clock=FrozenClock(recorded_at=transcript.recorded_clock),
        retrieval=FrozenRetrievalProvider(
            recorded_hits=tuple(retrieval),
        ),
        tools=FrozenToolExecutor(
            recorded_outputs=tuple(tools),
        ),
        llm_request=request,
    )


def _decode_json_dict(raw: str) -> dict[str, Any]:
    """Decode a JSON dict or return {} on decode failure (best-effort)."""
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _log.warning("replay decode of dict payload failed: %s", exc)
        return {}
    if isinstance(decoded, dict):
        return decoded
    _log.warning(
        "replay expected dict payload but decoded to %s", type(decoded).__name__,
    )
    return {}


def _decode_json_list(raw: str) -> list[dict[str, Any]]:
    """Decode a JSON list of dicts or return [] on decode failure."""
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _log.warning("replay decode of list payload failed: %s", exc)
        return []
    if not isinstance(decoded, list):
        _log.warning(
            "replay expected list payload but decoded to %s",
            type(decoded).__name__,
        )
        return []
    return [item for item in decoded if isinstance(item, dict)]


def _canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic byte-form of a decision dict for equality scoring."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _match_fraction(diffs: dict[str, str]) -> float:
    """Fraction of decision fields that matched between recorded and replay."""
    if not diffs:
        return 1.0
    matches = sum(1 for status in diffs.values() if status == "equal")
    return matches / len(diffs)


async def replay(
    *,
    transcript_id: str,
    candidate_version: str,
    llm_client: ReplayLLMClient | None = None,
    version_store: PromptVersionStore | None = None,
) -> DecisionDiff:
    """Module-level entry: build a harness, run the replay, return the diff."""
    harness = ReplayHarness(version_store=version_store)
    return await harness.replay(
        transcript_id=transcript_id,
        candidate_version=candidate_version,
        llm_client=llm_client,
    )

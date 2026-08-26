"""dante -- the AILA console conversational agent.

Owned by the platform (not any module). Called from
:meth:`aila.platform.runtime.orchestrator.AILAPlatform.console_reply`.
It receives the operator's chat message, the prior conversation
history, and (optionally) a bound module/investigation context, then
returns a :class:`DanteReply` carrying the reply text plus zero or
more validated proposed actions the frontend can render as confirm
buttons.

The agent never mutates anything. It calls the LLM via
:class:`aila.platform.llm.client.AilaLLMClient.chat_json` with a JSON
schema for the ``{reply, actions}`` response shape, validates the raw
actions against the frozen DanteAction contract, and returns.
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from aila.platform.agents.dante.prompt import (
    _REGISTRY,
    DANTE_PROMPT_VERSION,
)
from aila.platform.llm.client import AilaLLMClient
from aila.platform.llm.correlation import correlation_scope
from aila.platform.routing.persona_model import resolve_effective_task_type

__all__ = ["DanteAgent", "DanteReply", "validate_dante_actions"]

_log = logging.getLogger(__name__)

# Base task_type dante routes through. Matches the task_type the
# ModuleRouter uses (see ``aila.platform.routing.router``); dante is a
# routing-style conversational call so it shares the operator-configured
# ``llm_model_routing`` binding by default. The persona-model router
# (req 31) is consulted in :meth:`DanteAgent.respond` to let an operator
# pin dante to a different model_role via
# ``persona_model_role_map`` without touching this constant.
_DANTE_BASE_TASK_TYPE = "routing"

_ALLOWED_MODULE_IDS = frozenset({"vr", "malware", "vulnerability", "forensics"})

# JSON-Schema for the model's structured response. Only ``kind``,
# ``label``, and ``summary`` are required on each action; the
# kind-specific params are optional at the schema level and are
# enforced (per-kind) by ``validate_dante_actions`` so we can drop
# malformed actions without failing the whole turn.
_RESPONSE_SCHEMA: dict[str, Any] = {
    "title": "DanteResponse",
    "type": "object",
    "properties": {
        "reply": {"type": "string"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": [
                            "open_wizard",
                            "enqueue_scan",
                            "create_tag",
                            "delete_tag",
                        ],
                    },
                    "label": {"type": "string"},
                    "summary": {"type": "string"},
                    "module_id": {"type": "string"},
                    "target_id": {"type": ["string", "null"]},
                    "query": {"type": "string"},
                    "system_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "key": {"type": "string"},
                },
                "required": ["kind", "label", "summary"],
            },
        },
    },
    "required": ["reply", "actions"],
}


@dataclass(frozen=True, slots=True)
class DanteReply:
    """Return value of :meth:`DanteAgent.respond`.

    ``text`` is the conversational reply shown in the chat. ``actions``
    is the validated list of DanteAction dicts to persist on the
    assistant message and hand back to the frontend.
    """

    text: str
    actions: list[dict[str, Any]] = field(default_factory=list)


def _clean_str(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _clean_optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _clean_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str):
            stripped = item.strip()
            if stripped:
                out.append(stripped)
    return out


def _validate_one(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a normalized DanteAction dict, or ``None`` if it fails
    the frozen contract for its ``kind``.

    Every valid action carries ``kind``, ``label``, ``summary``, plus
    exactly the kind-specific params defined in the contract; other
    incoming fields are dropped.
    """
    kind = _clean_str(raw.get("kind"))
    label = _clean_str(raw.get("label"))
    summary = _clean_str(raw.get("summary"))
    if not kind or not label or not summary:
        return None
    # Cap label length at 60 chars per the frozen contract.
    if len(label) > 60:
        label = label[:60]

    base: dict[str, Any] = {"kind": kind, "label": label, "summary": summary}

    if kind == "open_wizard":
        module_id = _clean_str(raw.get("module_id"))
        if module_id not in _ALLOWED_MODULE_IDS:
            return None
        base["module_id"] = module_id
        target_id = _clean_optional_str(raw.get("target_id"))
        base["target_id"] = target_id
        return base

    if kind == "enqueue_scan":
        query = _clean_str(raw.get("query"))
        if not query:
            return None
        base["query"] = query
        system_ids = _clean_str_list(raw.get("system_ids"))
        if system_ids:
            base["system_ids"] = system_ids
        return base

    if kind in ("create_tag", "delete_tag"):
        key = _clean_str(raw.get("key"))
        if not key:
            return None
        base["key"] = key
        return base

    # Unknown kind -- schema enum should already reject it, but be
    # defensive against a lenient provider.
    return None


def validate_dante_actions(raw_actions: object) -> list[dict[str, Any]]:
    """Filter a raw actions payload down to valid, contract-shaped rows.

    Every returned dict is safe to persist as ``actions_json`` and to
    return in the API response.
    """
    if not isinstance(raw_actions, list):
        return []
    validated: list[dict[str, Any]] = []
    for entry in raw_actions:
        if not isinstance(entry, Mapping):
            continue
        cleaned = _validate_one(entry)
        if cleaned is not None:
            validated.append(cleaned)
    return validated


def _fallback_reply(reason: str) -> DanteReply:
    _log.debug("dante fallback: %s", reason)
    return DanteReply(
        text=(
            "I could not produce a response this turn. Try rephrasing "
            "the request, or check that the platform LLM is enabled."
        ),
        actions=[],
    )


class DanteAgent:
    """Console conversational agent.

    Not a singleton -- built fresh per-call inside
    :meth:`AILAPlatform.console_reply`. Holds a reference to the shared
    :class:`AilaLLMClient` so it can issue a JSON-schema-guided
    ``chat_json`` request.
    """

    def __init__(
        self,
        *,
        client: AilaLLMClient,
        config_registry: object | None = None,
    ) -> None:
        self._client = client
        # ``config_registry`` is accepted for symmetry with other agents
        # but dante does not read module-scoped config; the reference
        # keeps a future extension path open without changing the call
        # site.
        self._config_registry = config_registry

    async def respond(
        self,
        *,
        query: str,
        history: Sequence[Mapping[str, str]],
        team_id: str | None = None,
        bound_module_id: str | None = None,
        bound_investigation_id: str | None = None,
    ) -> DanteReply:
        """Run one dante turn and return the validated reply.

        ``history`` is the prior conversation as ``{role, content}``
        entries (roles are ``"user"`` or ``"assistant"``). ``query`` is
        the new operator message. Bound-case context is appended to
        the system prompt when the operator is chatting from inside a
        module investigation view.
        """
        loaded = await _REGISTRY.resolve("dante")
        base_prompt = loaded.body
        system_prompt = base_prompt
        if bound_investigation_id:
            module_hint = bound_module_id or "unknown"
            system_prompt = (
                f"{base_prompt}\n\n"
                f"Console context: the operator is currently viewing "
                f"investigation {bound_investigation_id} in the "
                f"{module_hint} module. The module worker owns that "
                "investigation's deep analysis. You advise at the "
                "console level -- for example, propose opening the "
                "module wizard, review a finding with the operator, "
                "or answer questions about the module -- but do not "
                "restart or drive the investigation yourself."
            )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
        ]
        for turn in history:
            role = turn.get("role") if isinstance(turn, Mapping) else None
            content = turn.get("content") if isinstance(turn, Mapping) else None
            if role in ("user", "assistant") and isinstance(content, str) and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": query})

        try:
            effective_task_type = await resolve_effective_task_type(
                _DANTE_BASE_TASK_TYPE,
                "dante",
                module_id="platform",
            )
        except (RuntimeError, ValueError, TypeError, KeyError):
            _log.exception(
                "dante: failed to resolve effective task_type; "
                "falling back to base=%s",
                _DANTE_BASE_TASK_TYPE,
            )
            effective_task_type = _DANTE_BASE_TASK_TYPE

        # RFC-09: stamp the (cost, prompt) join keys for this console turn.
        # dante is not investigation-scoped, so only the prompt attribution
        # pair is supplied; the hash is over the exact system prompt sent.
        prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
        try:
            with correlation_scope(
                prompt_content_hash=prompt_hash,
                prompt_version=DANTE_PROMPT_VERSION,
            ):
                response = await self._client.chat_json(
                    effective_task_type,
                    messages,
                    _RESPONSE_SCHEMA,
                    team_id=team_id,
                )
        except (RuntimeError, ValueError, TypeError, KeyError, OSError):
            _log.exception("dante: chat_json call failed")
            return _fallback_reply("chat_json raised")

        if response.disabled:
            return DanteReply(
                text=(
                    "The platform LLM is currently disabled. An admin "
                    "can re-enable it under platform config."
                ),
                actions=[],
            )

        raw = response.content or ""
        if not raw.strip():
            return _fallback_reply("empty content")

        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            _log.warning("dante: failed to parse JSON response: %r", raw[:200])
            # Treat a non-JSON reply as pure conversational text so the
            # operator still sees the model's words instead of a
            # canned error.
            return DanteReply(text=raw.strip(), actions=[])

        if not isinstance(parsed, Mapping):
            return _fallback_reply("response was not an object")

        reply_text = _clean_str(parsed.get("reply"))
        if not reply_text:
            reply_text = "(no reply)"
        actions = validate_dante_actions(parsed.get("actions"))
        return DanteReply(text=reply_text, actions=actions)

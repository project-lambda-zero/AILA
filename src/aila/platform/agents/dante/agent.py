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
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text

from aila.platform.agents.dante.prompt import (
    _REGISTRY,
    DANTE_PROMPT_VERSION,
)
from aila.platform.llm.client import AilaLLMClient
from aila.platform.llm.correlation import correlation_scope
from aila.platform.llm.errors import LLMError
from aila.platform.routing.persona_model import resolve_effective_task_type
from aila.storage.database import async_session_scope

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
                            "steer_investigation",
                        ],
                    },
                    "label": {"type": "string"},
                    "summary": {"type": "string"},
                    "module_id": {"type": "string"},
                    "target_id": {"type": ["string", "null"]},
                    "investigation_id": {"type": ["string", "null"]},
                    "steering_text": {"type": ["string", "null"]},
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

    if kind == "steer_investigation":
        inv_id = _clean_str(raw.get("investigation_id"))
        steering_text = _clean_str(raw.get("steering_text"))
        if not inv_id or not steering_text:
            return None
        base["investigation_id"] = inv_id
        base["steering_text"] = steering_text
        mod = _clean_str(raw.get("module_id")) or "vr"
        base["module_id"] = mod if mod in _ALLOWED_MODULE_IDS else "vr"
        target_id = _clean_optional_str(raw.get("target_id"))
        if target_id:
            base["target_id"] = target_id
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


async def _build_investigations_context(
    query: str = "",
    team_id: str | None = None,
    bound_investigation_id: str | None = None,
) -> str:
    """Build real-time summary of active and recent investigations for Dante."""
    del team_id
    lines: list[str] = [
        "## Real-Time Platform Investigations Summary (LIVE DATA)",
        "The following active investigations are currently loaded in platform memory and database:",
        "CRITICAL INSTRUCTION: You HAVE full real-time access to the investigations below. When the operator asks about any investigation by name, short-code (e.g. VR-E8A5, VR-1E14), or UUID, ALWAYS report the factual details provided below. NEVER state that you lack access to investigations data.",
    ]

    # Look for short-code patterns or UUID prefixes in query or bound ID (e.g. VR-E8A5, e8a52875)
    matched_prefixes: list[str] = []
    if bound_investigation_id:
        matched_prefixes.append(bound_investigation_id[:4].lower())
        matched_prefixes.append(bound_investigation_id.lower())

    for m in re.finditer(r"(?:VR|MW|FOR)-([0-9a-fA-F]{4})", query):
        matched_prefixes.append(m.group(1).lower())
    for m in re.finditer(r"\b([0-9a-fA-F]{4,8})\b", query):
        matched_prefixes.append(m.group(1).lower())

    try:
        async with async_session_scope() as db:
            # 1. VR investigations query
            vr_q = text("""
                SELECT i.id, i.status, i.title, i.initial_question, i.strategy_family, i.target_id,
                       t.display_name, t.kind as target_kind, t.analysis_state
                FROM vr_investigations i
                LEFT JOIN vr_targets t ON i.target_id = t.id
                ORDER BY i.created_at DESC
                LIMIT 6
            """)
            vr_res = list((await db.exec(vr_q)).all())

            # Targeted VR lookups if matched
            for prefix in matched_prefixes:
                t_q = text("""
                    SELECT i.id, i.status, i.title, i.initial_question, i.strategy_family, i.target_id,
                           t.display_name, t.kind as target_kind, t.analysis_state
                    FROM vr_investigations i
                    LEFT JOIN vr_targets t ON i.target_id = t.id
                    WHERE i.id LIKE :p
                    LIMIT 2
                """).bindparams(p=f"{prefix}%")
                t_res = list((await db.exec(t_q)).all())
                vr_res.extend(t_res)

            # Dedup VR records
            seen_vr: set[str] = set()
            dedup_vr: list[Any] = []
            for r in vr_res:
                if r[0] not in seen_vr:
                    seen_vr.add(r[0])
                    dedup_vr.append(r)

            if dedup_vr:
                lines.append("\n### Vulnerability Research (VR) Investigations:")
                for r in dedup_vr:
                    inv_id, status, title, init_q, strategy, target_id, t_name, t_kind, t_state = r
                    short_code = f"VR-{inv_id[:4].upper()}"
                    target_desc = f"{t_name} ({t_kind}, state: {t_state})" if t_name else "target pending"
                    lines.append(
                        f"- [{short_code}] (UUID: {inv_id})\n"
                        f"  * Status: {status}\n"
                        f"  * Target: {target_desc} (target_id: {target_id})\n"
                        f"  * Strategy: {strategy}\n"
                        f"  * Title: {title or 'Untitled'}\n"
                        f"  * Question: {init_q or 'N/A'}"
                    )

            # 2. Malware investigations
            try:
                mw_q = text("""
                    SELECT i.id, i.status, i.title, t.display_name, t.kind as target_kind
                    FROM malware_investigations i
                    LEFT JOIN malware_targets t ON i.target_id = t.id
                    ORDER BY i.created_at DESC
                    LIMIT 4
                """)
                mw_res = list((await db.exec(mw_q)).all())
                if mw_res:
                    lines.append("\n### Malware Investigations:")
                    for r in mw_res:
                        inv_id, status, title, t_name, t_kind = r
                        short_code = f"MW-{inv_id[:4].upper()}"
                        target_desc = f"{t_name} ({t_kind})" if t_name else "sample pending"
                        lines.append(
                            f"- [{short_code}] (UUID: {inv_id})\n"
                            f"  * Status: {status}\n"
                            f"  * Target: {target_desc}\n"
                            f"  * Title: {title or 'Untitled'}"
                        )
            except (RuntimeError, ValueError, OSError):
                _log.debug("dante: malware query skipped")

            # 3. Forensics investigations
            try:
                for_q = text("""
                    SELECT id, status, question
                    FROM forensics_investigations
                    ORDER BY created_at DESC
                    LIMIT 4
                """)
                for_res = list((await db.exec(for_q)).all())
                if for_res:
                    lines.append("\n### Forensics Investigations:")
                    for r in for_res:
                        inv_id, status, question = r
                        short_code = f"FOR-{inv_id[:4].upper()}"
                        lines.append(
                            f"- [{short_code}] (UUID: {inv_id})\n"
                            f"  * Status: {status}\n"
                            f"  * Question: {question or 'N/A'}"
                        )
            except (RuntimeError, ValueError, OSError, KeyError, TypeError, AttributeError) as e:
                _log.debug("dante: forensics query skipped: %s", e)

    except (RuntimeError, ValueError, OSError, KeyError, TypeError) as exc:
        _log.warning("dante: failed to query investigations context: %s", exc)

    return "\n".join(lines)


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
        inv_context = await _build_investigations_context(
            query=query,
            team_id=team_id,
            bound_investigation_id=bound_investigation_id,
        )
        system_prompt = f"{inv_context}\n\n---\n\n{base_prompt}"
        if bound_investigation_id:
            module_hint = bound_module_id or "unknown"
            system_prompt += (
                f"\n\nConsole context: the operator is currently viewing "
                f"investigation {bound_investigation_id} in the "
                f"{module_hint} module. The module worker owns that "
                "investigation's deep analysis. You advise at the "
                "console level -- for example, propose opening the "
                "module wizard, review a finding with the operator, "
                "or steer the investigation when requested -- but do not "
                "restart the investigation yourself."
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
        except LLMError as exc:
            _log.warning("dante: chat_json raised LLMError (%s) -- falling back to plain chat", exc)
            try:
                with correlation_scope(
                    prompt_content_hash=prompt_hash,
                    prompt_version=DANTE_PROMPT_VERSION,
                ):
                    response = await self._client.chat(
                        effective_task_type,
                        messages,
                        team_id=team_id,
                    )
            except (LLMError, RuntimeError, ValueError, TypeError, KeyError, OSError) as chat_exc:
                _log.exception("dante: plain chat fallback failed: %s", chat_exc)
                return _fallback_reply(f"chat failed: {chat_exc}")
        except (RuntimeError, ValueError, TypeError, KeyError, OSError) as exc:
            _log.exception("dante: chat_json call failed: %s", exc)
            return _fallback_reply(f"chat_json raised: {exc}")

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

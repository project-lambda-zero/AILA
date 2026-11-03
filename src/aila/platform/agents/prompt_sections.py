"""Byte-stable prompt and outcome helpers shared by reasoning modules."""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningTurnDecision,
)
from aila.platform.mcp.adapters import KNOWN_TOOLS, specialized_tools
from aila.platform.mcp.adapters.known_tools import tools_for_language
from aila.platform.prompts import PromptNotFoundError

__all__ = [
    "PROMPT_CONFIDENCE_RANK",
    "format_param",
    "load_prompt_seed_from_file",
    "outcome_payload",
    "render_active_directives_section",
    "render_available_tools_section",
    "render_operator_messages_section",
    "render_pattern_section",
    "render_retrieved_knowledge_section",
]


_PATTERN_SECTION_BUDGET = 3000
_RETRIEVED_SECTION_BUDGET: int = 4000

PROMPT_CONFIDENCE_RANK = {
    "exact": 0, "strong": 1, "medium": 2,
    "caveated": 3, "weak": 4, "unknown": 5,
}


def render_pattern_section(patterns: list[dict[str, Any]]) -> str:
    """Render reusable patterns from prior investigations."""
    if not patterns:
        return ""
    header = (
        "# Applicable patterns from prior investigations\n\n"
        "These patterns were extracted from successful prior investigations on\n"
        "similar targets. Use them to guide your hypothesis formation and tool\n"
        "selection -- they represent proven techniques.\n\n"
    )
    lines: list[str] = []
    used = len(header)
    for p in patterns:
        title = str(p.get("summary") or "(untitled pattern)").strip()
        kind = str(p.get("kind") or "unknown").strip()
        body = str(p.get("body") or "").strip()
        block = f"## Pattern: {title}\nKind: {kind}\n"
        if body:
            block += f"{body}\n"
        block += "\n"
        if used + len(block) > _PATTERN_SECTION_BUDGET:
            remaining = _PATTERN_SECTION_BUDGET - used
            if remaining > 80:
                lines.append(block[: remaining - 4] + "...\n")
            break
        lines.append(block)
        used += len(block)
    if not lines:
        return ""
    return header + "".join(lines)


def render_retrieved_knowledge_section(
    hits: list[dict[str, Any]],
    *,
    header: str,
) -> str:
    """Render bounded prior knowledge using the module's exact header."""
    if not hits:
        return ""
    lines: list[str] = []
    used = len(header)
    for h in hits:
        namespace = str(h.get("namespace") or "")
        parts = namespace.split(".")
        kind = parts[1] if len(parts) > 1 else (namespace or "knowledge")
        score = h.get("score")
        content = str(h.get("content") or "").strip()
        if not content:
            continue
        score_str = f" (relevance {float(score):.2f})" if isinstance(score, (int, float)) else ""
        block = f"## {kind}{score_str}\n{content}\n\n"
        if used + len(block) > _RETRIEVED_SECTION_BUDGET:
            remaining = _RETRIEVED_SECTION_BUDGET - used
            if remaining > 80:
                lines.append(block[: remaining - 4] + "...\n")
            break
        lines.append(block)
        used += len(block)
    if not lines:
        return ""
    return header + "".join(lines)


def render_operator_messages_section(messages: list[dict[str, Any]]) -> str:
    """Render pending operator messages as a mandatory prompt section."""
    if not messages:
        return ""
    lines: list[str] = [
        "# *** OPERATOR STEERING -- MANDATORY OVERRIDE ***",
        "",
        "The human operator sent these messages. They override the",
        "default strategy, override your current hypothesis, and override",
        "any prior tool-selection plan. Read each one, decide what action",
        "it dictates, and make that your next move. Ignoring a steering",
        "message is a contract violation.",
        "",
        "ACK CONTRACT: after you actually act on a steering message,",
        "include its id in your decision's observables under the",
        "reserved key `_acked_operator_messages` as a JSON list of",
        "strings (one id per element). Acknowledged messages stop",
        "appearing on subsequent turns. ONLY ACK after acting --",
        "premature ACK loses the steering forever. fix §333 --",
        "canonical shape is a list; the comma-separated string shape",
        "is still accepted at read time for legacy case_state rows but",
        "MUST NOT be emitted by new decisions.",
        "Example: observables: {\"_acked_operator_messages\":",
        "[\"<id1>\", \"<id2>\"]}",
        "",
    ]
    for entry in messages:
        intent = entry.get("intent") or "unclassified"
        text = entry.get("text") or ""
        msg_id = entry.get("id") or "?"
        lines.append(f"- [id={msg_id} intent={intent}] {text}")
    lines.append("")
    lines.append("*** END OPERATOR STEERING ***")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_active_directives_section(case_state: ReasoningCaseState) -> str:
    """Render non-empty ``_directive.*`` observables in insertion order."""
    directives = {
        k: v for k, v in case_state.observables.items()
        if k.startswith("_directive.") and isinstance(v, str) and v.strip()
    }
    if not directives:
        return ""
    lines: list[str] = [
        "# *** ACTIVE DIRECTIVES (MANDATORY -- act on these THIS TURN) ***",
        "",
    ]
    for key, value in directives.items():
        label = key[len("_directive."):]
        lines.append(f"## directive: {label}")
        lines.append(value.rstrip())
        lines.append("")
    lines.append("*** END DIRECTIVES ***")
    lines.append("")
    return "\n".join(lines) + "\n"


def format_param(param: dict[str, Any]) -> str:
    """Render one parameter as its exact call signature."""
    name = param.get("name", "?")
    ptype = param.get("type", "any")
    if param.get("required"):
        return f"{name}: {ptype} [required]"
    if "default" in param:
        default = param["default"]
        rendered = json.dumps(default)
        if len(rendered) > 60:
            rendered = rendered[:57] + "..."
        return f"{name}: {ptype} = {rendered}"
    return f"{name}: {ptype}"


def render_available_tools_section(
    target_kind: str | None = None,
    tool_specs: dict[str, list[dict[str, Any]]] | None = None,
    primary_language: str | None = None,
    applicable_servers: set[str] | None = None,
    *,
    applicable_servers_for_kind: Callable[[str | None], set[str]],
) -> str:
    """Render applicable MCP tools with live schemas when available."""
    specialized = set(specialized_tools())
    if applicable_servers is not None:
        applicable = set(applicable_servers)
    else:
        applicable = set(applicable_servers_for_kind(target_kind))
    applicable.add("knowledge")
    specs_by_server = tool_specs or {}
    parts: list[str] = ["# Available tools\n"]
    if target_kind:
        parts.append(
            f"\nTarget kind: `{target_kind}` -- only servers applicable "
            f"to this kind are listed below. Use the **exact** "
            f"parameter names shown in each signature; the bridge "
            f"rejects unknown kwargs.\n",
        )
    for server in sorted(KNOWN_TOOLS):
        if server not in applicable:
            continue

        live_specs = specs_by_server.get(server) or []
        if live_specs:
            parts.append(
                f"\n## {server} ({len(live_specs)} tools -- live schema)\n\n",
            )
            for spec in sorted(live_specs, key=lambda s: s.get("name", "")):
                tool_name = spec.get("name", "?")
                full = f"{server}.{tool_name}"
                marker = " [structured]" if full in specialized else ""
                params = spec.get("params") or []
                signature = ", ".join(format_param(p) for p in params)
                parts.append(f"- `{full}({signature})`{marker}\n")
            parts.append("\n")
        else:
            tool_names = sorted(tools_for_language(server, primary_language))
            parts.append(
                f"\n## {server} ({len(tool_names)} tools -- "
                f"schema unavailable)\n\n",
            )
            for name in tool_names:
                full = f"{server}.{name}"
                marker = " [structured]" if full in specialized else ""
                parts.append(f"- `{full}`{marker}\n")
            parts.append("\n")
    return "".join(parts)


def outcome_payload(decision: ReasoningTurnDecision) -> dict[str, Any]:
    """Build the outcome payload, with structured keys taking precedence."""
    base: dict[str, Any] = {
        "answer": decision.answer or "",
        "reasoning": decision.reasoning,
        "provenance": decision.provenance.model_dump(mode="json"),
        "contract": (
            decision.contract.model_dump(mode="json") if decision.contract else None
        ),
    }
    structured = decision.payload or {}
    for k, v in structured.items():
        base[k] = v
    return base


def load_prompt_seed_from_file(
    strategy_family: str,
    persona_voice: str | None = None,
    *,
    prompt_dir: Path,
    fallback_base: str,
    error_label: str,
) -> str:
    """Read a module prompt seed with its declared fallback and error label."""
    leaf = strategy_family.rsplit(".", 1)[-1]
    base_path = prompt_dir / f"system_{leaf}.md"
    if not base_path.exists():
        base_path = prompt_dir / fallback_base
    if not base_path.exists():
        raise PromptNotFoundError(f"{error_label}: {base_path}")
    base = base_path.read_text(encoding="utf-8")
    if not persona_voice:
        return base
    persona_path = prompt_dir / f"persona_{persona_voice.lower()}.md"
    if not persona_path.exists():
        return base
    persona_prefix = persona_path.read_text(encoding="utf-8")
    return f"{persona_prefix}\n\n---\n\n{base}"

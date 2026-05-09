"""Data classification pipeline step for LLM prompts.

Scans every message for sensitive patterns (IPs, hostnames, SSH keys,
credentials) and classifies the prompt as PUBLIC, INTERNAL, or RESTRICTED.
Runs as the first pre-call step in the pipeline.

RESTRICTED behavior is operator-configurable:
  - fail (default): raise ClassificationBlockedError, blocking the API call.
  - redact: replace sensitive tokens with [REDACTED-*] tags and continue.

Data posture modes (Phase 173) alter classification behavior:
  - transparent: skip classification entirely, mark as PUBLIC.
  - standard (default): full classification with per-task-type config.
  - paranoid: full classification, always redact RESTRICTED (never fail).

Audit events are emitted for every classification. No prompt content is
stored in audit records (D-13).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from .errors import ClassificationBlockedError

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry
    from ..events.emitter import EventEmitter
    from .config import LLMRouting

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Classification levels (D-04)
# ---------------------------------------------------------------------------

class ClassificationLevel(IntEnum):
    """Ordered classification levels. Higher value = more sensitive."""

    PUBLIC = 0
    INTERNAL = 1
    RESTRICTED = 2


# ---------------------------------------------------------------------------
# Pattern dataclass and registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SensitivePattern:
    """A compiled regex pattern with its classification level and redaction tag."""

    name: str
    regex: re.Pattern[str]
    level: ClassificationLevel
    redact_tag: str


# Module-level registry -- built-in patterns compiled at import time
_PATTERNS: list[SensitivePattern] = []
_PATTERNS_BY_NAME: dict[str, SensitivePattern] = {}

# File extensions to exclude from FQDN matches (Pitfall 3)
_FILE_EXTENSIONS: frozenset[str] = frozenset({
    "py", "json", "tar", "gz", "yaml", "toml", "md", "txt", "csv", "log",
    "xml", "html", "js", "ts", "css", "sh", "bat", "exe", "dll", "so",
    "zip", "pdf", "cfg", "ini", "conf", "bak", "tmp", "lock", "whl",
    "rst", "png", "jpg", "jpeg", "gif", "svg", "ico",
})

# Version-like pattern: v1.2.3, 2.0.0, etc.
_VERSION_RE = re.compile(r"^v?\d+\.\d+")


def register_pattern(
    name: str,
    regex: str,
    level: ClassificationLevel,
    redact_tag: str,
) -> None:
    """Register a new sensitive pattern. Called at startup for extensions."""
    pattern = SensitivePattern(
        name=name,
        regex=re.compile(regex),
        level=level,
        redact_tag=redact_tag,
    )
    _PATTERNS.append(pattern)
    _PATTERNS_BY_NAME[pattern.name] = pattern


def _is_fqdn_false_positive(match_text: str) -> bool:
    """Check if an FQDN regex match is actually a file extension or version."""
    last_dot = match_text.rfind(".")
    if last_dot >= 0:
        suffix = match_text[last_dot + 1 :].lower()
        if suffix in _FILE_EXTENSIONS:
            return True
    return bool(_VERSION_RE.match(match_text))


# ---------------------------------------------------------------------------
# Built-in patterns (D-01, D-05, D-06, D-07)
# ---------------------------------------------------------------------------

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
_DOT_OCTET = rf"(?:{_OCTET}\.)"

# RFC1918 IPs -> RESTRICTED (D-05)
register_pattern(
    name="rfc1918_ip",
    regex=(
        r"\b(?:"
        rf"10\.{_DOT_OCTET}{{2}}{_OCTET}"
        rf"|172\.(?:1[6-9]|2\d|3[01])\.{_DOT_OCTET}{_OCTET}"
        rf"|192\.168\.{_DOT_OCTET}{_OCTET}"
        r")\b"
    ),
    level=ClassificationLevel.RESTRICTED,
    redact_tag="[REDACTED-IP]",
)

# Public IPs -> INTERNAL
register_pattern(
    name="public_ip",
    regex=rf"\b{_DOT_OCTET}{{3}}{_OCTET}\b",
    level=ClassificationLevel.INTERNAL,
    redact_tag="[REDACTED-IP]",
)

# FQDNs -> INTERNAL (minimum 3 labels: host.domain.tld)
register_pattern(
    name="fqdn",
    regex=r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b",
    level=ClassificationLevel.INTERNAL,
    redact_tag="[REDACTED-HOST]",
)

# SSH key headers -> RESTRICTED
register_pattern(
    name="ssh_key",
    regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----",
    level=ClassificationLevel.RESTRICTED,
    redact_tag="[REDACTED-KEY]",
)

# Credential patterns -> RESTRICTED (case-insensitive via (?i))
register_pattern(
    name="credential",
    regex=r"(?i)(?:password|passwd|api_key|apikey|token|secret|access_key|private_key)\s*[=:]\s*\S+",
    level=ClassificationLevel.RESTRICTED,
    redact_tag="[REDACTED-CRED]",
)

# CVE IDs -> PUBLIC (never contributes to classification escalation, D-06)
register_pattern(
    name="cve_id",
    regex=r"\bCVE-\d{4}-\d{4,}\b",
    level=ClassificationLevel.PUBLIC,
    redact_tag="",
)


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """Result of classifying a message list."""

    level: ClassificationLevel
    pattern_types: list[str]
    match_count: int


# ---------------------------------------------------------------------------
# Core classification function (D-03: scan full message list)
# ---------------------------------------------------------------------------

def classify_messages(messages: list[dict[str, Any]]) -> ClassificationResult:
    """Scan all message content and return aggregate classification.

    Iterates all messages, extracts string content (Pitfall 5: non-string
    content skipped), runs all patterns, aggregates to max level.
    """
    matched_patterns: list[tuple[str, ClassificationLevel]] = []

    for msg in messages:
        content = msg.get("content", "")
        if not content or not isinstance(content, str):
            continue

        for pattern in _PATTERNS:
            for match in pattern.regex.finditer(content):
                matched_text = match.group()

                # FQDN false positive filter (Pitfall 3)
                if pattern.name == "fqdn" and _is_fqdn_false_positive(matched_text):
                    continue

                # Skip public IPs that are actually RFC1918
                # rfc1918_ip is registered before public_ip, but public_ip
                # regex also matches RFC1918 addresses. We suppress the
                # public_ip match when the same text was already captured as
                # rfc1918_ip by checking against the rfc1918 pattern.
                if pattern.name == "public_ip":
                    rfc1918_pat = _PATTERNS_BY_NAME["rfc1918_ip"]
                    if rfc1918_pat.regex.fullmatch(matched_text):
                        continue

                matched_patterns.append((pattern.name, pattern.level))

    if not matched_patterns:
        return ClassificationResult(
            level=ClassificationLevel.PUBLIC,
            pattern_types=[],
            match_count=0,
        )

    max_level = max(p[1] for p in matched_patterns)
    triggered_names = sorted(set(p[0] for p in matched_patterns))

    return ClassificationResult(
        level=ClassificationLevel(max_level),
        pattern_types=triggered_names,
        match_count=len(matched_patterns),
    )


# ---------------------------------------------------------------------------
# Restricted behavior resolution (D-08)
# ---------------------------------------------------------------------------

async def _resolve_restricted_behavior(
    task_type: str,
    registry: ConfigRegistry,
) -> str:
    """Read restricted behavior config. Default: 'fail' (conservative)."""
    val = await registry.get(
        "platform",
        f"llm_pipeline_classify_restricted_behavior_{task_type}",
    )
    if val is not None and str(val).strip().lower() == "redact":
        return "redact"
    return "fail"


# ---------------------------------------------------------------------------
# Redaction (D-09, D-11)
# ---------------------------------------------------------------------------

def _redact_messages(
    messages: list[dict[str, Any]],
    patterns: list[SensitivePattern],
) -> int:
    """Replace sensitive tokens in messages with redaction tags.

    Only redacts RESTRICTED-level patterns (not INTERNAL or PUBLIC).
    Returns total replacement count.
    """
    redacted_count = 0
    for msg in messages:
        content = msg.get("content", "")
        if not content or not isinstance(content, str):
            continue
        for pattern in patterns:
            if pattern.level < ClassificationLevel.RESTRICTED:
                continue
            new_content, n = pattern.regex.subn(pattern.redact_tag, content)
            if n > 0:
                content = new_content
                redacted_count += n
        msg["content"] = content
    return redacted_count


# ---------------------------------------------------------------------------
# Audit event emission (D-12, D-13, CLASS-04)
# ---------------------------------------------------------------------------

def _emit_classification_event(
    ctx: dict[str, Any],
    routing: LLMRouting,
    result: ClassificationResult,
    emitter: EventEmitter | None,
) -> None:
    """Emit classification audit event. No prompt content stored (D-13)."""
    if emitter is None:
        return

    from ..events.event import PlatformEvent

    emitter.emit(
        PlatformEvent(
            stage="llm_classification",
            action="classify",
            key=f"llm.classify.{ctx['task_type']}",
            message=f"Classified as {result.level.name}",
            details={
                "classification_level": result.level.name,
                "task_type": ctx["task_type"],
                "model_id": routing.model_id,
                "provider": routing.base_url,
                "pattern_types_triggered": result.pattern_types,
                "redacted": ctx.get("redacted", False),
                "posture_mode": ctx.get("posture_mode", "standard"),
            },
        )
    )


# ---------------------------------------------------------------------------
# Pipeline step factory (D-06/116, D-10, D-11)
# ---------------------------------------------------------------------------

def make_classify_step(
    registry: ConfigRegistry,
    emitter: EventEmitter | None = None,
) -> Any:
    """Create the classify pipeline step closure.

    The returned async callable matches the StepFn protocol:
    ``async def step(ctx, messages, routing) -> None``.

    Args:
        registry: ConfigRegistry for restricted behavior config lookups.
        emitter: Optional EventEmitter for audit logging.

    Returns:
        Async step function for pipeline registration.
    """

    async def _classify_step(
        ctx: dict[str, Any],
        messages: list[dict[str, Any]],
        routing: LLMRouting,
    ) -> None:
        # Resolve data posture mode (Phase 173 -- DPM-03)
        posture = str(await registry.get("platform", "data_posture_mode") or "standard")
        ctx["posture_mode"] = posture

        # Transparent posture: skip classification entirely
        if posture == "transparent":
            ctx["classification"] = ClassificationLevel.PUBLIC.name
            if emitter:
                from ..events.event import PlatformEvent

                emitter.emit(
                    PlatformEvent(
                        stage="llm_classification",
                        action="classify",
                        key=f"llm.classify.{ctx['task_type']}",
                        message="Classification bypassed (transparent posture)",
                        details={
                            "posture_mode": "transparent",
                            "task_type": ctx["task_type"],
                            "classification_level": ClassificationLevel.PUBLIC.name,
                        },
                        run_id=ctx.get("run_id", ""),
                    )
                )
            return

        # Standard / paranoid: full classification
        result = classify_messages(messages)
        ctx["classification"] = result.level.name

        if result.level == ClassificationLevel.RESTRICTED:
            if posture == "paranoid":
                # Paranoid mode: always redact, never fail
                count = _redact_messages(messages, _PATTERNS)
                ctx["redacted"] = True
                ctx["redacted_count"] = count
            else:
                # Standard mode: use per-task-type config
                behavior = await _resolve_restricted_behavior(ctx["task_type"], registry)

                if behavior == "fail":
                    pattern_list = ", ".join(result.pattern_types)
                    _emit_classification_event(ctx, routing, result, emitter)
                    raise ClassificationBlockedError(
                        f"RESTRICTED data detected: prompt contains {pattern_list}. "
                        f"Configure llm_pipeline_classify_restricted_behavior_"
                        f"{ctx['task_type']}=redact to allow redacted send."
                    )

                # behavior == "redact"
                count = _redact_messages(messages, _PATTERNS)
                ctx["redacted"] = True
                ctx["redacted_count"] = count

        _emit_classification_event(ctx, routing, result, emitter)

    return _classify_step
